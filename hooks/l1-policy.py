#!/usr/bin/env python3
"""Claude Code PreToolUse capability-policy hook for the L1 Opus session.

Lane F (docs/l1opt/CONTRACT.md, docs/l1opt/ownership.toon).

The hook reads one Claude Code ``PreToolUse`` JSON payload on stdin and prints
one JSON object on stdout:

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "allow" | "deny" | "ask",
                            "permissionDecisionReason": "..."}}

The reason sentence starts with the decision word and ends with a stable
``[reason_code=...]``.  The sentence is prose and may be reworded; the code is
the contract, so tests and dashboards assert on the code and not on the wording.
Every code the hook can emit is listed in ``REASON_CODES``.

The policy in ``claude-hooks/policy.toon`` is a CAPABILITY allow-list, not a
blacklist: a Bash segment is allowed only when its executable is one of the
listed capabilities, a read-only git sub-command, or a reader scoped to the
home ``.claude`` directory.  Anything that reaches a remote host, a container
runtime or the network is denied with the reason ``write a brief and
dispatch``.  Compound commands (``&&``, ``||``, ``;``, ``|``, newlines,
``$( )`` and back-ticks) are split into segments and every segment is checked,
so chaining cannot smuggle a denied capability.

Three additions sit on top of the static policy:

* a soft per-session tool-call budget (warning above the soft limit, ``ask``
  above twice the soft limit, never a deny),
* ``L1_POLICY_OVERRIDE=<reason>`` which allows a call and appends a redacted
  audit line to a jsonl log,
* ``ask`` for anything the hook cannot classify, so an unrecognised tool can
  never silently widen the session.

Modes
-----

The hook runs in one of two modes, chosen by ``--mode``, else
``L1_POLICY_MODE``, else the ``mode`` key in ``policy.toon``, else
``shadow``:

``enforce``
    today's behaviour: the decision goes to stdout and Claude Code acts on it.

``shadow``
    the hook evaluates the *same* policy and reaches the *same* decision, then
    appends one redacted JSON line to the audit log (with ``"shadow": true``)
    and exits 0 with an empty stdout, so Claude Code proceeds normally and the
    deny list can be measured before it can block anybody.  Budget warnings and
    the budget ``ask`` are logged only in this mode too.

Shadow never changes what the policy decides; it only changes what the hook
says out loud.  ``decide()`` is mode-free: it is the transport that differs.

Standard library only.  No network access.
"""

import argparse
import json
import os
import re
import sys
import tempfile
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX only
    fcntl = None

VERSION = "1.1.0"
POLICY_BASENAME = "policy.toon"

ALLOW = "allow"
DENY = "deny"
ASK = "ask"

# The two hook modes. `shadow` is the default so that installing the hook can
# never block a session before it has been measured.
SHADOW = "shadow"
ENFORCE = "enforce"
MODES = (SHADOW, ENFORCE)
DEFAULT_MODE = SHADOW

MODE_ENV_VAR = "L1_POLICY_MODE"
SHADOW_LOG_ENV_VAR = "L1_POLICY_SHADOW_LOG"
AUDIT_LOG_ENV_VAR = "L1_POLICY_AUDIT_LOG"
DEFAULT_SHADOW_AUDIT_LOG = "shadow-audit.jsonl"

# The stable reason codes.  `permissionDecisionReason` is prose and may be
# reworded; the code appended to it is the contract, so a test asserts on this
# table rather than on a sentence.  code -> decision it can only produce.
REASON_CODES = {
    # Bash, allowed
    "bash.capability": ALLOW,
    "bash.git_read": ALLOW,
    "bash.claude_home_read": ALLOW,
    "bash.read_any": ALLOW,
    "bash.compound_allowed": ALLOW,
    "bash.empty": ALLOW,
    # Bash, denied
    "bash.denied.remote": DENY,
    "bash.denied.container": DENY,
    "bash.denied.network": DENY,
    "bash.denied.cluster": DENY,
    "bash.denied.host": DENY,
    "bash.denied.code": DENY,
    "bash.denied.smuggle": DENY,
    "bash.denied.git_write": DENY,
    "bash.denied.unknown": DENY,
    "bash.denied.read_guard": DENY,
    "bash.denied.lan_address": DENY,
    # Write / Edit
    "write.allowed_path": ALLOW,
    "write.denied_path": DENY,
    "write.unknown_path": ASK,
    # MCP and native tools
    "mcp.allow": ALLOW,
    "mcp.denied_remote": DENY,
    "mcp.unlisted": ASK,
    "tool.allow": ALLOW,
    "tool.denied_remote": DENY,
    "tool.ask": ASK,
    "tool.unknown": ASK,
    # budget, override and the envelope around the decision
    "budget.ask": ASK,
    "override.allow": ALLOW,
    "input.empty": ALLOW,
    "input.unreadable": ASK,
    "input.other_event": ALLOW,
    "error.internal": ASK,
}

DEFAULT_DENY_REASON = "write a brief and dispatch"
DEFAULT_DISPATCH_HINT = (
    "plan and dispatch instead: write a brief under .claude/plans and dispatch it"
)

# argv0 values that only ever wrap another program. They are denied on sight
# rather than peeled, so `sudo git status` cannot escalate past the policy.
SMUGGLE_WRAPPERS = frozenset([
    "xargs", "eval", "env", "nohup", "setsid", "command", "exec", "watch",
    "sudo", "doas", "nice", "stdbuf", "ionice", "caffeinate",
])

# Wrappers that only put a bound around exactly one command, so the command
# they wrap is still fully classified. `timeout 30 git status` is a deadline
# on git status, not a capability of its own. The wrapped argv0 goes through
# the same rules as an unwrapped one, so `timeout 30 ssh host` still denies.
PEELABLE_WRAPPERS = frozenset(["timeout"])

# Wrapper flags that consume the next argument as their value. Peeling has to
# step over the value too, or `timeout -s TERM 5 git status` would classify
# `TERM` as the command.
WRAPPER_VALUE_FLAGS = frozenset(["-k", "--kill-after", "-s", "--signal"])

# Shell redirection operators. parse_commands() keeps one as a token of its
# own so that a redirect belonging to a loop or a conditional is recognised
# as syntax rather than mistaken for a program name.
REDIRECT_OPERATOR_RE = re.compile(r"^&?[<>]{1,2}[&>]*$")

# `timeout`'s duration operand: 30, 5s, 1m30s, 2h, 1h2m30s ...
_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?(?:\d+(?:\.\d+)?[smhd]?)*$")

# Leading shell keywords that are syntax, not programs. `parse_commands()`
# splits a loop into `for f in a b` / `do <body>` / `done` / `while <cond>`,
# so the header and the terminator are recognised before argv0 is.
SHELL_KEYWORDS = frozenset([
    "if", "then", "elif", "else", "fi", "while", "until", "for", "do", "done",
    "case", "esac", "select", "function", "time",
])

# Words that introduce a variable assignment rather than a program.
SHELL_ASSIGNMENT_KEYWORDS = frozenset([
    "export", "readonly", "declare", "typeset", "local",
])

# Keywords whose whole segment is a header. The list they introduce runs to the
# separator that `parse_commands()` already split on, so nothing in the segment
# is a program and the whole thing is dropped.
WHOLE_HEADER_KEYWORDS = frozenset(["for", "case", "select"])

# awk keywords after which `<` and `>` redirect rather than compare.
AWK_OUTPUT_KEYWORDS = frozenset(["print", "printf"])

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

GIT_GLOBAL_VALUE_FLAGS = frozenset([
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
])

WRITE_TOOL_NAMES = frozenset(["Write", "Edit", "MultiEdit", "NotebookEdit"])

REDACTED = "<redacted>"

_SECRET_TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"),
)


# ---------------------------------------------------------------------------
# TOON reader (the subset policy.toon uses)
# ---------------------------------------------------------------------------


class PolicyError(Exception):
    """Raised when policy.toon cannot be understood at all."""


def _split_toon_row(line):
    """Split one tabular row into fields, honouring TOON double quotes."""
    fields = []
    buf = []
    quoted = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quoted:
            if ch == "\\" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                quoted = False
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not buf:
            quoted = True
            i += 1
            continue
        if ch == ",":
            fields.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    fields.append("".join(buf))
    return fields


def _strip_comment(line):
    """Drop a trailing `# ...` comment that is not inside a quoted field."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            quoted = not quoted
        elif ch == "#" and not quoted and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


_TABLE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)\[(?P<count>\d+)\]\{([^}]*)\}:\s*$"
)


def parse_toon(text):
    """Parse the scalar/tabular TOON subset used by policy.toon.

    Returns ``{"scalars": {key: value}, "tables": {name: {"fields": [...],
    "rows": [[...]], "declared": int}}}``.
    """
    scalars = {}
    tables = {}
    current = None
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        indented = line[:1] in (" ", "\t")
        if indented and current is not None:
            current["rows"].append(_split_toon_row(stripped))
            continue
        current = None
        header = _TABLE_RE.match(stripped)
        if header:
            fields = [f.strip() for f in header.group(3).split(",")]
            current = {
                "fields": fields,
                "rows": [],
                "declared": int(header.group("count")),
            }
            tables[header.group("name")] = current
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            scalars[key.strip()] = value.strip().strip('"')
            continue
        raise PolicyError("cannot parse policy line: %r" % stripped)
    return {"scalars": scalars, "tables": tables}


# ---------------------------------------------------------------------------
# glob matching with real ** semantics
# ---------------------------------------------------------------------------


def glob_match(pattern, text):
    """Match `text` against `pattern`, where `**` also crosses `/`."""
    return _glob_match(pattern, 0, text, 0, {})


def _glob_match(pat, pi, text, ti, memo):
    key = (pi, ti)
    if key in memo:
        return memo[key]
    if pi == len(pat):
        result = ti == len(text)
    elif pat.startswith("**", pi):
        rest = pi + 2
        if rest < len(pat) and pat[rest] == "/":
            rest += 1
            result = _glob_match(pat, rest, text, ti, memo) or (
                ti < len(text) and _glob_match(pat, pi, text, ti + 1, memo)
            )
        else:
            result = _glob_match(pat, rest, text, ti, memo) or (
                ti < len(text) and _glob_match(pat, pi, text, ti + 1, memo)
            )
    elif ti == len(text):
        result = False
    else:
        ch = pat[pi]
        if ch == "*":
            result = _glob_match(pat, pi + 1, text, ti + 1, memo)
        elif ch == "?":
            result = _glob_match(pat, pi + 1, text, ti + 1, memo)
        elif ch == "[":
            close = pat.find("]", pi)
            if close == -1:
                result = pat[pi] == text[ti] and _glob_match(pat, pi + 1, text, ti + 1, memo)
            else:
                body = pat[pi + 1:close]
                negate = body.startswith("!")
                if negate:
                    body = body[1:]
                hit = text[ti] in body
                result = (hit != negate) and _glob_match(pat, close + 1, text, ti + 1, memo)
        else:
            result = ch == text[ti] and _glob_match(pat, pi + 1, text, ti + 1, memo)
    memo[key] = result
    return result


# ---------------------------------------------------------------------------
# shell splitting
# ---------------------------------------------------------------------------


def _extract_balanced(text, start):
    """Return (inner, index_after_close) for the `(` at `start`, quote aware."""
    depth = 0
    i = start
    n = len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            if quote == "'":
                if ch == "'":
                    quote = None
            elif ch == "\\" and i + 1 < n:
                i += 2
                continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    return text[start + 1:], n


def parse_heredoc(command, start):
    """Return the index just after the heredoc that begins at `start`.

    `start` points at the `<` of a `<<`.  The heredoc body is data, never a
    command, so it is skipped up to and including the delimiter line; parsing
    then resumes on the next line, which means a command trailing a heredoc is
    still split out and checked on its own.  `<<<` is a herestring: the rest of
    the operator line is data too.
    """
    n = len(command)
    i = start + 2
    if i < n and command[i] == "<":
        end = command.find("\n", i)
        return n if end == -1 else end
    strip_tabs = False
    if i < n and command[i] == "-":
        strip_tabs = True
        i += 1
    while i < n and command[i] in " \t":
        i += 1
    quote = None
    if i < n and command[i] in ("'", '"'):
        quote = command[i]
        i += 1
    delimiter = []
    while i < n and command[i] not in " \t;|&<>\n":
        if quote and command[i] == quote:
            quote = None
            i += 1
            continue
        delimiter.append(command[i])
        i += 1
    word = "".join(delimiter)
    end = command.find("\n", i)
    if not word or end == -1:
        return n if end == -1 else end
    i = end + 1
    while i < n:
        end = command.find("\n", i)
        line = command[i:] if end == -1 else command[i:end]
        probe = line.lstrip("\t") if strip_tabs else line
        if probe == word:
            return n if end == -1 else end + 1
        if end == -1:
            return n
        i = end + 1
    return n


def parse_commands(command):
    """Split a shell line into segments.

    Returns a list of token lists.  Every construct that could start another
    program (`&&`, `||`, `;;`, `;`, `|`, `&`, newline, `$( )`, back-ticks)
    produces a new entry, and each substitution is split recursively.
    """
    segments = []
    current = []
    word = []
    quote = None
    i = 0
    n = len(command)

    def flush_word():
        if word:
            current.append("".join(word))
            del word[:]

    def flush_segment():
        flush_word()
        if current:
            segments.append(list(current))
            del current[:]

    while i < n:
        ch = command[i]
        if quote == "'":
            if ch == "'":
                quote = None
            else:
                word.append(ch)
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < n and command[i + 1] in '"\\$`':
                word.append(command[i + 1])
                i += 2
                continue
            if ch == '"':
                quote = None
                i += 1
                continue
            if ch == "$" and i + 1 < n and command[i + 1] == "(":
                flush_word()
                inner, i = _extract_balanced(command, i + 1)
                segments.extend(parse_commands(inner))
                continue
            word.append(ch)
            i += 1
            continue
        # unquoted
        if ch == "\\":
            if i + 1 < n:
                word.append(command[i + 1])
                i += 2
                continue
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "`":
            flush_word()
            j = command.find("`", i + 1)
            if j == -1:
                segments.extend(parse_commands(command[i + 1:]))
                i = n
            else:
                segments.extend(parse_commands(command[i + 1:j]))
                i = j + 1
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            flush_word()
            inner, i = _extract_balanced(command, i + 1)
            segments.extend(parse_commands(inner))
            continue
        if ch == "#" and not word:
            j = command.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch in " \t":
            flush_word()
            i += 1
            continue
        if ch == "\n":
            flush_segment()
            i += 1
            continue
        if command.startswith("&&", i) or command.startswith("||", i) or command.startswith(";;", i):
            flush_segment()
            i += 2
            continue
        if ch in ";|&":
            flush_segment()
            i += 1
            continue
        if ch in "<>":
            # redirection: keep the operator as a token of its own and the
            # target as the next one, so a redirect that belongs to a shell
            # construct (`while read l; do wc -l $l; done < list.txt`) stays
            # visible instead of looking like a bare unknown word.
            if command.startswith("<<", i):
                # a heredoc body is data, never a command
                flush_segment()
                i = parse_heredoc(command, i)
                continue
            flush_word()
            j = i + 1
            if j < n and command[j] == ">":
                j += 1
            if j < n and command[j] in "<>&":
                j += 1
            current.append(command[i:j])
            i = j
            while i < n and command[i] in " \t":
                i += 1
            while i < n and command[i] not in " \t;|&<>\n":
                word.append(command[i])
                i += 1
            continue
        word.append(ch)
        i += 1
    flush_segment()
    return segments


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def _table_rows(doc, name):
    table = doc["tables"].get(name)
    if table is None:
        return []
    fields = table["fields"]
    out = []
    for row in table["rows"]:
        padded = list(row) + [""] * (len(fields) - len(row))
        out.append(dict(zip(fields, padded[:len(fields)])))
    return out


def _int_scalar(doc, key, default):
    try:
        return int(str(doc["scalars"].get(key, default)).strip())
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# mode selection
# ---------------------------------------------------------------------------


def normalise_mode(value, default=DEFAULT_MODE):
    """Fold a mode string onto one of MODES.

    Anything unrecognised - a typo, an empty string, a value from a newer
    policy.toon than this hook understands - reads as `default`.  The default
    is shadow, so a typo can never turn into a hook that blocks the session.
    """
    text = (value or "").strip().lower()
    return text if text in MODES else default


def resolve_mode(env, policy=None, override=None):
    """Pick the mode: --mode first, then L1_POLICY_MODE, then policy.toon.

    Returns (mode, source) so a caller can tell the operator where the mode
    came from without re-deriving the precedence.
    """
    candidates = (
        ("--mode", override),
        (MODE_ENV_VAR, (env or {}).get(MODE_ENV_VAR)),
        ("policy.toon", getattr(policy, "mode", None)),
    )
    for source, value in candidates:
        text = (value or "").strip()
        if text:
            return normalise_mode(text), source
    return DEFAULT_MODE, "default"


class Policy(object):
    """Typed view over policy.toon."""

    def __init__(self, doc, path):
        self.path = path
        self.doc = doc
        scalars = doc["scalars"]
        self.version = _int_scalar(doc, "policy_version", 1)
        self.deny_reason = scalars.get("deny_reason") or DEFAULT_DENY_REASON
        self.dispatch_hint = scalars.get("dispatch_hint") or DEFAULT_DISPATCH_HINT
        # `mode` is the fallback when neither --mode nor L1_POLICY_MODE is
        # set. It is a plain scalar so an operator can flip the whole hook
        # from shadow to enforce by editing one line of policy.toon.
        self.mode = normalise_mode(scalars.get("mode"))
        self.shadow_audit_log = (scalars.get("shadow.audit_log")
                                  or DEFAULT_SHADOW_AUDIT_LOG)
        self.budget_soft_limit = max(0, _int_scalar(doc, "budget.soft_limit", 40))
        self.budget_ask_multiplier = max(1, _int_scalar(doc, "budget.ask_multiplier", 2))

        self.bash_capabilities = {}
        for row in _table_rows(doc, "bash_capabilities"):
            argv0 = (row.get("argv0") or "").strip()
            if argv0:
                self.bash_capabilities[argv0.lower()] = row.get("capability") or argv0

        self.bash_read_any = set()
        for row in _table_rows(doc, "bash_read_any"):
            argv0 = (row.get("argv0") or "").strip()
            if argv0:
                self.bash_read_any.add(argv0.lower())

        # A reader is allowed, but only in one form. `mode` says how the rule
        # is applied to the segment arguments; see bash_read_guards.
        self.bash_read_guards = {}
        for row in _table_rows(doc, "bash_read_guards"):
            argv0 = (row.get("argv0") or "").strip().lower()
            mode = (row.get("mode") or "").strip().lower()
            value = row.get("value") or ""
            if argv0 and mode and value:
                self.bash_read_guards.setdefault(argv0, []).append((mode, value))

        self.bash_read_denied_paths = []
        for row in _table_rows(doc, "bash_read_denied_paths"):
            pattern = (row.get("glob") or "").strip()
            if pattern:
                self.bash_read_denied_paths.append(pattern)

        self.shell_keywords = set()
        for row in _table_rows(doc, "shell_syntax_keywords"):
            keyword = (row.get("keyword") or "").strip().lower()
            if keyword:
                self.shell_keywords.add(keyword)
        # The built-in list is the floor: a policy.toon that forgets the table
        # still parses a loop header as syntax rather than as an unknown argv0.
        self.shell_keywords |= SHELL_KEYWORDS

        self.shell_assignment_denied = set()
        for row in _table_rows(doc, "shell_assignment_denied"):
            name = (row.get("name") or "").strip().upper()
            if name:
                self.shell_assignment_denied.add(name)

        self.shell_wrappers = set(PEELABLE_WRAPPERS)
        for row in _table_rows(doc, "shell_wrappers"):
            argv0 = (row.get("argv0") or "").strip().lower()
            if argv0:
                self.shell_wrappers.add(argv0)

        self.shell_wrapper_value_flags = set(WRAPPER_VALUE_FLAGS)
        for row in _table_rows(doc, "shell_wrapper_value_flags"):
            flag = (row.get("flag") or "").strip()
            if flag:
                self.shell_wrapper_value_flags.add(flag)

        self.budget_exempt_tools = set()
        for row in _table_rows(doc, "budget.exempt_tools"):
            name = (row.get("name") or "").strip().lower()
            if name:
                self.budget_exempt_tools.add(name)

        self.bash_read_claude_home = set()
        self.bash_read_stdin_ok = set()
        for row in _table_rows(doc, "bash_read_claude_home"):
            argv0 = (row.get("argv0") or "").strip()
            if argv0:
                self.bash_read_claude_home.add(argv0.lower())
                if (row.get("stdin_ok") or "").strip().lower() in ("yes", "true", "1"):
                    self.bash_read_stdin_ok.add(argv0.lower())

        self.git_read_subcommands = set()
        for row in _table_rows(doc, "git_read_subcommands"):
            sub = (row.get("subcommand") or "").strip()
            if sub:
                self.git_read_subcommands.add(sub)

        self.git_write_flags = set()
        for row in _table_rows(doc, "git_write_flags"):
            flag = (row.get("flag") or "").strip()
            if flag:
                self.git_write_flags.add(flag)

        self.bash_denied = {}
        for table_name in ("bash_denied", "bash_denied_interpreters", "bash_denied_extra"):
            for row in _table_rows(doc, table_name):
                argv0 = (row.get("argv0") or "").strip()
                if argv0:
                    self.bash_denied[argv0.lower()] = row.get("category") or "denied"

        lan_rows = _table_rows(doc, "lan_address_re")
        self.lan_pattern = None
        if lan_rows and lan_rows[0].get("pattern"):
            try:
                self.lan_pattern = re.compile(lan_rows[0]["pattern"])
            except re.error:
                self.lan_pattern = None

        self.tools = {}
        for row in _table_rows(doc, "tools"):
            name = (row.get("name") or "").strip()
            if name:
                self.tools[name.lower()] = (row.get("decision") or ASK).lower()

        self.write_tools = set()
        for row in _table_rows(doc, "write_tools"):
            name = (row.get("name") or "").strip()
            if name:
                self.write_tools.add(name)

        self.write_allowed_paths = []
        for row in _table_rows(doc, "write_allowed_paths"):
            pattern = (row.get("glob") or "").strip()
            if pattern:
                self.write_allowed_paths.append(pattern)

        self.write_path_keys = []
        for row in _table_rows(doc, "write_path_keys"):
            key = (row.get("key") or "").strip()
            if key:
                self.write_path_keys.append(key)

        self.mcp_tools = {}
        for row in _table_rows(doc, "mcp_tools"):
            name = (row.get("name") or "").strip()
            if name:
                self.mcp_tools[name.lower()] = (row.get("decision") or ASK).lower()

        self.override_env_var = scalars.get("override.env_var") or "L1_POLICY_OVERRIDE"
        self.override_audit_log = scalars.get("override.audit_log") or "override-audit.jsonl"

        self.redact_value_keys = set()
        for row in _table_rows(doc, "override.redact_value_keys"):
            key = (row.get("key") or "").strip()
            if key:
                self.redact_value_keys.add(key.lower())

        self.redact_assignments = set()
        for row in _table_rows(doc, "redact_assignments"):
            name = (row.get("prefix") or "").strip()
            if name:
                self.redact_assignments.add(name.upper())

    @property
    def budget_ask_limit(self):
        return self.budget_soft_limit * self.budget_ask_multiplier


def default_policy_path():
    """policy.toon is found beside this script, always, with no arguments."""
    here = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(here, POLICY_BASENAME)


def load_policy(path=None):
    """Load and type policy.toon. `path` defaults to the file next to this script."""
    path = path or default_policy_path()
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return Policy(parse_toon(text), path)


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def redact(text, policy):
    """Mask anything that looks like a credential.

    Secrets are referenced by variable name only, so the value side of a
    sensitive assignment, a sensitive flag and a known token prefix are the
    only things that ever get rewritten.
    """
    if not text:
        return text
    out = str(text)
    for key in sorted(getattr(policy, "redact_value_keys", set()) or set()):
        out = re.sub(
            r"(?i)(--?%s)(=|\s+)(\S+)" % re.escape(key),
            lambda m: "%s%s%s" % (m.group(1), m.group(2), REDACTED),
            out,
        )
    for name in sorted(getattr(policy, "redact_assignments", set()) or set()):
        out = re.sub(r"\b%s\s*=\s*\S+" % re.escape(name), "%s=%s" % (name, REDACTED), out)
        out = re.sub(r"\$\{%s\}\S*" % re.escape(name), "${%s}%s" % (name, REDACTED), out)
        out = re.sub(r"\$%s\S*" % re.escape(name), "$%s%s" % (name, REDACTED), out)
    for pattern in _SECRET_TOKEN_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------


def _home(env):
    home = env.get("HOME") or ""
    if not home:
        home = os.path.expanduser("~")
    if not home or home == "~":
        return None
    return home


def home_claude_dir(env):
    home = _home(env)
    if not home:
        return None
    return os.path.normpath(os.path.join(home, ".claude"))


def normalise_path(raw, cwd, env):
    """Expand `~`, resolve against cwd and normalise.  Never touches disk."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().strip('"').strip("'")
    home = env.get("HOME") or ""
    if home:
        if text == "~":
            text = home
        elif text.startswith("~/"):
            text = os.path.join(home, text[2:])
    text = os.path.expanduser(text)
    if not os.path.isabs(text):
        text = os.path.join(cwd or os.getcwd(), text)
    return os.path.normpath(text)


def under(path, parent):
    """True when `path` is `parent` or lives below it."""
    if not path or not parent:
        return False
    if path == parent:
        return True
    return path.startswith(parent.rstrip(os.sep) + os.sep)


def path_is_allowed(path, policy):
    return any(glob_match(pattern, path) for pattern in policy.write_allowed_paths)


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------


class Verdict(object):
    """One decision, the reason prose, and a stable machine readable code.

    `code` is the contract.  It is the part a test, a log line or a dashboard
    may assert on; the prose around it is written for the model and may be
    reworded.  Every code the hook can emit is listed in `REASON_CODES`.
    """

    def __init__(self, decision, reason, capability="", code="", detail=None):
        self.decision = decision
        self.reason = reason
        self.capability = capability
        self.code = code
        self.detail = detail or {}

    def as_dict(self):
        out = {"decision": self.decision, "reason": self.reason}
        if self.capability:
            out["capability"] = self.capability
        if self.code:
            out["reason_code"] = self.code
        if self.detail:
            out.update(self.detail)
        return out


def deny(policy, capability, reason, code):
    return Verdict(DENY, "%s: %s; %s." % (DENY, reason, policy.deny_reason),
                   capability, code)


def allow(reason, capability, code, detail=None):
    return Verdict(ALLOW, "%s: %s" % (ALLOW, reason), capability, code, detail)


def ask(reason, capability, code, detail=None):
    return Verdict(ASK, "%s: %s" % (ASK, reason), capability, code, detail)


_REASON_CODE_RE = re.compile(r"\s*\[reason_code=[a-z0-9_.]+\]")


def with_reason_code(reason, code):
    """Stamp the stable code onto the end of the reason prose.

    The decision word stays in front so the sentence still starts `deny: ` and
    the code is appended last, so nothing that reads the middle of the sentence
    moves when a code is added.  Re-stamping replaces an earlier code rather
    than stacking a second one.
    """
    body = _REASON_CODE_RE.sub("", reason or "").rstrip()
    if not code:
        return body
    return "%s [reason_code=%s]" % (body, code)


# ---------------------------------------------------------------------------
# Bash evaluation
# ---------------------------------------------------------------------------


def argv0_of(token):
    """Basename of the first word, tolerant of `PATH` and Windows separators."""
    token = (token or "").strip().replace("\\", "/")
    return os.path.basename(token)


def _git_subcommand(tokens):
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in GIT_GLOBAL_VALUE_FLAGS:
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        return token
    return ""


def _is_redirect_operator(token):
    """True for a redirection operator: `<`, `>>`, `>&`, `&>` ...

    It is shell syntax rather than a program name or an argument, so it is
    never classified as argv0 and never scanned as a reader's own word.
    """
    return bool(token) and REDIRECT_OPERATOR_RE.match(token) is not None


def _looks_like_path(token, cwd):
    if not token or token.startswith("-"):
        return False
    if any(ch in token for ch in "/~") or token.startswith("."):
        return True
    try:
        return os.path.exists(normalise_path(token, cwd, {}) or "")
    except (OSError, ValueError):
        return False


def _peel_wrappers(tokens, policy):
    """Strip leading wrappers that only bound the program that follows.

    `timeout 30 git status` classifies as `git status`: the deadline changes
    when the command dies, not what it is, so the wrapped argv0 goes through
    exactly the same rules. A wrapper that can re-invoke more than one program
    (`xargs`, `env`, `sudo`) is in SMUGGLE_WRAPPERS instead and never gets here.
    """
    i = 0
    while i < len(tokens):
        if argv0_of(tokens[i]).lower() not in policy.shell_wrappers:
            break
        j = i + 1
        while j < len(tokens):
            token = tokens[j]
            if token in policy.shell_wrapper_value_flags:
                j += 2
                continue
            if token.startswith("-") and token != "-":
                j += 1
                continue
            # the duration operand, but only when a command follows it
            if j + 1 < len(tokens) and _DURATION_RE.match(token):
                j += 1
                continue
            break
        if j <= i + 1:
            # A wrapper with nothing after it runs nothing at all.
            return []
        i = j
    return tokens[i:]


def _strip_shell_prefix(tokens, policy):
    """Drop leading assignments and keywords, then hand back the program.

    `parse_commands()` splits on every separator, so a shell preamble arrives
    as its own segment: `NAME=value; cmd` gives `["NAME=value"]`, and
    `for f in a b; do cat $f; done` gives `["for","f","in","a","b"]`,
    `["do","cat","$f"]` and `["done"]`. None of those is a program, and
    classifying them as one is what made an otherwise allowed chain look
    unknown. Returns None when the segment holds no program at all.

    Only syntax is removed: the body of a loop, the condition of a `while`
    and the command after `do` are still handed to the classifier. Raises
    ValueError for an assignment the policy refuses to treat as setup.
    """
    tokens = list(tokens)
    while tokens:
        head = tokens[0]
        lowered = head.lower()
        if lowered in SHELL_ASSIGNMENT_KEYWORDS:
            tokens.pop(0)
            continue
        if _ASSIGNMENT_RE.match(head):
            name = head.split("=", 1)[0]
            if name in policy.shell_assignment_denied:
                raise ValueError(name)
            tokens.pop(0)
            continue
        if lowered in policy.shell_keywords:
            if lowered in WHOLE_HEADER_KEYWORDS:
                # `for f in a b` and `case $x in` are headers: their word list
                # runs up to the separator that already split this segment, so
                # the whole segment is syntax and never names a program.
                return None
            tokens.pop(0)
            if tokens and _is_redirect_operator(tokens[0]):
                # `while read -r l; do wc -l $l; done < list.txt` puts the
                # redirect on the terminator segment. The loop body has been
                # classified already, so this one is syntax plus a file name
                # and runs no program at all.
                return None
            continue
        break
    return tokens or None


def _flag_forbidden(tokens, flag):
    """True when a forbidden flag is present, glued to its value or not."""
    for token in tokens[1:]:
        if token == flag:
            return True
        if (len(flag) == 2 and not flag.startswith("--")
                and token.startswith(flag) and len(token) > 2):
            # `-i.bak` is still `-i`; only the short form glues a value on.
            if not token[2:3].isalpha():
                return True
    return False


def _flag_required(tokens, flag):
    """True when a required flag is present in any spelling."""
    for token in tokens[1:]:
        if token == flag or token.startswith(flag + "="):
            return True
        if (len(flag) == 2 and not flag.startswith("--")
                and token.startswith(flag) and len(token) > 2):
            return True
    return False


def _mask_awk_regexes(tokens):
    """Blank out `/.../` regex literals so a `|` inside one is not a pipe.

    `awk '/foo|bar/'` matches an alternation and runs nothing, while
    `awk '{ print | "sh" }'` runs a shell. The two are only distinguishable by
    the regex delimiters, so the delimiters are blanked before the guard looks
    for a pipe. Both spellings of the match operator (`/re/`, `!/re/`) and a
    bare regex on either side of one are covered by the same pass.
    """
    masked = []
    for token in tokens:
        out = []
        i = 0
        n = len(token)
        while i < n:
            if token[i] == "/" and (i == 0 or token[i - 1] != "\\"):
                j = i + 1
                closed = False
                while j < n:
                    if token[j] == "\\":
                        j += 2
                        continue
                    if token[j] == "/":
                        closed = True
                        break
                    j += 1
                if not closed:
                    # An unterminated `/` is division or a bare slash, not a
                    # regex: leave the rest of the token as it was.
                    out.append(token[i:])
                    i = n
                    continue
                out.append(" " * (j + 1 - i))
                i = j + 1
                continue
            out.append(token[i])
            i += 1
        masked.append("".join(out))
    return masked


def _awk_statement_head(token, index):
    """The awk keyword that opens the statement holding `token[index]`.

    `>` compares in `NR>1` and redirects in `{print $1 > "out"}`, and only the
    statement the operator sits in tells them apart. Scanning back to the last
    `;`, `{` or `}` and reading the first word after it answers that question:
    `print` and `printf` redirect, every other head compares.
    """
    start = 0
    for i in range(index - 1, -1, -1):
        if token[i] in ";{}":
            start = i + 1
            break
    i = start
    while i < index:
        if token[i].isalnum() or token[i] == "_":
            j = i
            while j < index and (token[j].isalnum() or token[j] == "_"):
                j += 1
            return token[i:j].lower()
        if token[i] in "'\"":
            # a string literal opens the statement: there is no keyword
            return ""
        i += 1
    return ""


def _mask_awk_comparisons(tokens):
    """Blank out `<` and `>` that compare rather than redirect.

    `awk -F',' 'NR>1 {print $2}' f.csv` filters a CSV and writes nothing, so
    denying it for a `>` inside the program was a false positive of the same
    shape as `sed` without `-n`. An operator in a statement opened by `print`
    or `printf` is left in place, so `awk '{print > "out"}' f.txt` denies.
    """
    masked = []
    for token in tokens:
        if "<" not in token and ">" not in token:
            masked.append(token)
            continue
        out = []
        i = 0
        n = len(token)
        while i < n:
            if (token[i] in "<>"
                    and _awk_statement_head(token, i) not in AWK_OUTPUT_KEYWORDS):
                j = i
                while j < n and token[j] == token[i]:
                    j += 1
                out.append(" " * (j - i))
                i = j
                continue
            out.append(token[i])
            i += 1
        masked.append("".join(out))
    return masked


def _read_guard_problem(tokens, policy):
    """Return the first `bash_read_guards` rule this segment trips, or None."""
    argv0 = argv0_of(tokens[0]).lower()
    # An awk program is an inline interpreter, so it is scanned with its regex
    # literals and its comparison operators masked before the character guards
    # run: neither a `/foo|bar/` alternation nor an `NR>1` filter writes.
    if argv0 == "awk":
        args = _mask_awk_comparisons(_mask_awk_regexes(tokens))
    else:
        args = tokens
    for mode, value in policy.bash_read_guards.get(argv0, ()):
        if mode == "forbid_flag" and _flag_forbidden(tokens, value):
            return "%s must not be passed" % value
        if mode == "require_flag" and not _flag_required(tokens, value):
            return "%s is required" % value
        if mode in ("forbid_char", "forbid_text"):
            for token in args[1:]:
                if token.startswith("-"):
                    # An option carries a setting, not a program: `-F'|'` names
                    # a separator. `awk -f prog` is denied by its own guard.
                    continue
                if _is_redirect_operator(token):
                    # `awk '{print}' f > out` is the shell writing, not the
                    # reader's own argument.
                    continue
                if value in token:
                    return "%r may not appear in an argument" % value
    return None


def _denied_read_path(tokens, policy, cwd, env):
    """Return the credential path this reader would open, or None."""
    for token in tokens[1:]:
        if token.startswith("-"):
            continue
        resolved = normalise_path(token, cwd, env)
        if not resolved:
            continue
        for pattern in policy.bash_read_denied_paths:
            if glob_match(pattern, resolved):
                return token
    return None


def _classify_segment(tokens, policy, cwd, env):
    """Return (verdict_or_None, argv0) for one command segment."""
    if not tokens:
        return None, ""
    tokens = _peel_wrappers(tokens, policy)
    if not tokens:
        return None, ""
    try:
        tokens = _strip_shell_prefix(tokens, policy)
    except ValueError as exc:
        return deny(
            policy,
            "bash-assignment",
            "setting %s changes how the next allowed program loads code, so it is "
            "not shell setup" % exc,
            "bash.denied.read_guard",
        ), "="
    if not tokens:
        # An assignment or a loop header with no program: nothing runs.
        return None, ""
    argv0 = argv0_of(tokens[0])
    lowered = argv0.lower()
    segment_text = " ".join(tokens)

    if lowered in policy.bash_denied or lowered in SMUGGLE_WRAPPERS:
        category = policy.bash_denied.get(lowered, "smuggle")
        code = "bash.denied.%s" % category
        if category == "smuggle":
            reason = ("'%s' re-invokes another program, so whatever capability it hides "
                      "cannot be checked" % argv0)
        elif category == "code":
            reason = ("running '%s' executes arbitrary code instead of a declared "
                      "capability" % argv0)
        else:
            reason = ("'%s' is category '%s' and is never available to the L1 session"
                      % (argv0, category))
        return deny(policy, "bash-%s" % lowered, reason, code), argv0

    if lowered == "git":
        sub = _git_subcommand(tokens)
        if sub in policy.git_read_subcommands:
            flagged = [t for t in tokens if t in policy.git_write_flags]
            if flagged:
                return deny(
                    policy,
                    "git-write",
                    "git %s with %s changes state; the L1 session only runs read-only git"
                    % (sub, " ".join(flagged)),
                    "bash.denied.git_write",
                ), argv0
            return allow("read-only git sub-command 'git %s'." % sub, "git-read",
                         "bash.git_read"), argv0
        return deny(
            policy,
            "git-write",
            "git %s changes state; only read-only git sub-commands are capabilities"
            % (sub or "<no sub-command>"),
            "bash.denied.git_write",
        ), argv0

    if lowered in policy.bash_capabilities:
        return allow(
            "capability '%s' is on the L1 capability list."
            % policy.bash_capabilities[lowered],
            policy.bash_capabilities[lowered],
            "bash.capability",
        ), argv0

    if lowered in policy.bash_read_any:
        problem = _read_guard_problem(tokens, policy)
        if problem:
            return deny(
                policy,
                "bash-%s" % lowered,
                "'%s' is only allowed in its read-only form: %s" % (argv0, problem),
                "bash.denied.read_guard",
            ), argv0
        secret = _denied_read_path(tokens, policy, cwd, env)
        if secret:
            return deny(
                policy,
                "bash-%s" % lowered,
                "'%s' would read '%s', which is a credential rather than "
                "something the L1 session plans from" % (argv0, secret),
                "bash.denied.read_guard",
            ), argv0
        return allow("read-only command '%s'." % argv0, "read-only",
                     "bash.read_any"), argv0

    if lowered in policy.bash_read_claude_home:
        home = _home(env)
        root = home_claude_dir(env)
        candidates = [t for t in tokens[1:] if _looks_like_path(t, cwd)]
        if not root:
            return deny(
                policy,
                "bash-%s" % lowered,
                "HOME is not set, so a read cannot be proven to stay inside the home "
                ".claude directory",
                "bash.denied.unknown",
            ), argv0
        if not candidates and lowered not in policy.bash_read_stdin_ok:
            return deny(
                policy,
                "bash-%s" % lowered,
                "'%s' without a path would read the working directory instead of the home "
                ".claude directory" % argv0,
                "bash.denied.unknown",
            ), argv0
        for token in candidates:
            resolved = normalise_path(token, cwd, env)
            if resolved and not under(resolved, root):
                return deny(
                    policy,
                    "bash-%s" % lowered,
                    "'%s' reads '%s', outside the home .claude directory" % (argv0, token),
                    "bash.denied.unknown",
                ), argv0
        return allow(
            "read-only command '%s' scoped to the home .claude directory." % argv0,
            "claude-home-read",
            "bash.claude_home_read",
        ), argv0

    if policy.lan_pattern is not None and policy.lan_pattern.search(segment_text):
        return deny(
            policy,
            "remote-address",
            "'%s' names a LAN, loopback or fleet address, which is a remote reach" % argv0,
            "bash.denied.lan_address",
        ), argv0

    return deny(
        policy,
        "unknown",
        "'%s' is not an allowed capability for the L1 session" % argv0,
        "bash.denied.unknown",
    ), argv0


def evaluate_bash(command, policy, cwd, env):
    """Check every segment of a (possibly compound) Bash command line."""
    segments = parse_commands(command or "")
    if not segments:
        return allow("empty command, nothing to run.", "empty", "bash.empty")
    checked = []
    verdicts = []
    for tokens in segments:
        verdict, argv0 = _classify_segment(tokens, policy, cwd, env)
        checked.append({
            "argv0": argv0,
            "decision": verdict.decision if verdict else "skip",
        })
        verdicts.append(verdict)
        if verdict is not None and verdict.decision == DENY:
            detail = dict(verdict.detail)
            detail["segments"] = checked
            return Verdict(DENY, verdict.reason, verdict.capability, verdict.code, detail)
    if len(segments) == 1:
        single = verdicts[0]
        if single is None:
            # `timeout` on its own peels to nothing: the line runs no program,
            # which is an allow rather than an internal error.
            return allow("nothing to run: the line names no program.", "empty",
                         "bash.empty", {"segments": checked})
        detail = dict(single.detail)
        detail["segments"] = checked
        return Verdict(single.decision, single.reason, single.capability,
                       single.code, detail)
    return allow(
        "all %d command segments (%s) are allowed capabilities; none of them smuggles a "
        "denied capability." % (len(segments), ", ".join(c["argv0"] for c in checked)),
        "compound-allowed",
        "bash.compound_allowed",
        {"segments": checked},
    )


# ---------------------------------------------------------------------------
# Write / Edit evaluation
# ---------------------------------------------------------------------------


def evaluate_write(tool, tool_input, policy, cwd, env):
    """Write-like tools may only touch .claude memory, plans and prompts."""
    path = None
    if isinstance(tool_input, dict):
        for key in policy.write_path_keys:
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                path = value
                break
    if path is None:
        return ask(
            "%s carried no recognisable path field, so the target cannot be checked."
            % tool,
            "write-unknown-path",
            "write.unknown_path",
        )
    resolved = normalise_path(path, cwd, env)
    if path_is_allowed(resolved, policy):
        return allow(
            "%s target '%s' is inside an allowed .claude memory/plans/prompts path."
            % (tool, path),
            "write-plan-path",
            "write.allowed_path",
            {"path": resolved},
        )
    return deny(
        policy,
        "write-outside-plan-paths",
        "%s target '%s' is outside the allowed .claude memory/plans/prompts paths"
        % (tool, path),
        "write.denied_path",
    )


# ---------------------------------------------------------------------------
# state / budget / audit
# ---------------------------------------------------------------------------


def resolve_state_dir(env, override=None):
    if override:
        return os.path.abspath(os.path.expanduser(override))
    value = env.get("L1_POLICY_STATE_DIR")
    if value:
        return os.path.abspath(os.path.expanduser(value))
    xdg = env.get("XDG_STATE_HOME")
    if xdg:
        return os.path.abspath(os.path.join(os.path.expanduser(xdg), "claude-hooks", "l1-policy"))
    home = _home(env)
    if home:
        return os.path.abspath(os.path.join(home, ".local", "state", "claude-hooks", "l1-policy"))
    return os.path.join(tempfile.gettempdir(), "l1-policy")


def _session_filename(session_id):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(session_id or "default"))[:96]
    return safe or "default"


class StateStore(object):
    """Per-session tool-call counter backed by one json file."""

    def __init__(self, directory):
        self.directory = directory

    def path_for(self, session_id):
        return os.path.join(self.directory, "%s.json" % _session_filename(session_id))

    def _ensure_dir(self):
        try:
            os.makedirs(self.directory, exist_ok=True)
        except OSError:
            pass

    def read(self, session_id):
        try:
            with open(self.path_for(session_id), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (IOError, OSError, ValueError):
            return {"session_id": session_id, "tool_calls": 0}
        if not isinstance(data, dict):
            return {"session_id": session_id, "tool_calls": 0}
        return data

    def bump(self, session_id, soft_limit=None):
        """Count one tool call for the session and return the new total."""
        self._ensure_dir()
        target = self.path_for(session_id)
        lock_fh = None
        try:
            lock_fh = open(target + ".lock", "a+")
            if fcntl is not None:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        except (IOError, OSError):
            lock_fh = None
        try:
            data = self.read(session_id)
            try:
                count = int(data.get("tool_calls") or 0) + 1
            except (TypeError, ValueError):
                count = 1
            data["session_id"] = session_id
            data["tool_calls"] = count
            data["updated_at"] = int(time.time())
            if soft_limit is not None:
                data["soft_limit"] = soft_limit
            tmp = "%s.%d.tmp" % (target, os.getpid())
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, sort_keys=True)
                    fh.write("\n")
                os.replace(tmp, target)
            except (IOError, OSError):
                pass
            return count
        finally:
            if lock_fh is not None:
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                except (IOError, OSError):
                    pass
                try:
                    lock_fh.close()
                except (IOError, OSError):
                    pass

    def reset(self, session_id):
        for path in (self.path_for(session_id), self.path_for(session_id) + ".lock"):
            try:
                os.unlink(path)
            except OSError:
                pass


def append_audit(path, record):
    """Append one json line to the override audit log."""
    try:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return True
    except (IOError, OSError):
        return False


def resolve_audit_log(env, state_dir, policy, override=None):
    if override:
        return os.path.abspath(os.path.expanduser(override))
    value = env.get(AUDIT_LOG_ENV_VAR)
    if value:
        return os.path.abspath(os.path.expanduser(value))
    return os.path.join(state_dir, policy.override_audit_log)


def resolve_shadow_log(env, state_dir, policy, override=None):
    """Where a shadow run appends its one line per tool call.

    ``L1_POLICY_SHADOW_LOG`` wins, then ``L1_POLICY_AUDIT_LOG`` so an operator
    who already pointed one log at a collector gets every line in it, then
    ``shadow.audit_log`` beside the session state file.
    """
    if override:
        return os.path.abspath(os.path.expanduser(override))
    for name in (SHADOW_LOG_ENV_VAR, AUDIT_LOG_ENV_VAR):
        value = (env or {}).get(name)
        if value:
            return os.path.abspath(os.path.expanduser(value))
    name = getattr(policy, "shadow_audit_log", None) or DEFAULT_SHADOW_AUDIT_LOG
    return os.path.join(state_dir, name)


# Keys copied out of a decision into a shadow audit line. Everything else in
# the detail block is dropped on purpose: the line is data, not a transcript.
SHADOW_DETAIL_KEYS = (
    "budget_warning",
    "budget_escalated",
    "budget_exempt",
    "tool_calls",
    "budget_soft_limit",
    "budget_ask_limit",
    "override",
)


def shadow_record(policy, detail=None, session_id="", tool="", tool_input=None,
                  mode=SHADOW):
    """Build the one redacted JSON line a shadow run writes.

    The decision and the reason code are recorded exactly as enforce would
    have returned them, so the log says what *would* have happened.  Every free
    text field goes through the same redactor the override log uses, so a
    shadow line can never carry a secret.
    """
    detail = detail or {}
    inner = detail.get("detail")
    if not isinstance(inner, dict):
        inner = {}
    record = {
        "ts": int(time.time()),
        "shadow": True,
        "mode": mode,
        "policy_version": policy.version,
        "session_id": session_id,
        "tool": tool or "",
        "summary": redact(tool_summary(tool or "", tool_input or {}), policy)[:500],
        "decision": detail.get("decision") or ALLOW,
        "reason_code": detail.get("reason_code") or "",
        "capability": detail.get("capability") or "",
        "reason": redact(detail.get("reason") or "", policy)[:500],
    }
    for key in SHADOW_DETAIL_KEYS:
        if key in inner:
            record[key] = inner[key]
        elif key in detail:
            record[key] = detail[key]
    return record


# ---------------------------------------------------------------------------
# decision
# ---------------------------------------------------------------------------


def tool_summary(tool, tool_input):
    if isinstance(tool_input, dict):
        for key in ("command", "file_path", "notebook_path", "path", "pattern", "url"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def evaluate_tool(payload, policy, cwd, env):
    """Map one PreToolUse payload onto a decision, before the budget runs."""
    tool = payload.get("tool_name") or payload.get("toolName") or ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("toolInput")
    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool == "Bash":
        return evaluate_bash(tool_input.get("command") or "", policy, cwd, env)

    if tool in policy.write_tools or tool in WRITE_TOOL_NAMES:
        return evaluate_write(tool, tool_input, policy, cwd, env)

    if tool.startswith("mcp__"):
        decision = policy.mcp_tools.get(tool.lower())
        if decision == ALLOW:
            return allow("MCP tool '%s' is on the L1 MCP list." % tool, "mcp",
                         "mcp.allow")
        if decision == DENY:
            return deny(policy, "mcp", "MCP tool '%s' reaches a remote host" % tool,
                        "mcp.denied_remote")
        return ask(
            "MCP tool '%s' is not on the L1 MCP list; list it in claude-hooks/policy.toon "
            "to allow it." % tool,
            "mcp-unlisted",
            "mcp.unlisted",
        )

    decision = policy.tools.get(tool.lower())
    if decision == ALLOW:
        return allow("tool '%s' is allowed." % tool, "tool", "tool.allow")
    if decision == DENY:
        return deny(policy, "tool", "tool '%s' reaches a remote host" % tool,
                    "tool.denied_remote")
    if decision == ASK:
        return ask(
            "tool '%s' can cross the plan-and-dispatch boundary; %s." % (tool, policy.dispatch_hint),
            "tool-ask",
            "tool.ask",
        )
    return ask(
        "tool '%s' is unknown to claude-hooks/policy.toon; %s."
        % (tool or "<empty>", policy.dispatch_hint),
        "tool-unknown",
        "tool.unknown",
    )


def render(decision, reason, code=None):
    """Wrap a decision in the Claude Code hookSpecificOutput envelope.

    The envelope carries exactly the three keys Claude Code reads; the stable
    reason code rides along at the end of the reason sentence, so nothing
    outside this function has to know how it is transported.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": with_reason_code(reason, code),
        }
    }


def decide(payload, policy, env=None, state_dir=None, audit_log=None, state_store=None):
    """Decide one PreToolUse call.  Returns (hook_output, detail_dict)."""
    env = os.environ if env is None else env
    cwd = payload.get("cwd") or env.get("L1_POLICY_CWD") or os.getcwd()
    session_id = payload.get("session_id") or payload.get("sessionId") or "default"
    tool = payload.get("tool_name") or payload.get("toolName") or ""

    if not state_dir:
        state_dir = resolve_state_dir(env)
    store = state_store if state_store is not None else StateStore(state_dir)
    # The harness calls some tools in the background on every turn. They are
    # decided like any other call but must not spend the session's budget:
    # ListAgents alone was asked 2652 times in the shadow review, which would
    # have put every long session over the ask threshold on its own.
    budget_exempt = bool(tool) and tool.strip().lower() in policy.budget_exempt_tools
    if budget_exempt:
        count = int(store.read(session_id).get("tool_calls") or 0)
    else:
        count = store.bump(session_id, policy.budget_soft_limit)

    verdict = evaluate_tool(payload, policy, cwd, env)

    override_raw = (env.get(policy.override_env_var) or "").strip()
    if override_raw:
        log_path = resolve_audit_log(env, state_dir, policy, audit_log)
        record = {
            "ts": int(time.time()),
            "session_id": session_id,
            "tool": tool,
            "summary": redact(tool_summary(tool, payload.get("tool_input")), policy)[:500],
            "base_decision": verdict.decision,
            "base_reason_code": verdict.code,
            "decision": ALLOW,
            "override_reason": redact(override_raw, policy)[:500],
            "override_env_var": policy.override_env_var,
            "policy_version": policy.version,
            "tool_calls": count,
        }
        audited = append_audit(log_path, record)
        reason = "%s: %s override by operator (%s); audited in %s." % (
            ALLOW,
            policy.override_env_var,
            redact(override_raw, policy)[:200],
            os.path.basename(log_path) if audited else "no audit log (write failed)",
        )
        detail = {
            "override": True,
            "audit_log": log_path,
            "audit_written": audited,
            "base_decision": verdict.decision,
            "base_reason_code": verdict.code,
            "tool_calls": count,
            "budget_exempt": budget_exempt,
            "session_id": session_id,
        }
        return render(ALLOW, reason, "override.allow"), {
            "capability": "override",
            "decision": ALLOW,
            "reason": with_reason_code(reason, "override.allow"),
            "reason_code": "override.allow",
            "detail": detail,
        }

    soft = policy.budget_soft_limit
    ask_limit = policy.budget_ask_limit
    over_budget = soft > 0 and count > soft
    warning = ""
    if over_budget:
        warning = ("tool call %d of this session is over the soft limit of %d; the ask "
                   "threshold is %d" % (count, soft, ask_limit))

    decision = verdict.decision
    reason = verdict.reason
    code = verdict.code
    escalated = False
    if over_budget and count > ask_limit and decision == ALLOW:
        # The budget escalates allow to ask. It never produces a deny.
        decision = ASK
        code = "budget.ask"
        escalated = True
        body = reason[len(ALLOW) + 2:] if reason.startswith(ALLOW + ": ") else reason
        reason = "%s: %s, but %s. %s." % (ASK, body.rstrip(". "), warning, policy.dispatch_hint)
    elif over_budget:
        # A warning does not change what the call is, so the verdict code stays
        # and the warning itself is reported as a boolean here.
        reason = "%s budget warning: %s." % (reason, warning)

    detail = dict(verdict.detail)
    detail.update({
        "override": False,
        "tool_calls": count,
        "budget_soft_limit": soft,
        "budget_ask_limit": ask_limit,
        "budget_warning": bool(over_budget),
        "budget_escalated": escalated,
        "budget_exempt": budget_exempt,
        "session_id": session_id,
    })
    return render(decision, reason, code), {
        "capability": verdict.capability,
        "decision": decision,
        "reason": with_reason_code(reason, code),
        "reason_code": code,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="l1-policy.py",
        description="Claude Code PreToolUse capability-policy hook (L1 plan-and-dispatch).",
    )
    parser.add_argument("--version", action="version", version="l1-policy %s" % VERSION)
    parser.add_argument("--policy", help="path to policy.toon (default: next to this script)")
    parser.add_argument("--command", help="evaluate this Bash command instead of reading stdin")
    parser.add_argument("--tool", help="evaluate this tool name, with --tool-input")
    parser.add_argument("--tool-input", help="JSON object for --tool")
    parser.add_argument("--session-id", help="session id for --command/--tool")
    parser.add_argument("--state-dir", help="override L1_POLICY_STATE_DIR for this call")
    parser.add_argument("--audit-log", help="override L1_POLICY_AUDIT_LOG for this call")
    parser.add_argument("--cwd", help="working directory the tool call targets")
    parser.add_argument("--annotate", action="store_true",
                        help="add a top level 'l1Policy' detail block to the output")
    parser.add_argument("--explain", action="store_true",
                        help="print the loaded policy summary as JSON and exit")
    parser.add_argument("--lint", action="store_true",
                        help="check policy.toon row counts and duplicates, then exit")
    parser.add_argument("--reset", action="store_true",
                        help="delete the budget state file for --session-id")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero on an internal error instead of degrading to ask")
    parser.add_argument("--mode", choices=list(MODES),
                        help="shadow (log the decision, block nothing) or enforce "
                             "(return the decision); overrides %s and policy.toon"
                             % MODE_ENV_VAR)
    parser.add_argument("--shadow-log",
                        help="override %s for this call" % SHADOW_LOG_ENV_VAR)
    return parser


def lint_policy(policy):
    """Return a list of problems with policy.toon.  Empty means clean."""
    problems = []
    for name, table in sorted(policy.doc["tables"].items()):
        if len(table["rows"]) != table["declared"]:
            problems.append("table %s declares %d rows but has %d"
                            % (name, table["declared"], len(table["rows"])))
        for row in table["rows"]:
            if len(row) != len(table["fields"]):
                problems.append("table %s has a row with %d fields, expected %d"
                                % (name, len(row), len(table["fields"])))
    for table_name, key in (
        ("bash_capabilities", "argv0"),
        ("bash_read_any", "argv0"),
        ("bash_read_claude_home", "argv0"),
        ("bash_denied", "argv0"),
        ("bash_denied_interpreters", "argv0"),
        ("bash_denied_extra", "argv0"),
        ("git_read_subcommands", "subcommand"),
        ("git_write_flags", "flag"),
        ("write_allowed_paths", "glob"),
        ("mcp_tools", "name"),
    ):
        seen = set()
        for row in _table_rows(policy.doc, table_name):
            value = (row.get(key) or "").strip()
            if value in seen:
                problems.append("table %s lists %r twice" % (table_name, value))
            seen.add(value)
    for table_name in ("bash_capabilities", "bash_read_any", "bash_read_claude_home"):
        for row in _table_rows(policy.doc, table_name):
            value = (row.get("argv0") or "").strip().lower()
            if value and value in policy.bash_denied:
                problems.append("%r is allowed by %s and denied at the same time"
                                % (value, table_name))
    for row in _table_rows(policy.doc, "bash_read_guards"):
        value = (row.get("argv0") or "").strip().lower()
        if value and value in policy.bash_denied:
            problems.append("%r is guarded by bash_read_guards and denied at the "
                            "same time" % value)
        if value and value not in policy.bash_read_any:
            problems.append("bash_read_guards constrains %r, which is not a reader"
                            % value)
    return problems


def explain_policy(policy):
    return {
        "policy_version": policy.version,
        "policy_path": policy.path,
        "deny_reason": policy.deny_reason,
        "dispatch_hint": policy.dispatch_hint,
        "budget_soft_limit": policy.budget_soft_limit,
        "budget_ask_limit": policy.budget_ask_limit,
        "budget_exempt_tools": sorted(policy.budget_exempt_tools),
        "bash_capabilities": sorted(policy.bash_capabilities),
        "bash_read_any": sorted(policy.bash_read_any),
        "bash_read_claude_home": sorted(policy.bash_read_claude_home),
        "bash_read_denied_paths": list(policy.bash_read_denied_paths),
        "shell_assignment_denied": sorted(policy.shell_assignment_denied),
        "git_read_subcommands": sorted(policy.git_read_subcommands),
        "git_write_flags": sorted(policy.git_write_flags),
        "bash_denied": sorted(policy.bash_denied),
        "tools": {k: v[0] for k, v in sorted(policy.tools.items())},
        "write_tools": sorted(policy.write_tools),
        "write_allowed_paths": policy.write_allowed_paths,
        "mcp_tools": {k: v[0] for k, v in sorted(policy.mcp_tools.items())},
        "override_env_var": policy.override_env_var,
        "mode": policy.mode,
        "default_mode": DEFAULT_MODE,
        "modes": list(MODES),
        "shadow_audit_log": policy.shadow_audit_log,
        "reason_codes": sorted(REASON_CODES),
    }


def _emit(out, annotate=False, detail=None):
    if annotate and detail is not None:
        out = dict(out)
        out["l1Policy"] = detail
    sys.stdout.write(json.dumps(out) + "\n")
    return 0


def emit_decision(out, mode, detail=None, annotate=False, policy=None, env=None,
                  state_dir=None, shadow_log=None, session_id="", tool="",
                  tool_input=None):
    """Return the exit code for one decision, according to the mode.

    ``enforce`` is unchanged: the envelope goes to stdout and Claude Code acts
    on it.  ``shadow`` computes exactly the same decision, appends one redacted
    audit line carrying it with ``"shadow": true``, and returns 0 with nothing
    on stdout, so Claude Code proceeds normally.  Budget warnings and the
    budget ``ask`` are recorded in the line and otherwise ignored, which is the
    only difference a shadow run can have.
    """
    if normalise_mode(mode) != ENFORCE:
        policy = policy if policy is not None else load_policy()
        env = os.environ if env is None else env
        if state_dir is None:
            state_dir = resolve_state_dir(env)
        log_path = resolve_shadow_log(env, state_dir, policy, shadow_log)
        append_audit(log_path, shadow_record(policy, detail, session_id, tool,
                                             tool_input, SHADOW))
        return 0
    return _emit(out, annotate, detail)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (IOError, OSError, PolicyError) as exc:
        sys.stderr.write("l1-policy: cannot load policy: %s\n" % exc)
        return 1

    if args.lint:
        problems = lint_policy(policy)
        for problem in problems:
            sys.stderr.write("l1-policy: lint: %s\n" % problem)
        if problems:
            return 1
        sys.stdout.write("l1-policy: policy %s lint ok\n" % policy.path)
        return 0

    if args.explain:
        sys.stdout.write(json.dumps(explain_policy(policy), indent=2, sort_keys=True) + "\n")
        return 0

    env = dict(os.environ)
    if args.state_dir:
        env["L1_POLICY_STATE_DIR"] = args.state_dir
    state_dir = resolve_state_dir(env, args.state_dir)
    store = StateStore(state_dir)

    mode, mode_source = resolve_mode(env, policy, args.mode)
    for _label, _value in (("--mode", args.mode),
                           (MODE_ENV_VAR, env.get(MODE_ENV_VAR)),
                           ("policy.toon", policy.doc["scalars"].get("mode"))):
        if _value and _value.strip().lower() not in MODES:
            sys.stderr.write(
                "l1-policy: %s=%r is not one of %s; using %s from %s\n"
                % (_label, _value, "/".join(MODES), mode, mode_source))
            break

    def finish(out, detail, payload=None):
        """Hand one decided payload to the mode: enforce prints, shadow logs."""
        payload = payload or {}
        return emit_decision(
            out, mode, detail, annotate=args.annotate, policy=policy, env=env,
            state_dir=state_dir, shadow_log=args.shadow_log,
            session_id=payload.get("session_id") or args.session_id or "default",
            tool=payload.get("tool_name") or payload.get("toolName") or args.tool or "",
            tool_input=payload.get("tool_input") or {},
        )

    if args.reset:
        store.reset(args.session_id or "default")
        sys.stdout.write(json.dumps({"reset": True, "state_dir": state_dir}) + "\n")
        return 0

    payload = None
    if args.command is not None:
        payload = {
            "session_id": args.session_id or "cli",
            "cwd": args.cwd or os.getcwd(),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": args.command},
        }
    elif args.tool:
        try:
            tool_input = json.loads(args.tool_input) if args.tool_input else {}
        except ValueError as exc:
            sys.stderr.write("l1-policy: --tool-input is not JSON: %s\n" % exc)
            return 2
        payload = {
            "session_id": args.session_id or "cli",
            "cwd": args.cwd or os.getcwd(),
            "hook_event_name": "PreToolUse",
            "tool_name": args.tool,
            "tool_input": tool_input,
        }

    if payload is None:
        raw = ""
        try:
            if not sys.stdin.isatty():
                raw = sys.stdin.read()
        except (IOError, OSError, ValueError):
            raw = ""
        if not raw.strip():
            return finish(render(
                ALLOW, "allow: no PreToolUse payload on stdin, nothing to decide.",
                "input.empty",
            ), {
                "capability": "empty-input", "decision": ALLOW,
                "reason_code": "input.empty", "detail": {},
            })
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            return finish(render(
                ASK,
                "ask: stdin was not a valid PreToolUse JSON payload (%s); the L1 policy could "
                "not be evaluated, so a human decides. %s." % (exc, policy.dispatch_hint),
                "input.unreadable",
            ), {"capability": "unreadable-input", "decision": ASK,
                "reason_code": "input.unreadable", "detail": {}})
        if not isinstance(payload, dict):
            return finish(render(
                ASK, "ask: the PreToolUse payload was not a JSON object.",
                "input.unreadable",
            ), {"capability": "unreadable-input", "decision": ASK,
                "reason_code": "input.unreadable", "detail": {}})

    event = payload.get("hook_event_name") or payload.get("hookEventName") or "PreToolUse"
    if event != "PreToolUse":
        return finish(render(
            ALLOW, "allow: hook_event_name is %r, not PreToolUse." % event,
            "input.other_event",
        ), {"capability": "other-event", "decision": ALLOW,
            "reason_code": "input.other_event", "detail": {"hook_event_name": event}})

    if args.session_id:
        payload["session_id"] = args.session_id
    if args.cwd:
        payload["cwd"] = args.cwd

    try:
        out, detail = decide(payload, policy, env=env, state_dir=state_dir,
                             audit_log=args.audit_log, state_store=store)
    except Exception as exc:  # noqa: BLE001 - a hook must never wedge the session
        if args.strict:
            raise
        sys.stderr.write("l1-policy: internal error: %s: %s\n" % (type(exc).__name__, exc))
        return finish(render(
            ASK,
            "ask: the L1 policy hook failed internally (%s: %s); a human decides. %s."
            % (type(exc).__name__, exc, policy.dispatch_hint),
            "error.internal",
        ), {"capability": "internal-error", "decision": ASK,
            "reason_code": "error.internal", "detail": {}})

    return finish(out, detail, payload)


if __name__ == "__main__":
    sys.exit(main())