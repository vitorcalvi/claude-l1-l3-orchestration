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

import json
import os
import re
import sys
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
    "bash.ssh_allowed": ALLOW,
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
    "bash.denied.git_force": DENY,
    "bash.denied.read_guard": DENY,
    "bash.denied.redirect_write": DENY,
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
    "tool.denied.read_guard": DENY,
    "error.failclosed": DENY,
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


def _bool_scalar(doc, key, default):
    raw = doc["scalars"].get(key)
    if raw is None:
        return default
    val = str(raw).strip().lower()
    if val in ("true", "1", "yes", "on"):
        return True
    if val in ("false", "0", "no", "off"):
        return False
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
        self.shadow_log_allow = _bool_scalar(doc, "shadow.log_allow", True)
        self.shadow_max_bytes = max(0, _int_scalar(doc, "shadow.max_bytes", 0))
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

        # ssh invocations whose WHOLE command line matches one of these
        # compiled regexes are allowed before the per-segment classifier
        # denies `ssh` as remote, provided the command carries no compound
        # operators. See policy.toon `ssh_allowed`.
        self.ssh_allowed = []
        for row in _table_rows(doc, "ssh_allowed"):
            pattern = (row.get("pattern") or "").strip()
            if not pattern:
                continue
            try:
                self.ssh_allowed.append(re.compile(pattern))
            except re.error:
                pass

        # Reason-code prefixes that stay enforced even while the global
        # mode is shadow. A deny whose `[reason_code=...]` starts with any
        # of these prefixes is emitted on stdout (as enforce) instead of
        # being shadow-logged.
        enforce_raw = (scalars.get("enforce_reason_prefixes") or "").strip()
        self.enforce_reason_prefixes = [
            part.strip()
            for part in enforce_raw.split(",")
            if part.strip()
        ]

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

        self.tool_read_denied_paths = [
            (row.get("glob") or "").strip()
            for row in _table_rows(doc, "tool_read_denied_paths")
            if (row.get("glob") or "").strip()]
        self.self_protect_paths = [
            (row.get("glob") or "").strip()
            for row in _table_rows(doc, "self_protect_paths")
            if (row.get("glob") or "").strip()]

        self.locked_reason_prefixes = [
            x.strip() for x in (scalars.get("locked_reason_prefixes") or "").split(",")
            if x.strip()]
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


CACHE_BASENAME = "policy-cache.json"
CACHE_SCHEMA = 1


def _policy_fingerprint(path):
    """(key dict, text) for the policy file: path, mtime_ns, size and sha256."""
    import hashlib  # lazy: only needed when a cache is in play
    with open(path, "rb") as fh:
        raw = fh.read()
    st = os.stat(path)
    key = {"schema": CACHE_SCHEMA, "path": os.path.abspath(path),
           "mtime_ns": st.st_mtime_ns, "size": st.st_size,
           "sha256": hashlib.sha256(raw).hexdigest()}
    return key, raw.decode("utf-8")


def _read_cache(cache_path, key):
    """Return the cached parsed doc when it matches `key`, else None."""
    try:
        with open(cache_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        doc = data["doc"]
        if data["key"] == key and isinstance(doc, dict) and "scalars" in doc and "tables" in doc:
            return doc
    except Exception:  # noqa: BLE001 - corrupt or mismatched cache is just a miss
        pass
    return None


def _write_cache(cache_path, key, doc):
    tmp = "%s.%d.tmp" % (cache_path, os.getpid())
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"key": key, "doc": doc}, fh)
        os.replace(tmp, cache_path)
    except (IOError, OSError):
        try:
            os.unlink(tmp)
        except OSError:
            pass


def load_policy(path=None, cache_dir=None):
    """Load and type policy.toon. `path` defaults to the file next to this script.

    With `cache_dir` the parsed document is cached as JSON there and reused
    while the policy's path, mtime_ns, size and sha256 are unchanged.  Any
    cache problem falls back to parsing policy.toon.
    """
    path = path or default_policy_path()
    if not cache_dir:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        return Policy(parse_toon(text), path)
    key, text = _policy_fingerprint(path)
    cache_path = os.path.join(cache_dir, CACHE_BASENAME)
    doc = _read_cache(cache_path, key)
    if doc is None:
        doc = parse_toon(text)
        _write_cache(cache_path, key, doc)
    return Policy(doc, path)


# Tools the harness polls constantly. In enforce mode with no override they
# are allowed without loading the policy (policy.toon lists both as allow and
# as budget-exempt). Shadow mode still logs, which needs the policy.
FAST_SAFE_TOOLS = frozenset(("ListAgents", "ToolSearch"))


def _fast_safe_allow(env):
    """Handle a safe-set stdin call before any policy load; True when done."""
    if env.get("L1_POLICY_OVERRIDE") or env.get("L1_TEST_RAISE") == "1":
        return False
    mode = (env.get(MODE_ENV_VAR) or "").strip().lower()
    if mode != ENFORCE:
        return False
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(payload, dict):
        return False
    tool = payload.get("tool_name") or payload.get("toolName") or ""
    event = payload.get("hook_event_name") or payload.get("hookEventName") or "PreToolUse"
    if tool not in FAST_SAFE_TOOLS or event != "PreToolUse":
        # hand the already-read payload back to the slow path
        sys.stdin = _ReplayStdin(raw)
        return False
    sys.stdout.write(json.dumps(render(
        ALLOW, "allow: tool '%s' is allowed." % tool, "tool.allow")) + "\n")
    return True


class _ReplayStdin(object):
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text

    def isatty(self):
        return False


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
# fail closed, break-glass, locked codes (D2, D3)
# ---------------------------------------------------------------------------

SAFE_TOOLS = frozenset(("TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
                        "ToolSearch", "AskUserQuestion", "ListAgents"))
READ_TOOLS = frozenset(("Read", "Grep", "Glob"))
GUARDED_TOOLS = READ_TOOLS | frozenset(("Edit", "Write", "MultiEdit", "NotebookEdit"))
# Directories (under $HOME) and files the fail-closed table always protects.
SECRET_DIRS = (".secrets", ".ssh", ".aws", os.path.join(".config", "gcloud"))
SECRET_FILES = (".netrc",)
# Codes no override and no shadow mode may lift (design D1/D2/D3).
LOCKED_CODE_PREFIXES = ("tool.denied.read_guard", "tool.denied.self_protect",
                        "bash.denied.remote_destructive", "bash.denied.ssh_compound",
                        "error.")
_BREAKGLASS_TAIL = r"/claude-backups/pre-fix-[0-9T]+/restore\.sh"


def is_locked_code(code, extra=()):
    code = code or ""
    return any(code.startswith(prefix) for prefix in tuple(LOCKED_CODE_PREFIXES) + tuple(extra))


def _secret_roots(env):
    home = _home(env)
    if not home:
        return []
    home = os.path.normpath(home)
    roots = [os.path.join(home, d) for d in SECRET_DIRS]
    roots += [os.path.join(home, f) for f in SECRET_FILES]
    return roots


def _resolve(path):
    """realpath of the path, or of its nearest existing parent plus the tail."""
    path = os.path.normpath(path)
    tail = []
    probe = path
    while probe and not os.path.lexists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        tail.insert(0, os.path.basename(probe))
        probe = parent
    return os.path.normpath(os.path.join(os.path.realpath(probe), *tail))


def _expand_glob(pattern, env):
    home = _home(env) or ""
    if pattern == "~":
        return home
    if pattern.startswith("~/"):
        return os.path.join(home, pattern[2:])
    return pattern


def _glob_root(expanded):
    """Literal directory prefix of a glob (everything before the first wildcard)."""
    cut = len(expanded)
    for ch in "*?[":
        idx = expanded.find(ch)
        if idx != -1:
            cut = min(cut, idx)
    prefix = expanded[:cut]
    if cut < len(expanded):
        prefix = prefix.rsplit("/", 1)[0]
    return prefix.rstrip("/")


def _path_variants(raw, cwd, env):
    """Lexical and realpath forms of a tool path, `$HOME` and `~` expanded."""
    text = raw.strip()
    home = _home(env) or ""
    if home:
        text = text.replace("${HOME}", home).replace("$HOME", home)
    norm = normalise_path(text, cwd, env)
    if not norm:
        return []
    out = [norm]
    real = _resolve(norm)
    if real != norm:
        out.append(real)
    return out


def _globs_hit(globs, variant, env, ancestors=False):
    for pattern in globs:
        expanded = _expand_glob(pattern, env)
        root = _glob_root(expanded)
        for form in set((expanded, root + "/**" if root and expanded.endswith("/**") else expanded)):
            if glob_match(form, variant):
                return pattern
        # A bare directory only counts for a recursive glob (`dir/**`) or a literal path;
        # `settings**.json` does not protect the directory that merely holds it.
        if root and variant == root and (expanded.endswith("/**") or root == expanded):
            return pattern
        if ancestors and root and under(root, variant):
            return pattern
        if ancestors and root and root != expanded:
            real_root = _resolve(root)
            if real_root != root and (under(variant, real_root) or under(real_root, variant)):
                return pattern
    return None


def tool_path_hit(tool, tool_input, policy, cwd, env):
    """read_guard: policy-listed secret globs, after ~/$HOME expansion and realpath."""
    if tool not in GUARDED_TOOLS or not isinstance(tool_input, dict):
        return None
    cwd = cwd or os.getcwd()
    searching = tool in ("Grep", "Glob")
    candidates = []
    for key in ("file_path", "path", "notebook_path"):
        if isinstance(tool_input.get(key), str):
            candidates.append(tool_input[key])
    if searching and not isinstance(tool_input.get("path"), str):
        candidates.append(cwd)
    if searching:
        for key in ("pattern", "glob"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.startswith(("~", "$HOME", "${HOME}", "/")):
                candidates.append(value)
    for raw in candidates:
        for variant in _path_variants(raw, cwd, env):
            hit = _globs_hit(policy.tool_read_denied_paths, variant, env, ancestors=searching)
            if hit:
                return "%s touches protected path %s (matches %s)" % (tool, variant, hit)
    return None


SELF_PROTECT_TOOLS = frozenset(("Write", "Edit", "MultiEdit", "NotebookEdit"))
WRITE_VERB_RE = re.compile(
    r"(?:^|[\s;&|(`])(?:tee|cp|mv|rm|ln|chmod|chown|truncate|install|dd|rsync|sed\s+-[A-Za-z]*i"
    r"|perl\s+-[A-Za-z]*i|python3?\s+-c|node\s+-e)(?=[\s;&|)`]|$)|>")


def _state_dir_hit(variant, env):
    """The resolved hook state dir (parsed-policy cache) is read-only to the agent."""
    state = resolve_state_dir(env)
    for root in set((state, _resolve(state))):
        if under(variant, root):
            return "state dir " + root
    return None


_PAYLOAD_WRITE_RE = re.compile(
    r"""['"][wax][bt+]*['"]|\.write|writeFile|appendFile|createWriteStream|unlink|rmtree"""
    r"""|rename|\bremove\b|copyfile|\bmove\b|\bcopy\b|os\.system|subprocess|""" + WRITE_VERB_RE.pattern)
_PATH_TOKEN_RE = re.compile(r"""[^\s;&|()<>=\"'`,]+""")
_COMMAND_PREFIXES = frozenset(("sudo", "env", "command", "nohup", "time", "exec", "doas",
                               "nice", "ionice", "timeout", "xargs", "busybox"))
_INTERP_INLINE = {"python3": "-c", "python": "-c", "node": "-e", "bash": "-c", "sh": "-c",
                  "zsh": "-c", "dash": "-c"}


def _protected_hit(tok, policy, cwd, env):
    if not tok or not re.search(r"[/~$.]", tok):
        return None
    for variant in _path_variants(tok, cwd, env):
        hit = _globs_hit(policy.self_protect_paths, variant, env) or _state_dir_hit(variant, env)
        if hit:
            return "Bash writes to protected path %s (%s)" % (variant, hit)
    return None


def _first_protected(tokens, policy, cwd, env):
    for tok in tokens:
        hit = _protected_hit(tok, policy, cwd, env)
        if hit:
            return hit
    return None


def _non_options(args):
    return [a for a in args if a and not a.startswith("-")]


def _segment_write_targets(tokens):
    """Return (write-target tokens, inline payload or None) for one command segment."""
    targets = []
    args = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if re.fullmatch(r"[<>]+[&<>]?", tok):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok.startswith(">") and target and target != "/dev/null" and not (
                    tok.endswith("&") and re.fullmatch(r"\d+|-", target)):
                targets.append(target)
            i += 2
            continue
        args.append(tok)
        i += 1
    while args and (args[0] in _COMMAND_PREFIXES or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", args[0])
                    or (args[0].startswith("-") and len(args) > 1)
                    or re.fullmatch(r"\d+[smhd]?", args[0])):
        args = args[1:]
    if not args:
        return targets, None
    cmd = os.path.basename(args[0])
    rest = args[1:]
    flags = [a for a in rest if a.startswith("-")]
    plain = _non_options(rest)
    if cmd in ("rm", "chmod", "chown", "truncate", "tee"):
        targets += plain
    elif cmd in ("sed", "perl"):
        if any(re.fullmatch(r"-[A-Za-z]*i.*", f) or f == "--in-place" for f in flags):
            targets += plain
    elif cmd in ("cp", "mv", "ln", "install", "rsync"):
        dest = None
        for k, a in enumerate(rest):
            if a in ("-t", "--target-directory") and k + 1 < len(rest):
                dest = rest[k + 1]
            elif a.startswith("--target-directory="):
                dest = a.split("=", 1)[1]
        if dest is None and len(plain) >= 2:
            dest = plain[-1]
        if dest:
            targets.append(dest)
    elif cmd == "dd":
        targets += [a[3:] for a in rest if a.startswith("of=")]
    elif cmd == "sort":
        for k, a in enumerate(rest):
            if a in ("-o", "--output") and k + 1 < len(rest):
                targets.append(rest[k + 1])
            elif a.startswith("--output="):
                targets.append(a.split("=", 1)[1])
    if cmd == "sed":
        # a sed script command `w file` / `e cmd` writes or executes; force a deny target
        for a in rest:
            if not a.startswith("-") and re.search(r"(?:^|[;{}\n])\s*[we]\s+\S", a):
                targets.append("<sed-script-write>")
    elif cmd in _INTERP_INLINE:
        flag = _INTERP_INLINE[cmd]
        for k, a in enumerate(rest):
            if a == flag and k + 1 < len(rest):
                return targets, (cmd, rest[k + 1])
    return targets, None


def _bash_write_hit(command, policy, cwd, env, depth=0):
    """A protected path only counts as a write target in its own segment."""
    for tokens in parse_commands(command):
        targets, inline = _segment_write_targets(tokens)
        hit = _first_protected(targets, policy, cwd, env)
        if hit:
            return hit
        if inline:
            cmd, payload = inline
            if cmd in ("bash", "sh", "zsh", "dash"):
                if depth < 4:
                    hit = _bash_write_hit(payload, policy, cwd, env, depth + 1)
                    if hit:
                        return hit
            elif _PAYLOAD_WRITE_RE.search(payload):
                hit = _first_protected(_PATH_TOKEN_RE.findall(payload), policy, cwd, env)
                if hit:
                    return hit
    return None


def self_protect_hit(tool, tool_input, command, policy, cwd, env):
    """self_protect: the hook, settings, retention script, backups and state dir are read-only to the agent."""
    cwd = cwd or os.getcwd()
    if tool in SELF_PROTECT_TOOLS and isinstance(tool_input, dict):
        for key in ("file_path", "notebook_path", "path", "filePath", "new_path", "target_path"):
            value = tool_input.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            for variant in _path_variants(value, cwd, env):
                hit = _globs_hit(policy.self_protect_paths, variant, env) or _state_dir_hit(variant, env)
                if hit:
                    return "%s target %s is protected (%s)" % (tool, variant, hit)
    if tool == "Bash" and command:
        return _bash_write_hit(command, policy, cwd, env)
    return None


def secret_path_hit(tool, tool_input, cwd, env, extended=False):
    """Return a reason string when the call touches a protected secret path."""
    if tool not in GUARDED_TOOLS or not isinstance(tool_input, dict):
        return None
    roots = [_resolve(r) for r in _secret_roots(env)]
    roots += _secret_roots(env)
    cwd = cwd or os.getcwd()
    candidates = []
    for key in ("file_path", "path", "notebook_path"):
        if isinstance(tool_input.get(key), str):
            candidates.append(tool_input[key])
    if tool in ("Grep", "Glob") and not isinstance(tool_input.get("path"), str):
        candidates.append(cwd)
    for key in ("pattern", "glob"):
        value = tool_input.get(key)
        if tool in ("Grep", "Glob") and isinstance(value, str) and (
                value.startswith("~") or value.startswith("$HOME") or value.startswith("/")):
            candidates.append(value)
    home = _home(env) or ""
    for raw in candidates:
        text = raw.strip()
        if home:
            text = text.replace("${HOME}", home).replace("$HOME", home)
        norm = normalise_path(text, cwd, env)
        if not norm:
            continue
        for variant in (norm, _resolve(norm)):
            for root in roots:
                if under(variant, root):
                    return "%s touches protected path %s" % (tool, root)
                if tool in ("Grep", "Glob") and under(root, variant):
                    return "%s root %s contains protected path %s" % (tool, variant, root)
            if extended:
                base = os.path.basename(variant)
                if (base.endswith(".pem") or base.startswith("id_rsa")
                        or base.startswith("id_ed25519")):
                    return "%s touches key file %s" % (tool, base)
    return None


def breakglass_ok(payload, env):
    """True for the sanctioned restore.sh whose sha256 matches breakglass.sha256."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return False
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    home = _home(env)
    if not isinstance(command, str) or not home:
        return False
    match = re.fullmatch("bash (" + re.escape(os.path.normpath(home)) + _BREAKGLASS_TAIL + ")",
                         command)
    if not match:
        return False
    try:
        import hashlib
        with open(match.group(1), "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        with open(os.path.join(home, ".claude", "hooks", "breakglass.sha256"), "r") as fh:
            wanted = (fh.read().split() or [""])[0].strip().lower()
    except (IOError, OSError):
        return False
    return bool(wanted) and wanted == actual


def failclosed(payload, why, env):
    """The D2 table. Exit 0 for safe/break-glass/harmless reads, else exit 2."""
    env = os.environ if env is None else env
    tool = ""
    tool_input = {}
    cwd = None
    if isinstance(payload, dict):
        tool = payload.get("tool_name") or payload.get("toolName") or ""
        tool_input = payload.get("tool_input")
        cwd = payload.get("cwd")
    if breakglass_ok(payload, env) or tool in SAFE_TOOLS:
        return 0
    if tool in READ_TOOLS and not secret_path_hit(tool, tool_input, cwd, env):
        return 0
    reason = ("deny: the L1 policy hook failed closed (%s); only the safe tool set and "
              "reads outside secret paths are allowed until it is repaired" % why)
    sys.stderr.write("l1-policy: %s\n" % reason)
    sys.stdout.write(json.dumps(render(DENY, reason, "error.failclosed")) + "\n")
    return 2


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
_REASON_CODE_VALUE_RE = re.compile(r"\[reason_code=([^\]]+)\]")


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
            # `~/` in the glob is expanded against HOME so the pattern
            # lines up with the resolved absolute path normalise_path()
            # produced: `~/.secrets/**` and `~/.ssh/**` only match when the
            # pattern itself is expanded to the same prefix.
            expanded_pattern = os.path.expanduser(pattern)
            if glob_match(expanded_pattern, resolved):
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
        if sub == "push":
            tail = tokens[2:]
            force_flag = any(
                t == "--force" or t == "-f"
                or t == "--force-with-lease"
                or t.startswith("--force-with-lease=")
                for t in tail
            )
            plus_ref = any(
                not t.startswith("-") and t.startswith("+")
                for t in tail
            )
            if force_flag or plus_ref:
                return deny(
                    policy,
                    "git-force",
                    "git push with force rewrites remote history; never from L1",
                    "bash.denied.git_force",
                ), argv0
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


_SSH_COMPOUND_RE = re.compile(r"[;&|<>(){}`\n]|\$\(")
_SSH_OPTS_WITH_ARG = frozenset("BbcDEeFIiJLlmOopQRSWw")
_REMOTE_PREFIXES = frozenset(("sudo", "env", "command", "nohup", "time", "exec", "doas",
                              "nice", "ionice", "timeout", "xargs", "busybox"))
_REMOTE_HALT = frozenset(("shutdown", "reboot", "poweroff", "halt"))


def _ssh_payloads(segments, policy):
    """Return the remote command text of every ssh segment ('' for a login)."""
    out = []
    for tokens in segments:
        tokens = _peel_wrappers(list(tokens), policy)
        if not tokens or argv0_of(tokens[0]).lower() != "ssh":
            continue
        rest = tokens[1:]
        i = 0
        host_seen = False
        while i < len(rest):
            tok = rest[i]
            if not host_seen and tok.startswith("-") and len(tok) > 1:
                i += 2 if (tok[-1] in _SSH_OPTS_WITH_ARG and len(tok) == 2) else 1
                continue
            if not host_seen:
                host_seen = True
                i += 1
                continue
            break
        out.append(" ".join(rest[i:]))
    return out


def _remote_destructive(payload):
    """Best-effort: name the destructive form in an ssh payload, else ''."""
    import shlex
    for part in re.split(r"[;&|\n(){}`]+|\$\(", payload):
        try:
            toks = shlex.split(part)
        except ValueError:
            toks = part.split()
        while toks and (toks[0] in _REMOTE_PREFIXES or "=" in toks[0].split("/")[0]
                        or (toks[0].startswith("-") and len(toks) > 1)):
            toks = toks[1:]
        if not toks:
            continue
        cmd = os.path.basename(toks[0])
        args = toks[1:]
        flags = [a for a in args if a.startswith("-")]
        short = "".join(f[1:] for f in flags if not f.startswith("--"))
        if cmd == "rm" and (("r" in short or "R" in short or "--recursive" in flags)
                            and ("f" in short or "--force" in flags)):
            return "rm -rf"
        if cmd == "find" and "-delete" in args:
            return "find -delete"
        if cmd.startswith("mkfs"):
            return "mkfs"
        if cmd == "dd" and any(a.startswith("of=") for a in args):
            return "dd of="
        if cmd in _REMOTE_HALT:
            return cmd
        if cmd == "docker" or cmd == "docker-compose":
            words = [a for a in args if not a.startswith("-")]
            if cmd == "docker" and words[:1] == ["compose"]:
                words = words[1:]
                cmd = "docker-compose"
            if cmd == "docker" and (words[:1] in (["rm"], ["rmi"]) or words[:2] == ["volume", "rm"]
                                    or words[:2] == ["system", "prune"]):
                return "docker " + " ".join(words[:2])
            if cmd == "docker-compose" and words[:1] == ["down"] and (
                    "-v" in args or "--volumes" in args):
                return "docker compose down -v"
        if cmd == "git" and "push" in args and any(
                a in ("-f", "--force") or a.startswith("--force-with-lease")
                or (a.startswith("+") and len(a) > 1) for a in args):
            return "git push --force"
        if cmd == "truncate" and "-s" in args and args[args.index("-s") + 1:][:1] == ["0"]:
            return "truncate -s 0"
    if re.search(r">\s*/dev/sd", payload):
        return "> /dev/sd"
    return ""


def _enforced_code(code, policy):
    code = code or ""
    return is_locked_code(code, policy.locked_reason_prefixes) or any(
        code.startswith(p) for p in policy.enforce_reason_prefixes)


def _inline_secret_hit(command, policy, cwd, env):
    """Any word of the line, quoted or inside an interpreter payload, on a read-denied path."""
    for tok in _PATH_TOKEN_RE.findall(command):
        if not re.search(r"[/~$.]", tok):
            continue
        for variant in _path_variants(tok, cwd, env):
            if _globs_hit(policy.tool_read_denied_paths, variant, env):
                return tok
    return None


def _inline_shell_verdict(tokens, policy, cwd, env, depth=0):
    """Verdict of the payload of `bash -c`, `sh -c`, `zsh -c`, or None."""
    tokens = _peel_wrappers(list(tokens), policy)
    if depth > 3 or len(tokens) < 3 or argv0_of(tokens[0]).lower() not in ("bash", "sh", "zsh", "dash"):
        return None
    for k, tok in enumerate(tokens[1:-1], 1):
        if tok == "-c" or (tok.startswith("-") and not tok.startswith("--") and tok.endswith("c")):
            verdict = evaluate_bash(tokens[k + 1], policy, cwd, env)
            return verdict if verdict.decision == DENY else None
    return None


def _redirect_target_allowed(target, policy, cwd, env):
    """A shell write target must be a path the Write tool may write (write_allowed_paths)."""
    home = _home(env)
    tgt = (target or "").strip("'\"")
    if not tgt or "$" in tgt or "`" in tgt or tgt.startswith("<"):
        return False
    if tgt.startswith("~"):
        tgt = home + tgt[1:]
    if not os.path.isabs(tgt):
        tgt = os.path.join(cwd or os.getcwd(), tgt)
    tgt = os.path.normpath(tgt)
    for pattern in policy.write_allowed_paths:
        pat = home + pattern[1:] if pattern.startswith("~") else pattern
        if glob_match(pat, tgt):
            return True
    return False


_HEREDOC_REDIR_RE = re.compile(r"(?:^|[\s;|&(])(\d*)(>&|&?>>?\|?)\s*([^\s;&|()]+)")


def _heredoc_line_write_targets(raw):
    """parse_commands drops redirects that share a line with `<<` / `<<<`; scan those lines raw."""
    found = []
    for line in (raw or "").split("\n"):
        if "<<" not in line:
            continue
        flat = re.sub(r'"[^"]*"|\'[^\']*\'', '""', line)
        for _fd, op, target in _HEREDOC_REDIR_RE.findall(flat):
            if op == ">&" and re.fullmatch(r"\d+|-", target):
                continue
            if target == "/dev/null":
                continue
            found.append(target)
    return found


def evaluate_bash(command, policy, cwd, env):
    """Check every segment of a (possibly compound) Bash command line."""
    segments = parse_commands(command or "")
    if not segments:
        return allow("empty command, nothing to run.", "empty", "bash.empty")
    # ssh payloads: best-effort remote destructive check and the compound
    # check run first and are enforced whatever the mode (design D1).
    raw_command = command or ""
    payloads = _ssh_payloads(segments, policy)
    for payload in payloads:
        if _SSH_COMPOUND_RE.search(payload):
            return deny(
                policy,
                "ssh-compound",
                "the ssh payload carries a shell operator, so no ssh_allowed exception applies",
                "bash.denied.ssh_compound",
            )
        hit = _remote_destructive(payload)
        if hit:
            return deny(
                policy,
                "ssh-remote-destructive",
                "the ssh payload looks destructive (%s); best-effort check" % hit,
                "bash.denied.remote_destructive",
            )
    # Staged L1 policy: an ssh invocation whose WHOLE command line fully
    # matches one of the compiled ssh_allowed regexes is allowed before the
    # per-segment classifier denies `ssh` as remote, but only when the
    # command carries no compound operators anywhere.
    if policy.ssh_allowed and payloads and not _SSH_COMPOUND_RE.search(raw_command):
        for pattern_re in policy.ssh_allowed:
            if pattern_re.fullmatch(raw_command):
                return allow(
                    "ssh command matches an allowed planner pattern.",
                    "ssh-allowed",
                    "bash.ssh_allowed",
                )
    secret = _inline_secret_hit(raw_command, policy, cwd, env)
    if secret:
        return deny(
            policy,
            "bash-read-guard",
            "the command names '%s', a credential path the L1 session never touches" % secret,
            "bash.denied.read_guard",
        )
    for wt in _heredoc_line_write_targets(raw_command):
        if not _redirect_target_allowed(wt, policy, cwd, env):
            return deny(
                policy,
                "bash-redirect-write",
                "the command writes '%s', which is outside write_allowed_paths" % wt,
                "bash.denied.redirect_write",
            )
    for tokens in segments:
        wtargets, _inline = _segment_write_targets(tokens)
        for wt in wtargets:
            if not _redirect_target_allowed(wt, policy, cwd, env):
                return deny(
                    policy,
                    "bash-redirect-write",
                    "the command writes '%s', which is outside write_allowed_paths" % wt,
                    "bash.denied.redirect_write",
                )
    checked = []
    verdicts = []
    for tokens in segments:
        verdict, argv0 = _classify_segment(tokens, policy, cwd, env)
        checked.append({
            "argv0": argv0,
            "decision": verdict.decision if verdict else "skip",
        })
        verdicts.append(verdict)
        inner = _inline_shell_verdict(tokens, policy, cwd, env)
        if inner is not None:
            verdicts.append(inner)
    denied = [v for v in verdicts if v is not None and v.decision == DENY]
    if denied:
        pick = next((v for v in denied if _enforced_code(v.code, policy)), denied[0])
        detail = dict(pick.detail)
        detail["segments"] = checked
        return Verdict(DENY, pick.reason, pick.capability, pick.code, detail)
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
    import tempfile  # lazy: only the no-HOME fallback needs it
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

    hit = secret_path_hit(tool, tool_input, cwd, env, extended=True)
    if hit:
        return deny(policy, "read-guard", hit, "tool.denied.read_guard")
    hit = tool_path_hit(tool, tool_input, policy, cwd, env)
    if hit:
        return deny(policy, "read-guard", hit, "tool.denied.read_guard")
    hit = self_protect_hit(tool, tool_input, tool_input.get("command") if tool == "Bash" else "",
                           policy, cwd, env)
    if hit:
        return deny(policy, "self-protect", hit, "tool.denied.self_protect")

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
    if env.get("L1_TEST_RAISE") == "1":
        raise RuntimeError("L1_TEST_RAISE=1 forced internal error")
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
    # D3: the override never lifts a locked (security) code.
    if override_raw and verdict.decision != ALLOW and is_locked_code(
            verdict.code, policy.locked_reason_prefixes):
        override_raw = ""
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
    import argparse  # lazy: the hot path never builds a parser
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
        "shadow_log_allow": policy.shadow_log_allow,
        "shadow_max_bytes": policy.shadow_max_bytes,
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
        if (not policy.shadow_log_allow
                and (detail or {}).get("decision") == ALLOW
                and not (detail or {}).get("budget_warning")
                and not (detail or {}).get("budget_escalated")):
            return 0
        env = os.environ if env is None else env
        if state_dir is None:
            state_dir = resolve_state_dir(env)
        log_path = resolve_shadow_log(env, state_dir, policy, shadow_log)
        if policy.shadow_max_bytes > 0:
            try:
                if os.path.getsize(log_path) > policy.shadow_max_bytes:
                    os.replace(log_path, log_path + ".1")
            except OSError:
                pass
        append_audit(log_path, shadow_record(policy, detail, session_id, tool,
                                             tool_input, SHADOW))
        return 0
    return _emit(out, annotate, detail)


def _fallback_payload(args):
    """Best-effort payload for the fail-closed path; None means unknown tool."""
    if args.command is not None:
        return {"tool_name": "Bash", "tool_input": {"command": args.command},
                "cwd": args.cwd or os.getcwd()}
    if args.tool:
        try:
            tool_input = json.loads(args.tool_input) if args.tool_input else {}
        except ValueError:
            tool_input = {}
        return {"tool_name": args.tool, "tool_input": tool_input,
                "cwd": args.cwd or os.getcwd()}
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    return payload if isinstance(payload, dict) else None


def main(argv=None):
    if argv is None and len(sys.argv) == 1 and _fast_safe_allow(dict(os.environ)):
        return 0
    args = build_parser().parse_args(argv)
    try:
        _cache_env = dict(os.environ)
        if args.state_dir:
            _cache_env["L1_POLICY_STATE_DIR"] = args.state_dir
        policy = load_policy(args.policy, cache_dir=resolve_state_dir(_cache_env, args.state_dir))
    except Exception as exc:  # noqa: BLE001 - missing, unreadable or unparsable policy
        sys.stderr.write("l1-policy: cannot load policy: %s\n" % exc)
        if args.lint or args.explain or args.reset:
            return 1
        return failclosed(_fallback_payload(args), "policy not loadable: %s" % exc,
                          dict(os.environ))

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
        # Staged L1 policy: while the global mode is shadow, a deny whose
        # `[reason_code=...]` starts with any enforce_reason_prefixes entry
        # is emitted with mode enforce for this single call (the envelope
        # goes to stdout, no shadow line is written) instead of being
        # shadow-logged. Everything else stays on the shadow path.
        effective_mode = mode
        reason_text = (
            out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
        )
        code_match = _REASON_CODE_VALUE_RE.search(reason_text)
        reason_code = code_match.group(1) if code_match else ""
        if (
            effective_mode == SHADOW
            and (detail.get("decision") if detail else None) == DENY
            and (is_locked_code(reason_code, policy.locked_reason_prefixes)
                 or (policy.enforce_reason_prefixes
                     and any(
                         reason_code.startswith(prefix)
                         for prefix in policy.enforce_reason_prefixes
                     )))
        ):
            effective_mode = ENFORCE
        return emit_decision(
            out, effective_mode, detail, annotate=args.annotate, policy=policy,
            env=env,
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
            return failclosed(None, "empty stdin", env)
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            return failclosed(None, "stdin is not JSON: %s" % exc, env)
        if not isinstance(payload, dict):
            return failclosed(None, "stdin payload is not a JSON object", env)

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

    if breakglass_ok(payload, env):
        return 0

    try:
        out, detail = decide(payload, policy, env=env, state_dir=state_dir,
                             audit_log=args.audit_log, state_store=store)
    except Exception as exc:  # noqa: BLE001 - a hook must never wedge the session
        if args.strict:
            raise
        sys.stderr.write("l1-policy: internal error: %s: %s\n" % (type(exc).__name__, exc))
        return failclosed(payload, "internal error %s: %s" % (type(exc).__name__, exc), env)

    return finish(out, detail, payload)


if __name__ == "__main__":
    sys.exit(main())