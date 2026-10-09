#!/usr/bin/env python3
"""brief - write a dispatch delta from a goal and acceptance lines alone.

Usage:
    brief new <recon|build|verify> --goal TEXT --accept TEXT [--accept TEXT]...
        [--scope TEXT] [--owned PATH] [--repo NAME] [--base REF] [--lane LANE]
        [--test CMD] [-o OUT] [--report PATH] [--max-deletes N] [--effort LEVEL]
    brief new --help

Why this exists
    L1 writes two things: the goal and the acceptance lines.  Every other field
    a dispatch needs is machine written here, so a delta can never be missing a
    routing section.  The rendered delta is validated before it is written:
    `dispatch` refuses an invalid delta with exit 65, `brief` refuses to write
    one at all with exit 1 (see docs/l1opt/CONTRACT.md).

Sections, in the order they are emitted.  All sixteen are required and every
one is non-empty:
    effort, execution, lane, goal, user_request, scope, non_goals,
    constraints, acceptance, evidence_required, unknowns, remote_worker,
    remote_mode, remote_test_cmd, remote_repo, remote_base
Two more are emitted when they carry information: `owned_paths` when --owned is
given, and `task_type` on verify (mechanical).

Templates
    recon   read-only on lane paid.  The only file the worker writes is the
            report under .agent-reports/; --test defaults to a no-op gate
            because a read-only recon has no code to run.
    build   editable.  The test command ends with an ownership check anchored at
            --base (base..HEAD, so uncommitted work cannot satisfy it) and a
            deletion cap appended after it.
    verify  read-only.  --test is required: a verification with no mechanical
            test proves nothing.

Validation, one clear line per problem, exit 1:
    - the test command is a single line;
    - no acceptance line carries an angle bracket or a parenthetical remark;
    - every required section is present, non-empty and free of nested headings;
    - goal is one line, execution is remote, remote_worker is claude,
      remote_mode is read-only or editable, and effort and lane are known.

Exit codes: 0 the delta was written, 1 invalid input or invalid delta,
2 usage.  Stdlib only; nothing is installed live and no network is touched.
"""

from __future__ import annotations

import argparse
import re
import sys

PROGRAM = "brief"
VERSION = "1.0.0"

KINDS = ("recon", "build", "verify")
# server-bin/remote-dispatch.py VALID_LANES plus `auto`; `bulk` is retired.
VALID_LANES = ("paid", "coding", "fast", "reasoning", "auto")
# dispatch effective_effort accepts exactly these.
VALID_EFFORTS = ("inherit", "low", "medium", "high", "xhigh")
VALID_MODES = ("read-only", "editable")
REMOTE_WORKER = "claude"

DEFAULT_REPO = "agent-orch"
DEFAULT_BASE = "main"
DEFAULT_LANE = "paid"

OWNERSHIP_TOOL = "agent-work-bin/bin/check-ownership"
OWNERSHIP_FILE = "docs/l1opt/ownership.toon"
REPORT_DIR = ".agent-reports"

TEMPLATE_EFFORT = {"recon": "medium", "build": "high", "verify": "low"}
TEMPLATE_MODE = {"recon": "read-only", "build": "editable", "verify": "read-only"}

REQUIRED_SECTIONS = (
    "effort",
    "execution",
    "lane",
    "goal",
    "user_request",
    "scope",
    "non_goals",
    "constraints",
    "acceptance",
    "evidence_required",
    "unknowns",
    "remote_worker",
    "remote_mode",
    "remote_test_cmd",
    "remote_repo",
    "remote_base",
)

TEST_REQUIRED_REASON = {
    "build": "the test command is the gate and the deletion cap is appended to it",
    "verify": "a read-only verification with no mechanical test proves nothing",
}

# What an acceptance line may never carry: an angle bracket or a parenthetical
# remark.  Both are mangled by the shell quoting a delta goes through, so a
# line carrying one is refused rather than silently rewritten.
BANNED_IN_ACCEPTANCE = {
    "<": "an angle bracket",
    ">": "an angle bracket",
    "(": "a parenthetical remark",
    ")": "a parenthetical remark",
}

HEADING_RE = re.compile(r"^##[ \t]+(?P<name>\S.*?)[ \t]*$")


class BriefError(Exception):
    """An input or delta defect that must exit 1 with a clear message."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def slugify(text, limit=60):
    """The same slug rule dispatch uses for a run id: [a-z0-9] runs become -."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:limit].strip("-") or "delta"


def bullets(items):
    """Render items as a `- item` block."""
    return "".join("- %s\n" % item for item in items)


def one_line(value, label):
    """Strip a single-line flag value or refuse it."""
    if "\n" in value or "\r" in value:
        raise BriefError("%s must be a single line" % label)
    return value.strip()


def dedupe(lines):
    """Keep the first of each repeated line, in the order given."""
    seen = set()
    out = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def plain(text, label):
    """Refuse an angle bracket or a parenthetical remark in an acceptance line."""
    found = sorted(
        {BANNED_IN_ACCEPTANCE[ch] for ch in text if ch in BANNED_IN_ACCEPTANCE}
    )
    if found:
        raise BriefError("%s carries %s: %r" % (label, " and ".join(found), text))
    return text


def report_path(goal):
    return "%s/%s.md" % (REPORT_DIR, slugify(goal))


def ownership_check(base):
    """The anchored ownership check: it diffs base..HEAD, never the worktree."""
    return "python3 %s %s %s HEAD" % (OWNERSHIP_TOOL, OWNERSHIP_FILE, base)


def deletion_cap(base, cap):
    """Count the files the job deleted between base and HEAD and cap them."""
    count = "git diff --name-only --diff-filter=D %s..HEAD | wc -l | tr -d ' '" % base
    return 'test "$(%s)" -le %d' % (count, cap)


def build_test_command(test, base, cap):
    """The caller test command, then the ownership check, then the cap."""
    return " && ".join([test, ownership_check(base), deletion_cap(base, cap)])


# --------------------------------------------------------------------------
# template blocks
# --------------------------------------------------------------------------
def recon_test(path):
    return "true  # read-only recon: the deliverable is %s" % path


def user_request(kind, goal):
    if kind == "recon":
        return (
            "Recon only: state what is true in the repository about: %s\n"
            "Answer with file:line evidence and change nothing." % goal
        )
    if kind == "build":
        return (
            "Build it: %s\n"
            "The delta below is already complete; work only from it." % goal
        )
    return (
        "Verify it: %s\n"
        "Re-run the test command and report PASS or FAIL per acceptance line."
        % goal
    )


def owned_line(owned):
    if owned:
        return "Owned paths: %s" % " ".join(owned)
    return "Owned paths: none named, so change nothing"


def recon_scope(goal, base, report, owned):
    return bullets(
        [
            "Read the repository at %s and answer: %s" % (base, goal),
            "Write the findings report to %s" % report,
            "Name one file:line for every claim in the report",
            owned_line(owned),
        ]
    )


def build_scope(owned):
    return bullets(
        [
            "Implement the goal above and stop at the first acceptance line "
            "that passes",
            owned_line(owned),
            "Add the tests under the owned paths next to the code they cover",
        ]
    )


def verify_scope(base):
    return bullets(
        [
            "Re-run the test command verbatim on a clean checkout of %s" % base,
            "Re-run exactly the backticked commands in scope and acceptance; "
            "substitute no other runner",
            "Report PASS or FAIL per acceptance line with the exit code",
            "Change nothing",
        ]
    )


def recon_constraints(lane, report):
    return bullets(
        [
            "Read-only job on lane %s: edit nothing" % lane,
            "The report at %s is the only file the worker writes" % report,
            "An unverified claim is written down as an unknown, never as a fact",
            "Never print or record a secret",
        ]
    )


def build_constraints(lane, owned, base, cap):
    return bullets(
        [
            "Editable job on lane %s: the only writable paths are the owned paths"
            % lane,
            owned_line(owned),
            "The test command is the gate. It ends with an ownership check "
            "anchored at %s and a deletion cap of %d deleted files" % (base, cap),
            "Never print or record a secret",
            "No force push, no deploy, no live install",
        ]
    )


def verify_constraints(lane):
    return bullets(
        [
            "Read-only job on lane %s: edit nothing and substitute no other runner"
            % lane,
            "Re-run exactly the test command section on a clean checkout",
            "A failing command is reported as FAIL; it is never repaired here",
            "Never print or record a secret",
        ]
    )


def recon_non_goals():
    return bullets(
        [
            "No code change, no commit, no deploy",
            "No speculation: an unverified claim is an unknown, not a finding",
            "No widening of the scope above",
        ]
    )


def build_non_goals():
    return bullets(
        [
            "No change outside the owned paths",
            "No deploy, no live install, no force push",
            "No refactor or cleanup the goal does not ask for",
        ]
    )


def verify_non_goals():
    return bullets(
        [
            "No fix and no edit: verification only",
            "No deploy, no live install",
            "No new test runner and no new test file",
        ]
    )


def template_acceptance(kind):
    """Acceptance lines the template guarantees on top of the caller's."""
    if kind == "recon":
        return [
            "The report exists and carries a file:line for every claim",
            "Nothing outside the report path changed",
        ]
    if kind == "build":
        return [
            "The test command exits 0",
            "Every changed path is inside an owned path and the deletion cap holds",
        ]
    return [
        "The test command is re-run verbatim and its exit code is reported",
        "Every acceptance line carries PASS or FAIL",
    ]


def evidence(kind, report, base, cap):
    if kind == "recon":
        return bullets(
            [
                "The report at %s with its line count" % report,
                "One file:line citation per claim",
                "The exit code of the test command",
            ]
        )
    if kind == "build":
        return bullets(
            [
                "The exit code of the test command",
                "The changed path list printed by the ownership check anchored "
                "at %s" % base,
                "The deletion count the cap of %d was measured against" % cap,
            ]
        )
    return bullets(
        [
            "One line per acceptance item: PASS or FAIL with the command and "
            "its exit code",
            "The file:line of every defect found",
        ]
    )


# --------------------------------------------------------------------------
# rendering and validation
# --------------------------------------------------------------------------
def render(spec):
    """Render the whole delta for one spec dict."""
    blocks = []

    def add(name, body, heading=None):
        blocks.append("## %s\n%s" % (heading or name, body))

    add("effort", spec["effort"] + "\n")
    add("execution", "remote\n", heading="execution: remote")
    add("lane", spec["lane"] + "\n")
    add("goal", spec["goal"] + "\n")
    add("user_request", spec["user_request"])
    add("scope", spec["scope"])
    add("non_goals", spec["non_goals"])
    add("constraints", spec["constraints"])
    add("acceptance", spec["acceptance"])
    add(
        "evidence_required",
        evidence(spec["kind"], spec["report"], spec["base"], spec["cap"]),
    )
    add("unknowns", "None recorded at dispatch time.\n")
    if spec["owned"]:
        add("owned_paths", "".join(path + "\n" for path in spec["owned"]))
    if spec["kind"] == "verify":
        add("task_type", "mechanical\n")
    add("remote_worker", REMOTE_WORKER + "\n")
    add("remote_mode", spec["mode"] + "\n")
    add("remote_test_cmd", spec["test_cmd"] + "\n")
    add("remote_repo", spec["repo"] + "\n")
    add("remote_base", spec["base"] + "\n")
    return "\n".join(blocks)


def canonical(name):
    """`execution: remote` and `execution` name the same section."""
    name = name.strip().lower()
    if name.startswith("execution"):
        return "execution"
    return name.rstrip(":")


def parse_sections(text):
    """Split a delta into {section: body}; the last block wins its name."""
    out = {}
    name = None
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            name = canonical(match.group("name"))
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return {key: "\n".join(value).strip() for key, value in out.items()}


def validate_delta(text):
    """Return every defect of a rendered delta; an empty list means valid."""
    problems = []
    sections = parse_sections(text)

    for name in REQUIRED_SECTIONS:
        if name not in sections:
            problems.append("missing section: %s" % name)
        elif not sections[name]:
            problems.append("empty section: %s" % name)

    for name, body in sorted(sections.items()):
        for line in body.splitlines():
            if HEADING_RE.match(line):
                problems.append(
                    "section %s carries a nested heading: %s" % (name, line.strip())
                )
                break

    goal = sections.get("goal", "")
    if len([line for line in goal.splitlines() if line.strip()]) != 1 and goal:
        problems.append("goal must be a single line")

    test_lines = [
        line.strip()
        for line in sections.get("remote_test_cmd", "").splitlines()
        if line.strip()
    ]
    if len(test_lines) > 1:
        problems.append(
            "the test command must be a single line, got %d" % len(test_lines)
        )

    for index, raw in enumerate(sections.get("acceptance", "").splitlines(), start=1):
        line = raw.strip().lstrip("-").strip()
        if not line:
            continue
        for ch in line:
            if ch in BANNED_IN_ACCEPTANCE:
                problems.append(
                    "acceptance line %d carries %s: %r"
                    % (index, BANNED_IN_ACCEPTANCE[ch], line)
                )
                break

    mode = sections.get("remote_mode", "").strip()
    if mode and mode not in VALID_MODES:
        problems.append("remote_mode must be read-only or editable, got %r" % mode)
    worker = sections.get("remote_worker", "").strip()
    if worker and worker != REMOTE_WORKER:
        problems.append("remote_worker must be %s, got %r" % (REMOTE_WORKER, worker))
    execution = sections.get("execution", "").strip()
    if execution and execution != "remote":
        problems.append("execution must be remote, got %r" % execution)
    effort = sections.get("effort", "").strip()
    if effort and effort not in VALID_EFFORTS:
        problems.append("effort must be one of: %s" % " ".join(VALID_EFFORTS))
    lane = sections.get("lane", "").strip()
    if lane and lane not in VALID_LANES:
        problems.append("lane must be one of: %s" % " ".join(VALID_LANES))

    return problems


# --------------------------------------------------------------------------
# input
# --------------------------------------------------------------------------
def build_spec(args):
    """Turn parsed arguments into a spec dict, or raise BriefError."""
    kind = args.kind

    if args.goal is None:
        raise BriefError("missing required flag --goal")
    goal = one_line(args.goal, "--goal")
    if not goal:
        raise BriefError("--goal is empty")

    accepts = []
    for index, raw in enumerate(args.accept, start=1):
        text = one_line(raw, "--accept %d" % index)
        if not text:
            raise BriefError("--accept %d is empty" % index)
        accepts.append(plain(text, "acceptance line %d from --accept" % index))
    if not accepts:
        raise BriefError(
            "missing required flag --accept: at least one acceptance line"
        )

    report = one_line(args.report, "--report") if args.report else report_path(goal)

    if args.test is None or not args.test.strip():
        if kind in TEST_REQUIRED_REASON:
            raise BriefError(
                "the %s template requires --test: %s"
                % (kind, TEST_REQUIRED_REASON[kind])
            )
        test_cmd = recon_test(report)
    else:
        test_cmd = one_line(args.test, "the test command from --test")
        if not test_cmd:
            raise BriefError("the test command from --test is empty")

    cap = args.max_deletes
    if cap < 0:
        raise BriefError("--max-deletes must not be negative")
    if args.max_deletes_given and kind != "build":
        raise BriefError("--max-deletes applies to the build template only")
    if args.report is not None and kind != "recon":
        raise BriefError("--report applies to the recon template only")

    lane = (args.lane or DEFAULT_LANE).strip().lower()
    if lane not in VALID_LANES:
        raise BriefError(
            "invalid --lane %r (expected one of: %s)"
            % (lane, " ".join(VALID_LANES))
        )

    effort = (args.effort or TEMPLATE_EFFORT[kind]).strip().lower()
    if effort not in VALID_EFFORTS:
        raise BriefError(
            "invalid --effort %r (expected one of: %s)"
            % (effort, " ".join(VALID_EFFORTS))
        )

    repo = one_line(args.repo, "--repo") if args.repo else DEFAULT_REPO
    if not repo:
        raise BriefError("--repo is empty")
    base = one_line(args.base, "--base") if args.base else DEFAULT_BASE
    if not base:
        raise BriefError("--base is empty")

    owned = []
    for index, raw in enumerate(args.owned, start=1):
        path = one_line(raw, "--owned %d" % index)
        if not path:
            raise BriefError("--owned %d is empty" % index)
        owned.append(path)

    if args.scope is None:
        if kind == "recon":
            scope = recon_scope(goal, base, report, owned)
        elif kind == "build":
            scope = build_scope(owned)
        else:
            scope = verify_scope(base)
    else:
        scope = args.scope
    scope = scope.strip() + "\n"
    if not scope.strip():
        raise BriefError("--scope is empty")

    if kind == "recon":
        constraints = recon_constraints(lane, report)
        non_goals = recon_non_goals()
    elif kind == "build":
        constraints = build_constraints(lane, owned, base, cap)
        non_goals = build_non_goals()
        test_cmd = build_test_command(test_cmd, base, cap)
    else:
        constraints = verify_constraints(lane)
        non_goals = verify_non_goals()

    return {
        "kind": kind,
        "effort": effort,
        "lane": lane,
        "goal": goal,
        "user_request": user_request(kind, goal),
        "scope": scope,
        "non_goals": non_goals,
        "constraints": constraints,
        "acceptance": bullets(dedupe(accepts + template_acceptance(kind))),
        "owned": owned,
        "mode": TEMPLATE_MODE[kind],
        "test_cmd": test_cmd,
        "repo": repo,
        "base": base,
        "report": report,
        "cap": cap,
    }


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Write a validated dispatch delta from --goal and --accept alone. "
            "recon is read-only and writes a report under %s/; build is "
            "editable and its test command ends with an ownership check "
            "anchored at --base plus a deletion cap; verify is read-only and "
            "requires --test." % REPORT_DIR
        ),
    )
    parser.add_argument("kind", choices=KINDS, help="delta template")
    parser.add_argument("--goal", help="one line: what the job must achieve")
    parser.add_argument(
        "--accept",
        action="append",
        default=[],
        metavar="TEXT",
        help="one acceptance line, repeatable; no angle brackets and no "
        "parenthetical remark",
    )
    parser.add_argument("--scope", help="override the generated scope block")
    parser.add_argument(
        "--owned",
        action="append",
        default=[],
        metavar="PATH",
        help="an owned path, repeatable; emitted as owned_paths",
    )
    parser.add_argument("--repo", help="remote repo name (default: %s)" % DEFAULT_REPO)
    parser.add_argument("--base", help="base ref (default: %s)" % DEFAULT_BASE)
    parser.add_argument("--lane", help="worker lane (default: %s)" % DEFAULT_LANE)
    parser.add_argument("--test", help="single-line mechanical test command")
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUT",
        help="write the delta to OUT instead of stdout; - means stdout",
    )
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="recon report path (default: %s/<slug>.md)" % REPORT_DIR,
    )
    parser.add_argument(
        "--max-deletes",
        type=int,
        default=0,
        metavar="N",
        help="deletion cap appended to the build test command (default: 0)",
    )
    parser.add_argument(
        "--effort",
        help="override the template effort (default: %s)"
        % "/".join(TEMPLATE_EFFORT[k] for k in KINDS),
    )
    parser.add_argument(
        "--version", action="version", version="%s %s" % (PROGRAM, VERSION)
    )
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "new":
        argv = argv[1:]
    args = build_parser().parse_args(argv)
    args.max_deletes_given = "--max-deletes" in argv

    try:
        spec = build_spec(args)
        text = render(spec)
        problems = validate_delta(text)
        if problems:
            raise BriefError("; ".join(problems))
        if args.output and args.output != "-":
            try:
                with open(args.output, "w", encoding="utf-8") as handle:
                    handle.write(text)
            except OSError as exc:
                raise BriefError("cannot write %s: %s" % (args.output, exc))
            sys.stderr.write("%s: wrote %s\n" % (PROGRAM, args.output))
        else:
            sys.stdout.write(text)
    except BriefError as exc:
        sys.stderr.write("%s: %s\n" % (PROGRAM, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
