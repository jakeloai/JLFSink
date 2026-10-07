#!/usr/bin/env python3
"""JLFSink v2.0.0 -- offline sink-knowledge database CLI for code review.

You spot a dangerous sink during code review; JLFSink tells you how to
exploit it: exploit methods, step-by-step chains and copy-paste commands
(ACTION-FIRST). ``--all`` additionally prints the educational layer.

Pure Python 3 standard library. No network access. License MIT (c) jakelo.ai.
"""

import argparse
import difflib
import glob
import json
import os
import re
import sys

VERSION = "2.1.0"
PROG = "jlfsink.py"

# Scoring tiers (SPEC section 4).
TIER_PATTERN = 100   # exact pattern hit
TIER_NAME = 60       # sink-name substring hit
TIER_CHAIN = 40      # chain-source hit
TIER_TEXT = 10       # explain/contexts free-text hit
MULTI_BONUS = 50     # bonus per matched keyword

PARTIAL_LIMIT = 5    # max partial matches rendered in text mode


# --------------------------------------------------------------------- color

class Palette:
    """Minimal ANSI palette (SPEC section 4).

    Auto-disabled when stdout is not a TTY or when NO_COLOR is set.
    Only these are colored: sink names (bold cyan), severity (P1/P2 red,
    P3 yellow, P4/P5 dim), payload/command lines (green), section headers
    (bold), the partial-matches header (dim). Nothing else.
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"

    def __init__(self, stream):
        self.enabled = (
            hasattr(stream, "isatty")
            and stream.isatty()
            and "NO_COLOR" not in os.environ
        )

    def wrap(self, text, *codes):
        if not self.enabled or not text:
            return text
        return "".join(codes) + text + self.RESET

    def bold(self, text):
        return self.wrap(text, self.BOLD)

    def dim(self, text):
        return self.wrap(text, self.DIM)

    def green(self, text):
        return self.wrap(text, self.GREEN)

    def sink_name(self, text):
        return self.wrap(text, self.BOLD, self.CYAN)

    def severity(self, sev):
        sev = (sev or "").upper()
        if sev in ("P1", "P2"):
            return self.wrap(sev, self.RED)
        if sev == "P3":
            return self.wrap(sev, self.YELLOW)
        if sev in ("P4", "P5"):
            return self.wrap(sev, self.DIM)
        return sev


# ------------------------------------------------------------- normalization

_QUOTE_CHARS = "\"'`"
# A query is cut at the first "(" (call args dropped) or "=" (attribute /
# assignment right-hand side dropped, e.g. v-html="msg" -> v-html).
_CUT_RE = re.compile(r"[(=]")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9.\-]+")
# Identifier chains immediately followed by "(" -- used to rescue the
# meaningful method out of wrappers such as $(x).html(str).
_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")


def strip_quotes(text):
    """Strip surrounding quote characters (single, double, backtick)."""
    text = text.strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in _QUOTE_CHARS:
        text = text[1:-1].strip()
    return text


def base_normalize(text):
    """normalize(q) per SPEC section 4.

    lowercase; strip surrounding quotes; cut at the first "(" or "=";
    collapse every character that is not [a-z0-9.-].
    """
    text = strip_quotes(text).lower()
    text = _CUT_RE.split(text, maxsplit=1)[0]
    return _NON_ALNUM_RE.sub("", text)


def norm_variants(text):
    """Both normalized variants of a pattern/name (SPEC section 4).

    Canonical form plus a second variant with dots/dashes removed:
    "v-html" -> {"v-html", "vhtml"}; "window.postMessage(" ->
    {"window.postmessage", "windowpostmessage"}.
    """
    base = base_normalize(text)
    if not base:
        return set()
    return {base, base.replace(".", "").replace("-", "")}


def query_candidates(query, known_patterns):
    """All normalized candidate forms of a raw user query.

    Includes the canonical variant, the dots-removed variant, and the
    object-prefix-stripped tail ONLY when that tail matches a known
    pattern (el.innerHTML -> innerhtml, window.postMessage -> postmessage).
    """
    candidates = set()
    raw = strip_quotes(query)
    pieces = [raw]
    # Method-call chains such as $(x).html(str): the meaningful token is the
    # called identifier chain ("html"), not the first-"(" cut ("$").
    for match in _CALL_RE.finditer(raw):
        pieces.append(match.group(1))
    for piece in pieces:
        base = base_normalize(piece)
        if not base:
            continue
        candidates |= norm_variants(piece)
        if "." in base:
            tail = base.rsplit(".", 1)[1]
            if tail and tail in known_patterns:
                candidates |= norm_variants(tail)
    return {cand for cand in candidates if cand}


# ------------------------------------------------------------------ database

class DatabaseError(Exception):
    """Raised for missing/corrupt database content (exit code 2)."""


class Entry:
    """A sink plus its precomputed matching index."""

    def __init__(self, sink):
        self.sink = sink
        self.patterns = set()
        for pattern in sink.get("patterns", []):
            self.patterns |= norm_variants(pattern)
        self.name_forms = norm_variants(sink.get("name", ""))
        self.chain_sources = set()
        for chain in sink.get("chains", []):
            self.chain_sources |= norm_variants(chain.get("source", ""))
        contexts = sink.get("contexts") or {}
        parts = [
            sink.get("explain", ""),
            sink.get("how_it_works", ""),
            sink.get("why_it_matters", ""),
            sink.get("waf_notes", ""),
            sink.get("eligibility", ""),
        ] + list(contexts.values())
        self.text = " ".join(str(part) for part in parts).lower()


class Database:
    def __init__(self, sinks, sources, warnings):
        self.sinks = sinks
        self.sources = sources
        self.warnings = warnings
        self.entries = [Entry(sink) for sink in sinks]
        self.known_patterns = set()
        for entry in self.entries:
            self.known_patterns |= entry.patterns


def load_database(db_dir):
    """Load every *.json file under db/ (sink files + sources.json)."""
    if not os.path.isdir(db_dir):
        raise DatabaseError(
            "database directory not found: {0}\n"
            "expected a db/ folder next to {1}".format(db_dir, PROG)
        )
    files = sorted(glob.glob(os.path.join(db_dir, "*.json")))
    if not files:
        raise DatabaseError("no .json database files found in {0}".format(db_dir))
    sinks = []
    sources = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                doc = json.load(handle)
        except OSError as exc:
            raise DatabaseError("cannot read {0}: {1}".format(path, exc))
        except ValueError as exc:
            raise DatabaseError("corrupt JSON in {0}: {1}".format(path, exc))
        if not isinstance(doc, dict):
            raise DatabaseError(
                "corrupt DB file {0}: top level must be an object".format(path)
            )
        if os.path.basename(path) == "sources.json":
            chunk = doc.get("sources")
            if not isinstance(chunk, list):
                raise DatabaseError(
                    "corrupt DB file {0}: missing 'sources' list".format(path)
                )
            sources.extend(c for c in chunk if isinstance(c, dict))
        else:
            chunk = doc.get("sinks")
            if not isinstance(chunk, list):
                raise DatabaseError(
                    "corrupt DB file {0}: missing 'sinks' list".format(path)
                )
            sinks.extend(c for c in chunk if isinstance(c, dict))
    if not sinks:
        raise DatabaseError("no sinks found in {0}".format(db_dir))
    warnings = self_check(sinks, sources)
    return Database(sinks, sources, warnings)


def self_check(sinks, sources):
    """Startup integrity check. Warns; never crashes (SPEC section 4)."""
    warnings = []
    seen = {}
    for sink in sinks:
        sid = sink.get("id", "<missing id>")
        if sid in seen:
            warnings.append("duplicate sink id: {0}".format(sid))
        seen[sid] = True
    names = {sink.get("name", "") for sink in sinks}
    for sink in sinks:
        for rel in sink.get("related", []):
            if rel not in names:
                warnings.append(
                    "sink {0}: related name not found: {1}".format(
                        sink.get("id", "?"), rel
                    )
                )
    source_names = {src.get("name", "") for src in sources}
    source_norms = set()
    for name in source_names:
        source_norms |= norm_variants(name)
    for sink in sinks:
        for chain in sink.get("chains", []):
            src = chain.get("source", "")
            if src in source_names:
                continue
            if norm_variants(src) & source_norms:
                continue
            warnings.append(
                "sink {0}: chain source not in sources.json: {1}".format(
                    sink.get("id", "?"), src
                )
            )
    return warnings


# ------------------------------------------------------------------ matching

def score_keyword(entry, candidates, raw_query):
    """Best matching tier of one keyword against one sink entry."""
    # Tier 1: exact pattern hit (100).
    if candidates & entry.patterns:
        return TIER_PATTERN
    # Tier 2: sink-name substring hit (60).
    for cand in candidates:
        if len(cand) < 3:
            continue
        for form in entry.name_forms:
            if cand in form or form in cand:
                return TIER_NAME
    # Tier 3: chain-source hit (40).
    for cand in candidates:
        if len(cand) < 3:
            continue
        for src in entry.chain_sources:
            if cand == src or (len(cand) >= 4 and (cand in src or src in cand)):
                return TIER_CHAIN
    # Tier 4: explain/contexts free-text hit (10).
    needle = strip_quotes(raw_query).lower()
    if len(needle) >= 3 and needle in entry.text:
        return TIER_TEXT
    return 0


def search(db, keywords):
    """Return (full_matches, partial_matches) as (entry, score) lists.

    Entry score = sum of per-keyword scores + 50 per matched keyword.
    Entries matching ALL keywords always rank before partial matches.
    """
    full = []
    partial = []
    for entry in db.entries:
        per_keyword = []
        for kw in keywords:
            candidates = query_candidates(kw, db.known_patterns)
            per_keyword.append(score_keyword(entry, candidates, kw))
        matched = sum(1 for s in per_keyword if s > 0)
        if matched == 0:
            continue
        total = sum(per_keyword) + MULTI_BONUS * matched
        target = full if matched == len(keywords) else partial
        target.append((entry, total))
    key = lambda item: (-item[1], item[0].sink.get("name", ""))
    full.sort(key=key)
    partial.sort(key=key)
    return full, partial


def suggestions(db, keywords):
    """difflib-based 'Did you mean' pool: all patterns + names + sources."""
    pool = []
    for sink in db.sinks:
        pool.append(sink.get("name", ""))
        pool.extend(sink.get("patterns", []))
    for src in db.sources:
        pool.append(src.get("name", ""))
    pool = [p for p in pool if p]
    found = []
    for kw in keywords:
        for match in difflib.get_close_matches(strip_quotes(kw), pool, n=3, cutoff=0.6):
            if match not in found:
                found.append(match)
    return found[:3]


# ----------------------------------------------------------------- rendering

def render_entry(pal, sink, show_all):
    """ACTION-FIRST default block; --all appends the educational layer."""
    lines = []
    name = sink.get("name", "?")
    header = "=== {0} [{1} · {2}] ===".format(
        pal.sink_name(name),
        sink.get("category", "?"),
        pal.severity(sink.get("severity", "?")),
    )
    lines.append(header)
    when = " · ".join(sink.get("exploitable_when", [])) or "-"
    lines.append("{0} {1}".format(pal.bold("EXPLOIT WHEN:"), when))
    if show_all and sink.get("severity_note"):
        lines.append(pal.dim("  severity note: {0}".format(sink["severity_note"])))

    for chain in sink.get("chains", []):
        lines.append("")
        lines.append(pal.bold("-- Chain: {0} -> {1} --".format(
            chain.get("source", "?"), name)))
        for idx, step in enumerate(chain.get("steps", []), 1):
            lines.append("  Step {0}: {1}".format(idx, step.get("action", "")))
            for label, key in (("payload", "payload"),
                               ("command", "command"),
                               ("confirm", "indicator")):
                value = step.get(key)
                if not value:
                    continue
                row = "    {0}{1}".format((label + ":").ljust(10), value)
                if label in ("payload", "command"):
                    row = pal.green(row)
                lines.append(row)

    if show_all:
        lines.append("")
        lines.append(pal.bold("EXPLAIN"))
        lines.append("  What: {0}".format(sink.get("explain", "")))
        lines.append("  How:  {0}".format(sink.get("how_it_works", "")))
        lines.append("  Why:  {0}".format(sink.get("why_it_matters", "")))
        contexts = sink.get("contexts") or {}
        if contexts:
            lines.append("")
            lines.append(pal.bold("CONTEXTS"))
            for ctx, desc in contexts.items():
                lines.append("  {0}: {1}".format(ctx, desc))
        if sink.get("waf_notes"):
            lines.append("")
            lines.append(pal.bold("WAF NOTES"))
            lines.append("  {0}".format(sink["waf_notes"]))
        lines.append("")
        lines.append(pal.bold("ELIGIBILITY"))
        lines.append("  {0}".format(sink.get("eligibility", "")))
        for chain in sink.get("chains", []):
            if chain.get("eligibility"):
                lines.append("  [{0}] {1}".format(
                    chain.get("source", "?"), chain["eligibility"]))
        mitigations = sink.get("mitigations", [])
        if mitigations:
            lines.append("")
            lines.append(pal.bold("MITIGATIONS"))
            for item in mitigations:
                lines.append("  - {0}".format(item))
        related = sink.get("related", [])
        if related:
            lines.append("")
            lines.append(pal.bold("RELATED"))
            lines.append("  {0}".format(" · ".join(related)))
        references = sink.get("references", [])
        if references:
            lines.append("")
            lines.append(pal.bold("REFERENCES"))
            for item in references:
                lines.append("  - {0}".format(item))
    return "\n".join(lines)


def render_list(pal, sinks):
    """Category-grouped table: sink name + severity, sorted (SPEC section 4)."""
    grouped = {}
    for sink in sinks:
        grouped.setdefault(sink.get("category", "?"), []).append(sink)
    blocks = []
    for category in sorted(grouped):
        chunk = grouped[category]
        lines = [pal.bold("{0} ({1})".format(category, len(chunk)))]
        for sink in sorted(chunk, key=lambda s: s.get("name", "")):
            lines.append("  {0}{1}".format(
                sink.get("name", "?").ljust(30),
                pal.severity(sink.get("severity", "?"))))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def render_sources(pal, sources):
    """Sources table with detonates column (SPEC section 4)."""
    lines = [pal.bold("{0}  {1}".format("SOURCE".ljust(28), "DETONATES"))]
    for src in sorted(sources, key=lambda s: s.get("name", "")):
        detonates = " · ".join(src.get("detonates", [])) or "-"
        lines.append("{0}  {1}".format(src.get("name", "?").ljust(28), detonates))
    return "\n".join(lines)


def render_categories(pal, sinks):
    """Category names + sink counts (SPEC section 4)."""
    counts = {}
    for sink in sinks:
        cat = sink.get("category", "?")
        counts[cat] = counts.get(cat, 0) + 1
    lines = [pal.bold("{0}  {1}".format("CATEGORY".ljust(20), "SINKS"))]
    for cat in sorted(counts):
        lines.append("{0}  {1}".format(cat.ljust(20), counts[cat]))
    return "\n".join(lines)


# ------------------------------------------------------------------ target

TARGET_TOKEN = re.compile(r"\bTARGET\b")


def normalize_target(raw):
    """Normalize -t input to a bare host[:port]; None if invalid.

    Accepts: example.com, https://example.com/, sub.example.com:8443,
    http://localhost:3000/path. Path/query are dropped (TARGET is a host
    placeholder, not a URL prefix).
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)  # strip scheme
    host = host.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if not host or " " in host or "@" in host:
        return None
    if not re.fullmatch(
            r"(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?",
            host):
        return None
    base = host.split(":")[0].lstrip("*.")
    if "." not in base and base.lower() != "localhost" and not re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}", base):
        return None  # single label that is not localhost/IP
    return host


def substitute_target(obj, host):
    """Recursively replace the TARGET token in strings within obj."""
    if isinstance(obj, str):
        return TARGET_TOKEN.sub(host, obj)
    if isinstance(obj, list):
        return [substitute_target(item, host) for item in obj]
    if isinstance(obj, dict):
        return {key: substitute_target(val, host) for key, val in obj.items()}
    return obj


# --------------------------------------------------------------------- json

def print_envelope(command, ok, data, extra=None):
    """Print the standard {"command","ok","count","data"} envelope."""
    doc = {"command": command, "ok": ok, "count": len(data), "data": data}
    if extra:
        doc.update(extra)
    print(json.dumps(doc, indent=2, ensure_ascii=False))


# ----------------------------------------------------------------------- cli

EXAMPLES = """examples:
  python jlfsink.py search eval
  python jlfsink.py search "el.innerHTML"
  python jlfsink.py search "$(x).html(str)" --all
  python jlfsink.py search location.hash innerHTML
  python jlfsink.py search eval -t example.com        # TARGET -> example.com
  python jlfsink.py search eval --json
  python jlfsink.py list
  python jlfsink.py list --category jquery
  python jlfsink.py sources
  python jlfsink.py categories

exit codes: 0 ok, 1 usage error / no results, 2 internal error
"""


class FriendlyParser(argparse.ArgumentParser):
    """argparse with SPEC exit codes: usage errors exit 1, never 2."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, "{0}: error: {1}\n".format(self.prog, message))


def build_parser():
    parser = FriendlyParser(
        prog=PROG,
        description=(
            "JLFSink {0} -- offline sink-knowledge database for code review. "
            "You spot the dangerous sink; JLFSink tells you how to exploit it "
            "(step-by-step chains + copy-paste commands).".format(VERSION)
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version="JLFSink {0}".format(VERSION))
    sub = parser.add_subparsers(
        dest="command", metavar="<command>", parser_class=FriendlyParser)

    p_search = sub.add_parser(
        "search",
        help="search sinks by keyword(s) or raw code snippet",
        description="Search the sink database by keyword(s) or raw code.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_search.add_argument(
        "keywords", nargs="*", metavar="kw",
        help="keyword or raw code snippet, e.g. eval, \"el.innerHTML\"")
    p_search.add_argument(
        "--all", action="store_true",
        help="append the educational layer (EXPLAIN, CONTEXTS, WAF NOTES, "
             "ELIGIBILITY, MITIGATIONS, RELATED, REFERENCES)")
    p_search.add_argument(
        "--json", action="store_true",
        help="machine-readable JSON envelope output")
    p_search.add_argument(
        "-t", "--target", metavar="HOST",
        help="your bug bounty target (e.g. example.com or "
             "https://app.example.com/) — every TARGET placeholder in "
             "payloads/commands is replaced with this host so output is "
             "copy-paste ready")

    p_list = sub.add_parser(
        "list", help="list all sinks grouped by category",
        description="List all sinks grouped by category (name + severity).")
    p_list.add_argument(
        "--category", metavar="C", help="only show this category")
    p_list.add_argument(
        "--json", action="store_true", help="JSON envelope output")

    p_sources = sub.add_parser(
        "sources", help="list all taint sources with what they detonate",
        description="List all taint sources with their detonates.")
    p_sources.add_argument(
        "--json", action="store_true", help="JSON envelope output")

    p_categories = sub.add_parser(
        "categories", help="list categories with sink counts",
        description="List category names with sink counts.")
    p_categories.add_argument(
        "--json", action="store_true", help="JSON envelope output")

    return parser


def cmd_search(db, args, pal):
    keywords = [kw for kw in args.keywords if kw.strip()]
    if not keywords:
        print("{0}: error: search requires at least one keyword".format(PROG),
              file=sys.stderr)
        print("usage: python {0} search <kw1> [kw2 ...] [--all] [--json]".format(PROG),
              file=sys.stderr)
        return 1
    command = "search " + " ".join(keywords)
    target = None
    if getattr(args, "target", None):
        target = normalize_target(args.target)
        if not target:
            print("{0}: error: invalid target host: {1!r}".format(
                PROG, args.target), file=sys.stderr)
            print("expected a domain or host, e.g. example.com, "
                  "app.example.com:8443, https://example.com/",
                  file=sys.stderr)
            return 1
        command += " -t " + target
    full, partial = search(db, keywords)

    if args.json:
        data = []
        for entry, score in full + partial:
            row = dict(entry.sink)
            row["score"] = score
            row["matched_all_keywords"] = (entry, score) in full
            data.append(row)
        extra = None
        if target:
            data = substitute_target(data, target)
            extra = {"target": target}
        if not data:
            extra = dict(extra or {})
            extra["suggestions"] = suggestions(db, keywords)
        print_envelope(command, ok=bool(data), data=data, extra=extra)
        return 0 if data else 1

    if not full and not partial:
        print("No sinks matched: {0}".format(" · ".join(keywords)))
        found = suggestions(db, keywords)
        if found:
            print("Did you mean: {0}?".format(", ".join(found)))
        else:
            print("Hint: run 'python jlfsink.py list' to browse all sinks, "
                  "or 'python jlfsink.py sources' to search by taint source.")
        return 1

    blocks = [render_entry(pal, entry.sink, args.all) for entry, _ in full]
    if partial:
        blocks.append(pal.dim("-- Partial matches --"))
        for entry, _ in partial[:PARTIAL_LIMIT]:
            blocks.append(render_entry(pal, entry.sink, args.all))
        if len(partial) > PARTIAL_LIMIT:
            blocks.append(pal.dim(
                "... and {0} more partial matches".format(
                    len(partial) - PARTIAL_LIMIT)))
    out = "\n\n".join(blocks)
    if target:
        out = substitute_target(out, target)
        print(pal.dim("Target: {0}  (TARGET placeholders replaced — "
                      "verify scope before firing)".format(target)))
        print("")
    print(out)
    if not args.all:
        top = (full or partial)[0][0].sink.get("name", "")
        hint = "\nNext: python {0} search {1} --all".format(PROG, top)
        if target:
            hint += " -t {0}".format(target)
        print(hint)
    return 0


def cmd_list(db, args, pal):
    sinks = db.sinks
    command = "list"
    if args.category:
        command += " --category " + args.category
        available = sorted({s.get("category", "") for s in sinks})
        if args.category not in available:
            print("{0}: error: unknown category: {1}".format(PROG, args.category),
                  file=sys.stderr)
            print("available categories: {0}".format(", ".join(available)),
                  file=sys.stderr)
            return 1
        sinks = [s for s in sinks if s.get("category") == args.category]
    if args.json:
        print_envelope(command, ok=True, data=sinks)
    else:
        print(render_list(pal, sinks))
    return 0


def cmd_sources(db, args, pal):
    if args.json:
        print_envelope("sources", ok=True, data=db.sources)
    else:
        print(render_sources(pal, db.sources))
    return 0


def cmd_categories(db, args, pal):
    counts = {}
    for sink in db.sinks:
        cat = sink.get("category", "?")
        counts[cat] = counts.get(cat, 0) + 1
    data = [{"category": cat, "sinks": counts[cat]} for cat in sorted(counts)]
    if getattr(args, "json", False):
        print_envelope("categories", ok=True, data=data)
    else:
        print(render_categories(pal, db.sinks))
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 1

    db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db")
    try:
        db = load_database(db_dir)
    except DatabaseError as exc:
        print("{0}: error: {1}".format(PROG, exc), file=sys.stderr)
        return 2
    for warning in db.warnings:
        print("{0}: warning: db: {1}".format(PROG, warning), file=sys.stderr)

    pal = Palette(sys.stdout)
    handlers = {
        "search": cmd_search,
        "list": cmd_list,
        "sources": cmd_sources,
        "categories": cmd_categories,
    }
    try:
        return handlers[args.command](db, args, pal)
    except BrokenPipeError:
        return 0
    except Exception as exc:  # no tracebacks ever (SPEC section 4)
        print("{0}: internal error: {1}".format(PROG, exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
