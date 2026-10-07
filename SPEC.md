# JLFSink v2.1.0 — SPEC.md

Offline sink-knowledge database CLI for code review. Python 3 stdlib only.
Executable: `python jlfsink.py`. License MIT © jakelo.ai.

Concept: the user does code review, spots a dangerous sink (e.g. `eval()`),
and queries JLFSink. Default output = exploit methods + step-by-step +
copy-paste commands (ACTION-FIRST). `--all` additionally prints the
educational layer (what it is / how it works / why it matters / contexts /
WAF notes / eligibility / mitigations / references).

## 1. Repo layout

```
├── SPEC.md
├── jlfsink.py        # CLI + matching engine
├── db/
│   ├── execution.json
│   ├── dom-write.json
│   ├── script-injection.json
│   ├── navigation.json
│   ├── attribute.json
│   ├── websocket.json
│   ├── misc.json
│   ├── jquery.json
│   ├── framework.json
│   ├── postmessage.json
│   ├── storage.json
│   ├── proto-pollution.json
│   └── sources.json
├── tests/test_jlfsink.py
└── README.md
```

DB file format: `{"category": "execution", "schema_version": "2.0", "sinks": [SINK, ...]}`
sources.json: `{"schema_version": "2.0", "sources": [SOURCE, ...]}`

## 2. SINK schema (all fields required unless noted)

```json
{
  "id": "sink-eval",
  "name": "eval",
  "category": "execution",
  "languages": ["javascript"],
  "patterns": ["eval", "window.eval", "globalThis.eval", "eval("],
  "severity": "P3",
  "severity_note": "P2 when chained to token theft",
  "explain": "One-paragraph what-it-is.",
  "how_it_works": "One-paragraph mechanics (why dangerous).",
  "why_it_matters": "One-paragraph impact framing.",
  "exploitable_when": ["location.hash", "postMessage", "document.referrer"],
  "chains": [
    {"source": "location.hash",
     "steps": [
       {"action": "Confirm source reaches sink", "payload": "#jlf-trace",
        "command": "open 'https://TARGET/page#jlf-trace' in a browser",
        "indicator": "the traced value is visible inside the eval() call"}
     ],
     "eligibility": "platform acceptance note for THIS chain"}
  ],
  "contexts": {"html-body": "...", "attr": "...", "js-string": "..."},
  "waf_notes": "...",
  "eligibility": "overall program-acceptance intel (honest)",
  "mitigations": ["..."],
  "related": ["setTimeout", "Function", "innerHTML"],
  "references": ["PortSwigger: DOM XSS", "OWASP WSTG: Client-side Testing"]
}
```

SOURCE schema: `{"id":"src-location-hash","name":"location.hash","explain":"...","detonates":["eval","innerHTML"],"notes":"fragment never reaches the server — server-side WAF is blind to it"}`

### Quality bar (the red line)
1. Payloads syntactically real; placeholders only TARGET / ATTACKER / SESSION_ID / YOUR_ACCOUNT; never "...".
2. Every step has an indicator the user can actually observe; chains 2-4 steps.
3. `command` = copy-paste ready (curl / browser-open instruction / ffuf where relevant).
4. Honest severity: P1-P5, no inflation (self-XSS chains say so explicitly in eligibility).
5. eligibility = real program intel (e.g. "DOM XSS accepted on all major platforms"; "requires victim pasting into console = self-XSS, usually NOT eligible").
6. references: 1-3 stable public methodology titles (PortSwigger/OWASP WSTG/HackTricks/MDN).

## 3. Coverage (67 sinks + 20 sources)

**execution** (4) · **dom-write** (7) · **script-injection** (7) ·
**navigation** (7) · **attribute** (7) · **jquery** (9) · **framework** (8) ·
**postmessage** (4) · **storage** (4) · **proto-pollution** (4) ·
**websocket** (3) · **misc** (3) — full ID list enforced by
`tests/test_jlfsink.py`.

## 4. CLI

```
python jlfsink.py search <kw1> [kw2 ...] [--all] [--json] [-t HOST]
python jlfsink.py list [--category C] [--json]
python jlfsink.py sources [--json]
python jlfsink.py categories [--json]
python jlfsink.py -h | --help
python jlfsink.py --version
```

Exit codes: 0 ok, 1 usage error, 2 internal error. No tracebacks ever;
friendly messages.

### Matching engine
- `normalize(q)`: lowercase; strip surrounding quotes; cut at first "(" or
  "=" (drop args / assignment right-hand side); collapse non-alnum except
  keep "-" and "."; also keep a second variant with dots/dashes removed
  ("v-html"→"vhtml"). Match against each sink's `patterns` (same
  normalization both sides).
- Object-prefix tail is kept only when it matches a known pattern
  ("el.innerHTML"→"innerhtml", "window.postMessage"→"postmessage").
  Method-call chains such as `$(x).html(str)` are rescued via the called
  identifier ("html").
- Per keyword score: exact pattern hit 100 > name substring 60 >
  chain-source hit 40 > explain/contexts text hit 10.
- Multi-keyword: entry score = sum of per-keyword scores + 50 × (#keywords
  matched). Rank desc; entries matching ALL keywords always before partial
  matches; partial matches shown under a dim "Partial matches" header.
- Zero results: difflib.get_close_matches over all patterns+names+sources →
  "Did you mean: X, Y?" exit 1.
- `-t HOST`: every `TARGET` token in output is replaced with the normalized
  host (scheme/path stripped). Accepts example.com, https://app.example.com/,
  host:port, localhost, IPs. `ATTACKER` is deliberately left as-is.

### Output (search)
Default per entry (ACTION-FIRST):
```
=== eval [execution · P2] ===
EXPLOIT WHEN: location.hash · postMessage · document.referrer

-- Chain: location.hash -> eval --
  Step 1: Confirm source reaches sink
    payload:  #jlf-trace
    command:  open 'https://TARGET/page#jlf-trace' in a browser
    confirm:  the traced value is visible inside the eval() call
  ...
Next: python jlfsink.py search eval --all
```
`--all` appends per entry: EXPLAIN (what/how/why), CONTEXTS, WAF NOTES,
ELIGIBILITY, MITIGATIONS, RELATED, REFERENCES.

### Color (serious, minimal)
ANSI auto-off when not TTY or NO_COLOR. Palette: sink names bold cyan;
severity P1/P2 red, P3 yellow, P4/P5 dim; payload/command green; section
headers bold. Nothing else colored.

DB loading: `db/` next to jlfsink.py; friendly error if missing/corrupt;
self-check at startup: unique ids, all `related` point to existing sink
names, all chain sources exist in sources.json (warn only, don't crash).

## 5. Tests

`python -m unittest discover tests -v` — normalization matrix (raw-code
table), ranking (exact>partial; multi-keyword AND-first), typo did-you-mean,
search default excludes explain / --all includes, JSON envelope,
list/sources/categories, zero-result exit 1, startup self-check, full DB
integrity (all 67 sink ids present, schema fields complete, quality-bar
lint: no "..." in payloads, every step has indicator, every chain has
eligibility, severity P1-P5), help menu runs, no-network (no socket use),
README quick-start examples all execute.
