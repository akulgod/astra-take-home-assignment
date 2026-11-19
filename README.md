# Android Vuln-Scan: Teacher→Student Distillation

A small end-to-end slice of teaching an open "student" model to find Android
vulnerabilities as well as a frontier "teacher" model, by distilling the
teacher's findings into **general** lessons and measuring the student's recall
lift.

> Development target: [InsecureShop](https://github.com/hax0rgb/InsecureShop)
> (intentionally vulnerable). **Nothing in `src/` is hardcoded to it** — app
> path, models, eval mode, and thresholds all live in `config/config.yaml`, so
> the harness runs on an unseen APK with only config changes.

## Results

Strict, deterministic matching (no LLM in the metric → reproducible). Student
recall is shown as its three per-run values; **precision** = matched ÷ findings
emitted (answer-key precision — see caveat below). Regenerate with
`python cli.py run`.

| App / mode | Reference | Student baseline | Student + lessons | **Recall lift** | Precision | Teacher ceiling |
|---|---|---|---|---|---|---|
| **InsecureShop — ground truth** | 19 curated vulns (independent of teacher & lessons) | 47.4% (53/32/58) | 68.4% (63/74/68) | **+21.1 pts** | 34% → 50% | 84.2% (16/19) |
| **InsecureShop — unseen-APK** | teacher's own 23 findings | 62.3% (74/39/74) | 89.9% (83/96/91) | **+27.5 pts** | 54% → 80% | — |

**How to read this.**

- **The ground-truth row is the headline, honest result.** Its answer key (19
  hand-labeled vulns) is independent of both the teacher and the lessons, so a
  lift means the student found more *real* vulns. Lessons add **+21.1 pts** of
  recall *and* raise precision (34→50) while emitting slightly fewer findings —
  more complete and more accurate, not merely noisier. Variance also collapses
  (recall stdev 0.114 → 0.043): the lessons make the student *reliable*, not
  just better on average.
- **Unseen-APK mode** (reference = teacher findings) is how you grade an app
  with no labels. It is partly self-referential — the lessons are distilled from
  the same teacher findings used as the reference — which biases the lift
  *upward*, so read its larger numbers (+27.5 here) as an upper bound, not the
  honest measure.

> **Precision caveat.** "Precision" here is matched-to-answer-key ÷ emitted, so
> it is capped by the reference size (≤ 19/26 in GT mode) and counts as "noise"
> any real vuln the answer key omits, plus duplicates the one-to-one rule
> rejects. Treat it as a relative signal (does it rise or fall with lessons?),
> not an absolute false-positive rate.

## Pipeline

```
ingest → teacher scan → student baseline → lessons (teacher, 1 pass) → student rescan → recall lift
```

1. **Ingest** (`src/ingest`) — decompile with jadx if given an `.apk`, parse the
   manifest (exported components, providers, permissions, debuggable/backup/
   cleartext), collect app source (library + generated code filtered, `@Metadata`
   stripped), and security-relevant resources.
2. **Scan** (`src/scan`) — a manifest summary is prepended to every chunk;
   returns structured `Finding`s (type, location, severity, evidence). Chunking
   is config-driven (`max_files_per_batch`, `max_chunk_chars`).
3. **Lessons** (`src/lessons`) — teacher generalizes its findings in one pass; a
   deterministic validator rejects any lesson that leaks an app-specific
   identifier (class/file/package/line).
4. **Match + eval** (`src/matching`, `src/eval`) — strict one-to-one match of
   findings against the reference; recall reported baseline vs. with-lessons,
   averaged over repeats.

## Match function

A finding matches a reference when **location overlaps** (shared CamelCase class
name) AND **categories agree**. Category agreement is exact, with one escape
hatch: `other` is the schema's explicit "couldn't categorize" label, so a
located finding filed under `other` (on either side) still counts — this
recovers findings a model placed correctly but filed under the catch-all,
without aliasing two *specific* categories to each other (which would hide a
real disagreement). Exact matches are claimed first, in a one-to-one assignment
(so duplicates can't inflate recall), and the `other` waiver requires *real*
class-name overlap — never a package-level location wildcard. jadx line numbers
are ignored (unstable). Fully deterministic — see the write-up for the rationale
and the LLM-judge experiment that was built, measured, and then removed to keep
the metric reproducible.

## Extensibility

- **Add a model → one YAML block.** Two adapters cover everything: `anthropic`,
  and `openai_compat` (OpenAI, Groq, OpenRouter, Gemini-OpenAI endpoint — differ
  only by `base_url` + key env). Per-model `tokens_param` handles API quirks.
- **Unseen APK with no ground truth** → set `eval.reference: teacher_findings`;
  the student is measured against the teacher's findings (no labels needed).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # fill in keys for the providers you use
```

Keys needed for the default config: `OPENAI_API_KEY` (teacher) and
`OPENROUTER_API_KEY` (student). `.env` is gitignored.

## Run

```bash
# Ingest-only smoke test (no API keys):
python cli.py ingest --config config/config.yaml

# Validate keys + model ids (one cheap call per role):
python cli.py check --config config/config.yaml

# Full pipeline (InsecureShop, ground-truth mode):
python cli.py run --config config/config.yaml
# → writes runs/<timestamp>/{teacher_findings,lessons,*_{match,findings},summary}.json
```

For **unseen-APK mode** (score the student against the teacher's own findings,
no labels needed), set `eval.reference: teacher_findings` in `config/config.yaml`
and re-run — the student output is cached, so only the reference changes.

## Configuration (`config/config.yaml`)

- `models:` — registry; each block is one model (provider, id, base_url, key env).
- `roles:` — which model is `teacher` / `student`.
- `app:` — decompiled dir or `.apk` path, plus library/generated-code exclude lists.
- `eval:` — `reference` (`ground_truth_file` | `teacher_findings`), `repeats`, match options.
- `run:` — cache dir, output dir, `max_files_per_batch`, `max_chunk_chars`.

## Deliverables

- **Write-up** (match function, 1M-LOC strategy, dynamic-analysis + diagram,
  models) — delivered as a Google Doc.
- **Recall before/after** — the Results table above; regenerate with
  `python cli.py run`.

## Known gaps / next steps (honest)

- **Resource/manifest scanning** — only `.java` is sent to the model, so GT-10
  (AWS Cognito in `strings.xml`) and GT-11 (FileProvider in `res/xml`) are
  currently unfindable. Pure-code fix that raises both models' ceiling.
- **Dependency/CVE analysis** — GT-08 (vulnerable component) needs it.
- **Proactive rate limiting / call budget** — today: sequential + retry-backoff.
