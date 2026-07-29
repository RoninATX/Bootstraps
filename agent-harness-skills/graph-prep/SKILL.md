---
name: graph-prep
description: Set up or retrofit the segment-graph pattern in a project - a derived NetworkX graph over the project's beans AND its knowledge docs, so agents retrieve context by actual citation instead of by filename convention. Use when the user says "set up the graph here / graph-prep this project / wire in the artifact graph", or when a project has beans + a knowledge folder but agents still find docs by guessing. Assumes beans and /knowledge-prep are already in place; checks and stops if not.
disable-model-invocation: false
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
argument-hint: "(optional) target project dir; mode is auto-detected (install vs backfill)"
---

# Graph Prep

Stand up the **segment-graph pattern** in a project that already has beans and a
`.claude/knowledge/` folder: a **derived** graph over both, recomputed on demand, that
answers *"what should I read before working on this?"* from real citations.

The problem it solves is narrow and concrete. A tracker knows a bean's `parent` and
`blockedBy`. It does not know which knowledge file explains that bean — and that file is
usually what an agent most needs. Meanwhile the knowledge index in `CLAUDE.md` is
maintained by hand and matched by filename guess. The graph replaces the guess with an
edge that already exists in the prose.

This skill is project-agnostic. It discovers the project's shape from the filesystem and
carries no single project's conventions.

## The doctrine (do not paraphrase these away)

**Derived, never stored.** The graph is rebuilt from beans and docs every time it is
used — sub-second even at ~1,000 artifacts. There is **no cache, no index file, no sync
step**. This is the property that makes the whole pattern safe: a derived view cannot go
stale, so it never needs reconciling and never lies. If you find yourself adding
persistence, you have reintroduced the problem the pattern exists to avoid.

**One graph, not two.** Beans and knowledge docs go in the *same* graph. The doc→bean
edge is the entire point; splitting them by type discards it. In a measured reference
workspace, doc→bean edges were roughly a third of all edges — the exact traversal agents
need, and the one no tracker models.

**Artifact grain, not concept grain.** Nodes are addressable artifacts — a bean, a
knowledge file, a wiki page. Do **not** extract "concepts" or topics as nodes. Concepts
require NLP to maintain, drift silently, and cannot be verified. Artifacts are already
addressable, already cited by id, and stay true as a side effect of ordinary work.

**Citations in prose are how edges form.** This is the one behavioral ask, and it is
usually already happening — people naturally write "paired with `<id>`" in a bean body.
The graph simply starts paying for a habit that currently earns nothing. Do not
introduce a metadata block, a front-matter `links:` field, or any other parallel
bookkeeping; prose citation is the mechanism.

**It does not replace beans-first orientation.** Beans and knowledge remain the source of
truth. The graph re-ranks what is offered and decides what to open. Any framing like
"check the graph instead of beans" is wrong and will degrade the workflow — the graph has
no content of its own.

**The segment boundary is not the folder boundary.** A project's segment includes its
sibling `<project>.wiki` folder if one exists. In the reference workspace a wiki
contributed 182 edges to its own project's beans while living in a different directory.
Miss this and the wiki looks like a foreign project.

**Self-contained per project.** The tool is vendored *into* the project, not shared from
a neighbor. A project's scope is bound to its own folder; a cross-project script
dependency breaks that and makes the project unusable in isolation.

## When to invoke

- `/graph-prep` in a project that has beans and `.claude/knowledge/` but no graph tooling.
- "set up the graph here", "wire in the artifact graph", "graph-prep this project".
- When agents in a project keep finding knowledge docs by guessing filenames.

Do **not** invoke to answer a single "what's related to X" question — that is `/context`
in a project already prepped.

## Step 0 - prerequisite gate (do this before anything else)

Three checks against the target project root. **Stop and report if any fail** — do not
partially install.

1. **Beans present?** `<project>/.beans/` exists and holds `.md` files. If not: this
   pattern has nothing to graph. Tell the user to run `beans init` and stop.
2. **Knowledge-prepped?** `<project>/.claude/knowledge/` exists with at least one file,
   and `CLAUDE.md` carries a `## Knowledge Folder` index. If not: run `/knowledge-prep`
   first and stop. The graph's highest-value edge is doc→bean; with no docs it degrades
   to a bean-only graph and is not worth installing yet.
3. **Python + networkx.** `python -c "import networkx"`. If missing, `pip install
   networkx scipy` (scipy is not a hard dependency of networkx but PageRank and most
   linear-algebra-backed algorithms import it lazily and hard-fail without it).

## Step 1 - measure citation density (this picks the mode)

Count, for the segment: real bean→bean prose citations (id-shaped tokens intersected
against the actual id set — never trust the regex alone) plus doc→bean citations,
divided by total artifacts (beans + docs).

```
density = (bean->bean + doc->bean) / (beans + docs)
```

Calibrate against observed values from a reference workspace:

| density | mode | meaning |
|---|---|---|
| **≥ 0.8** | **install** | artifacts already cite each other; the graph will be useful immediately |
| **0.25 - 0.8** | **backfill, then install** | structure exists but is thin |
| **< 0.25** | **backfill first** | a graph built today would be nearly empty |

Report the number to the user before proceeding. A project with hundreds of beans and a
density near zero is common and is not a failure — it means work was tracked without
cross-referencing, and the backfill is the actual value on offer.

## Step A - install (density ≥ 0.8)

1. **Vendor the tool — copy, do not reimplement.** The reference implementation ships
   with this skill at `graphscout.py` (same directory as this file). Copy it to
   **`<project>/.claude/graph/graphscout.py`** — this path is fixed, not a suggestion.

   **If `graphscout.py` is not beside this `SKILL.md`**, the skill was installed without
   its script (copied by hand, or the harness only picked up the markdown). Fetch it from
   the source repo rather than reconstructing it — it is ~900 lines and the parts that look
   redundant are load-bearing:

   ```bash
   # from the skill directory
   curl -fsSL -o graphscout.py \
     https://raw.githubusercontent.com/RoninATX/Bootstraps/main/agent-harness-skills/graph-prep/graphscout.py
   ```

   Verify before use: `python graphscout.py --help` should list the `beans`, `notes`,
   `context` and `rot` subcommands. If it raises at import, read the message — the module
   has deliberate import-time invariants that refuse to load in a misconfigured state, and
   the message names what to fix. Requires `networkx` (plus `scipy`, which PageRank imports
   lazily and hard-fails without); `matplotlib` only for `--png`.
   It self-locates the workspace by walking up to the nearest `.beans`, so it works from
   wherever it lands, but consistency is worth more than convenience here: `.claude/graph/`
   sits beside `.claude/knowledge/` as the same kind of thing (agent-facing infrastructure,
   not product code), and a predictable path is what lets a workspace-level operation —
   "refresh every vendored copy" — exist at all. Four early adopters chose three different
   locations; that is the drift this rule exists to stop.

   Copying rather than rewriting is deliberate. A from-scratch implementation reliably
   reproduces the same silent bugs — case-sensitive id matching in particular, which in
   testing found 60 edges where 924 existed.

   **If the project needs something the reference lacks, copy first, modify second, and
   mark the change in the code itself** with a comment beginning `LOCAL DIVERGENCE` that
   states what changed, why, and the measurement that justified it. A note in the
   knowledge file is not enough — the next person to refresh this tool is holding the
   *file*, and a marker they can `grep` is the only thing that reliably stops them
   overwriting your work. Also mention it in `artifact-graph.md`, but the code marker is
   the load-bearing one.

   What it provides: segment discovery, beans via `beans --beans-path <dir> query
   ... --json`, docs from `.claude/knowledge`, `.claude/domain`, `.claude/tools`,
   `.claude/skills` and the sibling `<project>.wiki`, a typed `MultiDiGraph`
   (`parent`, `blocked_by`, `mentions`, `cites`, `see`), and the `context <target>`
   command. It also carries `rot` — every id cited in the segment that resolves to
   nothing, from beans *and* docs, with `file:line`. Run it after the install and
   whenever a tracker gets pruned: a bean naming a dead bean is visible the moment you
   open it, but a **knowledge file naming a dead bean is silent** — the edge simply never
   forms and the graph looks healthy, so the rot needs a report of its own rather than an
   absence. `rot --cross` additionally judges ids belonging to sibling segments, which
   neither segment can do alone (its own prefix set doesn't contain the foreign prefix,
   so a dead sibling id reads as ordinary hyphenated English). Plus `beans`
   (whole-workspace analysis) and `notes` (any folder of linked markdown), which are
   useful but not required by this pattern.
2. **Install the `/context` skill** into `<project>/.claude/skills/context/SKILL.md`,
   pointing at the vendored script. Describe the output groups and state plainly that it
   does not replace beans-first orientation.
3. **Wire `CLAUDE.md`** — add a short `## Artifact Graph` section (template below).
4. **Add the knowledge file as `.claude/knowledge/artifact-graph.md`** and index it in the
   Knowledge Folder section. Use that exact name: it matches the `## Artifact Graph`
   section header it documents, and it names the **pattern** rather than the library —
   a doc called after the tool ages badly the moment the tool changes, and it reads as a
   scouting write-up rather than as the operating manual it actually is.
5. **Verify on real targets** — run `context` against a bean you know is well-connected
   and one you expect to be isolated. Show the user both. An isolated result is a valid
   outcome, not a bug. Then run `rot` once: a fresh install is the cheapest moment to
   clear dead ids, and it establishes the baseline for later runs.

## Step B - backfill (density < 0.8)

The artifacts exist but do not reference each other. This is the brownfield case, it is a
**content** pass rather than a tooling pass, and it is the common case — not the exception.

**Expect a freshly knowledge-prepped project to score near zero, and do not read that as
a failure of the knowledge pass.** `/knowledge-prep` produces *descriptive* subsystem
docs; its doctrine explicitly forbids task-directed content, so it has no reason to cite
bean ids and correctly does not. A project is never more graph-ready immediately after
knowledge-prep — it is better organized and no better connected. In a measured reference
project, 14 newly written knowledge files cited **zero** beans, including the file whose
subject was the bean tracker itself.

Work the two axes separately. They have different value and different difficulty.

### B1 - doc→bean (do this first; it is where the value is)

This is the edge no tracker models and the one `/context` exists to serve. For each
knowledge doc, ask: **which beans explain why this subsystem is the way it is?**

- Search beans for the doc's distinctive vocabulary — subsystem names, table names,
  service names, external tools — rather than for generic terms.
- Favor beans that record a *decision*, a *migration*, or a *reversal* over beans that
  merely touched the area. The bean that explains a constraint is worth citing; the bean
  that fixed a typo in that subsystem is not.
- **Cite where the bean answers a "why", not as a changelog.** This is what keeps the
  citation compatible with knowledge-prep's doctrine — that skill already tells you to
  preserve the "why we chose this" texture, and a bean id is often the most honest
  citation for it. A doc listing every bean that ever touched its subsystem has become a
  changelog and is now worse than it was.
- One to three citations in a doc is usually right. If a doc seems to need ten, the doc
  is probably covering two subsystems.

### B2 - bean→bean

Cluster beans by title/body similarity, shared vocabulary, and time proximity. Look for
beans that are obviously phases of one effort, or that supersede or reverse each other.
Prefer citing *across* efforts — a bean citing its own sibling adds little that the
`parent` edge does not already carry.

On a large tracker this is a long tail and mostly low value. Do not attempt exhaustive
coverage; the goal is a connected graph, not a complete one. **Stop when the hubs are
connected** — the beans and docs an agent would actually reach for.

### B3 - always

1. **Propose every edge before writing it.** List as `<source> should cite <target> —
   because <reason>`. Never mass-edit unattended. A wrong citation is worse than a
   missing one: a missing edge merely fails to help, while a wrong edge silently
   misdirects every future retrieval, and nobody re-reads a citation to check it.
2. **Write accepted edges as prose**, in the voice of the surrounding text
   ("the two-channel split came from `<id>`"), never as a metadata block or a `links:`
   field.
3. **Note the doc-shaped gaps.** If several beans orbit a subsystem with no knowledge
   file, that missing file is the highest-value thing to write — it becomes a hub the
   moment it exists. Report these; do not write them as part of this pass.
4. **Batch for review.** On a corpus of hundreds, propose in themed batches by subsystem,
   not as one undifferentiated list — a reviewer can judge "these six touch the ETL
   pipeline" and cannot meaningfully judge two hundred mixed rows.
5. **Re-measure**, report before/after density, then proceed to Step A.

## Step U - refresh an already-installed tool

When a fix lands in the reference and vendored copies need it. **Never blind-copy over a
vendored tool.** Copy-over-share buys each project independence and charges drift as the
price; this step is how the bill gets paid, and the whole cost of skipping it is silent.

1. **Grep the vendored copy for `LOCAL DIVERGENCE` first.** If there are none, copying the
   reference over it is safe — say so and do it.
2. **If there are markers, merge — do not clobber.** Read each one: it states what changed
   and why. Apply the reference's new changes *around* the local ones, keep every marker
   intact, and re-verify. Divergences are usually load-bearing and measured; in a
   reference fleet of five installs, two carried them, and a blind re-copy would have
   silently dropped 13 real edges in one project and 90% of the doc→doc edges in another.
3. **Re-verify after merging** — `context` on a known-connected artifact and `rot`. A
   merge that quietly reverted a divergence looks exactly like a healthy graph, because
   the missing edges simply never form.
4. **Ask whether the divergence should be promoted instead.** A local change that fixes a
   *general* defect belongs upstream in the reference, not re-merged forever in one
   project. A change that encodes something genuinely project-specific — this repo's
   hand-named ids, this repo's citation habits — stays local. When promoting, move it to
   the reference, drop the marker locally, and note the promotion in `artifact-graph.md`.

The field finds real defects: `rot` itself, and two separate node-identity collisions, all
originated in project installs rather than in the reference. Treat divergence as a signal
worth reading, not as debt to be normalized away.

## Conventions (bake these into every output)

**The `## Artifact Graph` section** for `CLAUDE.md` — this text encodes retrieve-first
and the citation habit, so it survives after the skill exits:

```markdown
## Artifact Graph

Beans and `.claude/` docs form one derived graph, rebuilt on demand (never cached).
Before planning work on a tracked item, run `/context <bean-id>` to get the artifacts
that actually cite it — read what DOCUMENTS it first. When writing a bean or a
knowledge file, cite related items by id in the prose (`paired with <id>`); those
citations are what create the edges.
```

**Node identity** is `<kind>/<stem>` for docs (`knowledge/secrets`, `memory/org-politics`)
and the bare id for beans. Keep it namespaced — it is what lets segments be joined later
without collisions, and it is nearly free now and expensive to retrofit.

**Match candidates by set membership, not by pattern.** An id-shaped regex will also
match ordinary hyphenated English (`zero-code`, `hard-fail`). Be permissive in the
pattern and validate every candidate against the real id set. Two traps, both silent:
ids may be cased inconsistently across projects (match case-insensitively — a
case-sensitive pass can find an order of magnitude fewer edges), and a short id slug is
indistinguishable from an English word (`<prefix>-side`, `<prefix>-only`), so any
"dangling reference" report needs a stoplist or it will drown real link rot in noise.

## Finish

- Show the density number, the mode chosen, and the files created or modified.
- Run `context` on two real targets and show the output — the pattern either visibly
  beats filename-guessing on that project's data or it does not, and the user should see
  which.
- If Step B wrote citations into beans or docs, list every artifact touched.
- This is tooling plus docs. Follow the project's contribution convention for committing;
  if unclear, ask rather than assume.
