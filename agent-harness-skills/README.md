# agent-harness skills

Portable agent skills that aren't tied to any one tool or workspace — they set up **project
conventions** that pay off no matter which coding agent you drive. Unlike `herdr/` (which is
specific to a multi-pane herdr workspace), these are general-purpose and **harness-agnostic**:
each works on both **Claude Code** and **Devin** (and other AGENTS.md-based harnesses).

## The one harness difference: the root instructions file

Every harness reads a root **instructions file** at the repo top level, but they name it
differently:

| Harness | Root instructions file |
|---------|------------------------|
| Claude Code | `CLAUDE.md` |
| Devin (and other AGENTS.md harnesses) | `AGENTS.md` |

These skills write it as **`CLAUDE.md`/`AGENTS.md`** — meaning *use whichever your harness reads*.
Pick the one your project uses and stay consistent; if a repo already has one of the two, extend
that file rather than adding a second. Everything else the skills produce — the `.claude/knowledge/`
folder, the index format, the per-topic docs — is identical across harnesses (it's just markdown
the root file points at, which any agent can read regardless of directory name).

## What's here

| Path | Purpose |
|------|---------|
| `knowledge-prep/` | Stand up (or retrofit) the lean-index + lazy-loaded `.claude/knowledge/` documentation pattern: a scannable root file that points to per-subsystem deep-context docs, so the root stays cheap to load every session while detail lives one hop away. |
| `graph-prep/` | Wire in the **segment-graph** pattern on top of that: a *derived* NetworkX graph over the project's issue tracker items **and** its knowledge docs, so an agent retrieves context by actual citation rather than by guessing filenames. Ships with `graphscout.py`. |
| `up-next/` | Answer *"what should I work on?"* from the tracker rather than from a decaying memory snapshot: active milestones, what's in flight, what's queued, and one recommended next item. Reads only. |

### Skills that assume a tracker

`up-next/` (and the optional graph half of `graph-prep/`) assume the **[beans](https://github.com/aaronsb/beans)**
CLI — a local, file-backed issue tracker queried over GraphQL. That's a narrower dependency than
the harness-agnostic claim above, so be explicit about it:

- **`knowledge-prep/` needs no tracker at all.** It works on any repo.
- **`graph-prep/` degrades gracefully** — the doc↔doc half of the graph works without a tracker;
  the doc↔work-item half is what needs one.
- **`up-next/` is tracker-shaped end to end.** The workflow ports to any tracker with a queryable
  API (Linear, Jira, GitHub Issues); the two queries in Step 1–2 are the only beans-specific part.
  Swap those and the synthesis, output shape and hand-off are unchanged.

If you're adapting `up-next` to a different tracker, the load-bearing detail is in Step 2: check
what your tracker's *closed* statuses actually are before filtering on "not completed." A store
that has accumulated legacy statuses will report long-finished work as open, and an orientation
tool that overstates open work is worse than none.

### Skills that ship a script

`graph-prep/` is the first skill here with an executable companion (`graphscout.py`, ~900
lines). Two consequences worth knowing before you install it:

- **Copy the whole folder, not just `SKILL.md`.** If the script is missing, the skill's own
  instructions tell the agent to fetch it from this repo by raw URL — but that only works with
  network access, so prefer copying both files together.
- **`graphscout.py` here is a GENERATED artifact — do not hand-edit it.** It is produced from the
  maintainer's reference copy by pure string substitution (project names → placeholders, one real
  filesystem path → a generic one). Fix bugs in the reference and regenerate; patching this copy
  directly forks it. That already happened once: two review fixes were applied here by hand while
  the same fixes were implemented upstream from a written spec, and the builds silently diverged
  on their *error messages* — behaviourally identical on the happy path, so no test caught it, and
  anyone pulling this copy over a reference-based install would have quietly traded down on
  diagnostics. Substitution-only generation makes that class of drift unrepresentable rather than
  merely discouraged.
- **The script is vendored per project, not shared.** `graph-prep` deliberately copies
  `graphscout.py` into each project at `.claude/graph/graphscout.py` rather than pointing at one
  central install. A project's scope should stay bound to its own folder; a cross-project script
  dependency breaks that, and a project that outlives your machine layout still works. The cost
  is that updates are a re-sync per copy, which the skill's Step U handles — **grep the vendored
  copy for `DIVERGENCE` and merge; only blind-copy when there are none.**

Requires `networkx` (and `scipy`, which PageRank imports lazily and hard-fails without).
`matplotlib` is optional, for `--png` only.

## Installing a skill

Copy the skill's folder into wherever your harness discovers skills, then invoke it by name:

- **Claude Code:** `cp -r knowledge-prep ~/.claude/skills/` (user-level) or `<repo>/.claude/skills/`
  (project-level), then `/knowledge-prep`. Same for `graph-prep` — `cp -r` the folder so
  `graphscout.py` travels with it.
- **Devin / other harnesses:** place it wherever that harness loads skill definitions and invoke
  per its convention.

Note: the `SKILL.md` frontmatter (`allowed-tools`, `disable-model-invocation`, `argument-hint`) is
Claude Code skill format. On a harness that uses different metadata, keep the body and adapt the
frontmatter to that harness's schema — the instructions themselves are harness-agnostic.
