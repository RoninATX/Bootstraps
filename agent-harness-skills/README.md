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

### Skills that ship a script

`graph-prep/` is the first skill here with an executable companion (`graphscout.py`, ~900
lines). Two consequences worth knowing before you install it:

- **Copy the whole folder, not just `SKILL.md`.** If the script is missing, the skill's own
  instructions tell the agent to fetch it from this repo by raw URL — but that only works with
  network access, so prefer copying both files together.
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
