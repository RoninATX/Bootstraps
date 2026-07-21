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

## Installing a skill

Copy the skill's folder into wherever your harness discovers skills, then invoke it by name:

- **Claude Code:** `cp -r knowledge-prep ~/.claude/skills/` (user-level) or `<repo>/.claude/skills/`
  (project-level), then `/knowledge-prep`.
- **Devin / other harnesses:** place it wherever that harness loads skill definitions and invoke
  per its convention.

Note: the `SKILL.md` frontmatter (`allowed-tools`, `disable-model-invocation`, `argument-hint`) is
Claude Code skill format. On a harness that uses different metadata, keep the body and adapt the
frontmatter to that harness's schema — the instructions themselves are harness-agnostic.
