---
name: knowledge-prep
description: Set up or retrofit the .claude/knowledge/ documentation pattern in a project - a lean, scannable root instructions file (CLAUDE.md for Claude Code, AGENTS.md for Devin - whichever applies) that indexes lazy-loaded per-subsystem knowledge files. Use when starting knowledge docs in a fresh repo, when the user says "set up the knowledge folder / knowledge pattern here", "prep this project's CLAUDE.md/AGENTS.md", or when an existing CLAUDE.md/AGENTS.md has grown fat and should be split into .claude/knowledge/ files.
disable-model-invocation: false
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
argument-hint: "(optional) target dir; mode is auto-detected (greenfield vs retrofit)"
---

# Knowledge Prep

> **Harness note.** This skill works for both **Claude Code** and **Devin** (and other
> AGENTS.md-based harnesses). The project's root **instructions file** is called `CLAUDE.md` on
> Claude Code and `AGENTS.md` on Devin — written throughout as **`CLAUDE.md`/`AGENTS.md`**,
> meaning *use whichever your harness reads*. Pick the one your project uses and stay consistent;
> if a repo already has one of the two, extend that file rather than adding a second. Everything
> else — the `.claude/knowledge/` folder, the index format, the per-topic files — is identical
> across harnesses.

Stand up the **`.claude/knowledge/` pattern** in any project: a **lean, scannable
`CLAUDE.md`/`AGENTS.md`** (whichever your harness uses) that indexes one paragraph + a pointer per
subsystem, backed by **topic-specific deep-context files** in `.claude/knowledge/<topic>.md` that
are **lazy-loaded** - an agent only reads `payments.md` when it's working on payments.

The goal is to keep `CLAUDE.md`/`AGENTS.md` cheap to load every session while the deep detail
lives one hop away, versioned in the repo alongside the code it describes. This skill is
project-agnostic: it discovers the project's shape from the filesystem, it does not carry any one
project's conventions.

## The doctrine (do not paraphrase these away)

**The knowledge-vs-memory test** - decide where a fact belongs:

- **knowledge** = facts that should be **true going forward** (codebase architecture, design decisions, process, cross-project API contracts). Lives in `.claude/knowledge/`, committed to the repo.
- **memory** = facts that were **true at a moment in time** (project state, who is doing what, external references). Stays in the assistant's auto-memory, never migrated into knowledge.

**Descriptive, not prescriptive.** Knowledge files describe *how the system works* ("the query pipeline runs 8 steps"), not *what the assistant should do* ("remember to run the tests"). If you are migrating from memory-style notes, this is a **rewrite, not a copy**: strip assistant-directed framing (any `Why:` / `How to apply:` scaffolding), but **keep the "why we chose this" texture** where it informs future decisions.

**One topic per file.** Filename is the topic slug (`fleet-manager.md`, `secrets.md`). A file earns its existence by being the thing you'd want open while working on that subsystem.

**Update in the same change.** This is the coupling that keeps knowledge from rotting: when you add, remove, or meaningfully change a subsystem's surface (new route, new env var, schema change), you update its knowledge file *in the same commit*. The skill bakes this rule into the `CLAUDE.md`/`AGENTS.md` header so it survives.

## When to invoke

- `/knowledge-prep` in a fresh repo with no (or a stub) `CLAUDE.md`/`AGENTS.md`.
- "set up the knowledge folder / knowledge pattern here", "prep this project's `CLAUDE.md`/`AGENTS.md`".
- An existing `CLAUDE.md`/`AGENTS.md` has grown into a wall of implementation detail and should be split.

Do **not** invoke for a one-off "add a note to `CLAUDE.md`/`AGENTS.md`" - that's a direct edit.

## Step 0 - detect the mode

Look at the target project root:

- **Greenfield** - no `CLAUDE.md`/`AGENTS.md`, or a thin stub, and no `.claude/knowledge/`. Scaffold from scratch (Step G).
- **Retrofit** - a `CLAUDE.md`/`AGENTS.md` already carries fat, multi-section implementation detail. Audit and split (Step R).

Also check for an assistant auto-memory dir for this project (**Claude Code only** - it keeps one at `~/.claude/projects/<project-slug>/memory/` with a `MEMORY.md` index; Devin has no equivalent). If it exists, its codebase-fact entries are migration candidates in Step R. If it doesn't, skip the memory audit - not every project has one.

Always create the folder first: `mkdir -p .claude/knowledge` (safe if it already exists).

## Step G - greenfield: scaffold

1. **Survey the codebase** to find the real subsystems. Use Glob/Grep and directory structure: top-level service dirs, workspace members / packages, distinct API surfaces, infra (docker-compose, CI), a secrets/config story. Aim for the handful of areas someone would actually need context on - not every folder.
2. **Draft one knowledge file per subsystem** you found. Each is a descriptive doc of *how that part works* - architecture, the important types/routes/env vars, the non-obvious design decisions and why. Write only what you can substantiate from the code; mark genuine unknowns as open rather than inventing.
3. **Write `CLAUDE.md`/`AGENTS.md`** as the lean index (see the template in Conventions). It carries: a short project overview, the `## Knowledge Folder` index section pointing at the files from step 2, a `## Commands` section (build/test/run, discovered from the repo), and any project-wide design philosophy worth stating once.

## Step R - retrofit: audit + migrate

1. **Audit `CLAUDE.md`/`AGENTS.md`** - identify the fat sections that should become their own knowledge files (anything that's a deep dive on one subsystem rather than a pointer). List them for the user before moving them.
2. **Audit the auto-memory dir** (if present) against the knowledge-vs-memory test. Codebase architecture / design decisions / process / cross-project contracts -> migrate to knowledge. Project state, task ownership, external pointers, user preferences, and assistant feedback -> **stay in memory**.
3. **Migrate as a rewrite.** For each fat section or knowledge-class memory, write a clean descriptive `.claude/knowledge/<topic>.md`. Merge related fragments into one topic file rather than mirroring the old split 1:1.
4. **Slim `CLAUDE.md`/`AGENTS.md`** - replace each moved section with a one-paragraph summary that points to its knowledge file. Add/refresh the `## Knowledge Folder` index.
5. **Reconcile the memory index** - if you migrated memory entries, remove them from `MEMORY.md` and delete the migrated memory files (they now live, rewritten, in knowledge). Leave point-in-time memories untouched.

## Conventions (bake these into every output)

**The `## Knowledge Folder` section header** in `CLAUDE.md`/`AGENTS.md` - use this exact rule text (it encodes consult-first + update-in-same-change):

```markdown
## Knowledge Folder

Topic-specific reference docs live in `.claude/knowledge/`. When working on a
subsystem listed below, consult its file first; when you add, remove, or
meaningfully change the underlying surface (new route, new env var, schema
change, etc.), update the matching file in the same change.

- `engram.md` — Core architecture: types, query pipeline, ...
- `env-vars.md` — Full environment variable tables
```

**Index bullets** are one line each: `` - `topic.md` — <what's inside + a hook that says why you'd open it> ``. The hook matters - it's what lets an agent decide, without opening the file, whether it's the one it needs.

**Knowledge file style**: start with a one-line what-this-is, then descriptive prose/tables of how the subsystem works. Present tense, factual. Capture the load-bearing *why* behind non-obvious decisions. No task lists, no "you should", no time-stamped status.

**Lazy-load contract**: the whole point is that these files are *not* loaded every session. Keep each self-contained enough to be read in isolation, and cross-link sibling files by name when a topic spans two (`see fleet-manager.md`).

## Finish

- Show the user the resulting `CLAUDE.md`/`AGENTS.md` index and the list of knowledge files created/migrated before committing.
- This is a **doc-only** change. Follow the project's contribution convention - some repos commit docs straight to the default branch, others want a PR. Check `CLAUDE.md`/`AGENTS.md` / `CONTRIBUTING` for the rule; if unclear, ask rather than assume.
- If you deleted migrated memory files, say so explicitly in the summary so the user knows what moved where.
