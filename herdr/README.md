# herdr coordinator skills

A portable, project-agnostic template for running a **multi-pane [herdr](https://github.com/) workspace**
where one Claude session acts as a **Coordinator** and the others act as **child apps**, all
communicating through a disciplined message protocol instead of you copy-pasting between panes.

These skills were battle-tested driving a four-pane workspace (one coordinator + three sibling
repos) and then stripped of anything project-specific so you can drop them into your own stack.
Everything app-specific is written as a `{placeholder}` you fill in once.

## The model

```
                 ┌─────────────────────┐
                 │     Coordinator     │  ← the "brain" pane; interrupt-buffer + router
                 │  cwd = <workspace>  │     (no app of its own; it brokers the others)
                 └──────────┬──────────┘
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  {AppA}    │  │  {AppB}    │  │  {AppC}    │   ← child panes, one per app/repo
     └────────────┘  └────────────┘  └────────────┘      each roleplays as itself
```

- The **Coordinator** owns no application. It is the *interrupt-buffer*: children never poke each
  other directly to **start** a coordination — every cross-app ask routes up through the
  Coordinator, which decides *when* to hand it to a possibly-busy sibling and *green-lights*
  direct pane-to-pane work.
- Each **child** pane is a Claude session working on one app/repo. It **roleplays as that app**:
  every message it injects into another pane is prefixed `From {AppName}:`.
- A human — the **Operator** — sits above all of it. An **unlabeled** turn in any pane is the
  Operator; their word overrides the choreography.

### The labeling law (the whole protocol in three lines)

Every turn arriving in a pane is exactly one of three classes, told apart by its prefix:

| Prefix on the incoming turn      | Who it is                    | Treat it as…                          |
|----------------------------------|------------------------------|---------------------------------------|
| `From {SiblingApp}:`             | a **peer child**             | a green-lit sibling working with you  |
| `From Coordinator:`              | the **Coordinator**          | routing / a green-light — *not* human |
| *(no prefix)*                    | the **Operator** (the human) | your normal user; overrides all       |

## What's here

| Path                                   | Role        | Genericized from | Purpose |
|----------------------------------------|-------------|------------------|---------|
| `coordinator/cross-coordinate/`        | Coordinator | coordinator comms | Receive a child's ask, decide interruptibility, relay + green-light, tie out |
| `coordinator/set-workspace/`           | Coordinator | workspace setup   | (Re)hydrate the panes: even the layout, name/color each pane, wire remote-control, poll status |
| `child/cross-coordinate/`              | Child app   | one child's comms | Raise an ask *up* to the Coordinator; read the three inbound classes; work a sibling directly once green-lit |

Each is a standard Claude Code skill (`SKILL.md` with frontmatter). The coordinator and child
`cross-coordinate` skills are **two halves of one protocol** — read them as a matched pair.

## How to adapt (fill in the placeholders)

Copy the folders you need into the relevant `.claude/skills/` directory, then search-and-replace:

| Placeholder        | Replace with                                                    | Example |
|--------------------|-----------------------------------------------------------------|---------|
| `{StackName}`      | your umbrella/initiative name (or delete if you have none)       | `Acme` |
| `{AppName}`        | **in the child skill** — that pane's own app name               | `Api` |
| `{AppA}`,`{AppB}`… | the concrete child app/pane names                               | `Web`, `Worker` |
| `{workspace-root}` | absolute path to the container dir the Coordinator runs in       | `C:\Users\me\Projects` |
| `{tracker}`        | your issue/task tracker command, or delete the tracking sections | `gh issue`, `jira` |
| `{status-cmd}`     | your "what's next / current work" command, if any                | `/up-next` |

Notes:
- **The Coordinator installs** `coordinator/*`. **Each child installs its own copy** of
  `child/cross-coordinate/`, with `{AppName}` set to *that* app. The two `cross-coordinate`
  skills can share the `name: cross-coordinate` slug because they never live in the same
  `.claude/skills/` directory.
- `{tracker}` (durable per-ask notes so relays stay one line) is **optional but recommended**.
  If you skip it, drop the tracking sections and keep the ask detail inline.
- `/rename`, `/color`, `/rc` are real Claude Code slash commands and stay literal. `{status-cmd}`
  is a custom skill you may or may not have.
- The platform gotchas the skills call out (Git Bash mangling a leading `/` into a Windows path;
  bash command-substituting backticks inside `herdr pane run "..."`) are Windows/Git-Bash
  specific — on a pure-POSIX host you can relax them, but they're harmless to keep.

## Preconditions (all three skills)

They only make sense **inside a herdr-managed pane** — each checks `HERDR_ENV=1` and stops
otherwise. They also never hardcode pane IDs: herdr recompacts IDs between sessions, so every
skill re-resolves panes by **label / cwd** on each run.
