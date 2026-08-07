# herdr coordinator skills

A portable, project-agnostic template for running a **multi-pane herdr workspace** (herdr being
an agent/pane/tab orchestrator that runs each Claude session in its own managed pane) where one
session acts as a **Coordinator** and the others act as **child apps**, all
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

### The labeling law (the core of the protocol, in three lines)

Every turn arriving in a pane is exactly one of three classes, told apart by its prefix:

| Prefix on the incoming turn      | Who it is                    | Treat it as…                          |
|----------------------------------|------------------------------|---------------------------------------|
| `From {SiblingApp}:`             | a **peer child**             | a green-lit sibling working with you  |
| `From Coordinator:`              | the **Coordinator**          | routing / a green-light — *not* human |
| *(no prefix)*                    | the **Operator** (the human) | your normal user; overrides all       |

### The one thing the labeling law can't fix

Knowing *who* sent a turn doesn't tell you *whether it's still true*. Messages cross panes
asynchronously, so a relay can age out in flight — a decision reaches one pane and not another,
or arrives after that pane already acted. Two panes then report opposite things about the same
file or commit, and **both are being honest**; they were simply told different things.

So the protocol carries one rule the three classes don't cover:

> **When accounts conflict, go read the artifact.** Don't adjudicate between panes and don't
> poll a third for a tiebreak. The file cannot be out of date with itself.

The Coordinator's corollary: **a reversal goes to every pane that received the original**, and
the decision lands in the tracker *before* it's relayed. A pane still acting on a superseded
instruction is following orders correctly — that's a fan-out failure, not a judgment one. The
artifact rule is the backstop for when the fan-out fails anyway, which is why it's the stronger
of the two: it doesn't depend on the Coordinator getting the broadcast right.

### Two delivery mechanics the protocol rests on

The labeling law only works if messages actually arrive. Two things break that silently — both
skills spell them out, and neither is optional reading:

- **`pane run`, always.** `herdr pane run <pane> "<text>"` types the text *and presses Enter*.
  `pane send-text` and `agent send` write the characters with **no** Enter, stranding your relay
  unsent in the recipient's composer: delivered from your side, invisible from theirs. Most
  "the other pane ignored me" incidents are this. (herdr's own `agent --help` says it outright:
  *agent send writes literal text; use pane run when you want command text plus Enter*.)
- **The `❯` composer line lies.** Claude Code auto-fills it with a machine-generated *suggested*
  prompt derived from that pane's last turn. A plain-text read can't tell it from real unsent
  operator input — only `agent read --ansi` can, and only in two steps: locate the composer by its
  `❯` glyph (decoding UTF-8), *then* faint-test that one line (`\x1b[2m` = ghost). Faint-testing a
  whole read is a false-positive machine — `\x1b[2m` is also ordinary transcript chrome. Never
  judge a pane's state, its interruptibility, or the Operator's intent from that line.

## What's here

| Path                                   | Role        | Genericized from | Purpose |
|----------------------------------------|-------------|------------------|---------|
| `coordinator/cross-coordinate/`        | Coordinator | coordinator comms | Receive a child's ask, decide interruptibility, relay + green-light, tie out; resolve conflicting reports and fan out reversals |
| `coordinator/set-workspace/`           | Coordinator | workspace setup   | (Re)hydrate the panes: even the layout, name/color each pane, wire remote-control, poll status |
| `child/cross-coordinate/`              | Child app   | one child's comms | Raise an ask *up* to the Coordinator; read the three inbound classes; work a sibling directly once green-lit; hold rather than act on a stale instruction |

Each is a standard Claude Code skill (`SKILL.md` with frontmatter). The coordinator and child
`cross-coordinate` skills are **two halves of one protocol** — read them as a matched pair.

**New to this?** [`EXAMPLE.md`](EXAMPLE.md) is a start-to-finish walkthrough — a fresh herdr run
set up as a Coordinator brokering two projects (`api` + `web`), including one full coordination
round-trip with the actual `From …:` messages that cross the panes. It's the fastest way to see
the pattern move.

## How to adapt (fill in the placeholders)

Copy the folders you need into the relevant `.claude/skills/` directory, then search-and-replace:

| Placeholder        | Replace with                                                    | Example |
|--------------------|-----------------------------------------------------------------|---------|
| `{StackName}`      | your umbrella/initiative name (or delete if you have none)       | `Acme` |
| `{AppName}`        | **in the child skill** — that pane's own app name               | `Api` |
| `{AppA}`,`{AppB}`… | the concrete child app/pane names                               | `Web`, `Worker` |
| `{workspace-root}` | absolute path to the container dir the Coordinator runs in       | `/home/me/acme` |
| `{tracker}`        | your issue/task tracker command, or delete the tracking sections | `gh issue`, `jira` |
| `{status-cmd}`     | your "what's next / current work" command, if any                | `/whats-next` |

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
  specific — on a pure-POSIX host you can relax them, but they're harmless to keep. The two
  delivery mechanics above (`pane run` vs. `send-text`; ghost composer suggestions) are **not**
  platform-specific — keep those verbatim.

## Preconditions (all three skills)

They only make sense **inside a herdr-managed pane** — each checks `HERDR_ENV=1` and stops
otherwise. They also never hardcode pane IDs: herdr recompacts IDs between sessions, so every
skill re-resolves panes by **label / cwd** on each run.
