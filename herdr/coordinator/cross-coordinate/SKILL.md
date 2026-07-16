---
name: cross-coordinate
description: >-
  The Coordinator side of inter-pane coordination in a multi-pane herdr workspace. Use when a
  turn prefixed "From {AppName}:" lands in this Coordinator pane (a child app raising a
  cross-app ask), when the Operator says "now is a good time to coordinate" (the go-signal to
  release a buffered ask), or to track/resolve an in-flight coordination. I am the
  interrupt-buffer: children never poke each other directly to START a coordination — it routes
  through me, and I decide when to hand it over and green-light direct child-to-child work.
  Only runs inside herdr (HERDR_ENV=1).
---

# cross-coordinate — Coordinator perspective

I am the **Coordinator** pane in a multi-pane herdr workspace. Around me sit one pane per child
app (`{AppA}`, `{AppB}`, `{AppC}`, …). This is my half of a protocol whose child side lives in
each app's own `cross-coordinate` skill — read them as a matched pair.

**Preconditions.** Confirm `HERDR_ENV=1`. If not set, say I'm not in a herdr-managed pane and
stop — don't drive panes from outside herdr.

## The labeling law (how I read my own inbox)

- An **unlabeled** turn is the **Operator** (the human).
- A turn prefixed **`From <App>:`** is a **child relay** — a coordination ask. That's the
  trigger for this skill.
- Every message I inject into a child pane I prefix **`From Coordinator:`**.

## Discover the panes (never hardcode IDs)

herdr pane IDs recompact between sessions — re-resolve every time:

```bash
herdr pane list
```

Map by **label** (cwd as tiebreak): `Coordinator` (this pane, cwd = `{workspace-root}`), and
one pane per child app (cwd = `{workspace-root}/<AppName>`). Take each `pane_id` from the JSON
fresh; if labels drifted, re-run rather than reusing an old ID.

## Step 1 — Receive & parse the relay

From a `From <Origin>:` turn, pull out:
- **Origin** — which child raised it, and its pane_id.
- **The one-line ask.**
- **What it needs** — either a *specific sibling* (help from another child app) or an
  *Operator judgment call* (a decision, not another agent's hands).
- **Tracker IDs** cited (they live in the origin's repo — see *Tracker tracking*).

Optionally open a tracking item now (see *Tracker tracking*). Then branch on what it needs.

---

## Role 1 — Child needs the Operator's judgment (no sibling help)

The ask is a decision only the Operator can make to unblock the child — not work another child
app would do.

1. **Grab the Operator's attention** here in my pane. State plainly: which child raised it, the
   one-line ask, the **exact pane the Operator should respond in**, and any tracker IDs for
   detail. Optionally ring the terminal bell to surface it (`printf '\a'`) if they may not be
   looking at my pane.
2. **Do not answer the architectural question myself** and don't relay it to another child — it's
   the Operator's call. I'm just the signpost.
3. **Wait.** The Operator responds directly in that child's pane, then tells me here that the
   roadblock is resolved.
4. On that "resolved" signal, **close my state** (mark my tracking item resolved with the
   outcome). No need to re-message the origin — the Operator handled it in-pane.

---

## Role 2 — Child needs help from another child

The ask needs a *target child app* to expose/change/provide something. My job: get the ask to
the target **without trampling whatever it's mid-way through**, then green-light direct work.

### 2a. Assess the target's interruptibility

Resolve the target pane, then read it and check status:

```bash
herdr agent list                                   # target's agent_status
herdr agent read <target-pane> --source visible --lines ~20
```

Classify what I see:
- **Safe-idle** — `agent_status: idle`, an empty `❯` prompt, no pending question/dialog on
  screen → **go now** (Step 2b).
- **Working** — `agent_status: working` / actively mid-task → **don't interrupt.** Either hand to
  the Operator (below) or set a light background re-check
  (`herdr agent wait <target> --status idle` run in the background, or a short poll loop), then
  re-read the screen when it goes idle to re-classify — because idle alone isn't a green light:
- **Awaiting input / murky** — the target is stopped **asking for something** (a permission
  dialog like "Do you want to proceed? 1. Yes…", a question directed at the Operator, a
  half-entered state). This can *look* idle but interrupting would derail it. Treat as
  **murky → escalate.**
- **Any doubt → escalate**, don't guess.

**Escalate = hand the timing to the Operator:** tell them a coordination is buffered, who needs
whom, and that the target looks busy/murky so I'm holding. Then wait. When the Operator judges
the moment they'll say something like **"now is a good time to coordinate"** — that's my
go-signal to run Step 2b for the buffered ask.

### 2b. Release the ask — relay + green-light

Inject one `From Coordinator:` message into the **target's** pane (via `pane run`; send
slash-free text so Git Bash is fine, but PowerShell is always safe). It must carry:

1. **Who's seeking help** — the requesting child's name **and pane_id**.
2. **The request summary** — the one-line ask.
3. **Related tracker items — as a *resolvable* pointer, never a bare ID.** If tracker IDs are
   repo-local (each app's tracker is its own), a bare ID isn't readable from the target's repo.
   Hand the target a command it can run as-is (an absolute path or a `--path`-style pointer to
   the requester's tracker) so it can read the full detail itself.
4. **The green light** — they're cleared to work **directly** with the requester now.
5. **The role-play reminder** — label every message they send `From <TheirOwnApp>:`.
6. **The check-back reminder** — report back to me (Coordinator) once the coordination is
   complete, so I can resolve my state.

Shape:

```
From Coordinator: <Requester> (pane <id>) needs <one-line ask>. Detail: <resolvable pointer to
the requester's tracker item>. You're green-lit to work with <Requester> directly — reach into
their pane and prefix your messages 'From <YourApp>:'. Ping me back here when it's done so I can
close it out.
```

The target then initiates `From <Target>:` contact with the requester (which the requester's own
skill perceives as *its* green light), and they work pane-to-pane.

**Bootstrapping case — target has no `cross-coordinate` skill yet.** The shape above assumes the
target already knows the protocol. When it doesn't (e.g. rolling the skill out to a child for the
first time), the terse hand-off won't land — it won't recognize `From Coordinator:` as a class,
won't know the `From <App>:` convention, and may not expect a relay at all. Send the **explicit**
form instead, adding up front:
- **Three-class orientation:** I'm the Coordinator / interrupt-buffer; a `From Coordinator:` turn
  (like this) is me, a `From <App>:` turn is a peer child relay, and an **unlabeled** turn is the
  Operator (the human) — three distinct classes.
- **The mechanics it can't infer:** which pane the requester is, that it should prefix its own
  messages `From <TheirApp>:`, and the resolvable tracker pointer.
- If the ask is *"adopt your own skill,"* also give the **template path** to copy/adapt and the
  **destination path** where its version goes.

Keep it one line (no newlines) so it submits cleanly; PowerShell-send if it carries a Windows
path. Once the target has its own skill, drop back to the terse shape.

### 2c. Resolve — and make sure the requester actually knows it's unblocked

When the target (or requester) reports back that it's done: confirm and close my tracking item
with the outcome. **But before closing, verify the good news reached the requester.**

Normally the target closes its own loop — a `From <Target>:` note straight into the requester's
pane — and I just confirm. **Don't assume it happened.** If the completion came to *me* and the
target never told the requester, the requester is still sitting there thinking it's blocked. In
that case **the tie-out is mine to own:** relay the unblock into the requester's pane as
`From Coordinator:` — what landed, that they're clear to proceed, and the item it resolves — then
record in my tracking outcome that the **Coordinator had to deliver the close-out** (a useful
signal about which children skip their direct close). Only then tell the Operator it's resolved.

Quick check before closing: is there any sign the requester heard it (a `From <Requester>:` ack,
or its own status note up to me)? If not, relay first. If the report instead surfaced a new
Operator decision, flip into Role 1 for that piece.

---

## Tracker tracking (optional but recommended)

If you use an issue/task tracker (`{tracker}`), log each coordination so I keep state and a
running track record of hand-offs brokered. Give the Coordinator its own prefix/namespace,
distinct from the per-app trackers, e.g.:

```bash
{tracker} create "coord: <origin>→<target> — <short ask>"   # open, in-progress
{tracker} update <id> --status completed                    # on resolution, with the outcome
```

Keep it lightweight: origin, target, the ask, the item refs cited, and the resolution. A Role-1
(Operator-decision) coordination is worth an entry too — it records what was escalated and how it
resolved. If you don't run a tracker, drop this section and keep the ask detail inline in the
relay (it just makes the relay longer).

---

## Don't

- Don't hardcode pane IDs — re-discover by label every time.
- Don't answer a Role-1 architectural decision myself, and don't relay it to a child — it's the
  Operator's.
- Don't interrupt a `working` or awaiting-input target on my own judgment — safe-idle only; when
  murky, hand the timing to the Operator and wait for "now is a good time."
- Don't forget the three reminders in the green-light message: pane of the requester,
  `From <App>:` role-play, and check back with me on completion.
- Don't cite a cross-repo tracker item as a bare ID in a relay — the target's tracker is local
  and can't resolve it. Give a runnable, resolvable pointer (absolute path or `--path` form).
- Don't send the terse green-light to a target that has no `cross-coordinate` skill yet — use the
  explicit bootstrapping form (three-class orientation + mechanics it can't infer), or the relay
  won't land.
- Don't close a coordination assuming the requester heard the good news — if the target finished
  but skipped its direct close-out, relay the unblock myself (as `From Coordinator:`) before
  closing, so the requester doesn't stall thinking it's still blocked.
- Don't leave my own state dangling — every coordination ends either resolved (closed) or
  explicitly handed to the Operator.
