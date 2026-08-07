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

## Sending into a child pane — the mechanics that make a message land

Every relay I inject is **typed input into someone else's live session**. As the router I'm the
pane that sends most, so a silent delivery failure here strands a child that's waiting on me.

### 1. Text without an Enter never submits

| Command | What it actually does |
|---------|-----------------------|
| `herdr pane run <pane> "<text>"` | types the text **and presses Enter** — delivered as a turn |
| `herdr pane send-text <pane> "<text>"` | types the text, **no Enter** — it sits unsent in their composer |
| `herdr agent send <target> "<text>"` | same — literal text, **no Enter** |

**Always `pane run`.** A `send-text` green-light strands the whole coordination: the requester
waits for a sibling that never got the ask, the target sees stray text on its `❯` line, and my
tracking item says "relayed." That the CLI carries a *separate*
`pane send-keys <pane> Enter` is the corroboration: submitting is its own act.

Keep every relay to a **single line** so it submits cleanly; if one genuinely must span lines,
`pane send-text` the block then `herdr pane send-keys <pane> Enter` **once**.

### 2. Prose is not a send

My ordinary output reaches the **Operator only** — it never appears in a child's pane. Narrating
"green-lighting {AppB} now" is not green-lighting anyone; only an explicit `pane run` is.

### 3. Sends are fire-and-forget

`pane run` prints nothing on success and there's no ack. A child's answer comes back only as a
`From <App>:` turn on its own timing. That's fine for an ask (the reply *is* the confirmation),
but for a send that draws no reply — a status note, the Step 2c close-out relay — confirm with
`herdr pane read <target> --source recent --lines 20` before recording it as delivered.

### 4. Two characters that mangle the string

- **Backticks** — bash command-substitutes them inside `herdr pane run "..."`. Write field and
  event names as plain text (`user_id` → user_id).
- **A leading `/`** — Git Bash on Windows path-converts it (`/rename` becomes
  `C:/Program Files/Git/rename`) and the target receives garbage. Send slash-prefixed payloads via
  **PowerShell**, or prefix the bash call with `MSYS_NO_PATHCONV=1`. (Pure-POSIX hosts are fine.)

## The `❯` composer line lies — ghost suggestions

Claude Code auto-populates a pane's composer (`❯`) line with a **suggested next prompt** it
generates from that pane's last turn. Nobody typed it. It reads like plausible Operator input
precisely *because* it's derived from the pane's own context. This bites me hardest in Step 2a,
where I'm judging whether a child is safe to interrupt: a ghost makes an idle pane look like it
has operator input pending, and a ghost that regenerates looks like a pane I can't get clean.

**The tell is colour, and only `--ansi` shows it:**

- `herdr agent read <pane> --source visible` (default `--format text`) **strips ANSI**, so a ghost
  suggestion and real unsent input arrive byte-identical. Blind. `--ansi` separates them — but only
  in two steps, and skipping the first is the trap.
- **Step 1 — locate the composer: the LAST `❯` line (U+276F, decoded as UTF-8) that sits between
  the input box's final two `─` rules.** Take **both** conditions; each alone has a live failure
  mode. The glyph alone hits transcript content — a pane displaying a doc *about* this rule had 5
  glyph matches, 4 of them prose, the first faint from line-number chrome, so step 1 + step 2 would
  call a diff line a ghost. The rules alone fabricate a composer on a pane that has none — 2 of 8
  panes swept (non-Claude agents) had zero `❯` lines while a last-two-rules span happily bracketed
  ordinary transcript. **No `❯` line means no visible composer: infer nothing.** Across the 6 panes
  that had one it was always the last glyph match, always 2 lines from the end. (cp1252 decoding
  yields mojibake, which is where the folk advice "don't match the glyph" came from.)
- **Step 2 — on that line only**, test for faint: text wrapped in **`\x1b[2m`** is a ghost; text
  with no faint is real typed input.
- **Never faint-test the whole read.** `\x1b[2m` is ordinary transcript chrome — bullet glyphs,
  line numbers, tree characters, truncated JSON. A six-pane sweep found faint on 67 lines, **none**
  of them a composer ghost. Faint is necessary, not sufficient; position is what decides.
- **The grey `\x1b[38;2;153;153;153m` (`#999`) is the `❯` marker's own colour**, not a ghost tell —
  it appears on empty composers with no ghost at all. Don't test for it in either direction.

**Rules:**

1. The composer line is **not** part of the interruptibility test. Classify from the **transcript
   above the input box** plus `agent_status` only.
2. If I must inspect composer content: find the `❯` line (UTF-8), then faint-test **that line** —
   not the transcript around it.
3. **Sending is unaffected** — `pane run` types real characters over whatever placeholder is
   showing, so I can never accidentally send a ghost and never need to clear one first. Don't
   chase it: Escape-then-run races, and the suggestion regenerates anyway.

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

Classify what I see — from the **transcript and `agent_status`**, never from the `❯` composer line
(whatever sits there is almost always a ghost suggestion, not operator input — see *The `❯`
composer line lies*):
- **Safe-idle** — `agent_status: idle`, the last turn visibly finished, no pending
  question/dialog on screen → **go now** (Step 2b).
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

Inject one `From Coordinator:` message into the **target's** pane — one line, via `pane run` so it
actually submits, backtick-free, PowerShell-sent if it carries a leading `/` or a Windows path
(see *Sending into a child pane*). It must carry:

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

## When accounts conflict: the artifact settles it

Panes report on shared state — a file, a commit, a deployed config — and two of them will
eventually tell you opposite things about it. Do **not** adjudicate between the reports, and
do not ask a third pane who's right. **Go read the artifact.** It is the one participant that
cannot be out of date with itself.

```bash
# two panes disagree about whether a change landed
grep -n "the_thing" /path/to/shared/file      # settles it in one command
```

This matters most when the conflicting reports are *both honest* — the usual cause is a
message that aged out in flight, or a decision that reached one pane and not another. Neither
pane is wrong about what it was told; they were told different things. Reading the file skips
the whole question of who to believe.

**Corollary — a reversal goes to every pane that received the original.** When I broadcast a
decision and then reverse it on new evidence, the reversal must reach *the same set of panes*,
not just the pane whose evidence changed my mind. A pane still acting on my earlier instruction
is following orders correctly; if it then ships something I've since rejected, that is my
fan-out failure, not its judgment failure. Two habits that prevent it:

- **Write the decision to the tracker before relaying it.** One authoritative record beats N
  pane-local ones, and a pane that missed a relay can still find the current answer.
- **On reversal, name the earlier instruction explicitly** — "I told you X; that was before
  <evidence>; it is now Y" — so the receiving pane can tell whether it already acted on X.

The artifact rule is the backstop for when both habits fail, which is why it's the stronger of
the two: it doesn't depend on me getting the fan-out right.

## Don't

- Don't hardcode pane IDs — re-discover by label every time.
- Don't answer a Role-1 architectural decision myself, and don't relay it to a child — it's the
  Operator's.
- Don't interrupt a `working` or awaiting-input target on my own judgment — safe-idle only; when
  murky, hand the timing to the Operator and wait for "now is a good time."
- Don't judge interruptibility (or Operator intent) from a pane's `❯` composer line — it's
  normally a machine-generated ghost suggestion. Transcript + `agent_status` only; if I must look,
  locate the composer line first, then faint-test **that line only**.
- Don't faint-test a whole read to find a ghost — `\x1b[2m` is common transcript chrome and will
  flag dozens of innocent lines. Position first, faint second.
- Don't deliver a relay with `pane send-text` or `agent send` — no Enter means it sits unsent in
  the target's composer while I record it as relayed. `pane run` or it didn't happen.
- Don't count narrating a green-light as sending one — prose reaches the Operator, not the pane.
- Don't record a no-reply send (a close-out, a status note) as delivered without a
  `pane read --source recent` on the target.
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
- Don't adjudicate between two panes' conflicting reports about shared state — read the artifact.
- Don't reverse a decision in one pane only. The reversal goes to every pane that got the
  original, and the tracker gets it before any of them.
