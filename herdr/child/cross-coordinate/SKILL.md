---
name: cross-coordinate
description: "Raise a cross-app coordination need up to the Coordinator pane BEFORE touching a sibling app directly — use when a {AppName} change needs a sibling app to render/consume/emit something, or needs an Operator architectural decision (not mere command permission). Also governs how to read the three inbound message classes: a 'From {SiblingApp}:' peer relay, a 'From Coordinator:' instruction/green-light, and an unlabeled Operator turn. Only runs inside herdr (HERDR_ENV=1)."
---

# cross-coordinate — inter-pane coordination (child side)

**{AppName}** runs as one pane in a multi-pane herdr workspace alongside its sibling apps and a
**Coordinator**. This skill replaces the old "copy this blurb into the other session" hand-relay.
The Coordinator is the interrupt-buffer: it decides *when* to hand your ask to a busy sibling and
*green-lights* that sibling to work with you directly, so nobody tramples an in-flight task.

> **Adapting this file:** set `{AppName}` to *this* app throughout, and `{SiblingApp}` /
> `{SiblingA}` to the concrete sibling names. Everything else is protocol and stays as-is.

**Preconditions.** Confirm `HERDR_ENV=1`. If not set, say you are not running inside a
herdr-managed pane and stop — do not drive panes from outside herdr.

**The one rule:** never poke a sibling app directly to *start* a coordination. Always raise it to
the Coordinator first. You may only interact with a sibling directly *after* the Coordinator
green-lights it (a `From {SiblingApp}:` relay lands in your pane, or the Coordinator explicitly
opens the channel).

---

## Three message classes (read the label first)

Every turn that arrives in this pane is one of three things. Read the prefix before you act:

| Prefix on the incoming turn | Who it is                    | How to treat it |
|-----------------------------|------------------------------|-----------------|
| `From {SiblingApp}:`        | A **peer sibling** relay     | A green-lit sibling working with you directly — respond per the inbound flow below |
| `From Coordinator:`         | The **Coordinator** (interrupt-buffer) | Coordination instructions or a green-light — **not** the Operator. Act on it, reply `From {AppName}:` |
| *(no prefix)*               | The **Operator** (the human) | Your normal user. Their word overrides coordination choreography |

The Coordinator is its own class — a `From Coordinator:` turn is not the Operator and not a peer.
It typically green-lights direct sibling contact, relays a sibling's ask, or asks you to close
out a coordination.

---

## When to use (outbound)

Trigger this whenever a {AppName} implementation need meets either bar:

1. **A sibling must render/consume/emit against a {AppName} interface.** You changed or added
   something on your side that a sibling now has to render, emit into, or read — a new field,
   event, route, schema shape, or contract they depend on. The coordination is announcing/shaping
   that contract, not asking a sibling to build *your* half.
2. **You need an Operator architectural decision.** Not "permission to run a command" — an actual
   design choice: a cross-app contract shape, a source-of-truth call, an encoding direction that
   affects other apps. Route it up rather than guessing.

If neither bar is met (you can implement it entirely inside {AppName}, or you just need a command
run), don't use this skill.

---

## Discover the panes (never hardcode IDs)

herdr pane IDs compact when panes close — re-read them every time:

```bash
herdr pane list
```

Label→pane_id map, to eyeball all panes at once (avoids fragile `grep`/`tr` parsing):

```bash
herdr pane list | python -c "import sys,json; [print(p['label'],'->',p['pane_id']) for p in json.load(sys.stdin)['result']['panes']]"
```

Match by **label** (and cwd as tiebreak): **Coordinator** → label `Coordinator`, cwd =
`{workspace-root}`; each sibling → label `{SiblingApp}`, cwd = `{workspace-root}/{SiblingApp}`.

To **script a send**, don't eyeball the map — resolve one label to its `pane_id`
deterministically (empty string if the pane is gone, so a closed pane yields nothing instead of
raising):

```bash
# → the pane_id for a given label, or nothing if the pane is gone
herdr pane list | python -c "import sys,json; ps=json.load(sys.stdin)['result']['panes']; print(next((p['pane_id'] for p in ps if p['label']=='Coordinator'), ''))"
```

Swap `Coordinator` for a sibling label as needed. An empty result means the pane closed — re-run
`herdr pane list` rather than reusing an old ID, and confirm the target pane still exists before
every send.

---

## Sending into another pane — the mechanics that make a message land

Every message in this protocol is **injected input**: you are typing into someone else's live
session. Two failure modes look identical from your side ("I sent it") and from theirs ("nothing
arrived"), so get these right before anything else in this skill.

### 1. Text without an Enter never submits

| Command | What it actually does |
|---------|-----------------------|
| `herdr pane run <pane> "<text>"` | types the text **and presses Enter** — delivered as a turn |
| `herdr pane send-text <pane> "<text>"` | types the text, **no Enter** — it sits unsent in their composer |
| `herdr agent send <target> "<text>"` | same — literal text, **no Enter** |

**Always `pane run`.** A `send-text` relay strands your message on the recipient's `❯` line, where
it looks to them like something they half-typed and to you like a delivered ask. That is the real
cause of most "the Coordinator never answered me" / "the sibling ignored my relay" reports: the
message was pasted, never submitted. That the CLI carries a *separate*
`pane send-keys <pane> Enter` is the corroboration: submitting is its own act.

Keep every relay to a **single line** so it submits cleanly. If a send genuinely must span lines,
`pane send-text` the block and then `herdr pane send-keys <pane> Enter` **once** — but prefer one
line plus a pointer to the durable note.

### 2. Prose is not a send

Your ordinary output reaches the **Operator only**. It never appears in another pane. Writing
"I'll let {SiblingApp} know" is not letting them know — the *only* channel to another pane is an
explicit `pane run`.

### 3. Sends are fire-and-forget

`pane run` prints nothing on success and there is no ack. A response comes back only as a labeled
inbound turn (`From {SiblingApp}:` / `From Coordinator:`), on the recipient's own timing. For a
send that won't draw a reply — a status ping, a close-out — confirm it landed with
`herdr pane read <target> --source recent --lines 20` rather than assuming.

### 4. Two characters that mangle the string

- **Backticks** — bash command-substitutes them inside `herdr pane run "..."`. Write field and
  event names as plain text (`user_id` → user_id).
- **A leading `/`** — Git Bash on Windows path-converts it (`/rename` becomes
  `C:/Program Files/Git/rename`) and the target receives garbage. Send slash-prefixed payloads via
  **PowerShell**, or prefix the bash call with `MSYS_NO_PATHCONV=1`. (Pure-POSIX hosts are fine.)

---

## The `❯` composer line lies — ghost suggestions

Claude Code auto-populates a pane's composer (`❯`) line with a **suggested next prompt** it
generates from that pane's last turn. Nobody typed it. It reads like plausible Operator input
precisely *because* it's derived from the pane's own context — which is what makes it dangerous
whenever you read a pane, including your own.

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

1. Never read the composer line as pane state or as Operator intent. Judge from the **transcript
   above the input box** plus `herdr agent get <pane>` / `herdr agent list` `agent_status`.
2. If you must inspect composer content: find the `❯` line (UTF-8), then faint-test **that line** —
   not the transcript around it.
3. **Sending is unaffected** — `pane run` types real characters over whatever placeholder is
   showing, so you can never accidentally send a ghost and never need to clear one first. Don't
   chase it: Escape-then-run races, and the suggestion regenerates anyway.

---

## Outbound flow — raising an ask

### 1. Back it with a durable note (recommended)

If you use an issue/task tracker (`{tracker}`), give each coordination ask a durable item so the
relay message can stay short and the sibling can read the full spec itself. Reuse an existing item
if one already speaks to the need; otherwise create one. In its body, pin the **contract** you're
exposing (field names, event names, result keys), **your side** (what you ship), and a
**checklist** of the cross-app steps for both sides to tick off as the contract firms up.

**A bare tracker ID is repo-local**: a sibling in another repo can't read your `<id>` from its own
cwd. If a sibling will need to read the item itself, hand them a *resolvable* pointer — an absolute
path or a `--path`-style form. (No tracker? Then carry the detail inline in the relay — it just
makes the relay longer.)

### 2. Draft the relay (labeled `From {AppName}:`)

Keep it to a **single line** — detail lives in the tracker item (or inline if you have none):

```
From {AppName}: <one-line ask>. Needs <{SiblingApp}>. Detail in <item-id or resolvable pointer>.
```

### 3. Auto-send to the Coordinator

Inject it straight into the Coordinator's pane (no confirm step — Claude queues it as its next
turn, the "next convenient interrupt"):

```bash
herdr pane run "<coordinator-pane-id>" "From {AppName}: <one-line ask>. Needs <sibling>. Detail in <item-id>."
```

`pane run` (not `send-text` / `agent send`) with a **single-line**, backtick-free message — see
*Sending into another pane* above for why each of those matters. It's fire-and-forget: nothing
confirms delivery, so if you want certainty the relay landed, `herdr pane read <coordinator-pane>
--source recent` rather than assuming.

### 4. Then wait — do not touch the sibling

After sending, **stop reaching toward the sibling.** Do the {AppName}-side work you can do without
them (ship and validate your interface so it's ready when they consume it), or move to other work.
The Coordinator will relay on its own timing and green-light direct contact. Tell the Operator
you've raised it and cite the item ID(s).

---

## Direct interaction once green-lit

When the Coordinator opens the channel, the sibling talks to you directly. Their turns arrive in
your pane clearly labeled — e.g. `From {SiblingApp}:`. That label is how you know it's a relay,
**not** the Operator (unlabeled turns are the Operator; a `From Coordinator:` turn is the
Coordinator).

- Reply into **their** pane, always prefixed `From {AppName}:`, via `pane run` and in plain text
  (no backticks — see *Sending into another pane*):
  ```bash
  herdr pane run "<sibling-pane-id>" "From {AppName}: confirmed - the field ships in the frame. Two questions: ..."
  ```
- Keep the tracker item updated as the contract firms up (check off checklist items).
- When the interface lands and your side is validated, mark the item completed and send a closing
  `From {AppName}:` note plus a status line up to the Coordinator.

---

## Inbound flow — you are the recipient

A `From {SiblingApp}:` peer relay (or a `From Coordinator:` hand-off) may land asking **you** for
something — usually a sibling that needs {AppName} to expose, add, or change an interface they
read.

1. **Reach a clean stopping point** in your own task first — don't abandon mid-edit. Then tell the
   Coordinator you're free:
   ```bash
   herdr pane run "<coordinator-pane-id>" "From {AppName}: at a clean stopping point, free to help <sibling>."
   ```
2. **Review and help.** Read their ask (and any item IDs they cite — resolve a sibling's item via
   its absolute path / `--path` pointer). Work it directly: answer questions, make the change and
   validate it, send status updates straight into their pane as `From {AppName}:`.
3. **Bubble up when needed.** If the task is **done**, or it surfaces a **design decision that
   needs the Operator** (a contract shape, a source-of-truth call), raise that to the Coordinator —
   don't decide a cross-app contract unilaterally, and don't leave a finished hand-off unannounced.
4. **Always label** every message you inject as `From {AppName}:`.

---

## Labeling cheat-sheet

| Situation | You do |
|-----------|--------|
| Message into any other pane | Prefix `From {AppName}:` |
| Turn arrives prefixed `From {SiblingApp}:` | Peer relay — respond per inbound flow |
| Turn arrives prefixed `From Coordinator:` | Coordinator instruction / green-light — act, reply `From {AppName}:` |
| Unlabeled turn | It's the Operator |
| Starting a coordination | Note first, then relay to **Coordinator** — never straight to the sibling |
| Sibling reaches you (green-lit) | Work with them **directly**, pane-to-pane |

## Don't

- Don't hardcode pane IDs (`w5:p3`) — re-discover by label every time.
- Don't open a coordination by messaging a sibling directly — it goes through the Coordinator.
- Don't mistake a `From Coordinator:` turn for the Operator — it's the interrupt-buffer, a distinct
  third class.
- Don't deliver a relay with `pane send-text` or `agent send` — they type the text with **no
  Enter**, so it sits unsent in the recipient's composer. `pane run` or it didn't happen.
- Don't treat saying something in prose as messaging another pane — your output goes to the
  Operator only; the pane hears nothing without an explicit `pane run`.
- Don't assume a no-reply send (status ping, close-out) landed — `pane read --source recent` the
  target if it matters.
- Don't put backtick characters inside a `herdr pane run "..."` string — bash will
  command-substitute them and mangle the relay.
- Don't read anything into another pane's `❯` composer line — it's usually a machine-generated
  ghost suggestion, not typed input. Judge by transcript + `agent_status`; if you must look, locate
  the composer line first, then faint-test **that line only**.
- Don't faint-test a whole read to find a ghost — `\x1b[2m` is common transcript chrome and will
  flag dozens of innocent lines. Position first, faint second.
- Don't send a fat multi-paragraph relay when you have a tracker — the item carries the detail, the
  relay is one line + ID.
- Don't hand a sibling a bare tracker ID — it's repo-local; give an absolute-path / `--path`
  pointer if they need to read it.
- Don't mark a coordination item completed while its checklist still has unchecked items.
- Don't take another pane's word for the state of a shared artifact when it conflicts with what
  I'm seeing — read the file. It cannot be out of date with itself, and two honest panes can be
  told different things by a relay that aged out in flight.
- Don't assume a `From Coordinator:` instruction is still current if it contradicts what I now
  observe — flag the conflict up rather than acting on the older of two instructions. Holding is
  cheap; shipping against a reversed decision is not.
