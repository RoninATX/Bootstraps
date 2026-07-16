---
name: set-workspace
description: >-
  Re-hydrate the coordinator workspace after a fresh/restored herdr session. herdr recreates the
  panes but not the Claude-side state, so this evens the child-pane stack, renames every herdr
  pane (Coordinator + one per child app), and drives each agent session through its
  /rename + /color + /rc remote-control setup, then fires a status command at each child. Use when
  starting or restoring the herdr window, or when the user says "set workspace", "set up the
  panes", "re-init the coordinator", or similar. Only runs inside herdr (HERDR_ENV=1).
---

# set-workspace

Run from the **Coordinator** pane, inside herdr (`HERDR_ENV=1`). Idempotent — safe to re-run.

**Guiding principle — fire the stateless commands blind, only check state on `/rc`.** Resize,
herdr `pane rename`, Claude `/rename`, and `/color` are harmless to re-issue: if they were
already correct the pane just blinks. So **fire them without pre-checking or verifying** — don't
read state to decide whether to run them, and don't re-read afterward to confirm. That skips a
whole read-assess-verify loop and a pile of tokens. The **one** exception is `/rc` (Remote
Control): it's **stateful** — running it when already connected opens a blocking panel you'd have
to dismiss (and risks a disconnect), so it's the only command that gets an at-a-glance state
check before firing (Step 3).

**Precondition check:** confirm `HERDR_ENV=1`. If not set, stop and tell the user this must run
inside a herdr pane.

## Step 0 — Discover the panes (never hardcode IDs)

herdr pane/workspace IDs recompact between sessions, so resolve them fresh every run:

1. `herdr pane current` → the pane running this skill = **Coordinator**. Note its `workspace_id`
   and `tab_id`; only operate within those.
2. `herdr pane list --workspace <that workspace>` → for each pane, take the **basename of its
   `cwd`** and map (case-insensitive) to a child app: cwd basename `<AppName>` → the `<AppName>`
   pane; the current pane (cwd = `{workspace-root}`) → **Coordinator**.
3. If a child pane you expect is missing, report which and continue with the ones present (don't
   invent panes). If a pane's `agent_status` isn't a live Claude (e.g. a bare shell), note it —
   the slash commands in Step 3/4 only make sense for a Claude pane.

Hold the resolved `pane_id`s for the rest of the run.

## Step 1 — Even the child-pane stack

The child agents typically share one vertical column. Balance their heights to equal shares. You
need **one** layout read to compute the moves (resize amounts are relative), but don't gate on
"already even" and don't re-read to verify — just compute and fire (per the guiding principle):

1. `herdr pane layout --current` → read the child panes' `rect.height`. Let `E` = their sum (the
   column extent) and `t = round(E / n)` for `n` child panes.
2. Fire the balancing moves. **`resize --amount` is a *fraction of the extent*, not rows**
   (`fraction ≈ rows / E`; keep amounts small, ~0.02–0.1). Walk the panes top-to-bottom: for each
   boundary, `delta = height_thisPane - t`; if `delta > 0` shrink it
   (`herdr pane resize --pane <thisPane> --direction up --amount <delta/E>`), if `delta < 0` grow
   it (`--direction down --amount <|delta|/E>`). Skip any move where `|delta| <= 1` (already a
   share).

That's it — no verify pass. If the user later eyeballs a lopsided column, re-run the skill.

## Step 2 — Rename the herdr panes

Set the herdr-side pane labels (distinct from the Claude session `/rename` in Step 3):

```
herdr pane rename <Coordinator>  "Coordinator"
herdr pane rename <AppA>         "{AppA}"
herdr pane rename <AppB>         "{AppB}"
# … one per child app
```

## Step 3 — Drive each agent's Claude-side setup

Inject these as real typed input via `herdr pane run <pane> "<slash-command>"` — one call per
line, in order. **On Windows, send them through the PowerShell tool** (or Bash prefixed with
`MSYS_NO_PATHCONV=1`): Git Bash mangles a leading `/` into a Windows path
(`/rename` → `C:/Program Files/Git/rename`) and the command arrives as garbage. (Pure-POSIX
hosts don't have this trap.)

Per child pane, in order — pick a distinct `/color` for each so panes are visually separable:

| Pane      | Commands (in order)                                    |
|-----------|--------------------------------------------------------|
| **{AppA}** | `/rename {AppA}` · `/color <ColorA>` · `/rc {AppA}`   |
| **{AppB}** | `/rename {AppB}` · `/color <ColorB>` · `/rc {AppB}`   |
| …         | …                                                      |

Send each pane's commands sequentially, with a short beat (~0.5s) between them so each settles.
**They do NOT all behave the same:**

- **`/rename <name>`** and **`/color <color>`** are inline and stateless — fire them blind, no
  need to check first or verify the confirmation echo (`Session renamed to: …`,
  `Session color set to: …`) landed. Re-applying an already-correct name/color is a no-op blink.
- **`/rc <name>` opens an interactive Remote Control panel** — it does *not* execute inline, and
  it's the one **stateful** command, so it gets the at-a-glance check below.
  **First, an at-a-glance check to skip it entirely:** look at the pane's bottom-right status line
  for a green **`/rc`** indicator. If it's there, remote control is already set up — don't run the
  command at all. Only run `/rc <name>` when that indicator is absent. When you do run it, it
  enables remote control (the pane shows a live session URL) but leaves a blocking menu open
  (`Disconnect / Show QR code / ❯ Continue · Enter to select · Esc to continue`). A menu that
  reads **"Disconnect this session"** (rather than a connect prompt) also confirms it was already
  connected. **After sending `/rc`, dismiss the panel** with
  `herdr pane send-keys <pane> Escape` so the pane returns to a clean `❯` prompt — do this before
  Step 4, since an open RC panel will eat the next injected input.

Because `/rc` opens the panel, keep it **last** of the three per pane (as ordered above), and
Esc-dismiss it. No verification pass on rename/color — fire and move on.

## Step 4 — Ask each agent what's on its radar

If your children carry a "what's next / current work" command (`{status-cmd}`), fire it at each
(same injection method / PowerShell):

```
herdr pane run <AppA> "{status-cmd}"
herdr pane run <AppB> "{status-cmd}"
```

Optionally `herdr agent wait <pane> --status idle` on each, then read their outputs and give the
user a consolidated one-line-per-app summary of what's on radar. If you have no such command,
skip this step.

## Step 5 — Report

Tell the user what was applied per pane (layout evened, names/colors/rc set, and the status
results if collected). Flag anything that didn't apply (missing pane, a command that didn't echo,
a non-Claude pane) rather than claiming blanket success.
