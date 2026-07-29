---
name: up-next
description: Show what's up next in a beans-tracked project — the live in-progress work, queued todos, and active milestone focus — as a prioritized baseline. Invoke via `/up-next [repo]` or when the user asks "what's next / what's up next / what should I work on / where were we / current state of work." Defaults to the current project; pass a sibling repo name to target that one instead.
---

# up-next

Produces an authoritative "what's up next" baseline from the **beans** tracker instead of decaying memory snapshots. The tracker is the source of truth for open work; this skill runs the standard focus query and synthesizes it into a prioritized read.

## When to invoke

Trigger on requests for the current state of work / what to do next. Recognized phrasings include but are not limited to:

- `/up-next`
- `/up-next <RepoName>` (any sibling repo in the workspace)
- "what's next / what's up next"
- "what should I work on"
- "where were we / current state of work / baseline me"
- "what's still open / what's in flight"

Do **not** invoke for a single specific bean's status ("is `Proj-abcd` done?") — read that bean file directly. This skill is for the *aggregate* picture.

## Repo resolution

1. **Explicit arg** (`/up-next <RepoName>`): resolve it against the sibling repos that **actually exist**, by globbing `*/.beans` from the workspace root:

   ```bash
   ls -d ../*/.beans        # or: find .. -maxdepth 2 -name .beans -type d
   ```

   Match the argument against those directory names, then target the hit with an absolute path. **Discover the list; never hardcode one.** A hardcoded table of repos is a remembered list, and a remembered list silently omits whatever was added after it was written — a repo that exists but isn't in the table reads as "unknown repo" rather than as a gap in the skill.

   Unrecognized argument → tell the user, show what *was* found, and stop. Do not guess a path.

2. **No arg**: use the current working directory's project. If a `.beans` dir exists at the repo root, target it directly (no `--beans-path` needed). If the cwd isn't a beans repo, say so and list the repos discovered above.

Do **not** `cd` into sibling repos to read them. Target them in place with `beans --beans-path <abs>/.beans <cmd>` and absolute paths — changing directory to read a neighbour is how a session loses track of which project it's in.

## What to do

1. **Pull active milestones** (the strategic frame — what focus the open work rolls up to):

   ```bash
   beans query '{ beans(filter: { type: ["milestone"], status: ["in-progress","todo"] }) { id title status } }' --json
   ```

   For a sibling repo, prepend the path flag:
   ```bash
   beans --beans-path <abs>/.beans query '{ ... }' --json
   ```

2. **Pull the open work** (everything not completed, milestones excluded), so in-progress and todo are separated:

   ```bash
   beans query '{ beans(filter: { excludeStatus: ["completed"] excludeType: ["milestone"] }) { id title status type } }' --json
   ```

   If `excludeType` isn't accepted by the installed beans version, fall back to fetching all non-completed and filter out `type == "milestone"` yourself.

   **Check the project's closed-status vocabulary before trusting "not completed."** Some trackers accumulate legacy statuses (`done`, `abandoned`) alongside the current set, and a filter that only excludes `completed` will report long-closed work as open. If the result looks implausibly large, count the statuses actually in use and widen the exclusion rather than presenting the noise as a baseline.

3. **Synthesize** — present, most-actionable first:
   - **In focus** — active milestone(s), one line each (`id` + title).
   - **In flight** — `status: in-progress` beans (these are what's actually being worked). Prefix each with its id.
   - **Queued** — `status: todo` beans, capped at ~10, ordered as returned. If there are more, note the overflow count rather than dumping all.
   - Skip `draft`/`blocked` unless nothing else is open, in which case surface them so the user isn't left with an empty list.

4. **Close with a single recommended next step** — the one bean you'd pick up first and why (usually the in-progress item closest to done, or the top todo under the active milestone). Keep it to one or two sentences.

5. **Hand off to `/context`, if the project has it.** Check for a `context` skill in the target project (`<repo>/.claude/skills/context/`). If present, end by naming the exact call for the recommended bean — `/context <that-bean-id>` — so the next move is one keystroke rather than a decision.

   This is the seam where orientation becomes work: `/up-next` answers *what to work on*, `/context` answers *what to read first*, and the bean you just recommended is the argument to the second. Offer it once, as part of the recommendation line — do not add a section for it, and do not run it unprompted, since the user may want a different bean than the one you picked.

   If the project has no `context` skill, say nothing about it. Never suggest installing one from here.

## Output shape

Terminal markdown, scannable, ids prefixed on every bean title. Example skeleton:

```
## Up next — ProjectName

**In focus**
- Proj-wxyz — <milestone title>

**In flight**
- Proj-abcd — <title>
- Proj-efgh — <title>

**Queued** (6)
- Proj-ijkl — <title>
- …

**Recommended:** pick up `Proj-abcd` — it's the closest in-flight item to done. Start with `/context Proj-abcd`.
```

(The trailing `/context …` appears only when the project actually has that skill.)

Keep it tight. This is a baseline, not a status report — no preamble, no restating the query.

## Notes

- `beans query` is read-only in this usage (a GraphQL read, no mutation), so it is safe to allowlist.
- If `beans` isn't found or the query errors, report the raw error and suggest `beans list` as a fallback — don't silently show an empty baseline. An empty baseline and a broken query look identical to the reader, which is the worst property an orientation tool can have.
- **The example ids above are deliberately placeholder-shaped** (`abcd`, `efgh`, `ijkl`, `wxyz` — runs of a repeating character work too, like `xxxx`). If your project also runs a citation-graph tool over its docs, realistic-looking example ids in a skill file get picked up as real citations and reported as link rot. Keep examples in placeholder form when editing this file.
