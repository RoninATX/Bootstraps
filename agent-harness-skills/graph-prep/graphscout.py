"""graphscout.py - NetworkX scouting harness.

Premise under test: when the data already lives in JSON / markdown / a dataframe,
how far does NetworkX get you before you actually need a graph database?

Two corpora, one analysis engine:

  beans  - every .beans repo in the workspace (work + personal), using both the
           DECLARED edges the tracker knows about (parent, blockedBy) and the
           IMPLICIT edges it does not (one bean's prose naming another bean's id,
           including across repo boundaries, which the tracker cannot represent
           at all).
  notes  - any folder of markdown, linked by [[wikilinks]] and relative .md
           links (Obsidian vault, .claude/knowledge, a repo wiki).

Usage:
    python graphscout.py beans
    python graphscout.py beans --repos ProjectOne project-two --json out.json
    python graphscout.py notes --root "/path/to/a/markdown/vault"
    python graphscout.py beans --png beans.png
    python graphscout.py context <bean-id|doc-stem>
    python graphscout.py rot                    # dead ids cited by beans AND docs

Requires: networkx (>=3.x). matplotlib only for --png.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx

def _find_workspace() -> Path:
    """The dir holding the project folders.

    Walk up from this file to the nearest ancestor containing a `.beans` dir --
    that is the segment root -- and take its parent. Falls back to a fixed depth
    so the tool keeps working when vendored somewhere without beans above it.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".beans").is_dir():
            return parent.parent
    return here.parents[2] if len(here.parents) > 2 else here.parent


WORKSPACE = _find_workspace()

BEAN_QUERY = """{ beans { id title status type priority body tags
                          parent { id } blockedBy { id } blocking { id }
                          createdAt updatedAt } }"""

# Loose id shape; every candidate is intersected with the real id set, so a
# permissive pattern costs nothing and a strict one would miss prefixes.
# Case-insensitive on purpose: repos mint ids in three different styles
# (proj-gjcp, ServiceOne-0bec, multi-word-repo-1rz3) and prose cites them
# in whatever case the author typed.
ID_RE = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-[a-z0-9]{4}\b", re.IGNORECASE)
WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)")
MDLINK_RE = re.compile(r"\[[^\]]*\]\(([^)#?]+\.md)\)")
SEE_RE = re.compile(r"see\s+([a-z0-9][a-z0-9._-]*\.md)", re.IGNORECASE)
# Many projects cite a neighbouring doc as a backticked PATH rather than as a
# markdown link -- `.claude/knowledge/pi.md`. The two patterns above see none of
# that, so the whole doc->doc layer silently reports zero edges and a file that
# points at four neighbours looks isolated, which is worse than a true isolate
# because it reads as answered. Measured in one segment: 92 backticked refs
# against 1 markdown link. Every hit is still resolved against the real doc set,
# so a path that names nothing simply finds nothing.
PATHREF_RE = re.compile(r"`([^`\s]+\.md)`")

# Doc folders that make up a segment alongside its beans. `.wiki` is handled
# separately because it is a *sibling folder*, not a subfolder -- the segment
# boundary is not the folder boundary.
DOC_DIRS = (
    (".claude/knowledge", "knowledge"),
    (".claude/domain", "memory"),
    (".claude/tools", "tools"),
    (".claude/skills", "skill"),
)

# Repo-root docs are cited constantly and were previously UNREPRESENTABLE -- citable
# but never nodes, so every reference to one silently formed no edge (root cites
# these a few times each). Widened to WITHIN-SEGMENT root docs only: these are the same
# project's files. Cross-segment refs are a different class and are refused
# outright by `_out_of_corpus` -- see that function for why the guard is a
# precondition of this widening rather than made redundant by it.
ROOT_DOCS = ("CLAUDE.md", "AGENTS.md")

# A 4-char slug is indistinguishable from an ordinary English word, so
# "ServiceOne-side" / "ServiceTwo-only" parse as bean ids. Only the *dangling*
# report is affected (real ids are confirmed against the id set), but 35 bogus
# "link rot" hits would have buried the 12 genuine ones.
NOT_A_SLUG = {
    "side", "mode", "host", "repo", "data", "auth", "only", "beta", "tier",
    "main", "wide", "like", "base", "page", "type", "time", "path", "docs",
    "gate", "flow", "sync", "node", "edge", "call", "test", "user", "core",
    "prod", "live", "free", "full", "next", "last", "open", "read", "safe",
    "blue", "grey", "gray", "dark", "bold", "wide", "size", "list", "team",
}

# Docs that TEACH the id convention write template ids on purpose -- a skill
# saying "a bare `Proj-xxxx` is repo-local" is not link rot, and reporting it as
# such trains people to ignore the report. Digit-only slugs are already excluded
# separately; these are the alpha placeholders.
PLACEHOLDER_SLUGS = {"abcd", "wxyz", "efgh", "ijkl", "mnop", "qrst", "uvwx"}


def _is_placeholder(slug: str) -> bool:
    """Template ids people write by hand: `xxxx`, `vvvv`, `abcd`, ...

    Enumerating them loses -- a dashboard example using `proj-vvvv` / `proj-wwww`
    slipped past a fixed set. A run of one repeated character is the general
    shape, so match that rather than growing the list forever.
    """
    return slug in PLACEHOLDER_SLUGS or len(set(slug)) == 1


def _is_dead_id(cand: str, known, prefixes) -> bool:
    """A candidate that looks like a real id for this workspace but resolves to nothing."""
    if cand in known:
        return False
    head, _, slug = cand.rpartition("-")
    return (head in prefixes
            and slug not in NOT_A_SLUG
            and not _is_placeholder(slug)
            and not slug.isdigit())

CLOSED = {"completed", "scrapped"}
EDGE_KINDS = ("parent", "blocked_by", "mentions", "links")


# ---------------------------------------------------------------- ingest: beans

def discover_repos() -> dict[str, Path]:
    return {
        p.parent.name: p
        for p in sorted(WORKSPACE.glob("*/.beans"))
        if p.is_dir()
    }


def load_beans(repos: dict[str, Path]) -> list[dict]:
    exe = shutil.which("beans") or "beans"
    rows: list[dict] = []
    for name, path in repos.items():
        # Bytes, not text=True: at least one repo emits cp1252 punctuation that
        # blows up strict utf-8 decoding inside subprocess's reader thread.
        proc = subprocess.run(
            [exe, "--beans-path", str(path), "query", BEAN_QUERY, "--json"],
            capture_output=True, shell=False,
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0 or not out.strip():
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            print(f"  ! {name}: beans query failed: {err[:200]}", file=sys.stderr)
            continue
        # A zero exit code is not a promise of clean JSON on stdout -- a warning
        # preamble or a truncated payload parses as garbage. This is a
        # WHOLE-WORKSPACE tool, so one noisy repo must not take down the other
        # eight: skip the segment loudly and keep going.
        try:
            payload = json.loads(out)
        except json.JSONDecodeError as e:
            print(f"  ! {name}: skipping segment, unparseable beans output "
                  f"({e}); first 120 chars: {out[:120]!r}", file=sys.stderr)
            continue
        for bean in payload.get("beans", []):
            bean["repo"] = name
            rows.append(bean)
    return rows


def build_bean_graph(beans: list[dict], extra_known=(), extra_prefixes=()) -> nx.MultiDiGraph:
    """Nodes = beans. Edges are typed, and mention edges are *derived* from prose.

    `extra_known` / `extra_prefixes` carry ids from OTHER segments. They never
    become nodes or edges -- they only widen what counts as resolvable, so a
    foreign id can be judged at all. Without them a single-segment scan cannot
    tell a live sibling id from a dead one: the prefix isn't in its own set, so
    both look like ordinary hyphenated English and are silently ignored.
    """
    g = nx.MultiDiGraph()
    known = {b["id"].lower(): b["id"] for b in beans}
    prefixes = {b["id"].rsplit("-", 1)[0].lower() for b in beans}
    resolvable = set(known) | {k.lower() for k in extra_known}
    all_prefixes = prefixes | {p.lower() for p in extra_prefixes}

    for b in beans:
        g.add_node(
            b["id"],
            kind="bean",
            repo=b["repo"],
            title=b.get("title") or "",
            status=b.get("status") or "",
            type=b.get("type") or "",
            priority=b.get("priority") or "",
            tags=tuple(b.get("tags") or ()),
            created=b.get("createdAt") or "",
            updated=b.get("updatedAt") or "",
            open=(b.get("status") or "") not in CLOSED,
        )

    dangling: list[tuple[str, str, str]] = []
    for b in beans:
        src = b["id"]
        parent = (b.get("parent") or {}).get("id")
        if parent:
            g.add_edge(src, parent, kind="parent")
        for blk in b.get("blockedBy") or []:
            g.add_edge(src, blk["id"], kind="blocked_by")

        # Implicit edges: ids named in prose. This is the layer the tracker has
        # no schema for -- and the only place cross-repo coupling shows up.
        seen: set[str] = set()
        for raw in ID_RE.findall(b.get("body") or ""):
            cand = raw.lower()
            if cand == src.lower() or cand in seen:
                continue
            seen.add(cand)
            if cand in known:
                g.add_edge(src, known[cand], kind="mentions")
            elif _is_dead_id(cand, resolvable, all_prefixes):
                # looks like a bean id, isn't one. No location: beans arrive
                # from the tracker query, not from a file we walked.
                dangling.append((src, raw, ""))

    g.graph["dangling"] = dangling
    # The segment graph reuses these to judge DOC citations by the same rule.
    g.graph["prefixes"] = all_prefixes
    g.graph["resolvable"] = resolvable
    g.graph["corpus"] = "beans"
    return g


# ---------------------------------------------------------------- ingest: notes

def build_note_graph(roots: list[Path]) -> nx.MultiDiGraph:
    """Nodes = markdown files. Edges = [[wikilinks]] + relative .md links."""
    g = nx.MultiDiGraph()
    files: list[Path] = []
    for root in roots:
        files.extend(p for p in root.rglob("*.md") if ".venv" not in p.parts)

    by_stem: dict[str, list[Path]] = defaultdict(list)
    for p in files:
        by_stem[p.stem.lower()].append(p)

    def key(p: Path) -> str:
        return str(p.resolve())

    for p in files:
        g.add_node(key(p), kind="note", title=p.stem, repo=p.parent.name,
                   path=str(p), status="", open=True)

    dangling: list[tuple[str, str, str]] = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        targets: list[str] = []
        for raw in WIKILINK_RE.findall(text):
            name = raw.strip()
            hits = by_stem.get(name.lower().removesuffix(".md"), [])
            if hits:
                targets.append(key(hits[0]))
            elif not Path(name).suffix:
                # Obsidian embeds (images, PDFs) share the [[...]] syntax but
                # aren't notes; an extensionless miss is a real unresolved link.
                dangling.append((key(p), name, str(p)))
        for rel in MDLINK_RE.findall(text):
            if _is_external(rel):
                continue
            cand = (p.parent / rel).resolve()
            if cand.exists():
                targets.append(str(cand))
            else:
                dangling.append((key(p), rel, str(p)))
        for t in dict.fromkeys(targets):
            if t != key(p) and t in g:
                g.add_edge(key(p), t, kind="links")

    g.graph["dangling"] = dangling
    g.graph["corpus"] = "notes"
    return g


# ------------------------------------------------------- segment graph (context)

# Filenames that name a container rather than a topic. A skill is always
# `<name>/SKILL.md`, so keying nodes on the file stem collapses every skill in a
# project into one node called `skill/SKILL` -- the citations of six different
# skills merge, and whichever file was loaded last supplies the path everyone
# sees. Fall back to the parent directory, which is the actual identity.
GENERIC_STEMS = {"skill", "readme", "index", "home", "_index"}

# A ROOT_DOCS entry whose stem is GENERIC is a silent-loss trap, so make the bad
# state unrepresentable rather than documenting it. `load_segment_docs` keys root
# docs on `f.stem` (never folded), while `_ref_stem` DOES fold a generic stem --
# so admitting `README.md` would key the node `readme` while every path-form ref
# folds to its parent directory and matches nothing. A bare `README.md` would
# resolve; `<repo>/README.md` and `../README.md` would vanish, costing exactly
# the partial-path refs the stem fallback exists to rescue.
#
# A plain `assert` would be stripped under `python -O`, which is a poor way to
# protect against silent loss, so this raises for real.
_generic_root_docs = {Path(n).stem.lower() for n in ROOT_DOCS} & GENERIC_STEMS
if _generic_root_docs:
    raise RuntimeError(
        f"ROOT_DOCS entries with generic stems resolve only in BARE form, "
        f"silently dropping every path-form reference: {sorted(_generic_root_docs)}. "
        f"Fold the node side too (see the three-pickup asymmetry) before admitting them."
    )


def _doc_stem(f: Path) -> str:
    return f.parent.name if f.stem.lower() in GENERIC_STEMS else f.stem


# Tie-break order when a referenced stem exists in several kinds and the citing
# doc's own kind isn't among them. Deliberately fixed rather than load-ordered so
# the same corpus always yields the same graph.
KIND_PRIORITY = ("knowledge", "memory", "tools", "skill", "root", "wiki")


def _resolve_doc_ref(by_stem: dict, stem: str, from_kind: str) -> str | None:
    """Pick which doc a `see X.md` reference means.

    Prefer a match in the citing doc's own kind -- a knowledge file writing
    `architecture.md` means the knowledge one, even when the wiki also has that
    page. Otherwise fall back to a stable kind order, never to load order.
    """
    cands = by_stem.get(stem) or []
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    same = [c for c in cands if c.split("/", 1)[0] == from_kind]
    if same:
        return same[0]
    return min(cands, key=lambda c: (KIND_PRIORITY.index(c.split("/", 1)[0])
                                     if c.split("/", 1)[0] in KIND_PRIORITY
                                     else len(KIND_PRIORITY), c))


def _ref_stem(ref: str) -> str:
    """Stem for a path REF, folded the same way `_doc_stem` folds a real file.

    `cross-coordinate/SKILL.md` names the cross-coordinate skill, not a doc
    called SKILL, so a generic filename defers to its parent directory here
    exactly as it did when the node was created. Without the symmetry the
    fallback looks up "skill", misses, and a ref naming a doc that plainly
    exists forms no edge.
    """
    p = Path(ref)
    if p.stem.lower() in GENERIC_STEMS and p.parent.name:
        return p.parent.name.lower()
    return p.stem.lower()


def _is_external(ref: str) -> bool:
    """A URL is not a local doc, however much it ends in `.md`.

    `build_notes_graph` has always skipped these; `build_segment_graph` never did,
    so a wiki page linking to a repo file on GitHub
    (`https://…/blob/main/docs/networking.md`) failed path resolution, fell through
    to the stem index, and FABRICATED a local edge to any doc whose stem matched
    the URL's basename. Shared by both graphs on purpose -- the doc-ref block has
    already produced four defects by letting two code paths drift apart.
    """
    return "://" in ref or ref.startswith("//")


def _out_of_corpus(ref: str, from_dir: Path, seg_root: Path, by_path: dict) -> bool:
    """A ref naming something real that is not part of THIS segment's doc corpus.

    Two disjoint cases, neither of which may fall through to the stem index:

    * **Another project's file.** A stem match here would let one segment's
      `/context` surface another segment's documents. This is a **disclosure
      control**, not only a correctness fix: a hub segment may cite another
      segment's RESTRICTED material (pre-release, legal-sensitive, embargoed),
      and without this guard widening `DOC_DIRS` would make that a resolvable
      node in a graph with no business resolving it.
      Structural prevention rather than convention.

      ⚠ **Do NOT "optimise" this into a containment check** (`is the path under
      seg_root`). It looks equivalent and is not. In a **root-as-segment** install
      `seg_root` IS the workspace, so every sibling project resolves *inside* it
      and containment would refuse nothing at all -- silently opening the boundary
      in the one install that actually cites restricted material. What enforces
      the boundary is `by_path` membership, in every install. (That is also what
      the sibling-wiki case forces, from the opposite direction: corpus that lives
      OUTSIDE seg_root. Two unrelated reasons, one test.)
    * **Inside the segment but not a doc node** -- e.g. a prompt template that
      shares a basename with a knowledge file (`forge/identity/templates/
      capabilities.md` vs `.claude/knowledge/capabilities.md`).

    A ref naming nothing real is NOT out-of-corpus: a bare `foo.md` still needs
    the stem fallback, which is load-bearing. The test is "names something real
    that isn't ours", never "path resolution failed".

    Deliberately ONE test rather than a containment check plus an identity check.
    An earlier version also refused anything resolving outside the segment root,
    which looked stricter and was simply wrong: the sibling `<repo>.wiki` is part
    of the corpus but lives OUTSIDE that root, so every wiki-relative ref was
    refused and four genuine wiki→knowledge edges vanished. Membership in
    `by_path` already answers "is this ours" for wiki and segment docs alike, and
    a non-existent cross-segment path discloses nothing.
    """
    for base in (from_dir, seg_root):
        try:
            cand = (base / ref).resolve()
        except (OSError, ValueError):
            continue
        if cand.exists() and cand not in by_path:
            return True
    return False


def _resolve_ref(ref: str, by_path: dict, by_stem: dict, from_dir: Path,
                 seg_root: Path, from_kind: str) -> str | None:
    """Resolve ANY doc reference -- by path first, then by folded stem.

    BOTH legs (markdown/see links and backticked paths) go through here, because
    a markdown link IS a path and resolving it by stem alone made it work only by
    accident: `../topic/README.md` folds to `topic` and hits, while
    `../README.md` folds to `..` and silently misses. Path-first fixes that and is
    strictly more precise -- it names one file rather than a name that may exist
    in several kinds. The stem fallback still catches a bare `foo.md` written from
    a directory the path does not resolve against.

    Kept as one function on purpose. This block has now grown the same
    two-legs-drifted-apart defect three times (raw stem vs `_ref_stem`, then
    stem-only vs path-then-stem); a single shared resolver is what stops a fourth.
    """
    if _is_external(ref) or _out_of_corpus(ref, from_dir, seg_root, by_path):
        return None
    # The stem fallback is NOT dead code, however redundant path-first makes it
    # look. Measured on a real segment: 24/24 refs resolve by_path with zero fallthrough,
    # yet 9 OTHER refs reach the graph only via the stem index. Deleting it
    # silently drops those. Path-first changed which branch wins, not whether
    # the second branch is needed.
    return (_resolve_doc_path(by_path, ref, from_dir, seg_root)
            or _resolve_doc_ref(by_stem, _ref_stem(ref), from_kind))


def _resolve_doc_path(by_path: dict, ref: str, from_dir: Path, seg_root: Path):
    """Resolve a backticked path ref to a node, or None.

    Tried relative to the citing doc first, then to the segment root -- backticked
    paths are conventionally written from the root (`.claude/knowledge/pi.md`)
    but a sibling-relative one should still land. This is a PATH match, so unlike
    a bare stem it is unambiguous by construction and never needs the
    `_resolve_doc_ref` kind tie-break.

    CALLER ASSUMPTION: `seg_root` is computed as `WORKSPACE / repo`, i.e. the
    segment is a CHILD of the workspace. That holds for an ordinary vendored
    install and not for a **root-as-segment** one, where the workspace root *is*
    the segment and `WORKSPACE / repo` names a directory that does not exist. The
    failure is silent rather than loud -- the citing-doc leg still resolves, so
    the segment-root leg just quietly matches nothing and root-relative refs stop
    forming edges. A root-as-segment install should route this through its own
    `segment_path()` (as a root-as-segment install must) rather than passing
    `WORKSPACE / repo` in.
    """
    for base in (from_dir, seg_root):
        try:
            hit = by_path.get((base / ref).resolve())
        except (OSError, ValueError):
            hit = None
        if hit:
            return hit
    return None


def load_segment_docs(repo: str) -> list[dict]:
    """Knowledge/memory/tools/skill docs, repo-root docs, and the sibling wiki."""
    base = WORKSPACE / repo
    out: list[dict] = []
    for name in ROOT_DOCS:
        f = base / name
        if f.is_file():
            out.append({"kind": "root", "path": f, "stem": f.stem})
    for sub, kind in DOC_DIRS:
        d = base / sub
        if d.is_dir():
            for f in sorted(d.rglob("*.md")):
                out.append({"kind": kind, "path": f, "stem": _doc_stem(f)})
    wiki = WORKSPACE / f"{repo}.wiki"
    if wiki.is_dir():
        for f in sorted(wiki.rglob("*.md")):
            out.append({"kind": "wiki", "path": f, "stem": _doc_stem(f)})
    return out


def sibling_ids(repo: str) -> tuple[set[str], set[str]]:
    """Bean ids + prefixes from every OTHER segment in the workspace.

    Only used to judge whether a foreign-prefix citation is live or dead --
    never to add nodes. Costs one `beans query` per sibling, so it is opt-in.
    """
    ids: set[str] = set()
    for name, path in discover_repos().items():
        if name == repo:
            continue
        for b in load_beans({name: path}):
            ids.add(b["id"].lower())
    return ids, {i.rsplit("-", 1)[0] for i in ids}


def build_segment_graph(repo: str, cross: bool = False) -> nx.MultiDiGraph:
    """A single project's beans AND docs in one graph.

    The whole point of the unified graph is the doc<->bean edge: the tracker
    knows nothing about which knowledge file explains a given bean, and the
    knowledge file is exactly what an agent needs to read next.
    """
    beans = load_beans({repo: WORKSPACE / repo / ".beans"})
    extra_ids, extra_prefixes = sibling_ids(repo) if cross else (set(), set())
    g = build_bean_graph(beans, extra_ids, extra_prefixes)
    g.graph["corpus"] = "segment"
    g.graph["segment"] = repo

    docs = load_segment_docs(repo)
    known = {n.lower(): n for n in g.nodes}
    # One stem can exist in more than one kind -- `architecture.md` commonly sits in
    # BOTH .claude/knowledge and the public wiki. A flat {stem: node} map silently
    # lets whichever loaded last win, so every knowledge->knowledge reference to a
    # colliding name gets misrouted to the wiki page. Keep all candidates and
    # resolve per citation instead.
    by_stem: dict[str, list[str]] = defaultdict(list)
    for d in docs:
        by_stem[d["stem"].lower()].append(f"{d['kind']}/{d['stem']}")
    # Path-keyed lookup for backticked path refs, which name a file outright.
    by_path = {d["path"].resolve(): f"{d['kind']}/{d['stem']}" for d in docs}

    for d in docs:
        node = f"{d['kind']}/{d['stem']}"
        g.add_node(node, kind=d["kind"], repo=repo, title=d["stem"],
                   path=str(d["path"]), status="", open=True)

    prefixes = g.graph.get("prefixes", set())
    resolvable = g.graph.get("resolvable", set(known))
    dangling = list(g.graph.get("dangling", []))

    for d in docs:
        node = f"{d['kind']}/{d['stem']}"
        try:
            text = d["path"].read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Line-by-line rather than whole-text, because a doc citing a DEAD id is
        # worth reporting with a location -- "somewhere in this 60KB file" is not
        # actionable. Live ids only need the edge, so they dedupe per doc.
        seen: set[str] = set()
        for lineno, line in enumerate(text.splitlines(), 1):
            for raw in ID_RE.findall(line):                      # doc -> bean
                cand = raw.lower()
                if cand in seen:
                    continue
                seen.add(cand)
                if cand in known:
                    g.add_edge(node, known[cand], kind="cites")
                elif _is_dead_id(cand, resolvable, prefixes):
                    try:
                        loc = f"{d['path'].relative_to(WORKSPACE)}:{lineno}"
                    except ValueError:
                        loc = f"{d['path']}:{lineno}"
                    dangling.append((node, raw, str(loc)))

        # doc -> doc. Two ways of naming a neighbour, deduped to ONE edge per
        # target: a doc that cites `pi.md` as both a markdown link and a
        # backticked path means one relationship, not two.
        # Assumes the segment is a child of the workspace -- a root-as-segment
        # install must substitute its own segment_path(repo). See _resolve_doc_path.
        seg_root = WORKSPACE / repo
        all_refs = (SEE_RE.findall(text) + MDLINK_RE.findall(text)
                    + PATHREF_RE.findall(text))
        targets = [_resolve_ref(ref, by_path, by_stem, d["path"].parent,
                                seg_root, d["kind"])
                   for ref in dict.fromkeys(all_refs)]
        for tgt in dict.fromkeys(t for t in targets if t and t != node):
            g.add_edge(node, tgt, kind="see")

    g.graph["dangling"] = dangling
    return g


def resolve(g: nx.MultiDiGraph, target: str) -> str | None:
    """Accept a bean id, a doc stem, or a kind/stem path -- any casing.

    Returns None and EXPLAINS WHY on both failure paths, so the caller just
    returns. Consolidated here rather than split with the caller because the two
    were contradicting each other: `context_report` printed "no artifact
    matching" for a None that an ambiguity had produced, telling the user the
    opposite of what happened.

    Ambiguity is reported, never guessed. The previous form ended with
    `hits[0] if len(hits) == 1 else (hits[0] if hits else None)` -- both branches
    yield `hits[0]`, a collapsed no-op that LOOKED like it handled ambiguity and
    was functionally `hits[0] if hits else None`. A multi-match silently returned
    the first candidate in `g.nodes` ITERATION ORDER, which is exactly the
    load-order dependency `_resolve_doc_ref` and `KIND_PRIORITY` exist to
    eliminate internally -- except this is the user-facing entry point, where
    guessing is strictly worse because the caller cannot tell it happened. Live
    case at the time of the fix: a segment holding both `knowledge/deployment`
    and `wiki/Deployment`.
    """
    t = target.lower()
    for n in g.nodes:                       # exact id / kind-stem wins outright
        if n.lower() == t:
            return n
    hits = [n for n in g.nodes
            if n.lower().endswith("/" + t) or g.nodes[n].get("title", "").lower() == t]
    if len(hits) == 1:
        return hits[0]
    seg = g.graph.get("segment")
    if not hits:
        print(f"no artifact matching {target!r} in segment {seg}", file=sys.stderr)
    else:
        print(f"{target!r} is ambiguous in segment {seg} -- {len(hits)} matches. "
              f"Re-run with one of:", file=sys.stderr)
        for n in sorted(hits):
            print(f"    {n}", file=sys.stderr)
    return None


# How each relation reads when it lands in a reading list.
RELATION = {
    ("parent", True): "its parent",
    ("parent", False): "child of it",
    ("blocked_by", True): "BLOCKS it (must land first)",
    ("blocked_by", False): "waits on it",
    ("mentions", True): "it references",
    ("mentions", False): "references it",
    ("cites", True): "it documents",
    ("cites", False): "DOCUMENTS it",
    ("see", True): "it points to",
    ("see", False): "points to it",
}


def rot_report(g: nx.MultiDiGraph) -> None:
    """Every id cited in this segment that resolves to nothing.

    The doc half of this is the reason the command exists. A bean naming a dead
    bean is visible the moment you open it; a *knowledge file* naming a dead bean
    is invisible -- the edge simply never forms, and the graph looks fine. That
    is a silent failure, so it needs a report of its own rather than an absence.
    """
    dangling = g.graph.get("dangling", [])
    if not dangling:
        print(f"\nno dangling references in segment "
              f"{g.graph.get('segment')} -- every cited id resolves")
        return

    by_id: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for src, raw, loc in dangling:
        by_id[raw].append((src, loc))

    docs = sum(1 for _, _, loc in dangling if loc)
    print(f"\n{'=' * 78}\nDANGLING REFERENCES in segment {g.graph.get('segment')}"
          f"\n{len(by_id)} dead id(s), {len(dangling)} citation(s)"
          f"  |  {docs} from docs, {len(dangling) - docs} from beans\n{'=' * 78}")

    for raw, sites in sorted(by_id.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"\n  {raw}   ({len(sites)} citation{'s' if len(sites) > 1 else ''})")
        for src, loc in sites:
            kind = g.nodes[src].get("kind", "?") if src in g else "?"
            print(f"      [{kind}] {src}{'   ' + loc if loc else ''}")
    print()


def context_report(g: nx.MultiDiGraph, target: str, hops: int = 1) -> None:
    node = resolve(g, target)
    if node is None:
        return                              # resolve() already explained why

    d = g.nodes[node]
    print(f"\n{'=' * 78}\n{node}  [{d.get('kind')}]"
          f"{'  ' + d['status'] if d.get('status') else ''}\n{d.get('title','')}"
          f"\n{'=' * 78}")

    groups: dict[str, list[tuple[str, str]]] = {}
    for u, v, e in g.out_edges(node, data=True):
        groups.setdefault(RELATION[(e["kind"], True)], []).append((v, e["kind"]))
    for u, v, e in g.in_edges(node, data=True):
        groups.setdefault(RELATION[(e["kind"], False)], []).append((u, e["kind"]))

    if not groups:
        print("\n  (no edges -- this artifact is isolated; nothing cites it and "
              "it cites nothing)")
        return

    # Docs first: for an agent about to work, what explains this matters most.
    order = ["DOCUMENTS it", "BLOCKS it (must land first)", "waits on it",
             "its parent", "child of it", "it references", "references it",
             "it documents", "it points to", "points to it"]
    seen: set[str] = set()
    for label in sorted(groups, key=lambda l: order.index(l) if l in order else 99):
        print(f"\n  {label}:")
        for n, _ in dict.fromkeys(groups[label]):
            nd = g.nodes[n]
            tag = nd.get("status") or nd.get("kind")
            path = nd.get("path")
            loc = f"  <- {Path(path).relative_to(WORKSPACE)}" if path else ""
            print(f"    {n:<34} [{tag}] {clip(nd.get('title',''), 40)}{loc}")
            seen.add(n)

    if hops > 1:
        ring = set()
        for n in seen:
            ring |= set(g.successors(n)) | set(g.predecessors(n))
        ring -= seen | {node}
        if ring:
            print(f"\n  2 hops out ({len(ring)}):")
            for n in sorted(ring)[:12]:
                print(f"    {n:<34} {clip(g.nodes[n].get('title',''), 40)}")
    print()


# -------------------------------------------------------------------- analysis

def subgraph(g: nx.MultiDiGraph, kinds: tuple[str, ...]) -> nx.DiGraph:
    """Collapse the typed multigraph to a simple DiGraph of the given edge kinds."""
    h = nx.DiGraph()
    h.add_nodes_from(g.nodes(data=True))
    for u, v, d in g.edges(data=True):
        if d.get("kind") in kinds:
            h.add_edge(u, v)
    return h


def clip(s: str, width: int) -> str:
    return s if len(s) <= width else s[: width - 1] + "\u2026"


def label(g, n: str, width: int = 58) -> str:
    d = g.nodes[n]
    if g.graph["corpus"] == "notes":
        # For notes the id is an absolute path; the folder is the useful context.
        return clip(f"{d.get('repo', '')}/{d.get('title', n)}", width + 12)
    return f"{n:<12} {clip(d.get('title', ''), width)}"


def report(g: nx.MultiDiGraph, top: int = 10) -> None:
    corpus = g.graph["corpus"]
    kinds = Counter(d["kind"] for _, _, d in g.edges(data=True))
    open_nodes = [n for n, d in g.nodes(data=True) if d.get("open")]

    print(f"\n{'=' * 78}\nCORPUS: {corpus}  |  {g.number_of_nodes()} nodes, "
          f"{g.number_of_edges()} edges  |  open: {len(open_nodes)}\n{'=' * 78}")
    print("edges by kind: " + ", ".join(f"{k}={v}" for k, v in kinds.most_common()))
    repos = Counter(d.get("repo", "?") for _, d in g.nodes(data=True))
    print("nodes by group: " + ", ".join(f"{k}={v}" for k, v in repos.most_common(12)))

    ref = subgraph(g, ("mentions", "links"))
    ref_edges = ref.number_of_edges()

    # 1. Cross-boundary coupling -- the edges no per-repo tracker can hold.
    cross = [(u, v) for u, v in ref.edges()
             if g.nodes[u].get("repo") != g.nodes[v].get("repo")]
    print(f"\n-- CROSS-GROUP REFERENCES ({len(cross)} of {ref_edges}) "
          "-- invisible to any single-repo view")
    pair = Counter((g.nodes[u]["repo"], g.nodes[v]["repo"]) for u, v in cross)
    for (a, b), n in pair.most_common(top):
        print(f"   {a} -> {b}: {n}")
    for u, v in cross[:top]:
        print(f"     {g.nodes[u]['repo']}/{label(g, u)}\n       -> "
              f"{g.nodes[v]['repo']}/{label(g, v)}")

    # 2. Centre of gravity: what everything else leans on.
    if ref_edges:
        pr = nx.pagerank(ref) if ref_edges else {}
        print(f"\n-- HUBS (pagerank over reference edges) --")
        for n, s in sorted(pr.items(), key=lambda kv: -kv[1])[:top]:
            if ref.in_degree(n) == 0:
                continue
            flag = "" if g.nodes[n].get("open") else "  [CLOSED]"
            print(f"   {s:.4f}  in={ref.in_degree(n):<3} {label(g, n)}{flag}")

        # 3. A closed/stale node that live work still points at = a stale anchor.
        stale = [n for n in ref.nodes
                 if not g.nodes[n].get("open")
                 and any(g.nodes[u].get("open") for u in ref.predecessors(n))]
        stale.sort(key=lambda n: -ref.in_degree(n))
        if stale:
            print(f"\n-- STALE ANCHORS ({len(stale)}) -- closed, but open work "
                  "still references them")
            for n in stale[:top]:
                live = [u for u in ref.predecessors(n) if g.nodes[u].get("open")]
                print(f"   in={len(live):<3} {label(g, n)}")
                for u in live[:3]:
                    print(f"          <- {label(g, u)}")

    # 4. Dependency reality: what is actually workable right now.
    if corpus == "beans":
        blocks = subgraph(g, ("blocked_by",))
        cycles = list(nx.simple_cycles(blocks))
        if cycles:
            print(f"\n-- BLOCKING CYCLES ({len(cycles)}) -- deadlocked by construction")
            for c in cycles[:top]:
                print("   " + " -> ".join(c) + f" -> {c[0]}")

        impact: dict[str, int] = {}
        for n in open_nodes:
            # everything that would become unblocked if n landed
            impact[n] = sum(1 for m in nx.ancestors(blocks, n)
                            if g.nodes[m].get("open"))
        ready = [n for n in open_nodes
                 if not any(g.nodes[b].get("open")
                            for b in blocks.successors(n))]
        ranked = sorted(ready, key=lambda n: (-impact[n], n))
        gated = [n for n in open_nodes if n not in set(ready)]
        print(f"\n-- READY NOW: {len(ready)} open, unblocked  |  GATED: {len(gated)}")
        for n in [r for r in ranked if impact[r]][:top]:
            print(f"   unblocks {impact[n]:<3} {g.nodes[n]['repo']:<18} {label(g, n)}")
        if gated:
            print("   -- gated:")
            for n in gated[:top]:
                blockers = [b for b in blocks.successors(n) if g.nodes[b].get("open")]
                print(f"      {label(g, n)}  <- waits on {', '.join(blockers)}")

        # 5. Hierarchy depth: how deep does the parent forest actually go?
        parents = subgraph(g, ("parent",))
        depths = {}
        for n in parents.nodes:
            d, cur, seen = 0, n, set()
            while True:
                nxt = next(iter(parents.successors(cur)), None)
                if nxt is None or nxt in seen:
                    break
                seen.add(nxt); cur = nxt; d += 1
            depths[n] = d
        deepest = sorted(depths.items(), key=lambda kv: -kv[1])[:5]
        hist = Counter(depths.values())
        print("\n-- PARENT FOREST depth histogram: " +
              ", ".join(f"d{k}={v}" for k, v in sorted(hist.items())))
        for n, d in deepest:
            if d:
                print(f"   depth {d}: {label(g, n)}")

    # 6. Clusters: which work actually hangs together, by structure not by folder.
    if ref_edges:
        und = ref.to_undirected()
        und.remove_nodes_from([n for n in list(und) if und.degree(n) == 0])
        if und.number_of_nodes() > 2:
            comms = sorted(nx.community.greedy_modularity_communities(und),
                           key=len, reverse=True)
            print(f"\n-- CLUSTERS ({len(comms)} communities over "
                  f"{und.number_of_nodes()} connected nodes)")
            for i, c in enumerate(comms[:5], 1):
                spread = Counter(g.nodes[n].get("repo") for n in c)
                tag = ("SPANS " + "+".join(spread)) if len(spread) > 1 else next(iter(spread))
                print(f"   #{i} ({len(c)} nodes, {tag})")
                for n in sorted(c, key=lambda n: -ref.degree(n))[:4]:
                    print(f"        {label(g, n)}")

    # 7. Link rot.
    dangling = g.graph.get("dangling", [])
    if dangling:
        print(f"\n-- DANGLING REFERENCES ({len(dangling)}) -- named but not found")
        for src, tgt, loc in dangling[:top]:
            print(f"   {label(g, src)}\n        -> {tgt}{'   ' + loc if loc else ''}")

    isolated = [n for n in g.nodes if g.degree(n) == 0 and g.nodes[n].get("open")]
    print(f"\n-- ISOLATED open nodes: {len(isolated)} "
          "(no parent, no blocker, referenced by nothing, references nothing)")
    for n in isolated[:top]:
        print(f"   {g.nodes[n].get('repo', ''):<18} {label(g, n)}")
    print()


# --------------------------------------------------------------------- outputs

def to_json(g: nx.MultiDiGraph, path: Path) -> None:
    """Cytoscape.js-shaped, the same envelope the Human Skill Tree viewer eats."""
    elements = {
        "nodes": [{"data": {"id": n, **{k: (list(v) if isinstance(v, tuple) else v)
                                        for k, v in d.items()}}}
                  for n, d in g.nodes(data=True)],
        "edges": [{"data": {"source": u, "target": v, "kind": d.get("kind")}}
                  for u, v, d in g.edges(data=True)],
    }
    path.write_text(json.dumps(elements, indent=2), encoding="utf-8")
    print(f"wrote {path}  ({len(elements['nodes'])} nodes, {len(elements['edges'])} edges)")


def to_png(g: nx.MultiDiGraph, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    h = subgraph(g, EDGE_KINDS)
    h.remove_nodes_from([n for n in list(h) if h.degree(n) == 0])
    groups = sorted({d.get("repo", "?") for _, d in h.nodes(data=True)})
    cmap = plt.get_cmap("tab20")
    colors = [cmap(groups.index(h.nodes[n].get("repo", "?")) % 20) for n in h]
    pos = nx.spring_layout(h, seed=7, k=0.35, iterations=60)
    plt.figure(figsize=(20, 14))
    nx.draw_networkx_edges(h, pos, alpha=0.18, width=0.6, arrowsize=5)
    nx.draw_networkx_nodes(h, pos, node_size=[18 + 9 * h.degree(n) for n in h],
                           node_color=colors, linewidths=0)
    hubs = sorted(h, key=lambda n: -h.degree(n))[:30]
    nx.draw_networkx_labels(h, pos, {n: h.nodes[n].get("title", n)[:34] for n in hubs},
                            font_size=7)
    plt.axis("off"); plt.tight_layout(); plt.savefig(path, dpi=130)
    print(f"wrote {path}  ({h.number_of_nodes()} connected nodes)")


# ------------------------------------------------------------------------ main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("beans", help="graph every .beans repo in the workspace")
    b.add_parser = None
    b.add_argument("--repos", nargs="*", help="limit to these repo names")

    n = sub.add_parser("notes", help="graph a folder of linked markdown")
    n.add_argument("--root", action="append", required=True, type=Path)

    c = sub.add_parser("context",
                       help="reading list for one artifact (beans + docs)")
    c.add_argument("target", help="bean id, doc stem, or kind/stem")
    c.add_argument("--hops", type=int, default=1)

    r = sub.add_parser("rot",
                       help="ids cited in this segment that resolve to nothing")
    r.add_argument("--cross", action="store_true",
                   help="also judge ids belonging to sibling segments "
                        "(catches a dead foreign id neither segment can see alone)")

    for p in (c, r):
        p.add_argument("--repo", default=None,
                       help="segment (default: cwd's project)")

    for p in (b, n):
        p.add_argument("--json", type=Path, help="write Cytoscape-shaped JSON")
        p.add_argument("--png", type=Path, help="render a spring-layout PNG")
        p.add_argument("--top", type=int, default=10)

    a = ap.parse_args()

    if a.cmd in ("context", "rot"):
        repo = a.repo
        if repo is None:
            cwd = Path.cwd().resolve()
            for parent in [cwd, *cwd.parents]:
                if parent.parent == WORKSPACE:
                    repo = parent.name
                    break
        if repo is None or not (WORKSPACE / repo / ".beans").is_dir():
            print(f"no bean segment for {repo!r}; pass --repo", file=sys.stderr)
            return 2
        g = build_segment_graph(repo, cross=getattr(a, "cross", False))
        if a.cmd == "rot":
            rot_report(g)
        else:
            context_report(g, a.target, hops=a.hops)
        return 0

    if a.cmd == "beans":
        repos = discover_repos()
        if a.repos:
            missing = set(a.repos) - repos.keys()
            if missing:
                print(f"unknown repo(s): {', '.join(sorted(missing))}\n"
                      f"available: {', '.join(repos)}", file=sys.stderr)
                return 2
            repos = {k: v for k, v in repos.items() if k in a.repos}
        print(f"loading {len(repos)} bean repo(s): {', '.join(repos)}")
        g = build_bean_graph(load_beans(repos))
    else:
        g = build_note_graph([r.resolve() for r in a.root])

    report(g, top=a.top)
    if a.json:
        to_json(g, a.json)
    if a.png:
        to_png(g, a.png)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
