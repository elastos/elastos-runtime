#!/usr/bin/env python3
"""Count the Runtime core (elastos/crates/elastos-runtime) as tests, comments, blank lines and code.

Test lines: files under the crate's tests/ directory (integration tests), modules declared only
under a test cfg (the module tree is followed from src/lib.rs and the binary roots), and every item
behind a cfg that holds only in tests, from its attributes through its end. Code lines hold
any code token, wherever comments sit on them, or begin inside a multi-line string literal. Comment
lines hold only comments or lie inside a block comment. Blank lines are blank.

  core-size.py                   a short table
  core-size.py --json            {"total", "tests", "comments", "blank", "code"}
  core-size.py --check           fail (exit 1) when code is above elastos/CORE-BUDGET or 50+ below it
  core-size.py --report          print that verdict without failing on it
  --base R                       with either, also show the change since the merge base of R and HEAD
CORE_BUDGET_MODE=advisory turns a failed --check verdict into a ::warning:: annotation and a line in
$GITHUB_STEP_SUMMARY, exiting 0; enforce (the default) exits 1. A construct the counter will not
guess at, a missing base or an unknown CORE_BUDGET_MODE exits 2 in every mode.
"""
import argparse
import bisect
import json
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # before Python 3.11 the strict reader alone decides
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
CRATE, BUDGET = "elastos/crates/elastos-runtime", "elastos/CORE-BUDGET"
SLACK = 50  # the budget may sit at most this far above the code; further, the check fails
MODES = ("enforce", "advisory")  # CORE_BUDGET_MODE: whether a failed budget verdict fails --check
READ_NAMES = {"include", "mod", "cfg", "cfg_attr", "path", "test", "all", "any", "not", "macro_rules"}
TOML_KEY = r"""\s*(?:[A-Za-z0-9_-]+|"[^"\\\n]*"|'[^'\n]*')\s*"""
TOML_TABLE = rf"{TOML_KEY}(?:\.{TOML_KEY})*"  # a table header: bare or quoted keys joined by dots
HEADER = re.compile(rf"(\[\[{TOML_TABLE}\]\]|\[{TOML_TABLE}\])\s*(?:#.*)?")  # an ordinary trailing comment
PLAIN_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")  # no escapes, no ..
OPEN, CLOSE = ("{", "(", "["), ("}", ")", "]")
CHAR = re.compile(r"'(\\(u\{[0-9a-fA-F]*\}|x..|.)|[^\\\n])'")
LIFETIME, WORD, RAW = re.compile(r"'\w*"), re.compile(r"\w+"), re.compile(r'#*"')
STRING, BLOCK = re.compile(r'"(?:\\.|[^"\\])*"?', re.S), re.compile(r"/\*|\*/")


class Refusal(Exception):
    """A construct the counter will not guess at. The check exits 2 and names its file and line."""

    def __init__(self, message, line=None):
        super().__init__(message)
        self.line = line


def lex(text):
    """Return (tokens, starts). tokens are (line, kind, value) for everything outside strings and
    comments, plus one 'literal' or 'comment' token where each begins. starts[n] is 'comment' or
    'string' when line n begins inside one, else None."""
    tokens, starts, i, n = [], [None], 0, len(text)

    def to(j, inside):
        nonlocal i
        starts.extend([inside] * text.count("\n", i, j))
        i = j

    while i < n:
        c, line = text[i], len(starts) - 1
        if c == "\n":
            to(i + 1, None)
        elif text.startswith("//", i):
            tokens.append((line, "comment", "//"))
            to(n if text.find("\n", i) < 0 else text.find("\n", i), None)
        elif text.startswith("/*", i):
            tokens.append((line, "comment", "/*"))
            depth, end = 0, n
            for mark in BLOCK.finditer(text, i):  # block comments nest
                depth += 1 if mark.group() == "/*" else -1
                if depth == 0:
                    end = mark.end()
                    break
            to(end, "comment")
        elif c == '"':
            end = STRING.match(text, i).end()
            tokens.append((line, "literal", text[i:end]))
            to(end, "string")
        elif c == "'":
            end = (CHAR.match(text, i) or LIFETIME.match(text, i)).end()
            tokens.append((line, "literal", text[i:end]))
            i = end
        elif c.isalpha() or c == "_":
            word = WORD.match(text, i).group()
            raw = RAW.match(text, i + len(word))
            if word in ("r", "br", "cr") and raw:
                end = text.find('"' + "#" * (len(raw.group()) - 1), raw.end())
                end = n if end < 0 else end + len(raw.group())
                tokens.append((line, "literal", text[i:end]))
                to(end, "string")
            elif word in ("b", "c") and text[i + 1:i + 2] in ("'", '"'):
                i += 1
            else:
                ident = word == "r" and text[i + 1:i + 2] == "#" and WORD.match(text, i + 2)
                word = "r#" + ident.group() if ident else word
                tokens.append((line, "word", word))
                i += len(word)
        elif c.isdigit():
            tokens.append((line, "literal", WORD.match(text, i).group()))
            i = WORD.match(text, i).end()
        else:
            if not c.isspace():
                tokens.append((line, "punct", c))
            i += 1
    return tokens, starts


def closer(vals, p):
    """Index of the bracket that closes the one at vals[p]."""
    depth = 0
    for q in range(p, len(vals)):
        depth += (vals[q] in OPEN) - (vals[q] in CLOSE)
        if depth == 0:
            return q
    return len(vals) - 1


def predicate(vals, p):
    """Evaluate the cfg predicate at vals[p] with test unset and every other option unknown, in
    three-valued logic: (True, False or None for unknown, next index). False means it can hold only
    in tests: no setting of the other options makes it true without test."""
    word = vals[p]
    if word in ("all", "any", "not") and vals[p + 1] == "(":
        end, q, parts = closer(vals, p + 1), p + 2, []
        while q < end:
            value, q = predicate(vals, q)
            parts.append(value)
            if vals[q] not in (",", ")"):
                raise Refusal(f"cannot read the cfg predicate at {vals[q]!r}")
            q += vals[q] == ","
        if word == "not":
            if len(parts) != 1:
                raise Refusal("not() takes one cfg predicate")
            return (None if parts[0] is None else not parts[0]), end + 1
        decisive = word == "any"  # any() is true once a part is; all() is false once a part is
        if decisive in parts:
            return decisive, end + 1
        return (None if None in parts else not decisive), end + 1
    if vals[p + 1] == "=":
        return None, p + 3
    if not re.fullmatch(r"\w+", word):
        raise Refusal(f"cannot read the cfg predicate at {word!r}")
    return (False if word == "test" else None), p + 1


def attr_is_test(vals, open_, close):
    """Whether the attribute whose [ is vals[open_] is a cfg that holds only in tests."""
    if vals[open_ + 1] == "cfg_attr" and {"cfg", "path"} & set(vals[open_ + 2:close]):
        raise Refusal("cfg_attr that sets cfg or path: the counter will not guess when it applies")
    if vals[open_ + 1] != "cfg" or vals[open_ + 2] != "(":
        return False
    value, q = predicate(vals, open_ + 3)
    q += vals[q] == ","
    if q != close - 1:
        raise Refusal("cfg() takes one predicate")
    return value is False


def item_extent(vals, i, end):
    """(last token, kind, name, (open, close) of its body or None) of the item at vals[i]."""
    p = i
    while True:  # visibility and qualifiers
        if vals[p] == "pub" and vals[p + 1] == "(":
            p = closer(vals, p + 1) + 1
        elif vals[p] in ("pub", "async", "unsafe", "safe", "default", "auto") or (
                vals[p] == "const" and vals[p + 1] in ("fn", "unsafe", "async", "extern")):
            p += 1
        elif vals[p] == "extern" and vals[p + 1] != "crate":
            p += 1 + vals[p + 1].startswith('"')
            if vals[p] == "{":
                return closer(vals, p), "extern", None, (p, closer(vals, p))
        else:
            break
    kind, q = vals[p], p
    if kind in ("use", "static", "const", "type", "extern"):  # these end at their ; (extern crate too)
        while vals[q] != ";" and q < end:
            q = closer(vals, q) + 1 if vals[q] in OPEN else q + 1
        return q, kind, None, None
    while vals[q + 1:q + 3] == [":", ":"]:
        q += 3
    if vals[q + 1] == "!":  # macro_rules! name {...}, path! {...} or path!(...);
        q += 2
        q += vals[q] not in OPEN
        c = closer(vals, q)
        if vals[q] != "{" and vals[c + 1] != ";":
            raise Refusal(f"macro {kind}! without its ;")
        return (c if vals[q] == "{" else c + 1), "macro", None, None
    if kind not in ("fn", "mod", "impl", "trait", "struct", "enum", "union"):
        raise Refusal(f"unrecognised item at {kind!r}")
    q, angle = p + 1, 0
    while q < end:  # the header ends at the body { or the ; outside <...>; const args {..} sit inside
        if vals[q] in OPEN and (vals[q] != "{" or angle):
            q = closer(vals, q)
        elif vals[q] == "{":
            return closer(vals, q), kind, vals[p + 1], (q, closer(vals, q))
        elif vals[q] == ";" and not angle:
            return q, kind, vals[p + 1], None
        elif vals[q] in ("<", ">") and vals[q - 1] != "-":
            angle += 1 if vals[q] == "<" else -1 if angle else 0
        q += 1
    raise Refusal(f"{kind} without a body or ;")


def parse_items(vals, lines, i, end, test, found, inline=()):
    """Walk the items in vals[i:end]: a module, impl, trait or extern body. Test items go to
    found['spans'] as token ranges, every attribute read to found['attrs'], and outline module
    declarations to found['mods']."""
    while vals[i] == "#" and vals[i + 1] == "!":  # inner attributes cover the rest of the body
        close = closer(vals, i + 2)
        found["attrs"].add(i)
        if not test and attr_is_test(vals, i + 2, close):
            found["spans"].append((i, end - 1))
            test = True
        i = close + 1
    while i < end:
        start, item_test = i, test
        try:
            while vals[i] == "#":
                close = closer(vals, i + 1)
                found["attrs"].add(i)
                item_test = item_test or attr_is_test(vals, i + 1, close)
                i = close + 1
            last, kind, name, body = item_extent(vals, i, end)
            if last >= end:
                raise Refusal(f"{kind} item does not end inside its block")
        except Refusal as error:
            error.line = lines[min(start, len(lines) - 1)] if error.line is None else error.line
            raise
        if item_test and not test:
            found["spans"].append((start, last))
        if kind == "mod" and body is None:
            found["mods"].append((name, vals[start:i], lines[i], item_test, inline))
            found["mod_tokens"].add(i + vals[i:last].index("mod"))
        elif kind == "mod" and ["#", "[", "path"] in [vals[k:k + 3] for k in range(start, i)]:
            raise Refusal("#[path] on an inline module: core-size.py does not follow it", lines[start])
        if body and kind in ("struct", "union", "enum") and not item_test:
            parse_fields(vals, lines, body[0], body[1], kind == "enum", found)
        if body and kind in ("mod", "impl", "trait", "extern"):
            parse_items(vals, lines, body[0] + 1, body[1], item_test, found, inline + (name,) * (kind == "mod"))
        i = last + 1


def parse_fields(vals, lines, open_, close, enum, found):
    """Mark test fields of a struct or union body, or test variants of an enum body, vals[open_:close],
    from their attributes through their comma. Field types close <...> before their comma."""
    i = open_ + 1
    while i < close:
        start, test = i, False
        while vals[i] == "#":
            found["attrs"].add(i)
            try:
                test = attr_is_test(vals, i + 1, closer(vals, i + 1)) or test
            except Refusal as error:
                raise Refusal(str(error), lines[i]) from None
            i = closer(vals, i + 1) + 1
        q, angle = i, 0
        while q < close and (vals[q] != "," or angle):
            if vals[q] in OPEN:
                q = closer(vals, q)
            elif not enum and vals[q] in ("<", ">") and vals[q - 1] != "-":
                angle += 1 if vals[q] == "<" else -1 if angle else 0
            elif enum and test and vals[q] == "=":
                raise Refusal("test enum variant with a discriminant: core-size.py will not guess its end",
                              lines[start])
            q += 1
        if test:
            found["spans"].append((start, min(q, close - 1)))
        i = q + 1


def analyse(tokens):
    """(test token indexes, test spans, outline module declarations) of one file's tokens, indexing
    its non-comment tokens. A test cfg anywhere else (a match arm, statement, expression, tuple field
    or parameter) is refused."""
    code = [t for t in tokens if t[1] != "comment"]
    vals, lines = [t[2] for t in code] + [""] * 4, [t[0] for t in code]
    for k in range(len(code)):  # names the counter reads are read in their plain spelling only
        if vals[k].startswith("r#") and (vals[k][2:] in READ_NAMES or vals[k - 1] == "mod"):
            raise Refusal(f"raw identifier {vals[k]}: core-size.py reads only the plain spelling", lines[k])
    found = {"spans": [], "attrs": set(), "mods": [], "mod_tokens": set(), "includes": []}
    parse_items(vals, lines, 0, len(code), False, found)
    for name, attrs, line, mod_test, inline in found["mods"]:
        try:
            path_attribute(attrs)
        except Refusal as error:
            raise Refusal(str(error), line) from None
    tests = {k for a, b in found["spans"] for k in range(a, b + 1)}
    for k in range(len(code)):  # module and source inclusions the item walk did not see are refused
        outline = vals[k] == "mod" and re.fullmatch(r"\w+", vals[k + 1]) and vals[k + 2] == ";"
        if outline and k not in found["mod_tokens"]:
            raise Refusal("module declared in a function body, block or macro: core-size.py does not follow it",
                          lines[k])
        if vals[k] == "include" and vals[k + 1] == "!":
            target = vals[k + 3] if vals[k + 2] in OPEN and closer(vals, k + 2) == k + 4 else ""
            if literal_text(target) is None:
                raise Refusal("include! of a path that is not one string literal", lines[k])
            try:
                found["includes"].append((plain_path(target), lines[k], k in tests))
            except Refusal as error:
                raise Refusal(str(error), lines[k]) from None
    for k in range(len(code)):
        open_ = k + 1 + (vals[k + 1] == "!")
        if vals[k] == "#" and k not in found["attrs"] and k not in tests and vals[open_] == "[":
            try:
                refuse = attr_is_test(vals, open_, closer(vals, open_))
            except Refusal as error:
                raise Refusal(str(error), lines[k]) from None
            if refuse:
                raise Refusal("test cfg on a match arm, statement, expression, tuple field or parameter:"
                              " core-size.py will not guess where it ends", lines[k])
    return tests, found["spans"], found["mods"], found["includes"]


def cargo_targets(text):
    """The [lib] and [[bin]] paths of a Cargo.toml, read only in their plain form: a `[lib]` or
    `[[bin]]` header line with bare keys and `path = "..."` holding a plain path. Any other spelling of
    a target or its keys is refused, and with tomllib so is any disagreement with a full TOML reading."""
    section, paths = "", []
    for number, line in enumerate((line.strip() for line in text.splitlines()), 1):
        def refuse(what):
            raise Refusal(f"{CRATE}/Cargo.toml:{number}: {what}: core-size.py reads only `[lib]` and `[[bin]]`"
                          ' tables with bare keys and a plain `path = "..."`')
        if line.startswith("["):
            header = HEADER.fullmatch(line)
            if not header:  # what follows a header must be readable, or the next table would go unseen
                refuse(f"table header written as {line}")
            section = header.group(1) if header else line
            target = re.sub(r"[\s\"'\[\]]", "", section).split(".")[0] in ("lib", "bin")
            if target and section not in ("[lib]", "[[bin]]"):
                refuse(f"target table written as {section}")
        elif re.match(r"""["']?(lib|bin)["']?\s*[.=]""", line):
            refuse("target defined by a dotted key or inline table")
        elif section in ("[lib]", "[[bin]]") and line and not line.startswith("#"):
            key = re.match(r"([A-Za-z0-9_-]+)\s*=", line)
            plain = re.fullmatch(r'path\s*=\s*("[^"\\]*")\s*(#.*)?', line)
            if not key or (key.group(1) == "path" and not plain):
                refuse(f"target key written as {line}")
            if plain:
                try:
                    paths.append(plain_path(plain.group(1)))
                except Refusal as error:
                    refuse(str(error))
    if tomllib:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise Refusal(f"{CRATE}/Cargo.toml: not TOML: {error}") from None
        targets = [data.get("lib", {})] + list(data.get("bin", []))
        if sorted(target.get("path", "") for target in targets if "path" in target) != sorted(paths):
            raise Refusal(f"{CRATE}/Cargo.toml: target paths that core-size.py cannot read plainly")
    return paths


def crate_roots(tree):
    """The crate's targets: [lib] and [[bin]] paths in Cargo.toml, src/lib.rs, src/main.rs, src/bin/."""
    roots = [posixpath.normpath(path) for path in cargo_targets(tree.get("Cargo.toml", ""))]
    roots += [path for path in tree if re.fullmatch(r"src/(lib|main|bin/[^/]+|bin/[^/]+/main)\.rs", path)]
    if not roots or any(root not in tree for root in roots):
        raise Refusal(f"{CRATE}: no target root, or a Cargo.toml target path that does not exist")
    return sorted(set(roots))


def literal_text(value):
    """The text between the quotes of a plain or raw string literal token, or None for any other token."""
    raw, plain = re.fullmatch(r'r(#*)"(.*)"\1', value, re.S), re.fullmatch(r'"(.*)"', value, re.S)
    return raw.group(2) if raw else plain.group(1) if plain else None


def plain_path(value):
    """The path in a string literal token. Anything but a plain relative ASCII path (letters, digits,
    _ . - and /, no escape, no segment starting with a dot, so no ..) is refused, not decoded."""
    text = literal_text(value)
    if text is None or not PLAIN_PATH.fullmatch(text):  # the character set leaves no room for escapes
        raise Refusal(f"path {value} is not a plain relative ASCII path: core-size.py will not guess the file")
    return text


def path_attribute(attrs):
    """The #[path = "..."] of a module declaration's attributes, or None."""
    for k in range(len(attrs) - 5):
        if attrs[k:k + 4] == ["#", "[", "path", "="] and attrs[k + 5] == "]":
            return plain_path(attrs[k + 4])
    return None


def module_file(tree, path, owns_dir, name, attrs, inline):
    """[(file, whether it owns its directory)] that `mod name;` in path can load; rustc needs one."""
    here = posixpath.dirname(path)
    folder = posixpath.join(here if owns_dir else path[:-3], *inline)
    given = path_attribute(attrs)
    if given is not None:
        options = [posixpath.normpath(posixpath.join(folder if inline else here, given))]
    else:
        options = [f"{folder}/{name}.rs", f"{folder}/{name}/mod.rs"]
    return [(option, given is not None or option.endswith("/mod.rs")) for option in options if option in tree]


def module_tree(tree, parsed):
    """{path: True when only test code reaches it} for every file the module tree and include! reach."""
    reached, queue = {}, [(root, False, True, False) for root in crate_roots(tree)]
    while queue:
        path, test, owns_dir, included = queue.pop()  # owns_dir: lib.rs, main.rs, mod.rs, #[path] files
        if path in reached and (test or not reached[path]):
            continue
        reached[path] = test
        here = posixpath.dirname(path)
        for target, line, include_test in parsed(path)[5]:  # include! pastes the file in place
            where, target = f"{CRATE}/{path}:{line + 1}", posixpath.normpath(posixpath.join(here, target))
            if target not in tree:
                raise Refusal(f"{where}: include! of {target}, which is not in the crate")
            queue.append((target, test or include_test, owns_dir, True))
        if included and parsed(path)[4]:
            raise Refusal(f"{CRATE}/{path}: module declared in an include!d file: core-size.py does not follow it")
        for name, attrs, line, mod_test, inline in parsed(path)[4]:
            options = module_file(tree, path, owns_dir, name, attrs, inline)
            if len(options) != 1:
                raise Refusal(f"{CRATE}/{path}:{line + 1}: mod {name} resolves to {len(options)} files")
            queue.append((options[0][0], test or mod_test, options[0][1], False))
    return reached


def count(tree):
    """tree: {path inside the crate: text} for its files. Counts its .rs files and every file the module
    tree or include! reaches. Returns the line totals."""
    analysed = {}

    def parsed(path):
        if path not in analysed:
            tokens, starts = lex(tree[path])
            try:
                analysed[path] = (tokens, starts) + analyse(tokens)
            except Refusal as error:
                where = f"{CRATE}/{path}" + ("" if error.line is None else f":{error.line + 1}")
                raise Refusal(f"{where}: {error}") from None
        return analysed[path]

    reached = module_tree(tree, parsed)
    totals = dict.fromkeys(("total", "tests", "comments", "blank", "code"), 0)
    for path in sorted({path for path in tree if path.endswith(".rs")} | set(reached)):
        lines = tree[path].split("\n")
        if lines[-1] == "":
            lines.pop()
        totals["total"] += len(lines)
        # The tree decides: a reached file is production unless only test code reaches it, wherever it
        # sits. Files under tests/ that it does not reach are the crate's integration tests.
        if reached.get(path) or (path not in reached and path.startswith("tests/")):
            totals["tests"] += len(lines)
            continue
        if path not in reached:
            raise Refusal(f"{CRATE}/{path}: the module tree does not reach it; core-size.py will not guess"
                          " whether it is compiled")
        tokens, starts, tests, spans, mods, includes = parsed(path)
        code = [token for token in tokens if token[1] != "comment"]
        firsts = [token[0] for token in code]
        # A line with any production token on it is code, wherever its comments or test items sit.
        live = {code[k][0] for k in range(len(code)) if k not in tests}
        dead = {code[k][0] for k in tests} | {n for a, b in spans for n in range(code[a][0], code[b][0] + 1)}
        notes = {line for line, kind, value in tokens if kind == "comment"}
        for n in range(len(lines)):
            if starts[n] == "string":  # the line continues the literal that is the last token before it
                (live if bisect.bisect_left(firsts, n) - 1 not in tests else dead).add(n)
            kind = ("code" if n in live else "tests" if n in dead else
                    "comments" if n in notes or starts[n] == "comment" else "blank")
            totals[kind] += 1
    return totals


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          encoding="utf-8", errors="replace").stdout


def worktree_files(root):
    listed = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", CRATE)
    return {path[len(CRATE) + 1:]: (root / path).read_text(encoding="utf-8", errors="replace")
            for path in set(filter(None, listed.split("\0"))) if (root / path).is_file()}


def ref_files(root, ref):
    listed = git(root, "ls-tree", "-r", "-z", "--name-only", ref, "--", CRATE)
    return {path[len(CRATE) + 1:]: git(root, "show", f"{ref}:{path}")
            for path in filter(None, listed.split("\0"))}


def read_budget(text):
    values = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(values) != 1 or not values[0].isdigit():
        raise Refusal(f"{BUDGET} must hold exactly one integer line besides # comments")
    return int(values[0])


def table(totals):
    rows = "".join(f"| {key} | {value} |\n" for key, value in totals.items())
    return f"| {CRATE} | lines |\n|---|---:|\n{rows}"


def check(root, totals, base):
    """Print the verdict against the budget and, with base, the change since base. Return the exit
    status and the failing verdict, or None when the core is within its budget."""
    code, budget = totals["code"], read_budget((root / BUDGET).read_text())
    notes = []
    if base:
        try:
            point = git(root, "merge-base", base, "HEAD").strip()
        except subprocess.CalledProcessError as error:
            raise Refusal(f"no merge base of {base} and HEAD (fetch the base with history): {error.stderr.strip()}")
        before = count(ref_files(root, point))["code"]
        try:
            old = read_budget(git(root, "show", f"{point}:{BUDGET}"))
        except subprocess.CalledProcessError:
            old = None
        notes.append(f"Change against {base} (merge base {point[:8]}): core code {code - before:+d} lines"
                     f" ({before} -> {code}).")
        notes.append(f"{BUDGET}: " + ("absent at the base" if old is None else "unchanged" if old == budget
                                      else f"changed {old} -> {budget} ({budget - old:+d})") + ".")
    failed = code > budget or budget - code > SLACK
    if code > budget:
        notes.append(f"FAIL: core code is {code} lines, above the budget of {budget} in {BUDGET}. Move code out"
                     f" of the core, or raise {BUDGET} in this change so reviewers see it.")
    elif budget - code > SLACK:  # a ratchet: room freed in the core cannot be spent again
        notes.append(f"FAIL: core code is {code} lines, {budget - code} below the budget of {budget}:"
                     f" lower {BUDGET} to {code} in this change.")
    else:
        notes.append(f"OK: core code is {code} lines, within the budget of {budget} in {BUDGET}.")
    print("".join(f"\n- {note}" for note in notes))
    return (1, notes[-1]) if failed else (0, None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print the totals as JSON")
    parser.add_argument("--check", action="store_true", help=f"fail when code is above {BUDGET}")
    parser.add_argument("--report", action="store_true", help="print the --check verdict without failing on it")
    parser.add_argument("--base", metavar="REF", help="with --check or --report, show the change since this ref")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.base and not (args.check or args.report):
        parser.error("--base needs --check or --report")
    try:
        mode = os.environ.get("CORE_BUDGET_MODE", "enforce")
        if mode not in MODES:
            raise Refusal(f"CORE_BUDGET_MODE must be enforce or advisory, not {mode!r}")
        totals = count(worktree_files(args.root))
        print(json.dumps(totals) if args.json else table(totals), end="\n" if args.json else "")
        status, verdict = check(args.root, totals, args.base) if args.check or args.report else (0, None)
        if args.check and verdict and mode == "advisory":  # warn, do not fail, until the budget enforces
            print(f"::warning title=core-size budget (advisory)::{verdict}")
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
                    summary.write(f"\n- Advisory only (CORE_BUDGET_MODE=advisory), not failing: {verdict}\n")
            return 0
        return status if args.check else 0
    except Refusal as error:
        print(f"core-size: refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
