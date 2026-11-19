#!/usr/bin/env python3
"""Measure the code the Runtime trusts: the core crate's code lines and each file of the trusted-code
list, counted by scripts/core-size.py's own counter and lexer under one rule (docs/TRUSTED-CODE.md).

  trusted-code.py            a text report
  trusted-code.py --json     the same numbers as JSON, for the gate that follows
The core number is core-size.py's count() of elastos/crates/elastos-runtime, so the two cannot disagree.
"""
import argparse
import bisect
import importlib.util
import json
import re
import sys
from pathlib import Path
from posixpath import normpath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "elastos/trusted-code.json"
LOCK, COMPONENTS = "elastos/Cargo.lock", "components.json"
KINDS = ("total", "tests", "comments", "blank", "code")

_spec = importlib.util.spec_from_file_location("core_size", Path(__file__).with_name("core-size.py"))
core_size = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core_size)


def statement_end(vals, q):
    """Last token of the cfg(test) statement or block that starts at vals[q]: its ; or comma at depth
    0, the brace that closes its final block at depth 0, or the token before the enclosing block ends.
    An else branch or else-if chain belongs to the same statement."""
    depth = 0
    p = q
    while p < len(vals):
        if vals[p] in core_size.OPEN:
            depth += 1
        elif vals[p] in core_size.CLOSE:
            if depth == 0:
                return p - 1
            depth -= 1
            if depth == 0 and vals[p] == "}" and vals[p + 1] != "else":
                return p + 1 if vals[p + 1] == ";" else p
        elif vals[p] in (";", ",") and depth == 0:
            return p
        p += 1
    return len(vals) - 1


def analyse(tokens):
    """(test token indexes, test spans, outline module declarations) as core-size.py's analyse gives
    them; where it refuses a #[cfg(test)] on a statement, that statement's own span from the attribute.
    A file that uses include! is refused on both paths: a counted file holds only its own text. The
    span stops at the statement's ;, a comma at bracket depth 0, or its final closing brace, so a line
    the counter cannot place stays code, never test."""
    try:
        tests, spans, mods, includes = core_size.analyse(tokens)
    except core_size.Refusal as error:
        if "test cfg on a match arm" not in str(error):
            raise
        code = [token for token in tokens if token[1] != "comment"]
        vals, lines = [token[2] for token in code] + [""] * 4, [token[0] for token in code]
        found = {"spans": [], "attrs": set(), "mods": [], "mod_tokens": set(), "includes": []}
        core_size.parse_items(vals, lines, 0, len(code), False, found)
        for k in range(len(code)):  # attributes the item walk did not consume sit on a statement
            if vals[k] == "#" and k not in found["attrs"] and vals[k + 1] == "[":
                if core_size.attr_is_test(vals, k + 1, core_size.closer(vals, k + 1)):
                    found["spans"].append((k, statement_end(vals, core_size.closer(vals, k + 1) + 1)))
            if vals[k] == "include" and vals[k + 1] == "!":
                found["includes"].append((core_size.literal_text(vals[k + 3]) or "another file", lines[k]))
        tests = {k for a, b in found["spans"] for k in range(a, b + 1)}
        spans, mods, includes = found["spans"], found["mods"], found["includes"]
    if includes:
        target, line = includes[0][:2]
        raise core_size.Refusal(f"include! of {target}: a counted file holds only its own text", line)
    return tests, spans, mods


def count_file(text, mods=None):
    """The line totals of one .rs file in core-size.py's classes: its count() per-file loop without
    the module tree, over its lexer and analyser. Outline module declarations go to mods when given."""
    tokens, starts = core_size.lex(text)
    tests, spans, found_mods = analyse(tokens)
    if mods is not None:
        mods.extend(found_mods)
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    code = [token for token in tokens if token[1] != "comment"]
    firsts = [token[0] for token in code]
    live = {code[k][0] for k in range(len(code)) if k not in tests}
    dead = {code[k][0] for k in tests} | {n for a, b in spans for n in range(code[a][0], code[b][0] + 1)}
    notes = {line for line, kind, value in tokens if kind == "comment"}
    totals = dict.fromkeys(KINDS, 0)
    for n in range(len(lines)):
        totals["total"] += 1
        if starts[n] == "string":
            (live if bisect.bisect_left(firsts, n) - 1 not in tests else dead).add(n)
        kind = ("code" if n in live else "tests" if n in dead else
                "comments" if n in notes or starts[n] == "comment" else "blank")
        totals[kind] += 1
    return totals


def test_file_totals(text):
    """A test file: every line is test code, so its count is zero."""
    lines = text.split("\n")
    return {"total": len(lines) - (lines[-1] == ""), "tests": len(lines) - (lines[-1] == ""),
            "comments": 0, "blank": 0, "code": 0}


def module_warnings(root, path, mods, listed):
    """Warnings for a listed file that declares a non-test `mod name;` whose file the manifest does not
    list: the count does not follow module targets, so that file's code stays out of the count."""
    here = path.rpartition("/")[0]
    owns = path.endswith("/mod.rs") or path.rpartition("/")[2] in ("lib.rs", "main.rs")
    folder = here if owns else path[:-3]
    warnings = []
    for name, attrs, line, mod_test, inline in mods:
        if mod_test:
            continue
        base = "/".join((folder,) + inline) if inline else folder
        given = core_size.path_attribute(attrs)
        targets = ([normpath(f"{base if inline else here}/{given}")] if given
                   else [f"{base}/{name}.rs", f"{base}/{name}/mod.rs"])
        found = [target for target in targets if (root / target).is_file()]
        if found and not listed.intersection(found):
            warnings.append({"path": path, "line": line + 1, "mod": name, "target": found[0]})
    return warnings


def file_rows(root, manifest):
    """One row per listed file: its path, its line totals, and why it has none."""
    rows, listed = [], set(manifest["files"])
    for path in manifest["files"]:
        row = {"path": path, "counts": dict.fromkeys(KINDS, 0),
               "in_core": path.startswith(core_size.CRATE + "/")}
        if not path.endswith(".rs"):
            row["error"] = "not a Rust file"
        elif not (root / path).is_file():
            row["error"] = "listed but absent"
        elif "tests" in normpath(path).split("/"):
            row["test_file"] = True
            row["counts"] = test_file_totals((root / path).read_text(encoding="utf-8"))
        else:
            mods = []
            try:
                row["counts"] = count_file((root / path).read_text(encoding="utf-8"), mods)
            except core_size.Refusal as error:
                where = path + ("" if error.line is None else f":{error.line + 1}")
                raise core_size.Refusal(f"{where}: {error}") from None
            row["module_warnings"] = module_warnings(root, path, mods, listed)
        rows.append(row)
    return rows


def lock_packages(text):
    """(name, version) of every [[package]] in a Cargo.lock, read without tomllib."""
    packages = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"$', block, re.M)
        version = re.search(r'^version = "([^"]+)"$', block, re.M)
        if name and version:
            packages.append((name.group(1), version.group(1)))
    return packages


def library_rows(manifest, packages):
    """One row per manifest library: an exact name or a prefix family, with the versions found and
    the version the issue records, when it gives one."""
    rows = []
    for entry in manifest["libraries"]:
        if "name" in entry:
            versions = sorted({version for name, version in packages if name == entry["name"]})
            row = {"entry": entry["name"], "packages": {entry["name"]: versions}, "found": bool(versions)}
            family = {}
            for name, version in packages:
                if name.startswith(entry["name"] + "-"):
                    family.setdefault(name, set()).add(version)
            row["family_not_covered"] = {name: sorted(family[name]) for name in sorted(family)}
        else:
            members = {}
            for name, version in packages:
                if name.startswith(entry["prefix"]):
                    members.setdefault(name, set()).add(version)
            row = {"entry": entry["prefix"] + "*", "found": bool(members),
                   "packages": {name: sorted(members[name]) for name in sorted(members)},
                   "family_not_covered": {}}
        if "issue_version" in entry:
            row["issue_version"] = entry["issue_version"]
            row["version_matches"] = row["found"] and row["packages"][entry["name"]] == [entry["issue_version"]]
        rows.append(row)
    return rows


def program_rows(manifest, external):
    """One row per manifest host program from components.json's external set, and every external entry
    the manifest does not list, whatever its kind."""
    rows = []
    for name in manifest["host_programs"]:
        component = external.get(name)
        row = {"name": name, "present": component is not None}
        if component is not None:
            row["install_path"] = component.get("install_path")
            row["platforms"] = sorted(component.get("platforms", {}))
            row["kind"] = ("native-provider" if (component.get("provider_runtime") or {}).get("substrate") == "native"
                           else "native-host" if name == "shell" else "other")
        rows.append(row)
    return rows, sorted(set(external) - set(manifest["host_programs"]))


def trusted_total(core_code, rows):
    """The code the tree trusts: the core crate plus each listed file outside it. A listed file inside
    the core crate is already in core_code, so it is named as excluded, not added again."""
    excluded = [row["path"] for row in rows if row.get("in_core")]
    outside = sum(row["counts"]["code"] for row in rows if not row.get("in_core"))
    return {"code": core_code + outside, "core_code": core_code,
            "listed_outside_core": outside, "excluded_in_core": excluded}


def measure(root, manifest):
    totals = core_size.count(core_size.worktree_files(root))
    files = file_rows(root, manifest)
    programs, unlisted = program_rows(manifest, json.loads((root / COMPONENTS).read_text(encoding="utf-8"))["external"])
    return {
        "root": str(root),
        "core": {"crate": core_size.CRATE, "code": totals["code"], "counts": totals,
                 "counter": "scripts/core-size.py:count"},
        "files": files,
        "trusted_code_total": trusted_total(totals["code"], files),
        "absent_candidates": manifest.get("absent_candidates", []),
        "libraries": library_rows(manifest, lock_packages((root / LOCK).read_text(encoding="utf-8"))),
        "host_programs": programs,
        "unlisted_programs": unlisted,
    }


def text(report):
    core, out = report["core"], []
    out.append(f"core crate {core['crate']}: {core['code']} code lines"
               f" ({core['counts']['tests']} tests, {core['counts']['comments']} comments,"
               f" {core['counts']['blank']} blank; {core['counter']})")
    out.append(f"allow-listed files ({len(report['files'])}; code lines under docs/TRUSTED-CODE.md):")
    out.append("file | code | total | tests | comments | blank | note")
    out.append("--- | ---: | ---: | ---: | ---: | ---: | ---")
    for row in report["files"]:
        counts = row["counts"]
        note = row.get("error") or ("test file" if row.get("test_file") else "")
        out.append(f"{row['path']} | {counts['code']} | {counts['total']} | {counts['tests']} |"
                   f" {counts['comments']} | {counts['blank']} | {note}")
    out.append(f"allow-listed code total: {sum(row['counts']['code'] for row in report['files'])} lines")
    total = report["trusted_code_total"]
    out.append(f"trusted-code total: {total['code']} code lines = core crate {total['core_code']} +"
               f" listed files outside the core {total['listed_outside_core']}")
    out.append("left out of that sum, already counted in the core crate: " +
               (", ".join(total["excluded_in_core"]) or "none"))
    out.append("module targets not followed (declared by a listed file, not listed):")
    warnings = [warning for row in report["files"] for warning in row.get("module_warnings", [])]
    for warning in warnings:
        out.append(f"{warning['path']}:{warning['line']}: mod {warning['mod']};"
                   f" {warning['target']} is not listed")
    if not warnings:
        out.append("none")
    out.append("")
    out.append("trusted libraries (elastos/Cargo.lock):")
    out.append("entry | packages and versions | issue version")
    out.append("--- | --- | ---")
    for row in report["libraries"]:
        versions = ", ".join(f"{name} {', '.join(found)}" for name, found in row["packages"].items()) or "missing"
        out.append(f"{row['entry']} | {versions} | {row.get('issue_version', '')}")
    out.append("lock packages in a listed entry's family that the entry does not cover:")
    gaps = [(row["entry"], name, versions)
            for row in report["libraries"] for name, versions in row["family_not_covered"].items()]
    for entry, name, versions in gaps:
        out.append(f"{entry} family: {name} {', '.join(versions)} not covered")
    if not gaps:
        out.append("none")
    out.append("")
    out.append("host programs (components.json external):")
    out.append("name | install path | platforms | kind | present")
    out.append("--- | --- | --- | --- | ---:")
    for row in report["host_programs"]:
        out.append(f"{row['name']} | {row.get('install_path') or ''} |"
                   f" {', '.join(row.get('platforms', []))} | {row.get('kind', '')} | {row['present']}")
    out.append("unlisted host programs: " + (", ".join(report["unlisted_programs"]) or "none"))
    out.append("issue candidates absent from this tree: " + (", ".join(report["absent_candidates"]) or "none"))
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    manifest_path = args.manifest or args.root / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = measure(args.root, manifest)
    except (OSError, ValueError, core_size.Refusal) as error:
        print(f"trusted-code: refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else text(report))
    missing = (any("error" in row for row in report["files"])
               or not all(row["found"] for row in report["libraries"])
               or not all(row["present"] for row in report["host_programs"]))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
