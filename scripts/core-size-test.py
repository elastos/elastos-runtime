#!/usr/bin/env python3
"""Line classes of scripts/core-size.py on small sources, and its budget check in throwaway git repos."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("core_size", Path(__file__).with_name("core-size.py"))
core_size = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core_size)

STRINGS_IN_TEST_MOD = '''fn kept() -> char {
    '{'
}

#[cfg(test)]
mod tests {
    #[test]
    fn braces_in_literals() {
        let plain = "}} // not a comment }";
        let raw = r#"}"} } "#;
        let bytes = br"}}";
        let open = '}';
        let lifetime: &'static str = "{";
    }
}
fn after() {}
'''

BLOCK_COMMENTS = '''/* one line */
/*
   } a closing brace inside a comment
   /* nested */ still inside
*/
fn code() {}
'''


def extent(source):
    """(1-based line where the first item of source ends, its kind)."""
    tokens = [t for t in core_size.lex(source)[0] if t[1] != "comment"]
    vals = [t[2] for t in tokens] + [""] * 4
    last, kind, name, body = core_size.item_extent(vals, 0, len(tokens))
    return tokens[last][0] + 1, kind


def counts(source, path="src/lib.rs"):
    return core_size.count({path: source})


class CountTest(unittest.TestCase):
    def test_cfg_test_module_with_braces_in_strings_and_raw_strings(self):
        self.assertEqual(counts(STRINGS_IN_TEST_MOD),
                         {"total": 16, "tests": 11, "comments": 0, "blank": 1, "code": 4})

    def test_cfg_all_test_over_several_lines(self):
        source = "#[cfg(all(\n    test,\n    unix\n))]\nmod tests {\n}\nfn kept() {}\n"
        self.assertEqual(counts(source)["tests"], 6)
        self.assertEqual(counts(source.replace("test,", "feature = \"test\","))["tests"], 0)

    def test_every_cfg_spelling_that_holds_only_in_tests(self):
        for cfg in ("test,", "all(all(test), unix)", "any(test, all(test, unix),)", "not(not(test))",
                    "all(test, not(unix))", "all(\n    unix,\n    test\n)"):
            source = f"#[cfg({cfg})]\nfn test_only() {{}}\nfn production() {{}}\n"
            try:  # refusing a valid spelling is a wrong classification too
                code = counts(source)["code"]
            except core_size.Refusal as error:
                code = f"refused: {error}"
            self.assertEqual(code, 1, cfg)
        for cfg in ("any(test, unix)", "not(test)", "all(unix, feature = \"test\")", "testing",
                    "not(any())", "not(all(not(test), feature = \"off\"))", "all()", "any(not(test), test)"):
            self.assertEqual(counts(f"#[cfg({cfg})]\nfn production() {{}}\n")["code"], 2, cfg)

    def test_unreadable_cfg_is_refused_with_its_line(self):
        for attribute in ("#[cfg(test test)]", "#[cfg_attr(unix, cfg(test))]", "#[cfg(not(test, unix))]"):
            with self.assertRaisesRegex(core_size.Refusal, r"^elastos/crates/elastos-runtime/src/lib.rs:2: "):
                counts(f"fn production() {{}}\n{attribute}\nfn other() {{}}\n")

    def test_test_items_end_where_the_item_ends(self):
        cases = {  # source: (test lines, code lines)
            "#[cfg(test)]\nconst T: usize = if true {\n    1\n} else {\n    2\n};\nfn production() {}\n": (6, 1),
            "#[cfg(test)]\nfn f() -> S<{ 1 }> {\n    S\n}\nfn production() {}\n": (4, 1),
            "#[cfg(test)]\nconst T: usize = { let x = 1; x };\nfn production() {}\n": (2, 1),
            "#[derive(Debug)]\n#[cfg(test)]\nstruct T {\n    a: u8,\n}\nfn production() {}\n": (5, 1),
            "impl S {\n    #[cfg(test)]\n    fn helper() {}\n    fn live() {}\n}\n": (2, 3),
            "#![cfg(test)]\nfn a() {}\nfn b() {}\n": (3, 0),
            "#[cfg(test)]\nmod tests {\n    struct S {\n        #[cfg(test)]\n        a: u8,\n    }\n}\n"
            "fn f() {}\n": (7, 1),
        }
        for source, (tests, code) in cases.items():
            totals = counts(source)
            self.assertEqual((totals["tests"], totals["code"]), (tests, code), source)

    def test_test_fields_and_variants_end_at_their_comma(self):
        cases = {  # the production field or variant after the test one stays code
            "struct S {\n    #[cfg(test)]\n    default: u8,\n    live: u8,\n}\n": (2, 3),
            "struct S {\n    #[cfg(test)]\n    hook: [u8; { 4 }],\n    live: u8,\n}\n": (2, 3),
            "struct S {\n    #[cfg(test)]\n    hook: HashMap<u8, Box<dyn Fn(u8) -> u8>>,\n    live: u8,\n}\n": (2, 3),
            "struct S {\n    live: u8,\n    #[cfg(test)]\n    hook: u8\n}\n": (2, 3),
            "struct S {\n    #[cfg(test)]\n    hook: HashMap<\n        u8,\n        u8,\n    >,\n"
            "    live: u8,\n}\n": (5, 3),
            "enum E {\n    A,\n    #[cfg(test)]\n    B(u8),\n    C { a: Vec<u8> },\n}\n": (2, 4),
        }
        for source, (tests, code) in cases.items():
            totals = counts(source)
            self.assertEqual((totals["tests"], totals["code"]), (tests, code), source)

    def test_production_tokens_on_a_test_line_are_code(self):
        cases = {  # source: (test lines, code lines); same-line inputs, and a string inside a test item
            "#[cfg(test)] fn t() {} pub fn production() {}\n": (0, 1),
            "#[cfg(test)]\nfn t() {\n}  pub fn production() {}\n": (2, 1),
            "struct S {\n    #[cfg(test)] hook: u8, live: u8,\n}\n": (0, 3),
            '#[cfg(test)]\nconst S: &str = "a\nb";\nfn p() {}\n': (3, 1),
            'const S: &str = "a\nb";\n': (0, 2),
        }
        for source, (tests, code) in cases.items():
            totals = counts(source)
            self.assertEqual((totals["tests"], totals["code"]), (tests, code), source)

    def test_test_cfg_on_arms_statements_and_tuple_fields_is_refused(self):
        cases = {  # guessing here hid the production field or arm after it
            "pub fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 if x < 2 => 1,\n"
            "        _ => 2,\n    }\n}\n": 3,
            "fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 => if x > 1 {\n"
            "            1\n        } else {\n            2\n        },\n        _ => 3,\n    }\n}\n": 3,
            "enum E {\n    #[cfg(test)]\n    B = 1 << 2,\n    C,\n}\n": 2,
            "struct S(\n    #[cfg(test)]\n    u8,\n    u16,\n);\n": 2,
            "fn f() {\n    #[cfg(test)]\n    check();\n    live();\n}\n": 2,
        }
        for source, line in cases.items():
            pattern = rf"src/lib.rs:{line}: test (cfg on a|enum variant)"
            with self.assertRaisesRegex(core_size.Refusal, pattern, msg=source):
                counts(source)

    def test_block_comments(self):
        self.assertEqual(counts(BLOCK_COMMENTS),
                         {"total": 6, "tests": 0, "comments": 5, "blank": 0, "code": 1})

    def test_code_line_with_trailing_comment_is_code(self):
        source = "// leading comment\nconst X: u8 = 1; // trailing comment\nconst Y: u8 = 2; /* trailing */\n"
        self.assertEqual(counts(source),
                         {"total": 3, "tests": 0, "comments": 1, "blank": 0, "code": 2})

    def test_code_after_a_leading_block_comment_is_code(self):
        self.assertEqual(counts("/* comment */ fn production() {}\n")["code"], 1)
        self.assertEqual(counts("/*\n*/ fn production() {}\n"),
                         {"total": 2, "tests": 0, "comments": 1, "blank": 0, "code": 1})
        self.assertEqual(counts("static X: u8 = f(\n    0\n);\n")["code"], 3)

    def test_the_module_tree_decides_what_is_test(self):
        tree = {"src/lib.rs": "mod production_test;\n#[cfg(test)]\nmod tests;\n",
                "src/production_test.rs": "pub fn production() {}\n", "src/tests.rs": "fn t() {}\n",
                "tests/integration.rs": "fn i() {}\n"}
        self.assertEqual(core_size.count(tree), {"total": 6, "tests": 4, "comments": 0, "blank": 0, "code": 2})

    def test_production_reach_beats_the_tests_directory(self):
        production = "pub fn production() {}\n"
        tree = {"Cargo.toml": '[lib]\npath = "lib.rs"\n',
                "lib.rs": '#[path = "tests/production.rs"]\npub mod production;\n',
                "tests/production.rs": production, "tests/integration.rs": "fn i() {}\n"}
        self.assertEqual(core_size.count(tree), {"total": 4, "tests": 1, "comments": 0, "blank": 0, "code": 3})
        target = {"Cargo.toml": '[lib]\npath = "tests/production.rs"\n', "tests/production.rs": production}
        self.assertEqual(core_size.count(target)["code"], 1)

    def test_include_pastes_its_file_in_place(self):
        production = "pub fn production() {}\n"
        tree = {"src/lib.rs": '#[cfg(test)]\nmod fixtures;\ninclude!("fixtures.rs");\n', "src/fixtures.rs": production}
        self.assertEqual(core_size.count(tree), {"total": 4, "tests": 2, "comments": 0, "blank": 0, "code": 2})
        tree = {"src/lib.rs": 'include!("production.inc");\n', "src/production.inc": production}
        self.assertEqual(core_size.count(tree)["code"], 2)
        tree = {"src/lib.rs": '#[cfg(test)]\nmod t {\n    include!("helpers.rs");\n}\n', "src/helpers.rs": production}
        self.assertEqual(core_size.count(tree)["tests"], 5)

    def test_raw_identifiers_and_unplain_paths_are_refused(self):
        hidden = "pub fn production() {}\n"
        cases = [  # (message, tree)
            ("src/lib.rs:1: raw identifier r#include",
             {"src/lib.rs": 'r#include!("hidden.inc");\n', "src/hidden.inc": hidden}),
            ("src/lib.rs:4: raw identifier r#hidden",
             {"src/lib.rs": "#[cfg(test)]\nmod hidden;\nfn f() {\n    mod r#hidden;\n}\n", "src/hidden.rs": hidden}),
            ("src/lib.rs:1: raw identifier r#cfg", {"src/lib.rs": "#[r#cfg(test)]\nfn t() {}\n"}),
            (r"src/lib.rs:1: path .*x68idden.inc. is not a plain",
             {"src/lib.rs": 'include!("../tests/\\x68idden.inc");\n', "tests/hidden.inc": hidden,
              "tests/x68idden.inc": ""}),
            (r"src/lib.rs:2: path .*a.*x2eb.rs. is not a plain",
             {"src/lib.rs": '#[path = "a\\x2eb.rs"]\nmod a;\n', "src/a.b.rs": "", "src/ax2eb.rs": ""}),
            (r"src/lib.rs:2: path .*b.*c.rs.* is not a plain", {"src/lib.rs": '#[path = r"b\\c.rs"]\nmod a;\n'}),
            ("src/lib.rs:1: path .*caf\u00e9.rs. is not a plain",
             {"src/lib.rs": 'include!("caf\u00e9.rs");\n', "src/caf\u00e9.rs": ""}),
            ("src/lib.rs:1: path .*/x.rs. is not a plain", {"src/lib.rs": 'include!("/x.rs");\n'}),
        ]
        for message, tree in cases:
            with self.assertRaisesRegex(core_size.Refusal, message, msg=tree["src/lib.rs"]):
                core_size.count(tree)
        self.assertEqual(core_size.count({"src/lib.rs": "struct S {\n    r#type: u8,\n}\n"})["code"], 3)

    def test_inclusions_it_cannot_follow_are_refused(self):
        cases = {  # message: tree
            "src/lib.rs:1: include! of src/production.inc, which is not in":
                {"src/lib.rs": 'include!("production.inc");\n'},
            "src/lib.rs:1: include! of a path that is not one string literal":
                {"src/lib.rs": 'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n'},
            # hidden.rs is also reached through a test module, so the orphan refusal does not catch it.
            "src/lib.rs:5: module declared in a function body": {"src/lib.rs": "#[cfg(test)]\nmod hidden;\nfn f() {\n"
                                                                 '    #[path = "hidden.rs"]\n    mod hidden;\n}\n',
                                                                 "src/hidden.rs": "pub fn production() {}\n"},
            "src/lib.rs:1: #.path. on an inline module": {"src/lib.rs": '#[path = "x"]\nmod m {\n}\n'},
            "src/inc.rs: module declared in an include!d file": {"src/lib.rs": 'include!("inc.rs");\n',
                                                                 "src/inc.rs": "mod x;\n", "src/x.rs": ""},
            "src/value.rs:1: unrecognised item": {"src/lib.rs": 'fn f() -> u32 {\n    include!("value.rs")\n}\n',
                                                  "src/value.rs": "1 + 2\n"},
        }
        for message, tree in cases.items():
            with self.assertRaisesRegex(core_size.Refusal, message):
                core_size.count(tree)

    def test_module_paths_resolve_like_rustc(self):
        tree = {"src/lib.rs": 'mod a;\n#[path = "elsewhere/p.rs"]\nmod p;\n'
                              "#[cfg(test)]\nmod tests {\n    mod helpers;\n}\n",
                "src/a.rs": "mod b;\n", "src/a/b.rs": "fn b() {}\n", "src/elsewhere/p.rs": "mod q;\n",
                "src/elsewhere/q.rs": "fn q() {}\n", "src/tests/helpers.rs": "fn h() {}\n"}
        self.assertEqual(core_size.count(tree), {"total": 12, "tests": 5, "comments": 0, "blank": 0, "code": 7})
        both = {"src/lib.rs": 'mod shared;\n#[cfg(test)]\n#[path = "shared.rs"]\nmod again;\n',
                "src/shared.rs": "fn s() {}\n"}
        self.assertEqual(core_size.count(both)["code"], 2)

    def test_files_the_module_tree_cannot_place_are_refused(self):
        cases = {"src/orphan.rs: the module tree does not reach it": {"src/orphan.rs": "fn o() {}\n"},
                 "src/lib.rs:1: mod gone resolves to 0 files": {"src/lib.rs": "mod gone;\n"},
                 "src/lib.rs:1: mod a resolves to 2 files": {"src/lib.rs": "mod a;\n", "src/a.rs": "",
                                                             "src/a/mod.rs": ""}}
        for message, tree in cases.items():
            with self.assertRaisesRegex(core_size.Refusal, message):
                core_size.count({"src/lib.rs": "mod production;\n", "src/production.rs": "", **tree})


class ItemExtentTest(unittest.TestCase):
    def test_items_end_at_their_own_end(self):
        cases = {
            "const T: usize = if true {\n    1\n} else {\n    2\n};\nfn production() {}\n": (5, "const"),
            "const T: usize = {\n    let x = 1;\n    x\n};\nfn production() {}\n": (4, "const"),
            "fn f() -> S<{ 1 }> {\n    S\n}\nfn production() {}\n": (3, "fn"),
            "impl<const N: usize> X for [u8; N] where S<{ N }>: Sized {\n}\nfn production() {}\n": (2, "impl"),
            'pub(crate) unsafe extern "C" fn f(g: fn() -> u8) -> u8 {\n    g()\n}\nfn production() {}\n': (3, "fn"),
            "struct T(u8);\nfn production() {}\n": (1, "struct"),
            "struct S<A, B> where A: Fn() -> B {\n    a: A,\n}\nfn production() {}\n": (3, "struct"),
            "macro_rules! m {\n    () => {};\n}\nfn production() {}\n": (3, "macro"),
            "thread_local!(static X: u8 = 1);\nfn production() {}\n": (1, "macro"),
            "use a::{\n    b,\n    c,\n};\nfn production() {}\n": (4, "use"),
            'extern "C" {\n    fn g();\n}\nfn production() {}\n': (3, "extern"),
            "mod outline;\nfn production() {}\n": (1, "mod"),
        }
        for source, expected in cases.items():
            self.assertEqual(extent(source), expected, source)

    def test_what_is_not_an_item_is_refused(self):
        for source in ("let x = 1;\n", "x.call();\n", "foo!(x)\nfn production() {}\n", "fn f()\n"):
            with self.assertRaises(core_size.Refusal, msg=source):
                extent(source)


class LexTest(unittest.TestCase):
    def test_braces_inside_literals_are_not_tokens(self):
        source = "let a = \"} {\"; let b = r#\"}\"#; let c = br\"{\"; let d = '}'; let e = b'{';\n"
        punct = [value for line, kind, value in core_size.lex(source)[0] if kind == "punct"]
        self.assertEqual(punct, ["=", ";"] * 5)


class ModuleHelpersTest(unittest.TestCase):
    def test_module_file(self):
        tree = dict.fromkeys(("src/tests/helpers.rs", "src/elsewhere/p.rs", "src/a/b.rs", "src/c/mod.rs"), "")
        path_attr = [token[2] for token in core_size.lex('#[path = "elsewhere/p.rs"]')[0]]
        cases = {("src/lib.rs", True, "helpers", (), ("tests",)): [("src/tests/helpers.rs", False)],
                 ("src/lib.rs", True, "p", tuple(path_attr), ()): [("src/elsewhere/p.rs", True)],
                 ("src/a.rs", False, "b", (), ()): [("src/a/b.rs", False)],
                 ("src/lib.rs", True, "c", (), ()): [("src/c/mod.rs", True)]}
        for (path, owns, name, attrs, inline), expected in cases.items():
            self.assertEqual(core_size.module_file(tree, path, owns, name, list(attrs), inline), expected, name)

    def test_crate_roots(self):
        tree = {"Cargo.toml": '[lib]\npath = "src/core.rs"\n\n[dependencies]\nx = { path = "../x" }\n\n'
                              '[[bin]]\nname = "tool"\npath = "tools/tool.rs"\n',
                "src/core.rs": "", "tools/tool.rs": "", "src/main.rs": "", "src/bin/extra.rs": "", "src/other.rs": ""}
        self.assertEqual(core_size.crate_roots(tree),
                         ["src/bin/extra.rs", "src/core.rs", "src/main.rs", "tools/tool.rs"])
        with self.assertRaises(core_size.Refusal):
            core_size.crate_roots({"Cargo.toml": '[lib]\npath = "src/gone.rs"\n'})

    def test_cargo_targets_are_read_only_in_their_plain_form(self):
        self.assertEqual(core_size.cargo_targets('[package]\nversion.workspace = true\n[lib]\nname = "x"\n'
                                                 'path = "src/lib.rs" # the library\n[[bin]]\npath = "src/t.rs"\n'
                                                 "[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"),
                         ["src/lib.rs", "src/t.rs"])
        cases = [  # (message, manifest)
            ("Cargo.toml:2: target key written as path = 'tests/production.rs'",
             "[lib]\npath = 'tests/production.rs'\n"),
            ('Cargo.toml:2: target key written as "path" = ', '[lib]\n"path" = "tests/production.rs"\n'),
            ("Cargo.toml:1: target defined by a dotted key or inline table",
             'lib = { path = "tests/production.rs" }\n'),
            ("Cargo.toml:2: target defined by a dotted key", '[package]\nlib.path = "tests/production.rs"\n'),
            ("Cargo.toml:1: target table written as \\[ lib \\]", '[ lib ]\npath = "src/lib.rs"\n'),
            ("Cargo.toml:1: target table written as \\[bin\\]", '[bin]\npath = "src/t.rs"\n'),
            ("Cargo.toml:2: target key written as path.workspace", "[lib]\npath.workspace = true\n"),
            ("Cargo.toml:2: path .* is not a plain", '[lib]\npath = "src/../x.rs"\n'),
        ]
        for message, manifest in cases:
            with self.assertRaisesRegex(core_size.Refusal, message, msg=manifest):
                core_size.cargo_targets(manifest)
        with self.assertRaisesRegex(core_size.Refusal, "Cargo.toml:2: target key"):  # the whole count refuses
            core_size.count({"Cargo.toml": "[lib]\npath = 'tests/production.rs'\n", "src/lib.rs": "",
                             "tests/production.rs": "pub fn production() {}\n"})

    def test_commented_target_headers_read_alike_with_and_without_tomllib(self):
        growth = "".join(f"pub fn p{n}() {{}}\n" for n in range(60))
        read = [  # a trailing comment on the header must not drop the target
            ('[[bin]] # tool\nname = "growth"\npath = "tests/growth.rs"\n', "tests/growth.rs"),
            ('[lib] # runtime\npath = "tests/production.rs"\n', "tests/production.rs"),
            ('[lib] # library\npath = "tests/production.rs" # the root\n', "tests/production.rs"),
        ]
        refused = ['[lib] junk\npath = "tests/production.rs"\n', '[lib]]\npath = "tests/production.rs"\n',
                   '"lib"."path" = "tests/production.rs"\n']
        for reader in (core_size.tomllib, None):  # None: no tomllib, as on Python 3.9
            with mock.patch.object(core_size, "tomllib", reader):
                for manifest, path in read:
                    try:
                        totals = core_size.count({"Cargo.toml": manifest, "src/lib.rs": "", path: growth})
                        result = (totals["code"], totals["tests"])
                    except core_size.Refusal as error:
                        result = f"refused: {error}"
                    self.assertEqual(result, (60, 0), (manifest, reader))
                for manifest in refused:
                    with self.assertRaisesRegex(core_size.Refusal, r"Cargo.toml:1: ", msg=(manifest, reader)):
                        core_size.count({"Cargo.toml": manifest, "src/lib.rs": "", "tests/production.rs": growth})

    def test_path_attribute(self):
        for attribute, expected in (('#[path = "a/b.rs"]', "a/b.rs"), ('#[path = r#"c.rs"#]', "c.rs"),
                                    ('#[doc = "x"]', None)):
            values = [token[2] for token in core_size.lex(attribute)[0]]
            self.assertEqual(core_size.path_attribute(values), expected, attribute)


class CheckTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="core-size-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.summary = self.root / "step-summary.md"
        # A caller may set CORE_BUDGET_MODE; each test chooses its own mode.
        self.environment = mock.patch.dict(os.environ, {"CORE_BUDGET_MODE": "enforce",
                                                        "GITHUB_STEP_SUMMARY": str(self.summary)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.git("init", "-q", "-b", "main")
        self.write(10, budget=10)
        self.commit("base")

    def git(self, *args):
        environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        *args], check=True, capture_output=True, env=environment)

    def write(self, lines, budget):
        source = self.root / core_size.CRATE / "src/lib.rs"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("// header\n" + "".join(f"fn f{n}() {{}}\n" for n in range(lines)))
        (self.root / core_size.BUDGET).write_text(f"# budget\n{budget}\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_check(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = core_size.main(["--check", "--root", str(self.root), *extra])
        return status, output.getvalue()

    def test_over_budget_fails_naming_both_numbers(self):
        self.write(12, budget=10)
        status, output = self.run_check()
        self.assertEqual(status, 1)
        self.assertIn("FAIL: core code is 12 lines, above the budget of 10", output)
        self.write(10, budget=10)
        self.assertEqual(self.run_check()[0], 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):  # --report prints the verdict; only --check fails on it
            self.assertEqual(core_size.main(["--report", "--root", str(self.root)]), 0)
        self.write(12, budget=10)
        with contextlib.redirect_stdout(output):
            self.assertEqual(core_size.main(["--report", "--root", str(self.root)]), 0)
        self.assertIn("FAIL: core code is 12 lines", output.getvalue())

    def test_advisory_mode_warns_and_exits_0(self):
        os.environ["CORE_BUDGET_MODE"] = "advisory"
        for lines, budget, verdict in ((12, 10, "FAIL: core code is 12 lines, above the budget of 10"),
                                       (10, 61, "FAIL: core code is 10 lines, 51 below the budget of 61:"
                                                " lower elastos/CORE-BUDGET to 10")):
            self.write(lines, budget)
            status, output = self.run_check()
            self.assertEqual(status, 0)
            self.assertIn(f"::warning title=core-size budget (advisory)::{verdict}", output)
            self.assertIn(f"- Advisory only (CORE_BUDGET_MODE=advisory), not failing: {verdict}",
                          self.summary.read_text())
        self.write(10, budget=10)
        self.assertNotIn("::warning", self.run_check()[1])

    def test_enforce_mode_fails_and_an_unknown_mode_is_refused(self):
        self.write(12, budget=10)
        self.assertEqual(self.run_check()[0], 1)
        self.assertFalse(self.summary.exists())
        for mode in ("advisery", ""):
            os.environ["CORE_BUDGET_MODE"] = mode
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(self.run_check()[0], 2)
                self.assertEqual(core_size.main(["--report", "--root", str(self.root)]), 2)
            self.assertIn(f"CORE_BUDGET_MODE must be enforce or advisory, not {mode!r}", errors.getvalue())

    def test_refusal_exits_2_naming_file_and_line(self):
        source = self.root / core_size.CRATE / "src/lib.rs"
        source.write_text("fn production() {}\n#[cfg_attr(unix, cfg(test))]\nfn other() {}\n")
        for mode in core_size.MODES:  # a counter that cannot read the core is broken, not advisory
            os.environ["CORE_BUDGET_MODE"] = mode
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(self.run_check()[0], 2, mode)
            self.assertIn("refused: elastos/crates/elastos-runtime/src/lib.rs:2: cfg_attr", errors.getvalue())

    def test_ratchet_fails_when_more_than_50_below(self):
        self.write(10, budget=61)
        status, output = self.run_check()
        self.assertEqual(status, 1)
        self.assertIn("FAIL: core code is 10 lines, 51 below the budget of 61: lower elastos/CORE-BUDGET to 10",
                      output)
        self.write(10, budget=60)
        status, output = self.run_check()
        self.assertEqual(status, 0)
        self.assertIn("OK: core code is 10 lines, within the budget of 60", output)

    def test_base_change_reports_code_and_budget(self):
        self.git("checkout", "-q", "-b", "grow")
        self.write(13, budget=13)
        self.commit("grow the core")
        self.git("checkout", "-q", "main")
        self.write(4, budget=10)
        self.commit("main moves on")
        self.git("checkout", "-q", "grow")
        status, output = self.run_check("--base", "main")
        self.assertEqual(status, 0)
        self.assertIn("core code +3 lines (10 -> 13).", output)
        self.assertIn("elastos/CORE-BUDGET: changed 10 -> 13 (+3).", output)
        self.write(13, budget=10)
        status, output = self.run_check("--base", "main")
        self.assertEqual(status, 1)
        self.assertIn("elastos/CORE-BUDGET: unchanged.", output)


if __name__ == "__main__":
    unittest.main()
