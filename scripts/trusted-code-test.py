#!/usr/bin/env python3
"""The per-file rule of scripts/trusted-code.py: #[cfg(test)] modules and statements, comments,
strings that hold //, and test files, each case pinned to its hand-counted number."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trusted_code = load("trusted_code", "trusted-code.py")
core_size = trusted_code.core_size

CFG_TEST_MODULE = """fn kept() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn one() {
        assert_eq!(super::kept(), 1);
    }
}
"""

CFG_TEST_STATEMENT = """fn f() -> u8 {
    #[cfg(test)]
    {
        let x = 1;
        let _ = x;
    }
    2
}
"""

CFG_TEST_STATEMENT_ELSE = """fn f() -> u8 {
    #[cfg(test)]
    if true {
        1
    } else {
        2
    };
    3
}
"""

INCLUDE_NORMAL = """fn f() {
    include!("generated.rs");
}
"""

INCLUDE_FALLBACK = """fn f() {
    #[cfg(test)]
    let one = 1;
    include!("generated.rs");
}
"""

COMMENTS = """/* head
 * two
 */
/// doc
fn f() {}

// tail
/* a /* nested */ b */
"""

URL_IN_STRING = """fn url() -> &'static str {
    "https://example.test/a//b"
}
"""

BLOCK_COMMENT_IN_RAW_STRING = """fn raw() -> &'static str {
    r#"/* not a comment */"#
}
"""


class CountFileTest(unittest.TestCase):
    def test_cfg_test_module_is_test_code(self):
        self.assertEqual(trusted_code.count_file(CFG_TEST_MODULE),
                         {"total": 11, "tests": 7, "comments": 0, "blank": 1, "code": 3})

    def test_cfg_test_statement_is_test_code(self):
        self.assertEqual(trusted_code.count_file(CFG_TEST_STATEMENT),
                         {"total": 8, "tests": 5, "comments": 0, "blank": 0, "code": 3})

    def test_cfg_test_statement_counts_its_else_branch_as_test(self):
        self.assertEqual(trusted_code.count_file(CFG_TEST_STATEMENT_ELSE),
                         {"total": 9, "tests": 6, "comments": 0, "blank": 0, "code": 3})

    def refusal_for(self, source):
        with tempfile.TemporaryDirectory() as folder:
            root, path = Path(folder), "elastos/crates/x/src/a.rs"
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text(source)
            with self.assertRaises(core_size.Refusal) as caught:
                trusted_code.file_rows(root, {"files": [path]})
        return str(caught.exception), path

    def test_include_is_refused_on_the_normal_path(self):
        message, path = self.refusal_for(INCLUDE_NORMAL)
        self.assertIn(f"{path}:2: include! of generated.rs", message)

    def test_include_is_refused_on_the_statement_fallback_path(self):
        message, path = self.refusal_for(INCLUDE_FALLBACK)
        self.assertIn(f"{path}:4: include! of generated.rs", message)

    def test_comments_and_blank_lines_are_not_code(self):
        self.assertEqual(trusted_code.count_file(COMMENTS),
                         {"total": 8, "tests": 0, "comments": 6, "blank": 1, "code": 1})

    def test_slashes_inside_a_string_are_code(self):
        self.assertEqual(trusted_code.count_file(URL_IN_STRING),
                         {"total": 3, "tests": 0, "comments": 0, "blank": 0, "code": 3})

    def test_block_comment_markers_inside_a_raw_string_are_code(self):
        self.assertEqual(trusted_code.count_file(BLOCK_COMMENT_IN_RAW_STRING),
                         {"total": 3, "tests": 0, "comments": 0, "blank": 0, "code": 3})

    def test_the_total_does_not_add_a_listed_core_file_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = ["elastos/crates/elastos-runtime/src/capability/store.rs",
                     "elastos/crates/elastos-server/src/runtime.rs"]
            for path, source in zip(paths, ("fn a() {}\n", "fn b() {\n}\n")):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(source)
            rows = trusted_code.file_rows(root, {"files": paths})
        self.assertEqual(trusted_code.trusted_total(10, rows),
                         {"code": 12, "core_code": 10, "listed_outside_core": 2,
                          "excluded_in_core": [paths[0]]})

    def test_a_listed_file_names_an_unlisted_module_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root, path = Path(folder), "elastos/crates/x/src/auth.rs"
            target = "elastos/crates/x/src/auth/child.rs"
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text("mod child;\n")
            (root / target).parent.mkdir(parents=True)
            (root / target).write_text("fn c() {}\n")
            rows = trusted_code.file_rows(root, {"files": [path]})
        self.assertEqual(rows[0]["module_warnings"],
                         [{"path": path, "line": 1, "mod": "child", "target": target}])

    def test_a_test_file_counts_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root, path = Path(folder), "elastos/crates/x/tests/integration.rs"
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text("fn one() {\n}\n")
            rows = trusted_code.file_rows(root, {"files": [path]})
        self.assertEqual(rows[0]["counts"],
                         {"total": 2, "tests": 2, "comments": 0, "blank": 0, "code": 0})
        self.assertTrue(rows[0]["test_file"])

    def test_the_per_file_rule_agrees_with_the_core_counter(self):
        for source in (CFG_TEST_MODULE, COMMENTS, URL_IN_STRING, BLOCK_COMMENT_IN_RAW_STRING):
            one_file_crate = {"src/lib.rs": source}
            self.assertEqual(trusted_code.count_file(source), core_size.count(one_file_crate), source)


if __name__ == "__main__":
    unittest.main()
