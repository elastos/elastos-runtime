# Trusted code: what the count includes

`elastos/trusted-code.json` lists the code the Runtime trusts: the ElastOS-written files that decide
who may do what, the in-process libraries from `elastos/Cargo.lock`, and the host programs of the
signed component set in `components.json`. `scripts/trusted-code.py` prints their numbers as text and
as JSON.

## The count rule

The unit is one line of a listed Rust file. A line is one of four kinds:

- **Code line**: holds at least one Rust token that is not a comment token. A line inside a
  multi-line string literal is code.
- **Blank line**: holds no token.
- **Comment line**: holds only comments, or lies inside a block or doc comment.
- **Test line**: belongs to an item under a test cfg, from the attribute through the item's end;
  belongs to a `#[cfg(test)]` statement, from the attribute through the statement's `;` when it has
  one, else through the closing brace of its final block, or through a comma at bracket depth 0; an
  `else` or `else if` branch belongs to the same span; or belongs to a whole test file, whose path
  has a `tests/` directory. The predicate is `core-size.py`'s: a cfg that cannot hold without `test`
  is a test cfg, so `#[cfg(all(test, unix))]` counts as test. A cfg that can hold without `test`
  counts as code, such as `#[cfg(any(test, feature = "x"))]`.

The count of a file is its code lines. Test, comment and blank lines are excluded. Generated code is
excluded: a listed file that uses `include!` is refused on every path, and the refusal names the file
and line, so generated text cannot enter the count unnoticed. Each file is counted on its own; a
`mod name;` target is not followed, so the list must name every file that makes a decision. The
counter prints a warning for each non-test `mod name;` in a listed file whose target is not listed.

The number moves without a change in behaviour: splits or joins of lines, moving code under a test
cfg, and any untracked file in the worktree all change it.

The third-party entries use the same manifest. A library is an exact `Cargo.lock` package name or a
prefix such as `cranelift-`. For each entry the JSON records the exact package names and versions it
found, and the run prints lock packages in an exact entry's family that the entry does not cover
(`wasmtime-environ` beside `wasmtime`, for example). Crates outside the manifest's families are not
checked: the manifest is the maintainer's agreed list, and the counter does not claim to cover the
rest of the lock. A host program is a `components.json` external key; every external entry the
manifest does not list is printed as unlisted, whatever its kind. The counter reads the versions
from those files and never records a version of its own.

The core crate's number comes from `scripts/core-size.py`'s own `count()`, so the two reports cannot
disagree. The trusted-code total adds the core crate and the listed files outside it. A listed file
inside the core crate is printed as left out of that sum, because the core count already holds it.

## Worked examples

**A small file, counted by hand.** Eleven lines:

```rust
fn kept() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn one() {
        assert_eq!(super::kept(), 1);
    }
}
```

Lines 1 to 3 hold code, line 4 is blank, and lines 5 to 11 are the `#[cfg(test)]` module. By hand:
3 code, 7 test, 1 blank. The script prints `{"total": 11, "tests": 7, "comments": 0, "blank": 1,
"code": 3}`.

**`elastos/crates/elastos-runtime/src/capability/store.rs`, counted by hand.** The file has 341 lines.
58 lines hold only comments, 33 are blank, and lines 256 to 341 are the `#[cfg(test)] mod tests`
block, 86 lines. The remaining 164 lines hold code. The script prints `code 164, total 341, tests 86,
comments 58, blank 33`, which matches the hand count.
