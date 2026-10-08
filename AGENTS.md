# Working on core-crypto as an AI agent

This file is for AI coding agents working in this repository. It summarises the team's AI policy, how we expect agents
to behave, and the conventions that aren't obvious from reading the code. Humans are welcome to read it too.

## The policy, in short

The team agreed on these rules. Everything else in this file serves them.

- AI is allowed in this codebase, but never mandatory, and it shouldn't take the joy out of the work.
- AI-written code is fine for tests, fixtures and test helpers, for experiments and proofs of concept, and for trivial
  changes.
- Main-body library code should be written by a human. AI may assist. The author must fully understand the code.
- Commit messages are written by a human.
- Comments and documentation must read as if a human wrote them. An AI draft is fine as a starting point.
- Commits that were largely or entirely written by AI should carry a `Co-Authored-By` trailer naming the model.
- Whoever authors a commit is responsible for it, whether or not an AI is listed as co-author. Opening a PR declares the
  commits good enough for review.

## How to behave

### Library code: suggest and review by default

For main-body library code (anything outside tests, fixtures, test helpers and experiments), the default is to explain,
suggest and review, not to edit. Point at the problem, propose a change, show a snippet if it helps, and let the human
write it.

If a human explicitly asks you to write library code, do it. It's their decision and their responsibility. Help them
meet the "fully understood" bar: call out anything non-obvious about the change, such as invariants it relies on, error
paths, and transaction behaviour, rather than handing over a diff and moving on.

Tests, fixtures, helpers, experiments and trivial changes don't need this caution.

### Never commit

Don't run `git commit` unless the human explicitly asks for it in that message. Leave the work in the tree and say it's
ready for review. The human reads every diff before it becomes a commit. "Fix this" or "update that" asks for a code
change, not a commit, and permission to commit once doesn't carry over to later work.

Even when asked to commit, don't write the message yourself. Ask the human for it, or leave the commit to them.

Branches are often built up with `fixup!` commits that get autosquashed before merging. Choosing which commit a change
belongs to is part of committing, so leave that to the human too.

### Pause between steps

When working through a multi-step plan, stop after each step and report what changed. The human may want to review and
commit before you continue. Don't chain steps together without a go-ahead.

### Co-author trailers

When a human is about to commit work you largely wrote, remind them to add a `Co-Authored-By` trailer naming the model.
If they do this often, suggest setting up a git trailer alias:

```sh
git config --global trailer.claude.key Co-Authored-By
git config --global trailer.claude.cmd "echo 'Claude Opus 5.5 <noreply@anthropic.com>' #"
```

After that, `git commit --trailer claude` adds the line. The trailing `#` swallows the argument git passes to the
command. Adjust the name to whichever model actually did the work.

### Keep this file current

This file is meant to grow and change over time. Two things should prompt an update:

- The orientation section below drifts as the code changes. You might notice it's wrong: a renamed crate, a moved
  directory, a `make` target that no longer exists.
- You notice a convention that isn't written down here. Either a human keeps applying the same pattern, or they tell you
  to follow it in your work.

Either way, don't edit this file in the middle of unrelated work. Tell the human what you noticed, and suggest a
follow-up PR to update this file once the current work is done. Like any other change, it needs two human approvals
before it's merged.

## Orientation

### Crates

This is a Cargo workspace. The toolchain is pinned in `rust-toolchain.toml`.

| Crate              | What it is                                                                                      |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| `crypto`           | The core library: MLS (via openmls), Proteus, E2EI, the transaction context and crypto provider |
| `crypto-ffi`       | The public FFI surface, defined once with UniFFI, and the platform bindings                     |
| `keystore`         | Encrypted persistent storage on SQLite (SQLCipher natively, a wasm VFS in the browser)          |
| `e2e-identity`     | ACME and OIDC flows for end-to-end identity                                                     |
| `crypto-macros`    | Proc macros used by the other crates                                                            |
| `obfuscate`        | Obfuscates sensitive values in logs                                                             |
| `interop`          | Interop tests between the native library and the platform bindings                              |
| `keystore-dump`    | Dumps a keystore to JSON                                                                        |
| `test-wire-server` | Imitates a Wire server for tests                                                                |

The platform bindings live under `crypto-ffi/bindings/` (Kotlin/JVM/Android, Swift, TypeScript). All of them are
generated from the same UniFFI interface, including the TypeScript ones. Those come from
[UBRN](https://github.com/jhugman/uniffi-bindgen-react-native), which builds a browser package (wasm, via wasm-bindgen)
and a native package (napi). So `crypto-ffi` targets wasm even though it contains almost no wasm-specific code. The
`wasm` and `napi` features and the `cfg(target_arch = "wasm32")` dependencies in `crypto-ffi/Cargo.toml` are where it
shows. Anything exposed through the FFI has to work there too.

The book under `cc-book/` holds the architecture docs (`cc-book/src/development/`) and the migration guide for the next
release (`cc-book/src/unreleased/`). `README.md` covers platform setup in detail.

### Building and testing

- Rust tests: `cargo nextest run`. Add `--features test-all-cipher` to run every ciphersuite. It's slow, so only do this
  when the change is ciphersuite-specific.
- Keystore on wasm: `wasm-pack test --headless --chrome -- ./keystore --locked`. nextest doesn't work with the wasm
  runner.
- Bindings: `make help` lists the targets, e.g. `make jvm-test`, `make ts-test`, `make android-test`. `make ios-test`
  only works on macOS.
- Formatting and lints: `make fmt` and `make check`, or a single language, e.g. `make rust-fmt` or `make rust-check`.
  Markdown goes through `mdformat` with a 120 column wrap, TOML through `taplo`.

Don't run `make all` or the full binding suite unless asked: it takes a long time and needs platform toolchains that may
not be installed.

### Git

- No merge commits. Branches are rebased onto `main`, and PRs are merged with
  [`merge-pr`](https://github.com/wireapp/merge-pr), which keeps history linear *and preserves commit SHAs*. A commit on
  `main` is the same SHA that ran CI on the PR. Don't assume squash or rebase merging.
- Commits follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Commits and tags are signed.

### Commit sequence

A PR's commits should be easy to review. Read in order, they should tell a story where each commit builds on the one
before it.

- Each commit makes one semantic change. Many small commits are better than a few large ones.
- Dependency changes go in their own commit, ideally the first one in the PR.
- When a refactor of an internal API ripples through the codebase, the core refactor is one commit, and updating the
  callers to the new signature is the next.
- Not every commit has to build. Readability for the reviewer comes first.
- Tests come first in the sequence, even if they were written after the code. A test that demonstrates a bug is easy to
  check that way: the reviewer runs it at the commit that added it and sees it fail, then runs it at the tip of the
  branch and sees it pass.
- Rewriting history within a PR to get a clean sequence is normal and encouraged.

You don't commit, so your part is to make this easy for the human. Order the work so it splits naturally: dependency
changes first, tests before the fix, the core refactor before the call-site updates. Treat those boundaries as natural
places to pause. When a diff mixes several changes, say how you'd split it. Don't rewrite history yourself (rebase,
amend, force-push) unless asked.

### Release notes

Any PR that changes something a library consumer can see needs a note under "Unreleased" in
`cc-book/src/release_notes.md`. That includes API changes, behaviour changes, deprecations and packaging changes. The
release notes are a plain list of changes. Write each note for the consumer: what changed, who is affected, and what
they need to do.

The migration guide in `cc-book/src/unreleased/` does a different job. It explains the principles behind a change: why
it happened, and how clients are expected to benefit. A PR that changes how a client thinks about core-crypto needs an
entry there. Most small changes, including deprecations with a mechanical replacement, belong only in the release notes.

## Code conventions

### Rust

- If a trait is imported only so its methods resolve, and the name never appears in the file, import it anonymously:
  `use core_crypto_keystore::traits::FetchFromDatabase as _;`.
- The workspace denies undocumented `unsafe` blocks and missing safety docs. Every `unsafe` block needs a `// SAFETY:`
  comment.

### Doc comments

These rules apply everywhere, and matter most in `crypto-ffi`, because those docs end up in the Kotlin, Swift and
TypeScript API references.

- The first line is a one-sentence summary, followed by a blank line before any further detail.
- Sentences end with punctuation. Labels and descriptors don't: `/// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519`
  needs no period.
- "See `Foo`" on its own is not documentation. Say what the item does.
- Avoid non-trivial markdown and intra-doc links in `crypto-ffi`. They render badly or not at all in the generated
  bindings.
- External URLs use autolinks, `<https://example.com>`, not `[text](https://example.com)`. They stay readable when the
  markdown isn't rendered.
- Write `X509`, not `X.509`.

### Tests

- Test our logic, not our dependencies. A test that only shows SQLite rejecting a `NULL` in a `NOT NULL` column, or
  enforcing a foreign key we declared, adds nothing. Good tests derive the expected value independently and compare it
  with what our code produced.
- Name tests after the property that should hold, and assert that property. This holds even for a test written to
  demonstrate a bug: it should fail now and pass once the bug is fixed. Don't invert the assertion to make it green, and
  don't `#[ignore]` it. Report that it's red and why.
- Write async tests as plain async bodies. Some existing tests wrap their body in `Box::pin(async move { ... }).await`.
  That's a workaround for tests that overflowed the stack, not house style, so don't copy it unless your test overflows.

## Keystore

### Migrations

- SQL migrations live in `keystore/src/connection/migrations/` and are applied by refinery. Whether you can edit one
  depends on whether it has been released:
  - Added on the current branch: edit freely.
  - Already on `main` but not in any release: editing is acceptable, but tell the human first. Only plain `vX.Y.Z` tags
    are releases. Tags with a suffix, such as `v10.0.0-pre.12` or `v10.3.1-test1`, are not: people installing those know
    the risks. To show a migration is unreleased, find the commit that added it with
    `git log --diff-filter=A --format=%H -- <file>`, then check that
    `git tag --contains <sha> 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'` prints nothing. Let the human decide whether
    to edit it or add a new migration. There's no team convention for this yet.
  - Released: don't edit it. Fix forward with a new migration. We have occasionally edited released migrations to fix
    catastrophic bugs, but that's a team decision, not something to propose casually.
- Some tables are rebuilt by later migrations, so the `CREATE TABLE` in any single file can be misleading. To see the
  real end state, use `compile-schema` (<https://github.com/wireapp/compile-schema>):
  `compile-schema keystore/src/connection/migrations`. The migrations register a custom `sha256_blob` function, so the
  plain `sqlite3` CLI can't apply them.
- `keystore/src/connection/composite-schema.sql` is generated. CI fails if it's stale. Regenerate it with
  `compile-schema` after changing migrations. Never edit it by hand, and never add comments to it.
- Much of what the keystore stores is opaque bytes: group state, key packages, key material, serialized credentials and
  so on. Keystore tests, including migration tests, only need to show those bytes survive exactly, so arbitrary bytes
  are fine. Building real values (an `MlsGroup` and matching credential, say) usually needs a crypto provider the
  keystore crate doesn't have. Only do it if it covers a gap no other test covers, and say which gap.
- `keystore/src/connection/idb_migration/legacy/` exists only to move old IndexedDB data into SQLite once. It's in
  minimal-maintenance mode. If a change there works, it ships. Don't propose style or fidelity cleanups.

### Transactions and errors

- There is no in-memory write buffer. Writes, including those from the openmls storage provider, go straight to the
  database inside a live transaction, and cancelling the transaction rolls them back. A half-failed operation can
  therefore leave partial writes behind. If something may already have written part of its state, propagate the error so
  the rollback cleans up. Don't swallow it and let the transaction commit.
- When an error crosses the FFI, it becomes an exception in the client language. By default that cancels the
  transaction, but clients can catch it and keep using the same transaction. So "the failed call's writes are gone" is
  not something we can rely on, for example when deciding whether a retry might find a row already present.
