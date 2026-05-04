# The CoreCrypto Book

This folder contains the source of the CoreCrypto Book, built with [mdBook](https://rust-lang.github.io/mdBook/).
The book covers core CoreCrypto concepts and migration guides for major releases.

## Prerequisites

- **mdBook** — install a released binary from the [mdBook releases page](https://github.com/rust-lang/mdBook/releases),
  or via Cargo from crates.io:

  ```sh
  cargo install mdbook --locked
  ```

- **mdbook-langtabs** — install a released binary from the [mdbook-langtabs releases page](https://github.com/nx10/mdbook-langtabs/releases),
  or via Cargo from a tagged release:

  ```sh
  cargo install --git https://github.com/nx10/mdbook-langtabs --tag v0.2.0 --locked
  ```

## Building

From the repository root:

```sh
mdbook build cc-book
```

Or equivalently via Make:

```sh
make cc-book
```

## Serving Locally

mdBook has a built-in development server that watches for changes and live-reloads:

```sh
mdbook serve cc-book --open
```
