# The CoreCrypto Book

This folder contains the source of the CoreCrypto Book.
This book contains both an overview of core CoreCrypto concepts, and detailed migration guides for certain major migrations.

## Building the Book

### Prerequisites

- Install the node modules

    ```sh
    pushd cc-book
    bun install
    popd
    ```

- [Install Ruby](https://www.ruby-lang.org/en/documentation/installation/)

- Install bundler

    ```sh
    pushd cc-book
    bundler_version="$(grep -A1 'BUNDLED WITH' Gemfile.lock | tail -n1)"
    sudo gem install bundler -v "$bundler_version"
    popd
    ```

- Install Ruby deps

    ```sh
    pushd cc-book
    bundle config set --local frozen true
    bundle config set --local path .bundle
    bundle install
    popd
    ```

### The Build

```sh
make cc-book
```
