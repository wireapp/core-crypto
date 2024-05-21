# Wire CoreCrypto

This crate is the core of this whole project. It contains a wrapper on top
of [openmls](https://github.com/openmls/openmls) for all the MLS operations. Most of them use
the [keystore](../keystore) in order to persist the group's state and make each operation atomic.
It only implements the required set of MLS operations required by Wire client applications ; it does not intend to be a
generic purpose MLS library.

This crate's public API could be used as-is by an hypothetical higher-level Rust client. However, since it's not the
case, it is exposed in the [crypto-ffi](../crypto-ffi) crate.

It differs from a general Rust library by adapting to wire-server delivery semantics (at least once) which occasionally
can send messages out-of-order. To do so it buffers messages intended for the next epoch and only merges them when the
right commit for that epoch has arrived. It also handles duplicate messages.

It also has the ability to renew proposals. Renewed proposal happen when the client has a local state (pending proposals
or commit) not yet accepted by the server. When this client tries to have its commit accepted by the server the latter
responds that this commit epoch is already taken. When this happens, the local proposals get recreated for the next
epoch and clients have all the latitude to commit them again in the right epoch.

This whole project does not do any I/O (expect a file I/O for the keystore on non-WASM platforms). It is so in order to
leave all the I/O to the higher-level library, [kalium](https://github.com/wireapp/kalium/).
