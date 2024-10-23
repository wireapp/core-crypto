# Decode

Decodes and pretty prints various wire formats for the proteus and mls protocols

## Installation

```
cargo install --git https://github.com/wireapp/core-crypto.git[decode]
```

## Examples

### Decode proteus prekey bundle
```
decode prekey-bundle pQABAQoCoQBYIJHnFfQBrfDW+f0MNoaGxi63gLbFMRfqfVGPhiLl5AWYA6EAoQBYIGOJPLc39t4CVMcwil00ri/XSvML7LF3IP2zg+YstiHuBPY=

```
Output:
```
ProteusPreKeyBundle {
    version: 1,
    prekey_id: 10,
    public_key: "91e715f401adf0d6f9fd0c368686c62eb780b6c53117ea7d518f8622e5e40598",
    identity_key: "63893cb737f6de0254c7308a5d34ae2fd74af30becb17720fdb383e62cb621ee",
    signature: None,
}
```
