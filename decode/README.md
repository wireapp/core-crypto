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

### Decode MLS message

```
decode mls-message AAEAATQAAQAA0T+Dx7aERkqm8jl1oWIAQgpjb25mZXJlbmNlAAAAAHN0YWdpbmcuemluZnJhLmlvAAAAAAAAAEMCAAAAAAACAAMAAAAHQEgwRgIhAOrk4aL0X6mJwCJWyNzKHIr5qXt05gx5FyP4rmcgviyYAiEAmUwSh7zTqTJAifMn/UnAVNjZKR19DukHS6iVkIP64Oo=
```
Output:
```
MlsMessageIn {
    version: Mls10,
    body: PublicMessage(
        PublicMessageIn {
            content: FramedContentIn {
                group_id: GroupId {
                    value: VLBytes { 0x00010000d13f83c7b684464aa6f23975a16200420a636f6e666572656e63650000000073746167696e672e7a696e6672612e696f },
                },
                epoch: GroupEpoch(
                    67,
                ),
                sender: External(
                    SenderExtensionIndex(
                        0,
                    ),
                ),
                authenticated_data: VLBytes { b"" },
                body: Proposal(
                    Remove(
                        RemoveProposal {
                            removed: LeafNodeIndex(
                                7,
                            ),
                        },
                    ),
                ),
            },
            auth: FramedContentAuthData {
                signature: Signature {
                    value: VLBytes { 0x3046022100eae4e1a2f45fa989c02256c8dcca1c8af9a97b74e60c791723f8ae6720be2c98022100994c1287bcd3a9324089f327fd49c054d8d9291d7d0ee9074ba8959083fae0ea },
                },
                confirmation_tag: None,
            },
            membership_tag: None,
        },
    ),
}
```
