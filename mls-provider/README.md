# Wire CoreCrypto MLS Provider

OpenMLS traits glue code

Calls into our Keystore + RustCrypto primitives.

This code is placed here in order to have it evolving at our own pace and not having to edit our openmls fork everytime.
In addition to the openmls one this one supports seeding the RNG with a custom seeds (for targets with insufficient or
untrusted source of entropy).
