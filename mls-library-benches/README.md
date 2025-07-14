# MLS Library Benches

The intent here is to compare Openmls with MlsRs on a level playing field.
As Core-Crypto is currently completely based on Openmls, we achieve a level playing field by not using Core-Crypto.
Instead, we add minimal equivalent implementions of a keystore and encryption suite for both Openmls and MlsRs, and
implement just enough for each of these to accomplish the following tasks:

- Init N users
- Add them to a conversation
- Generate M messages (parametrizing the conversation by number of senders)
- Benchmark decryption performance, parametrizing by number of senders.


The basic plan is to run with these parameter sets:

- Number of messages in `[10, 100, 1000, 10_000]`
- Number of senders in `[1, 10, 100, 1000]`, limiting such that `n_senders <= n_messages`.

For fairness, both implementations will use the default ciphersuite and an artificial in-memory keystore.
