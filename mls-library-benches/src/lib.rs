pub mod mls_rs;
pub mod openmls;

use rand::{Rng, distr::StandardUniform};
use rand_distr::{Distribution, Normal};

/// This struct generates random plaintext messages.
///
/// It produces purely random values in messages whose length is controlled by its parameters.
pub struct PlaintextGenerator {
    pub message_length_distribution: Normal<f64>,
    pub min_message_length: usize,
}

impl Default for PlaintextGenerator {
    fn default() -> Self {
        let message_length_distribution = Normal::new(1024.0, 512.0).expect("stdev is finite here");
        Self {
            message_length_distribution,
            min_message_length: 4,
        }
    }
}

impl PlaintextGenerator {
    /// Generate a plaintext message.
    ///
    /// The message length follows a gaussian distribution according to `self.message_length_distribution`,
    /// with a minimum of `self.min_message_length`.
    ///
    /// The message contents are completely random and arbitrary.
    fn generate_plaintext(&self, rng: &mut impl Rng) -> Vec<u8> {
        let message_length = (self.message_length_distribution.sample(rng).floor() as isize)
            .max(self.min_message_length as isize) as usize;
        let mut message = Vec::with_capacity(message_length);
        message.extend(<StandardUniform as Distribution<u8>>::sample_iter(StandardUniform, rng).take(message_length));
        message
    }
}

/// Implementors of this trait should have two pieces of data:
///
/// - A "user", in whatever form that takes, who is a member of a MLS group
/// - A list of encrypted messages in that group
pub trait BenchmarkCase {
    /// Decrypt all messages.
    ///
    /// The return value is the crc32 hash of all plaintext. This should be validated against the
    /// hash of the input messages both to ensure correctness and to ensure that
    fn decrypt_all(self) -> u32;
}

pub trait BenchSetup {
    type Case: BenchmarkCase;

    /// Identifier of this benchmark; i.e. "OpenMLS" or "MlsRs"
    fn ident() -> &'static str;

    /// Set up a benchmark case.
    ///
    /// This accepts a plaintext generator, the number of _senders_, and the number of messages.
    ///
    /// Note that the number of group members is always 1 higher than the number of senders;
    /// the recipient sends no messages in this group.
    ///
    /// It produces a benchmark case, and the CRC32 of the plaintext all generated messages.
    fn setup(
        &mut self,
        plaintext_generator: &PlaintextGenerator,
        n_senders: usize,
        n_messages: usize,
    ) -> (Self::Case, u32);
}
