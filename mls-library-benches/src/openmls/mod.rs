use crate::{BenchSetup, BenchmarkCase};

#[derive(Default)]
pub struct OpenMls;

impl BenchSetup for OpenMls {
    type Case = Case;

    fn ident() -> &'static str {
        "OpenMLS"
    }

    fn setup(
        &mut self,
        plaintext_generator: &crate::PlaintextGenerator,
        n_senders: usize,
        n_messages: usize,
    ) -> (Self::Case, u32) {
        todo!()
    }
}

pub struct Case {
    messages: Vec<Vec<u8>>,
}

impl BenchmarkCase for Case {
    fn decrypt_all(self) -> u32 {
        todo!()
    }
}
