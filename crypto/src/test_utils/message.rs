use openmls::framing::MlsMessageInBody;
use openmls::prelude::{GroupEpoch, MlsMessageIn, MlsMessageOut};

pub trait MessageExt {
    fn epoch(&self) -> Option<GroupEpoch>;
}

impl MessageExt for MlsMessageOut {
    fn epoch(&self) -> Option<GroupEpoch> {
        let msg_in = MlsMessageIn::from(self.clone());
        match msg_in.extract() {
            MlsMessageInBody::PublicMessage(m) => Some(m.epoch()),
            MlsMessageInBody::PrivateMessage(m) => Some(m.epoch()),
            _ => None,
        }
    }
}
