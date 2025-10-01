use openmls::{
    framing::MlsMessageInBody,
    prelude::{GroupEpoch, MlsMessageIn, MlsMessageOut, group_info::VerifiableGroupInfo},
};

pub trait MessageExt {
    fn epoch(&self) -> Option<GroupEpoch>;
    fn group_info(&self) -> Option<VerifiableGroupInfo>;
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

    fn group_info(&self) -> Option<VerifiableGroupInfo> {
        let msg_in = MlsMessageIn::from(self.clone());
        match msg_in.extract() {
            MlsMessageInBody::GroupInfo(vgi) => Some(vgi),
            _ => None,
        }
    }
}
