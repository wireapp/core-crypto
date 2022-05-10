#[cfg(test)]
mod tests {
    use core_crypto::{prelude::MlsConversationConfiguration, MlsCentral, MlsCentralConfiguration};

    const MSG: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum";

    #[test]
    fn increment_message() {
        let user_uuid = uuid::Uuid::new_v4().hyphenated();
        let client_id = format!("{user_uuid}:1234@members.wire.com");
        let config = MlsCentralConfiguration::builder()
            .store_path("increment_message.edb".into())
            .identity_key("test1234".into())
            .client_id(client_id)
            .build()
            .unwrap();

        let central = MlsCentral::try_new(config).unwrap();
        let _ = central.client_keypackages(100).unwrap();

        let conversation_id = uuid::Uuid::new_v4();
        let cid_bytes = conversation_id.as_bytes().to_vec();

        central
            .new_conversation(cid_bytes.clone(), MlsConversationConfiguration::default())
            .unwrap();

        let mut lengths = Vec::with_capacity(MSG.len());

        for i in 0..MSG.len() {
            lengths.push(central.encrypt_message(cid_bytes.clone(), &MSG[0..=i]).unwrap().len());
        }

        lengths.into_iter().enumerate().for_each(|(i, len)| {
            println!("msg.len[{i}] => enc.len[{len}]");
        });

        central.wipe();
    }
}
