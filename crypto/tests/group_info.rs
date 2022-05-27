#[cfg(test)]
mod tests {
    use core_crypto::{
        prelude::{ConversationMember, MlsCentralConfiguration, MlsConversationConfiguration},
        MlsCentral,
    };

    const CLIENT_LIMIT: usize = 64;

    fn generate_client() -> MlsCentral {
        let user_uuid = uuid::Uuid::new_v4().hyphenated();
        let client_id = format!("{user_uuid}:1234@members.wire.com");
        let mut tmp_dir = tempfile::tempdir().unwrap().into_path();
        tmp_dir.push("stub.edb");

        let config =
            MlsCentralConfiguration::try_new(tmp_dir.to_str().unwrap().into(), "test1234".into(), client_id).unwrap();

        let central = MlsCentral::try_new_in_memory(config).unwrap();
        central
    }

    #[test]
    fn group_info_size() {
        let root_client = generate_client();

        let clients = (0..=CLIENT_LIMIT)
            .map(|_| generate_client())
            .collect::<Vec<MlsCentral>>();

        let conversation_id = uuid::Uuid::new_v4();
        let cid_bytes = conversation_id.as_bytes().to_vec();

        root_client
            .new_conversation(cid_bytes.clone(), MlsConversationConfiguration::default())
            .unwrap();

        let mut lengths = Vec::with_capacity(CLIENT_LIMIT + 1);
        let state = root_client.export_public_group_state(&cid_bytes).unwrap();
        lengths.push(state.len());

        for client in clients.iter() {
            let kp = client.client_keypackages(1).unwrap();
            let members_to_add =
                ConversationMember::new(client.client_id().unwrap().into(), kp[0].key_package().clone());
            root_client
                .add_members_to_conversation(&cid_bytes, &mut [members_to_add])
                .unwrap();
            let state = root_client.export_public_group_state(&cid_bytes).unwrap();
            lengths.push(state.len());
        }

        lengths.into_iter().enumerate().for_each(|(i, len)| {
            println!("group.len[{i}] => state.len[{len}]");
        });
    }
}
