// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#[cfg(test)]
mod tests {
    use core_crypto::{
        prelude::{ConversationMember, MlsCentralConfiguration, MlsConversationConfiguration},
        MlsCentral,
    };

    const CLIENT_LIMIT: usize = 64;

    async fn generate_client() -> MlsCentral {
        let user_uuid = uuid::Uuid::new_v4().hyphenated();
        let client_id = format!("{user_uuid}:1234@members.wire.com");
        let mut tmp_dir = tempfile::tempdir().unwrap().into_path();
        tmp_dir.push("stub.edb");

        let config = MlsCentralConfiguration::try_new(tmp_dir.to_str().unwrap(), "test1234", &client_id).unwrap();

        MlsCentral::try_new_in_memory(config).await.unwrap()
    }

    #[cfg_attr(not(target_family = "wasm"), async_std::test)]

    async fn group_info_size() {
        let mut root_client = generate_client().await;

        let mut clients = vec![];
        for _ in 0..=CLIENT_LIMIT {
            clients.push(generate_client().await);
        }

        let conversation_id = uuid::Uuid::new_v4();
        let cid_bytes = conversation_id.as_bytes().to_vec();

        root_client
            .new_conversation(cid_bytes.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();

        let mut lengths = Vec::with_capacity(CLIENT_LIMIT + 1);
        let state = root_client.export_public_group_state(&cid_bytes).await.unwrap();
        lengths.push(state.len());

        for client in clients.iter() {
            let kp = client.client_keypackages(1).await.unwrap();
            let members_to_add =
                ConversationMember::new(client.client_id().unwrap().into(), kp[0].key_package().clone());
            root_client
                .add_members_to_conversation(&cid_bytes, &mut [members_to_add])
                .await
                .unwrap();
            let state = root_client.export_public_group_state(&cid_bytes).await.unwrap();
            lengths.push(state.len());
        }

        lengths.into_iter().enumerate().for_each(|(i, len)| {
            println!("group.len[{i}] => state.len[{len}]");
        });
    }
}
