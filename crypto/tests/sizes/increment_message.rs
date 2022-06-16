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
        prelude::{MlsCentralConfiguration, MlsConversationConfiguration},
        MlsCentral,
    };

    const MSG: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum";

    #[cfg_attr(not(target_family = "wasm"), async_std::test)]

    fn increment_message() {
        let user_uuid = uuid::Uuid::new_v4().hyphenated();
        let client_id = format!("{user_uuid}:1234@members.wire.com");
        let config = MlsCentralConfiguration::try_new("increment_message.edb", "test1234", &client_id).unwrap();

        let mut central = MlsCentral::try_new(config).await.unwrap();
        let _ = central.client_keypackages(100).await.unwrap();

        let conversation_id = uuid::Uuid::new_v4();
        let cid_bytes = conversation_id.as_bytes().to_vec();

        central
            .new_conversation(cid_bytes.clone(), MlsConversationConfiguration::default())
            .await
            .unwrap();

        let mut lengths = Vec::with_capacity(MSG.len());

        for i in 0..MSG.len() {
            lengths.push(
                central
                    .encrypt_message(cid_bytes.clone(), &MSG[0..=i])
                    .await
                    .unwrap()
                    .len(),
            );
        }

        lengths.into_iter().enumerate().for_each(|(i, len)| {
            println!("msg.len[{i}] => enc.len[{len}]");
        });

        central.wipe().await.unwrap();
    }
}
