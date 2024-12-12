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

use core_crypto::prelude::MlsCommitBundle;
use core_crypto::MlsTransport;
use core_crypto_ffi::CommitBundle;
use openmls::prelude::MlsMessageOut;
use spinoff::Spinner;
use tokio::sync::RwLock;

pub(crate) struct RunningProcess {
    spinner: Option<Spinner>,
    is_task: bool,
}

impl std::fmt::Debug for RunningProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningProcess")
            .field("is_task", &self.is_task)
            .finish()
    }
}

impl RunningProcess {
    pub(crate) fn new(msg: impl AsRef<str> + std::fmt::Display, is_task: bool) -> Self {
        let spinner = if std::env::var("CI").is_err() {
            Some(Spinner::new(
                spinoff::spinners::Aesthetic,
                msg.as_ref().to_owned(),
                if is_task {
                    spinoff::Color::Green
                } else {
                    spinoff::Color::Blue
                },
            ))
        } else {
            if is_task {
                log::info!("{msg}");
            } else {
                log::debug!("{msg}");
            }

            None
        };

        Self { spinner, is_task }
    }

    pub(crate) fn update(&mut self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(spinner) = &mut self.spinner {
            spinner.update_text(msg.as_ref().to_owned());
        } else if self.is_task {
            log::info!("{msg}");
        } else {
            log::debug!("{msg}");
        }
    }

    pub(crate) fn success(self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(mut spinner) = self.spinner {
            spinner.success(msg.as_ref());
        } else {
            log::info!("{msg}");
        }
    }
}

#[async_trait::async_trait]
pub trait MlsTransportTestExt: MlsTransport {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle;
    async fn latest_welcome_message(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.welcome.unwrap().clone()
    }
}

#[derive(Debug, Default)]
pub struct MlsTransportSuccessProvider {
    latest_commit_bundle: RwLock<Option<MlsCommitBundle>>,
    latest_message: RwLock<Option<Vec<u8>>>,
}

#[async_trait::async_trait]
impl MlsTransport for MlsTransportSuccessProvider {
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        self.latest_commit_bundle.write().await.replace(commit_bundle);
        Ok(core_crypto::MlsTransportResponse::Success)
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        self.latest_message.write().await.replace(mls_message);
        Ok(core_crypto::MlsTransportResponse::Success)
    }
}

#[async_trait::async_trait]
impl MlsTransportTestExt for MlsTransportSuccessProvider {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle {
        self.latest_commit_bundle
            .read()
            .await
            .clone()
            .expect("latest_commit_bundle")
    }
}

#[async_trait::async_trait]
impl core_crypto_ffi::MlsTransport for MlsTransportSuccessProvider {
    async fn send_commit_bundle(&self, _commit_bundle: CommitBundle) -> core_crypto_ffi::MlsTransportResponse {
        core_crypto_ffi::MlsTransportResponse::Success
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto_ffi::MlsTransportResponse {
        self.latest_message.write().await.replace(mls_message);
        core_crypto_ffi::MlsTransportResponse::Success
    }
}
