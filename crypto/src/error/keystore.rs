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

/// A key store operation failed
//
// This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
// and it feels a bit silly to add the dependency only for this.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct KeystoreError {
    /// What was happening in the caller
    pub context: &'static str,
    /// What happened with the keystore
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl KeystoreError {
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn wrap<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self {
            source: Box::new(source),
            context,
        }
    }

    /// Some of the error variants for WASM are not thread-safe at all
    /// (looking at you, [idb::Error]), so we have to construct an approximation
    /// of them instead.
    #[cfg(target_family = "wasm")]
    pub(crate) fn wrap<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::error::Error,
    {
        move |source| {
            let ts = threadsafe_error::Threadsafe::from(&source);
            Self {
                source: Box::new(ts),
                context,
            }
        }
    }
}

#[cfg(target_family = "wasm")]
mod threadsafe_error {
    #[derive(Debug, thiserror::Error)]
    #[error("{message}")]
    pub(crate) struct Threadsafe {
        message: String,
        #[source]
        inner: Option<Box<Threadsafe>>,
    }

    impl Threadsafe {
        fn new(message: impl ToString) -> Self {
            Self {
                message: message.to_string(),
                inner: None,
            }
        }

        fn set_inner(&mut self, inner: Self) {
            self.inner = Some(Box::new(inner));
        }
    }

    impl<E: std::error::Error + ?Sized> From<&E> for Threadsafe {
        fn from(err: &E) -> Self {
            let mut ts = Self::new(err);
            if let Some(source) = err.source() {
                ts.set_inner(Self::from(source))
            }
            ts
        }
    }
}
