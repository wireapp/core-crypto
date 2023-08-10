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

use spinoff::Spinner;

pub struct RunningProcess {
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
    pub fn new(msg: impl AsRef<str> + std::fmt::Display, is_task: bool) -> Self {
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

    pub fn update(&mut self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(spinner) = &mut self.spinner {
            spinner.update_text(msg.as_ref().to_owned());
        } else if self.is_task {
            log::info!("{msg}");
        } else {
            log::debug!("{msg}");
        }
    }

    pub fn success(self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(mut spinner) = self.spinner {
            spinner.success(msg.as_ref());
        } else {
            log::info!("{msg}");
        }
    }
}
