use spinoff::Spinner;

#[derive(Debug)]
pub struct RunningProcess {
    spinner: Option<Spinner>,
    is_task: bool,
}

impl RunningProcess {
    pub fn new(msg: impl AsRef<str> + std::fmt::Display, is_task: bool) -> Self {
        let spinner = if std::env::var("CI").is_err() {
            Some(Spinner::new(
                spinoff::Spinners::Aesthetic,
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
        if let Some(spinner) = self.spinner {
            spinner.success(msg.as_ref());
        } else {
            log::info!("{msg}");
        }
    }
}
