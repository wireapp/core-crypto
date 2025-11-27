#[cfg(feature = "proteus")]
use std::cell::Cell;
use std::{
    cell::RefCell,
    io::{BufRead as _, BufReader, Read as _},
    process::{Child, ChildStdout, Command, Stdio},
    time::Duration,
};

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use core_crypto::{KeyPackageIn, Keypackage};
use tls_codec::Deserialize as _;

use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};

#[derive(Debug)]
struct SimulatorDriver {
    device: String,
    process: Child,
    output: RefCell<BufReader<ChildStdout>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum InteropResult {
    #[serde(rename = "success")]
    Success { value: String },
    #[serde(rename = "failure")]
    Failure { message: String },
}

#[derive(thiserror::Error, Debug)]
#[error("simulator driver error: {msg}")]
struct SimulatorDriverError {
    msg: String,
}

impl SimulatorDriver {
    fn new(device: String, application: String) -> Self {
        let application = Self::launch_application(&device, &application).expect("Failed to launch application");

        Self {
            device,
            process: application.0,
            output: RefCell::new(application.1),
        }
    }

    fn launch_application(device: &str, application: &str) -> Result<(Child, BufReader<ChildStdout>)> {
        log::info!("launching application: {} on {}", application, device);

        let activity = format!("{}/.MainActivity", application);

        log::info!("killing any existing activity of {}", application);
        // Kill any existing activity to be in a clean state
        Command::new("adb")
            .args(["-s", device, "shell", "am", "force-stop", application])
            .output()
            .expect("Failed to launch application");

        log::info!("starting {}", application);
        // Start the interop application
        Command::new("adb")
            .args(["-s", device, "shell", "am", "start", "-W", "-n", activity.as_str()])
            .output()
            .expect("Failed to launch application");

        // Retrieve the current process id of our application
        let pidof = Command::new("adb")
            .args(["-s", device, "shell", "pidof", "-s", application])
            .output()
            .expect("Failed to launch application");

        let pid = String::from_utf8(pidof.stdout)
            .expect("pidof output is not valid utf8")
            .trim()
            .to_string();
        log::info!("retrieved {} pid", pid);

        // Start monitoring the system output of our application
        //
        // without formatting (raw)
        // only include system out and silence all other logs (System.out:I *:S)
        let mut process = Command::new("adb")
            .args([
                "-s",
                device,
                "logcat",
                "--pid",
                pid.as_str(),
                "-v",
                "raw",
                "System.out:I *:S",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to launch application");

        let mut output = BufReader::new(
            process
                .stdout
                .take()
                .expect("Expected stdout to be available on child process"),
        );

        // Wait for the child process to launch or fail
        std::thread::sleep(Duration::from_secs(3));
        match process.try_wait() {
            Ok(None) => {}
            Ok(Some(exit_status)) => {
                let mut error_message = String::new();
                process
                    .stderr
                    .map(|mut stderr| stderr.read_to_string(&mut error_message));
                panic!("Failed to launch application ({}): {}", exit_status, error_message)
            }
            Err(error) => {
                panic!("Failed to launch application: {}", error)
            }
        }

        log::info!("waiting for ready signal on system.out");

        // Waiting for confirmation that the application has launched.
        let mut line = String::new();
        while !line.contains("Ready") {
            line.clear();
            output
                .read_line(&mut line)
                .expect("was expecting ready signal on stdout");
        }

        log::info!("application launched: {}", line);
        Ok((process, output))
    }

    async fn execute(&self, action: String) -> Result<String> {
        let args = [
            "-s",
            self.device.as_str(),
            "shell",
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.RUN",
            action.as_str(),
        ];

        log::info!("adb {}", args.join(" "));

        Command::new("adb")
            .args(args)
            .output()
            .expect("Failed to execute action");

        let mut result = String::new();
        let mut output = self.output.try_borrow_mut()?;

        output.read_line(&mut result)?;

        log::info!("{}", result);

        let result: InteropResult = serde_json::from_str(result.trim())?;

        match result {
            InteropResult::Success { value } => Ok(value),
            InteropResult::Failure { message } => Err(SimulatorDriverError { msg: message }.into()),
        }
    }
}

impl Drop for SimulatorDriver {
    fn drop(&mut self) {
        self.process.kill().expect("expected child process to be killed")
    }
}

#[derive(Debug)]
pub(crate) struct CoreCryptoAndroidClient {
    driver: SimulatorDriver,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

impl CoreCryptoAndroidClient {
    pub(crate) async fn new() -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let client_id_base64 = general_purpose::STANDARD.encode(client_id_str.as_str());
        let ciphersuite = CIPHERSUITE_IN_USE as u16;

        let output = Command::new("adb")
            .args(["get-serialno"])
            .output()
            .expect("Failed to get connected android device");

        let device = String::from_utf8(output.stdout)
            .expect("output is not valid utf8")
            .trim()
            .to_string();
        let driver = SimulatorDriver::new(device, "com.wire.androidinterop".into());
        log::info!("initialising core crypto with ciphersuite {ciphersuite}");
        driver
            .execute(format!(
                "--es action init-mls --es client_id {client_id_base64} --ei ciphersuite {ciphersuite}"
            ))
            .await?;

        Ok(Self {
            driver,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CoreCryptoAndroidClient {
    fn client_name(&self) -> &str {
        "CoreCrypto::android"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Android
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::MLS | EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoAndroidClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let ciphersuite = CIPHERSUITE_IN_USE as u16;
        let start = std::time::Instant::now();
        let kp_base64 = self
            .driver
            .execute(format!("--es action get-key-package --ei ciphersuite {ciphersuite}"))
            .await?;
        let kp_raw = general_purpose::STANDARD.decode(kp_base64)?;
        let kp: Keypackage = KeyPackageIn::tls_deserialize(&mut kp_raw.as_slice())?.into();

        log::info!(
            "KP Init Key [took {}ms]: Client {} [{}] - {}",
            start.elapsed().as_millis(),
            self.client_name(),
            hex::encode(&self.client_id),
            hex::encode(kp.hpke_init_key()),
        );

        Ok(kp_raw)
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let client_id_base64 = general_purpose::STANDARD.encode(client_id);
        self.driver
            .execute(format!(
                "--es action remove-client --es cid {cid_base64} --es client {client_id_base64}"
            ))
            .await?;

        Ok(())
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let welcome_base64 = general_purpose::STANDARD.encode(welcome);
        let conversation_id_base64 = self
            .driver
            .execute(format!("--es action process-welcome --es welcome {welcome_base64}"))
            .await?;
        let conversation_id = general_purpose::STANDARD.decode(conversation_id_base64)?;

        Ok(conversation_id)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let message_base64 = general_purpose::STANDARD.encode(message);
        let encrypted_message_base64 = self
            .driver
            .execute(format!(
                "--es action encrypt-message --es cid {cid_base64} --es message {message_base64}"
            ))
            .await?;
        let encrypted_message = general_purpose::STANDARD.decode(encrypted_message_base64)?;

        Ok(encrypted_message)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let message_base64 = general_purpose::STANDARD.encode(message);
        let result = self
            .driver
            .execute(format!(
                "--es action decrypt-message --es cid {cid_base64} --es message {message_base64}"
            ))
            .await?;

        if result == "decrypted protocol message" {
            Ok(None)
        } else {
            let decrypted_message = general_purpose::STANDARD.decode(result)?;
            Ok(Some(decrypted_message))
        }
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoAndroidClient {
    async fn init(&mut self) -> Result<()> {
        self.driver.execute("--es action init-proteus".into()).await?;
        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);

        let prekey_base64 = self
            .driver
            .execute(format!("--es action get-prekey --es id {prekey_last_id}"))
            .await?;
        let prekey = general_purpose::STANDARD.decode(prekey_base64)?;

        Ok(prekey)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let prekey_base64 = general_purpose::STANDARD.encode(prekey);
        self.driver
            .execute(format!(
                "--es action session-from-prekey --es session_id {session_id} --es prekey {prekey_base64}"
            ))
            .await?;

        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let message_base64 = general_purpose::STANDARD.encode(message);
        let decrypted_message_base64 = self
            .driver
            .execute(format!(
                "--es action session-from-message --es session_id {session_id} --es message {message_base64}"
            ))
            .await?;
        let decrypted_message = general_purpose::STANDARD.decode(decrypted_message_base64)?;

        Ok(decrypted_message)
    }
    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let plaintext_base64 = general_purpose::STANDARD.encode(plaintext);
        let encrypted_message_base64 = self
            .driver
            .execute(format!(
                "--es action encrypt-proteus --es session_id {session_id} --es message {plaintext_base64}"
            ))
            .await?;
        let encrypted_message = general_purpose::STANDARD.decode(encrypted_message_base64)?;

        Ok(encrypted_message)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);
        let decrypted_message_base64 = self
            .driver
            .execute(format!(
                "--es action decrypt-proteus --es session_id {session_id} --es message {ciphertext_base64}"
            ))
            .await?;
        let decrypted_message = general_purpose::STANDARD.decode(decrypted_message_base64)?;

        Ok(decrypted_message)
    }

    async fn fingerprint(&self) -> Result<String> {
        let fingerprint = self.driver.execute("--es action get-fingerprint".into()).await?;

        Ok(fingerprint)
    }
}
