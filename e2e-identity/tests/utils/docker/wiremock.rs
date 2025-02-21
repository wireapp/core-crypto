use crate::utils::docker::SHM;
use std::borrow::Cow;
use std::{collections::HashMap, path::PathBuf};
use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, Image, ImageExt, core::WaitFor};

/// Allows to run WireMock in Docker. Uses stubs to mock responses to predefined requests.
/// The stubs are generated in [crate::E2eTest::new_jwks_uri_mock].
#[derive(Debug)]
pub struct WiremockImage {
    pub volumes: Vec<Mount>,
    pub env_vars: HashMap<String, String>,
    pub stubs_dir: PathBuf,
}

impl WiremockImage {
    const NAME: &'static str = "ghcr.io/beltram/stubr";
    const TAG: &'static str = "latest";
    pub const PORT: ContainerPort = ContainerPort::Tcp(80);
    const PORTS: &'static [ContainerPort] = &[Self::PORT];

    pub async fn run(
        host: &str,
        stubs: Vec<serde_json::Value>,
    ) -> testcontainers::core::error::Result<ContainerAsync<WiremockImage>> {
        let image = Self::default();
        image.write_stubs(stubs);
        image
            .with_container_name(host)
            .with_network(super::NETWORK)
            .with_privileged(true)
            .with_shm_size(SHM)
            .start()
            .await
    }

    fn write_stubs(&self, stubs: Vec<serde_json::Value>) {
        for stub in stubs {
            let stub_name = format!("{}.json", super::rand_str());
            let stub_content = serde_json::to_string_pretty(&stub).unwrap();
            let stub_file = self.stubs_dir.join(stub_name);
            std::fs::write(stub_file, stub_content).unwrap();
        }
    }
}

impl Image for WiremockImage {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn tag(&self) -> &str {
        Self::TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::seconds(1)]
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        &self.volumes
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        // Listen on the given port and return a response according the stubs.
        vec!["/stubs".to_string(), "-p".to_string(), WiremockImage::PORT.to_string()]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        Self::PORTS
    }
}

impl Default for WiremockImage {
    fn default() -> Self {
        let stubs_dir = std::env::temp_dir().join(super::rand_str());
        std::fs::create_dir(&stubs_dir).unwrap();
        let host_volume = stubs_dir.as_os_str().to_str().unwrap();
        Self {
            volumes: vec![Mount::bind_mount(host_volume, "/stubs")],
            env_vars: HashMap::default(),
            stubs_dir,
        }
    }
}
