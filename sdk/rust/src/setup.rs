use crate::{Client, Config, Device, Result, Transport};

/// Configuration for the simple Orbit client setup path.
pub struct Setup {
    pub api_origin: String,
    pub application_id: String,
    pub environment_id: String,
    pub issuer: String,
    pub installation_id: String,
}

impl Client {
    /// Build a client with strict HTTPS transport and an unbound installation.
    pub fn connect(setup: Setup) -> Result<Self> {
        let transport = Transport::new(&setup.api_origin)?;
        let config = Config {
            application_id: setup.application_id,
            environment_id: setup.environment_id,
            issuer: setup.issuer,
        };
        let device = Device {
            installation_id: setup.installation_id,
            fingerprint: None,
            fingerprint_provider: None,
        };
        Self::new(config, device, transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Access, Error};

    fn setup() -> Setup {
        Setup {
            api_origin: "https://orbit.example.test".into(),
            application_id: "app".into(),
            environment_id: "test".into(),
            issuer: "https://orbit.example.test".into(),
            installation_id: "installation_1234".into(),
        }
    }

    #[test]
    fn connect_builds_an_unbound_client_without_network_access() {
        let client = Client::connect(setup()).unwrap();

        assert_eq!(client.0.config.application_id, "app");
        assert_eq!(client.0.config.environment_id, "test");
        assert_eq!(client.0.config.issuer, "https://orbit.example.test");
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
    }

    #[test]
    fn connect_rejects_invalid_origin_and_scope() {
        let mut invalid_origin = setup();
        invalid_origin.api_origin = "http://orbit.example.test".into();
        assert!(matches!(
            Client::connect(invalid_origin),
            Err(Error::Configuration)
        ));

        let mut invalid_scope = setup();
        invalid_scope.application_id = "app/other".into();
        assert!(matches!(
            Client::connect(invalid_scope),
            Err(Error::Configuration)
        ));
    }
}
