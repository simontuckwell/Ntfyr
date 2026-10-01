use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use tracing::warn;

#[derive(Clone)]
pub struct KeyringItem {
    pub attributes: HashMap<String, String>,
    // we could zero-out this region of memory
    pub secret: Vec<u8>,
}

impl KeyringItem {
    pub async fn attributes(&self) -> HashMap<String, String> {
        self.attributes.clone()
    }
    pub async fn secret(&self) -> &[u8] {
        &self.secret[..]
    }
}

#[async_trait]
pub trait LightKeyring {
    async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> anyhow::Result<Vec<KeyringItem>>;
    async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &str,
        replace: bool,
    ) -> anyhow::Result<()>;
    async fn delete(&self, attributes: HashMap<&str, &str>) -> anyhow::Result<()>;
}

pub struct RealKeyring {
    pub(crate) keyring: oo7::Keyring,
}

#[async_trait]
impl LightKeyring for RealKeyring {
    async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> anyhow::Result<Vec<KeyringItem>> {
        let items = self.keyring.search_items(&attributes).await?;

        let mut out_items = vec![];
        for item in items {
            out_items.push(KeyringItem {
                attributes: item.attributes().await?,
                secret: item.secret().await?.to_vec(),
            });
        }
        Ok(out_items)
    }

    async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &str,
        replace: bool,
    ) -> anyhow::Result<()> {
        self.keyring
            .create_item(label, &attributes, secret, replace)
            .await?;
        Ok(())
    }

    async fn delete(&self, attributes: HashMap<&str, &str>) -> anyhow::Result<()> {
        self.keyring.delete(&attributes).await?;
        Ok(())
    }
}

pub struct NullableKeyring {
    pub(crate) search_response: Vec<KeyringItem>,
}

impl NullableKeyring {
    #[allow(dead_code)]
    pub fn new(search_response: Vec<KeyringItem>) -> Self {
        Self { search_response }
    }
}

/// Wraps an `oo7::dbus::Collection` directly. Used as a fallback when the file
/// backend (driven by `org.freedesktop.portal.Secret`) is unusable in a sandbox
/// — for example when the portal is missing or returns a 0-byte master key —
/// but the host Secret Service is reachable via `--talk-name=org.freedesktop.secrets`.
pub struct DBusKeyring {
    collection: oo7::dbus::Collection,
}

#[async_trait]
impl LightKeyring for DBusKeyring {
    async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> anyhow::Result<Vec<KeyringItem>> {
        let items = self.collection.search_items(&attributes).await?;
        let mut out_items = vec![];
        for item in items {
            out_items.push(KeyringItem {
                attributes: item.attributes().await?,
                secret: item.secret().await?.to_vec(),
            });
        }
        Ok(out_items)
    }

    async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &str,
        replace: bool,
    ) -> anyhow::Result<()> {
        self.collection
            .create_item(label, &attributes, secret, replace, None)
            .await?;
        Ok(())
    }

    async fn delete(&self, attributes: HashMap<&str, &str>) -> anyhow::Result<()> {
        for item in self.collection.search_items(&attributes).await? {
            item.delete(None).await?;
        }
        Ok(())
    }
}

/// Fallback used when the system Secret Service / Secret portal is unavailable.
/// Refuses writes with a descriptive error so the UI can surface the failure
/// instead of silently losing credentials.
pub struct UnavailableKeyring {
    reason: String,
}

impl UnavailableKeyring {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl LightKeyring for UnavailableKeyring {
    async fn search_items(
        &self,
        _attributes: HashMap<&str, &str>,
    ) -> anyhow::Result<Vec<KeyringItem>> {
        Ok(vec![])
    }

    async fn create_item(
        &self,
        _label: &str,
        _attributes: HashMap<&str, &str>,
        _secret: &str,
        _replace: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!(
            "System keyring unavailable, cannot save secret: {}",
            self.reason
        )
    }

    async fn delete(&self, _attributes: HashMap<&str, &str>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl LightKeyring for NullableKeyring {
    async fn search_items(
        &self,
        _attributes: HashMap<&str, &str>,
    ) -> anyhow::Result<Vec<KeyringItem>> {
        Ok(self.search_response.clone())
    }

    async fn create_item(
        &self,
        _label: &str,
        _attributes: HashMap<&str, &str>,
        _secret: &str,
        _replace: bool,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn delete(&self, _attributes: HashMap<&str, &str>) -> anyhow::Result<()> {
        Ok(())
    }
}
impl NullableKeyring {
    pub fn with_credentials(credentials: Vec<(String, Credential)>) -> Self {
        let mut search_response = vec![];

        for (server, credential) in credentials {
            let (attributes, secret) = match &credential {
                Credential::Basic { username, password } => (
                    HashMap::from([
                        ("type".to_string(), BASIC_AUTH_TYPE.to_string()),
                        ("username".to_string(), username.clone()),
                        ("server".to_string(), server),
                    ]),
                    password.clone().into_bytes(),
                ),
                Credential::Bearer { token } => (
                    HashMap::from([
                        ("type".to_string(), TOKEN_AUTH_TYPE.to_string()),
                        ("server".to_string(), server),
                    ]),
                    token.clone().into_bytes(),
                ),
            };
            search_response.push(KeyringItem { attributes, secret });
        }

        Self { search_response }
    }
}

/// Try the auto-detected oo7 backend first (file-in-sandbox or DBus on host).
/// If that fails — common when the Flatpak `org.freedesktop.portal.Secret`
/// implementation is missing or returns a 0-byte master key — try the host
/// Secret Service directly via DBus. As a last resort fall back to an
/// `UnavailableKeyring` so the application keeps running.
pub async fn build_keyring(label: &str) -> Arc<dyn LightKeyring + Send + Sync> {
    match oo7::Keyring::new().await {
        Ok(kr) => return Arc::new(RealKeyring { keyring: kr }),
        Err(e) => {
            warn!(
                store = label,
                error = %e,
                "Default keyring backend unavailable, attempting Secret Service fallback"
            );
        }
    }

    match oo7::dbus::Service::new().await {
        Ok(service) => match service.default_collection().await {
            Ok(collection) => {
                return Arc::new(DBusKeyring { collection });
            }
            Err(e) => {
                warn!(store = label, error = %e, "Failed to open default Secret Service collection")
            }
        },
        Err(e) => warn!(store = label, error = %e, "Secret Service DBus connection failed"),
    }

    warn!(
        store = label,
        "No usable keyring backend; secrets will not be persisted this session"
    );
    Arc::new(UnavailableKeyring::new(
        "no Secret portal or Secret Service available",
    ))
}

/// Keyring attribute value marking Basic-auth (username/password) items.
pub const BASIC_AUTH_TYPE: &str = "password";
/// Keyring attribute value marking Bearer-token items.
pub const TOKEN_AUTH_TYPE: &str = "token";

#[derive(Debug, Clone, PartialEq)]
pub enum Credential {
    /// Username/password authentication sent as HTTP Basic auth.
    Basic { username: String, password: String },
    /// Ntfy access token authentication sent as HTTP Bearer auth.
    Bearer { token: String },
}

impl Credential {
    /// Username identifying this account, if any. Token-based accounts have none.
    pub fn username(&self) -> Option<&str> {
        match self {
            Credential::Basic { username, .. } => Some(username),
            Credential::Bearer { .. } => None,
        }
    }

    /// Apply these credentials as an Authorization header on a request.
    pub fn authenticate(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Credential::Basic { username, password } => req.basic_auth(username, Some(password)),
            Credential::Bearer { token } => req.bearer_auth(token),
        }
    }
}

#[derive(Clone)]
pub struct Credentials {
    keyring: Arc<dyn LightKeyring + Send + Sync>,
    creds: Arc<RwLock<HashMap<String, Credential>>>,
}

impl Credentials {
    pub async fn new() -> anyhow::Result<Self> {
        let keyring = build_keyring("credentials").await;
        let mut this = Self {
            keyring,
            creds: Default::default(),
        };
        this.load().await?;
        Ok(this)
    }
    pub async fn new_nullable(credentials: Vec<(String, Credential)>) -> anyhow::Result<Self> {
        let mut this = Self {
            keyring: Arc::new(NullableKeyring::with_credentials(credentials)),
            creds: Default::default(),
        };
        this.load().await?;
        Ok(this)
    }
    pub async fn load(&mut self) -> anyhow::Result<()> {
        let mut loaded: HashMap<String, Credential> = HashMap::new();

        // Basic-auth credentials (legacy and current schema).
        let values = self
            .keyring
            .search_items(HashMap::from([("type", BASIC_AUTH_TYPE)]))
            .await?;
        for item in values {
            let attrs = item.attributes().await;
            if attrs.get("type").map(String::as_str) != Some(BASIC_AUTH_TYPE) {
                continue;
            }
            let (Some(server), Some(username)) = (attrs.get("server"), attrs.get("username"))
            else {
                warn!("skipping keyring credential with missing server or username attribute");
                continue;
            };
            let password = std::str::from_utf8(item.secret().await)?.to_string();
            loaded.insert(
                server.clone(),
                Credential::Basic {
                    username: username.clone(),
                    password,
                },
            );
        }

        // Bearer-token credentials.
        let values = self
            .keyring
            .search_items(HashMap::from([("type", TOKEN_AUTH_TYPE)]))
            .await?;
        for item in values {
            let attrs = item.attributes().await;
            if attrs.get("type").map(String::as_str) != Some(TOKEN_AUTH_TYPE) {
                continue;
            }
            let Some(server) = attrs.get("server") else {
                warn!("skipping token keyring credential with missing server attribute");
                continue;
            };
            let token = std::str::from_utf8(item.secret().await)?.to_string();
            loaded.insert(server.clone(), Credential::Bearer { token });
        }

        *self.creds.write().unwrap() = loaded;
        Ok(())
    }
    pub fn get(&self, server: &str) -> Option<Credential> {
        self.creds.read().unwrap().get(server).cloned()
    }
    pub fn list_all(&self) -> HashMap<String, Credential> {
        self.creds.read().unwrap().clone()
    }
    pub async fn insert(&self, server: &str, credential: Credential) -> anyhow::Result<()> {
        {
            let creds = self.creds.read().unwrap();
            if let Some(existing) = creds.get(server) {
                // Only one account per server; replacing is allowed for the same account.
                let same_account = match (&existing, &credential) {
                    (
                        Credential::Basic { username: u1, .. },
                        Credential::Basic { username: u2, .. },
                    ) => u1 == u2,
                    (Credential::Bearer { .. }, Credential::Bearer { .. }) => true,
                    _ => false,
                };
                if !same_account {
                    anyhow::bail!("You can add only one account per server");
                }
            }
        }
        match &credential {
            Credential::Basic { username, password } => {
                let attrs = HashMap::from([
                    ("type", BASIC_AUTH_TYPE),
                    ("username", username.as_str()),
                    ("server", server),
                ]);
                self.keyring
                    .create_item("Password", attrs, password, true)
                    .await?;
            }
            Credential::Bearer { token } => {
                let attrs = HashMap::from([("type", TOKEN_AUTH_TYPE), ("server", server)]);
                self.keyring
                    .create_item("Access token", attrs, token, true)
                    .await?;
            }
        }

        self.creds
            .write()
            .unwrap()
            .insert(server.to_string(), credential);
        Ok(())
    }
    pub async fn delete(&self, server: &str) -> anyhow::Result<()> {
        let credential = {
            self.creds
                .read()
                .unwrap()
                .get(server)
                .ok_or(anyhow::anyhow!("server creds not found"))?
                .clone()
        };
        match credential {
            Credential::Basic { username, .. } => {
                let attrs = HashMap::from([
                    ("type", BASIC_AUTH_TYPE),
                    ("username", username.as_str()),
                    ("server", server),
                ]);
                self.keyring.delete(attrs).await?;
            }
            Credential::Bearer { .. } => {
                let attrs = HashMap::from([("type", TOKEN_AUTH_TYPE), ("server", server)]);
                self.keyring.delete(attrs).await?;
            }
        }
        self.creds
            .write()
            .unwrap()
            .remove(server)
            .ok_or(anyhow::anyhow!("server creds not found"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrips_basic_and_token_credentials() {
        let creds = Credentials::new_nullable(vec![
            (
                "https://ntfy.sh".to_string(),
                Credential::Basic {
                    username: "user".to_string(),
                    password: "secret".to_string(),
                },
            ),
            (
                "https://self.hosted".to_string(),
                Credential::Bearer {
                    token: "tk_secret".to_string(),
                },
            ),
        ])
        .await
        .unwrap();

        assert_eq!(
            creds.get("https://ntfy.sh"),
            Some(Credential::Basic {
                username: "user".into(),
                password: "secret".into(),
            })
        );
        assert_eq!(
            creds.get("https://self.hosted"),
            Some(Credential::Bearer {
                token: "tk_secret".into()
            })
        );
        assert_eq!(creds.get("https://unknown"), None);
    }

    #[tokio::test]
    async fn enforces_one_account_per_server() {
        let creds = Credentials::new_nullable(vec![(
            "https://x.test".to_string(),
            Credential::Basic {
                username: "alice".to_string(),
                password: "pw".to_string(),
            },
        )])
        .await
        .unwrap();

        // Replacing the same Basic account is allowed.
        creds
            .insert(
                "https://x.test",
                Credential::Basic {
                    username: "alice".into(),
                    password: "new-pw".into(),
                },
            )
            .await
            .unwrap();

        // A different username on the same server is rejected.
        let err = creds
            .insert(
                "https://x.test",
                Credential::Basic {
                    username: "bob".into(),
                    password: "pw".into(),
                },
            )
            .await;
        assert!(err.is_err());

        // Switching auth kind on the same server is rejected too.
        let err = creds
            .insert(
                "https://x.test",
                Credential::Bearer {
                    token: "tk_x".into(),
                },
            )
            .await;
        assert!(err.is_err());

        // A token account can be added for a different server and replaced.
        creds
            .insert(
                "https://y.test",
                Credential::Bearer {
                    token: "tk_1".into(),
                },
            )
            .await
            .unwrap();
        creds
            .insert(
                "https://y.test",
                Credential::Bearer {
                    token: "tk_2".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            creds.get("https://y.test"),
            Some(Credential::Bearer {
                token: "tk_2".into()
            })
        );
    }
}
