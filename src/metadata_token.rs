#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Token cache which automatically fetches token from Google cloud metadata. This can be used
/// inside Google cloud VMs and containers.
pub struct MetadataToken {
    // this field contains the JWT and the expiry thereof. They are in the same Option because if
    // one of them is `Some`, we require that the other be `Some` as well.
    token: tokio::sync::RwLock<Option<(String, u64)>>,
    // store the access scope for later use if we need to refresh the token
    access_scope: String,
}

impl Default for MetadataToken {
    fn default() -> Self {
        MetadataToken::new("https://www.googleapis.com/auth/devstorage.full_control")
    }
}

impl MetadataToken {
    /// Construct a new token cache.
    pub fn new(scope: &str) -> Self {
        Self {
            token: tokio::sync::RwLock::new(None),
            access_scope: scope.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl crate::TokenCache for MetadataToken {
    async fn scope(&self) -> String {
        self.access_scope.clone()
    }

    async fn token_and_exp(&self) -> Option<(String, u64)> {
        self.token.read().await.as_ref().map(|d| (d.0.clone(), d.1))
    }

    async fn set_token(&self, token: String, exp: u64) -> crate::Result<()> {
        *self.token.write().await = Some((token, exp));
        Ok(())
    }

    async fn fetch_token(&self, client: &reqwest::Client) -> crate::Result<(String, u64)> {
        let now = now();
        let response: TokenResponse = client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .json()
            .await?;
        Ok((response.access_token, now + response.expires_in))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
