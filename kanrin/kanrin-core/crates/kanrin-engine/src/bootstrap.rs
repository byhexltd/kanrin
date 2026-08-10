use async_trait::async_trait;
use kanrin_transport::Endpoint;

/// Method for discovering available endpoints.
#[async_trait]
pub trait BootstrapMethod: Send + Sync {
    fn name(&self) -> &str;
    async fn discover(&self) -> Result<Vec<Endpoint>, BootstrapError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("discovery failed: {0}")]
    Failed(String),
    #[error("no endpoints found")]
    NoEndpoints,
    #[error("network error: {0}")]
    Network(String),
}

/// Static list of endpoints from config file.
pub struct HardcodedBootstrap {
    endpoints: Vec<Endpoint>,
}

impl HardcodedBootstrap {
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        Self { endpoints }
    }
}

#[async_trait]
impl BootstrapMethod for HardcodedBootstrap {
    fn name(&self) -> &str {
        "hardcoded"
    }

    async fn discover(&self) -> Result<Vec<Endpoint>, BootstrapError> {
        if self.endpoints.is_empty() {
            return Err(BootstrapError::NoEndpoints);
        }
        Ok(self.endpoints.clone())
    }
}

/// Fetch endpoints from Admiral API.
pub struct AdmiralBootstrap {
    api_url: String,
    auth_token: String,
}

impl AdmiralBootstrap {
    pub fn new(api_url: String, auth_token: String) -> Self {
        Self { api_url, auth_token }
    }
}

#[async_trait]
impl BootstrapMethod for AdmiralBootstrap {
    fn name(&self) -> &str {
        "admiral"
    }

    async fn discover(&self) -> Result<Vec<Endpoint>, BootstrapError> {
        // TODO: HTTP request to Admiral API
        // GET /api/v1/config with auth header
        Err(BootstrapError::Failed("not implemented yet".into()))
    }
}

/// Bootstrap engine that tries multiple methods in order.
pub struct BootstrapEngine {
    methods: Vec<Box<dyn BootstrapMethod>>,
}

impl BootstrapEngine {
    pub fn new() -> Self {
        Self { methods: Vec::new() }
    }

    pub fn add_method(&mut self, method: Box<dyn BootstrapMethod>) {
        self.methods.push(method);
    }

    /// Try all methods in order, return first successful result.
    pub async fn discover(&self) -> Result<Vec<Endpoint>, BootstrapError> {
        let mut last_error = None;

        for method in &self.methods {
            match method.discover().await {
                Ok(endpoints) if !endpoints.is_empty() => {
                    tracing::info!(
                        method = method.name(),
                        count = endpoints.len(),
                        "bootstrap discovered endpoints"
                    );
                    return Ok(endpoints);
                }
                Ok(_) => {
                    last_error = Some(BootstrapError::NoEndpoints);
                }
                Err(e) => {
                    tracing::debug!(method = method.name(), error = %e, "bootstrap method failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(BootstrapError::NoEndpoints))
    }
}
