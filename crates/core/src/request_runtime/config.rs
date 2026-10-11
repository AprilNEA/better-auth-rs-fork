use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{AuthRequest, AuthResult};

/// Source of the authentication service URL.
#[derive(Debug, Clone, Default)]
pub enum BaseUrl {
    /// Resolve environment variables, then the incoming Request.
    #[default]
    Auto,
    Static(String),
    Dynamic(DynamicBaseUrl),
}

impl BaseUrl {
    /// The string in `options.baseURL`; a dynamic policy has no string value.
    pub fn as_static(&self) -> Option<&str> {
        match self {
            Self::Static(value) => Some(value),
            Self::Auto | Self::Dynamic(_) => None,
        }
    }
}

impl From<String> for BaseUrl {
    fn from(value: String) -> Self {
        Self::Static(value)
    }
}

impl From<&str> for BaseUrl {
    fn from(value: &str) -> Self {
        Self::Static(value.to_owned())
    }
}

/// Host allowlist and optional fallback for request-dependent URLs.
#[derive(Debug, Clone)]
pub struct DynamicBaseUrl {
    pub allowed_hosts: Vec<String>,
    pub fallback: Option<String>,
    /// Omission differs from `Auto` when constructing the trusted-origin list.
    pub protocol: Option<BaseUrlProtocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseUrlProtocol {
    Http,
    Https,
    Auto,
}

/// Resolve trusted origins or providers from the original Request, when present.
#[async_trait]
pub trait TrustedValuesResolver: Send + Sync {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>>;
}

/// Static values or a request-dependent asynchronous resolver.
#[derive(Clone)]
pub enum TrustedValues {
    Static(Vec<String>),
    Dynamic(Arc<dyn TrustedValuesResolver>),
    /// Ordered plugin contributions; use `merge` to construct this variant.
    Merged(Arc<MergedOrigins>),
}

impl Default for TrustedValues {
    fn default() -> Self {
        Self::Static(Vec::new())
    }
}

impl fmt::Debug for TrustedValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(values) => formatter.debug_tuple("Static").field(values).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
            Self::Merged(_) => formatter.write_str("Merged(..)"),
        }
    }
}

impl From<Vec<String>> for TrustedValues {
    fn from(value: Vec<String>) -> Self {
        Self::Static(value)
    }
}

impl TrustedValues {
    pub fn as_static(&self) -> Option<&[String]> {
        match self {
            Self::Static(values) => Some(values),
            Self::Dynamic(_) | Self::Merged(_) => None,
        }
    }

    pub async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        let values = match self {
            Self::Static(values) => values.clone(),
            Self::Dynamic(resolver) => resolver.resolve(request).await?,
            Self::Merged(resolver) => resolver.resolve(request).await?,
        };
        Ok(values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect())
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_) | Self::Merged(_))
    }

    /// Merge plugin contributions after initial trust resolution.
    /// Static entries precede concurrent resolver results in declaration order.
    pub fn merge(sources: Vec<Self>) -> Self {
        let mut values = Vec::new();
        let mut resolvers = Vec::new();
        for source in sources {
            match source {
                Self::Static(entries) => values.extend(entries),
                Self::Dynamic(resolver) => resolvers.push(resolver),
                Self::Merged(source) => {
                    values.extend(source.values.iter().cloned());
                    resolvers.extend(source.resolvers.iter().cloned());
                }
            }
        }
        if resolvers.is_empty() {
            Self::Static(values)
        } else {
            Self::Merged(Arc::new(MergedOrigins { values, resolvers }))
        }
    }
}

/// Composed trusted-origin sources; construct with `TrustedValues::merge`.
pub struct MergedOrigins {
    values: Vec<String>,
    resolvers: Vec<Arc<dyn TrustedValuesResolver>>,
}

#[async_trait]
impl TrustedValuesResolver for MergedOrigins {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        let mut values = self.values.clone();
        let resolvers = self.resolvers.clone();
        let request = request.cloned();
        let results = super::concurrent::all(
            "Trusted-origin resolver task",
            resolvers.into_iter().map(|resolver| {
                let request = request.clone();
                async move { resolver.resolve(request.as_ref()).await }
            }),
        )
        .await?;
        values.extend(results.into_iter().flatten());
        values.retain(|value| !value.is_empty());
        Ok(values)
    }
}
