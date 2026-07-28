use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use tokio::io::AsyncWriteExt;

use crate::{RegistryError, RegistryResult, UpstreamClient, UpstreamRequest, UpstreamResponse};

#[derive(Clone)]
pub struct ReqwestUpstreamClient {
    client: reqwest::Client,
}

impl ReqwestUpstreamClient {
    pub fn new(socks_proxy: &str, timeout: Duration) -> RegistryResult<Self> {
        let proxy = reqwest::Proxy::all(socks_proxy)
            .map_err(|error| RegistryError::Invalid(format!("configure SOCKS proxy: {error}")))?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent(concat!("sendbox-registry/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| RegistryError::Invalid(format!("build HTTP client: {error}")))?;
        Ok(Self { client })
    }

    async fn send(&self, request: &UpstreamRequest) -> RegistryResult<reqwest::Response> {
        let mut builder = self.client.get(&request.url);
        if let Some(accept) = request.accept.as_deref() {
            let value = HeaderValue::from_str(accept).map_err(|error| {
                RegistryError::Invalid(format!("invalid accept header: {error}"))
            })?;
            builder = builder.header(ACCEPT, value);
        }
        if let Some(authorization) = request.authorization.as_deref() {
            let mut value = HeaderValue::from_bytes(authorization).map_err(|error| {
                RegistryError::Invalid(format!("invalid registry authorization: {error}"))
            })?;
            value.set_sensitive(true);
            builder = builder.header(AUTHORIZATION, value);
        }
        builder
            .send()
            .await
            .map_err(|error| RegistryError::Upstream(error.to_string()))
    }
}

#[async_trait]
impl UpstreamClient for ReqwestUpstreamClient {
    async fn fetch(&self, request: UpstreamRequest) -> RegistryResult<UpstreamResponse> {
        let response = self.send(&request).await?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|length| length > request.maximum_bytes)
        {
            return Err(RegistryError::Upstream(format!(
                "response from {} exceeds {} bytes",
                request.url, request.maximum_bytes
            )));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| RegistryError::Upstream(error.to_string()))?;
            let next = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| RegistryError::Upstream("response size overflowed".to_owned()))?;
            if u64::try_from(next).unwrap_or(u64::MAX) > request.maximum_bytes {
                return Err(RegistryError::Upstream(format!(
                    "response from {} exceeds {} bytes",
                    request.url, request.maximum_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse {
            status,
            content_type,
            body,
        })
    }

    async fn download(&self, request: UpstreamRequest, destination: &Path) -> RegistryResult<u64> {
        let response = self.send(&request).await?;
        if !response.status().is_success() {
            return Err(RegistryError::Upstream(format!(
                "download from {} returned HTTP {}",
                request.url,
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > request.maximum_bytes)
        {
            return Err(RegistryError::Upstream(format!(
                "download from {} exceeds {} bytes",
                request.url, request.maximum_bytes
            )));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|error| io_error("create quarantine file", destination, error))?;
        let mut file = tokio::fs::File::from_std(file);
        let mut total = 0_u64;
        let mut stream = response.bytes_stream();
        let result = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| RegistryError::Upstream(error.to_string()))?;
                total = total
                    .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| {
                        RegistryError::Upstream("download size overflowed".to_owned())
                    })?;
                if total > request.maximum_bytes {
                    return Err(RegistryError::Upstream(format!(
                        "download from {} exceeds {} bytes",
                        request.url, request.maximum_bytes
                    )));
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|error| io_error("write quarantine file", destination, error))?;
            }
            file.sync_all()
                .await
                .map_err(|error| io_error("sync quarantine file", destination, error))
        }
        .await;
        if result.is_err() {
            drop(file);
            let _ = tokio::fs::remove_file(destination).await;
        }
        result.map(|()| total)
    }
}

fn io_error(action: &str, path: &Path, error: io::Error) -> RegistryError {
    RegistryError::Cache(format!("{action} {}: {error}", path.display()))
}
