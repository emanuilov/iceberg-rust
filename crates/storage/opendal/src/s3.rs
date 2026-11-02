// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use iceberg::io::{
    CLIENT_REGION, S3_ACCESS_KEY_ID, S3_ALLOW_ANONYMOUS, S3_ASSUME_ROLE_ARN,
    S3_ASSUME_ROLE_EXTERNAL_ID, S3_ASSUME_ROLE_SESSION_NAME, S3_DISABLE_CONFIG_LOAD,
    S3_DISABLE_EC2_METADATA, S3_ENDPOINT, S3_PATH_STYLE_ACCESS, S3_REGION, S3_RETRY_MAX_WAIT_MS,
    S3_RETRY_MIN_WAIT_MS, S3_RETRY_NUM_RETRIES, S3_SECRET_ACCESS_KEY, S3_SESSION_TOKEN, S3_SSE_KEY,
    S3_SSE_MD5, S3_SSE_TYPE,
};
use iceberg::{Error, ErrorKind, Result};
use opendal::layers::RetryLayer;
use opendal::services::S3Config;
use opendal::{Configurator, Operator};
/// AWS credentials: access key ID, secret access key, and optional session token.
pub use reqsign_aws_v4::Credential as AwsCredential;
/// Trait for types that can asynchronously supply [`AwsCredential`] to a [`CustomAwsCredentialLoader`].
pub use reqsign_core::ProvideCredential;
use reqsign_core::{ProvideCredentialChain, ProvideCredentialDyn};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::utils::{from_opendal_error, is_truthy};

/// The `s3.retry.*` properties of an S3 storage. Setting any of them applies the configured policy with jitter;
/// with none set the operator keeps OpenDAL's default retries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct S3Retry {
    num_retries: Option<usize>,
    min_wait_ms: Option<NonZeroU64>,
    max_wait_ms: Option<NonZeroU64>,
}

impl S3Retry {
    pub(crate) fn from_properties(props: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            num_retries: parse_property(props, S3_RETRY_NUM_RETRIES)?,
            min_wait_ms: parse_property(props, S3_RETRY_MIN_WAIT_MS)?,
            max_wait_ms: parse_property(props, S3_RETRY_MAX_WAIT_MS)?,
        })
    }

    pub(crate) fn layer(&self) -> RetryLayer {
        let mut layer = RetryLayer::new();
        if self.num_retries.is_none() && self.min_wait_ms.is_none() && self.max_wait_ms.is_none() {
            return layer;
        }
        if let Some(times) = self.num_retries {
            layer = layer.with_max_times(times);
        }
        if let Some(ms) = self.min_wait_ms {
            layer = layer.with_min_delay(Duration::from_millis(ms.get()));
        }
        if let Some(ms) = self.max_wait_ms {
            layer = layer.with_max_delay(Duration::from_millis(ms.get()));
        }
        layer.with_jitter()
    }
}

fn parse_property<T: FromStr>(props: &HashMap<String, String>, key: &str) -> Result<Option<T>>
where T::Err: std::error::Error + Send + Sync + 'static {
    props
        .get(key)
        .map(|value| {
            value.parse().map_err(|error| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!("Invalid property `{key}`: expected a non-negative integer, with positive waits"),
                )
                .with_context("value", format!("{value:?}"))
                .with_source(error)
            })
        })
        .transpose()
}

/// Parse iceberg props to s3 config.
pub(crate) fn s3_config_parse(mut m: HashMap<String, String>) -> Result<S3Config> {
    let mut cfg = S3Config::default();
    // Match Iceberg `S3FileIOProperties.PATH_STYLE_ACCESS_DEFAULT = false`:
    // virtual-host-style addressing is the spec default. opendal's own
    // default is path-style, which disagrees with the Java SDK and breaks
    // S3-compatible stores that only accept virtual-hosted-style URLs.
    // Any explicit `s3.path-style-access` property below overrides this.
    cfg.enable_virtual_host_style = true;
    if let Some(endpoint) = m.remove(S3_ENDPOINT) {
        cfg.endpoint = Some(endpoint);
    };
    if let Some(access_key_id) = m.remove(S3_ACCESS_KEY_ID) {
        cfg.access_key_id = Some(access_key_id);
    };
    if let Some(secret_access_key) = m.remove(S3_SECRET_ACCESS_KEY) {
        cfg.secret_access_key = Some(secret_access_key);
    };
    if let Some(session_token) = m.remove(S3_SESSION_TOKEN) {
        cfg.session_token = Some(session_token);
    };
    if let Some(region) = m.remove(S3_REGION) {
        cfg.region = Some(region);
    };
    if let Some(region) = m.remove(CLIENT_REGION) {
        cfg.region = Some(region);
    };
    if let Some(path_style_access) = m.remove(S3_PATH_STYLE_ACCESS) {
        cfg.enable_virtual_host_style = !is_truthy(path_style_access.to_lowercase().as_str());
    };
    if let Some(arn) = m.remove(S3_ASSUME_ROLE_ARN) {
        cfg.role_arn = Some(arn);
    }
    if let Some(external_id) = m.remove(S3_ASSUME_ROLE_EXTERNAL_ID) {
        cfg.external_id = Some(external_id);
    };
    if let Some(session_name) = m.remove(S3_ASSUME_ROLE_SESSION_NAME) {
        cfg.role_session_name = Some(session_name);
    };
    let s3_sse_key = m.remove(S3_SSE_KEY);
    if let Some(sse_type) = m.remove(S3_SSE_TYPE) {
        match sse_type.to_lowercase().as_str() {
            // No Server Side Encryption
            "none" => {}
            // S3 SSE-S3 encryption (S3 managed keys). https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html
            "s3" => {
                cfg.server_side_encryption = Some("AES256".to_string());
            }
            // S3 SSE KMS, either using default or custom KMS key. https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
            "kms" => {
                cfg.server_side_encryption = Some("aws:kms".to_string());
                cfg.server_side_encryption_aws_kms_key_id = s3_sse_key;
            }
            // S3 SSE-C, using customer managed keys. https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html
            "custom" => {
                cfg.server_side_encryption_customer_algorithm = Some("AES256".to_string());
                cfg.server_side_encryption_customer_key = s3_sse_key;
                cfg.server_side_encryption_customer_key_md5 = m.remove(S3_SSE_MD5);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "Invalid {S3_SSE_TYPE}: {sse_type}. Expected one of (custom, kms, s3, none)"
                    ),
                ));
            }
        }
    };

    if let Some(allow_anonymous) = m.remove(S3_ALLOW_ANONYMOUS)
        && is_truthy(allow_anonymous.to_lowercase().as_str())
    {
        cfg.skip_signature = true;
    }
    if let Some(disable_ec2_metadata) = m.remove(S3_DISABLE_EC2_METADATA)
        && is_truthy(disable_ec2_metadata.to_lowercase().as_str())
    {
        cfg.disable_ec2_metadata = true;
    };
    if let Some(disable_config_load) = m.remove(S3_DISABLE_CONFIG_LOAD)
        && is_truthy(disable_config_load.to_lowercase().as_str())
    {
        cfg.disable_config_load = true;
    };

    Ok(cfg)
}

/// Build new opendal operator from give path.
pub(crate) fn s3_config_build(
    cfg: &S3Config,
    customized_credential_load: &Option<CustomAwsCredentialLoader>,
    path: &str,
) -> Result<Operator> {
    let url = Url::parse(path)?;
    let bucket = url.host_str().ok_or_else(|| {
        Error::new(
            ErrorKind::DataInvalid,
            format!("Invalid s3 url: {path}, missing bucket"),
        )
    })?;

    let mut builder = cfg
        .clone()
        .into_builder()
        // Set bucket name.
        .bucket(bucket);

    if let Some(loader) = customized_credential_load {
        let chain = ProvideCredentialChain::new().push(Arc::clone(&loader.0));
        builder = builder.credential_provider_chain(chain);
    }

    Ok(Operator::new(builder).map_err(from_opendal_error)?.finish())
}

/// Custom AWS credential loader.
///
/// Wraps any [`ProvideCredential`] implementation for use with the S3 storage backend.
/// Use [`CustomAwsCredentialLoader::new`] to create one, then pass it to
/// [`OpenDalStorageFactory::S3`](crate::OpenDalStorageFactory).
pub struct CustomAwsCredentialLoader(Arc<dyn ProvideCredentialDyn<Credential = AwsCredential>>);

impl Clone for CustomAwsCredentialLoader {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl std::fmt::Debug for CustomAwsCredentialLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomAwsCredentialLoader")
            .finish_non_exhaustive()
    }
}

impl CustomAwsCredentialLoader {
    /// Create a new custom AWS credential loader from any [`ProvideCredential`] implementation.
    pub fn new(provider: impl ProvideCredential<Credential = AwsCredential> + 'static) -> Self {
        Self(Arc::new(provider) as Arc<dyn ProvideCredentialDyn<Credential = AwsCredential>>)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU64;

    use iceberg::io::{
        S3_PATH_STYLE_ACCESS, S3_RETRY_MAX_WAIT_MS, S3_RETRY_MIN_WAIT_MS, S3_RETRY_NUM_RETRIES,
    };

    use super::{S3Retry, s3_config_parse};

    fn parse_with(prop: Option<&str>) -> bool {
        let mut props = HashMap::new();
        if let Some(v) = prop {
            props.insert(S3_PATH_STYLE_ACCESS.to_string(), v.to_string());
        }
        s3_config_parse(props).unwrap().enable_virtual_host_style
    }

    #[test]
    fn s3_config_parse_path_style_access() {
        // Match Iceberg S3FileIOProperties.PATH_STYLE_ACCESS_DEFAULT = false.
        assert!(parse_with(None));
        assert!(parse_with(Some("false")));
        assert!(!parse_with(Some("true")));
    }

    fn retry(props: &[(&str, &str)]) -> iceberg::Result<S3Retry> {
        S3Retry::from_properties(
            &props
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn s3_retry_unset_keeps_the_default() {
        let unset = retry(&[]).unwrap();
        assert_eq!(
            (unset.num_retries, unset.min_wait_ms, unset.max_wait_ms),
            (None, None, None)
        );
    }

    #[test]
    fn s3_retry_properties_are_parsed() {
        let parsed = retry(&[
            (S3_RETRY_NUM_RETRIES, "10"),
            (S3_RETRY_MIN_WAIT_MS, "2000"),
            (S3_RETRY_MAX_WAIT_MS, "20000"),
        ])
        .unwrap();
        assert_eq!(
            (parsed.num_retries, parsed.min_wait_ms, parsed.max_wait_ms),
            (Some(10), NonZeroU64::new(2000), NonZeroU64::new(20000))
        );
        let no_retries = retry(&[(S3_RETRY_NUM_RETRIES, "0")]).unwrap();
        assert_eq!(no_retries.num_retries, Some(0));
    }

    #[test]
    fn s3_retry_rejects_invalid_values() {
        for (key, invalid) in [
            (S3_RETRY_NUM_RETRIES, "-1"),
            (S3_RETRY_NUM_RETRIES, "abc"),
            (S3_RETRY_NUM_RETRIES, ""),
            (S3_RETRY_MIN_WAIT_MS, "0"),
            (S3_RETRY_MIN_WAIT_MS, "abc"),
            (S3_RETRY_MAX_WAIT_MS, "0"),
            (S3_RETRY_MAX_WAIT_MS, "12.5"),
        ] {
            let err = retry(&[(key, invalid)]).unwrap_err().to_string();
            assert!(err.contains(key), "{key}={invalid}: {err}");
        }
    }
}
