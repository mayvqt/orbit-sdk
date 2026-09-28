//! Management API transport.

use crate::app::Failure;
use reqwest::{Method, Url, header};
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_URL: &str = "https://orbit.mayvie.dev";

pub struct Api {
    runtime: tokio::runtime::Runtime,
    client: reqwest::Client,
    base: Url,
    authorization: header::HeaderValue,
    application_id: String,
    environment_id: String,
}

pub struct Response {
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> Result<Value, Failure> {
        serde_json::from_slice(&self.body)
            .map_err(|_| Failure::Other("the API returned an unreadable response".into()))
    }
}

/// Validate the API origin. Plain HTTP is accepted only for loopback hosts in
/// development builds.
pub fn base_url(value: &str) -> Result<Url, Failure> {
    let invalid = |why: &str| Failure::Usage(format!("invalid API URL `{value}`: {why}"));
    let url = Url::parse(value).map_err(|_| invalid("not a URL"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    let http_allowed = cfg!(any(test, feature = "local-development")) && loopback;
    if !(url.scheme() == "https" || url.scheme() == "http" && http_allowed) {
        return Err(invalid("use https://"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(invalid("remove credentials, query and fragment"));
    }
    Ok(url)
}

impl Api {
    pub fn new(
        base: Url,
        token: &str,
        application_id: String,
        environment_id: String,
    ) -> Result<Self, Failure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Failure::Other(format!("cannot start: {error}")))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("orbit-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| Failure::Other(format!("cannot start HTTPS client: {error}")))?;
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Failure::Usage("the management token is malformed".into()))?;
        authorization.set_sensitive(true);
        Ok(Self {
            runtime,
            client,
            base,
            authorization,
            application_id,
            environment_id,
        })
    }

    /// Build `/api/management/v1/<segments>` with each segment percent-encoded
    /// and the scope parameters every management route requires.
    pub fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Url {
        let mut url = self.base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty()
                .extend(["api", "management", "v1"])
                .extend(segments);
        }
        url.query_pairs_mut()
            .append_pair("application_id", &self.application_id)
            .append_pair("environment_id", &self.environment_id)
            .extend_pairs(query);
        url
    }

    pub fn send(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Response, Failure> {
        let mut request = self
            .client
            .request(method, self.url(segments, query))
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        self.runtime.block_on(async move {
            let response = request.send().await.map_err(transport)?;
            let status = response.status();
            let body = response.bytes().await.map_err(transport)?.to_vec();
            if status.is_success() {
                Ok(Response { body })
            } else {
                Err(api_error(status.as_u16(), &body))
            }
        })
    }

    pub fn get(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<Response, Failure> {
        self.send(Method::GET, segments, query, None)
    }

    pub fn post(&self, segments: &[&str], body: &Value) -> Result<Response, Failure> {
        self.send(Method::POST, segments, &[], Some(body))
    }
}

fn transport(error: reqwest::Error) -> Failure {
    Failure::Transport(error.without_url().to_string())
}

fn api_error(status: u16, body: &[u8]) -> Failure {
    let error = serde_json::from_slice::<Value>(body).ok();
    let field = |name: &str| {
        error
            .as_ref()
            .and_then(|v| v["error"][name].as_str())
            .map(str::to_owned)
    };
    Failure::Api {
        status,
        code: field("code").unwrap_or_else(|| format!("http_{status}")),
        message: field("message").unwrap_or_else(|| "request failed".into()),
        request_id: field("request_id"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        assert!(base_url("https://orbit.mayvie.dev").is_ok());
        assert!(base_url("https://example.test/orbit/").is_ok());
        assert!(base_url("http://127.0.0.1:8080").is_ok());
        for bad in [
            "http://orbit.mayvie.dev",
            "https://user:pw@example.test",
            "https://example.test/?q=1",
            "https://example.test/#x",
            "ftp://example.test",
            "orbit.mayvie.dev",
        ] {
            assert!(base_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn urls_encode_segments_and_carry_scope() {
        let api = Api::new(
            base_url("https://example.test/orbit/").unwrap(),
            crate::config::tests::TOKEN,
            "app 1".into(),
            "env&1".into(),
        )
        .unwrap();
        let url = api.url(&["licences", "../x?y"], &[("after", "c1")]);
        assert_eq!(
            url.as_str(),
            "https://example.test/orbit/api/management/v1/licences/..%2Fx%3Fy?application_id=app+1&environment_id=env%261&after=c1"
        );
    }

    #[test]
    fn error_envelopes() {
        let Failure::Api {
            status,
            code,
            message,
            request_id,
        } = api_error(
            404,
            br#"{"error":{"code":"not_found","message":"Not found.","request_id":"req_1"}}"#,
        )
        else {
            panic!()
        };
        assert_eq!((status, code.as_str()), (404, "not_found"));
        assert_eq!(
            (message.as_str(), request_id.as_deref()),
            ("Not found.", Some("req_1"))
        );
        let Failure::Api { code, .. } = api_error(502, b"<html>") else {
            panic!()
        };
        assert_eq!(code, "http_502");
    }
}
