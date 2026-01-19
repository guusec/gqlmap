use anyhow::{Context, Result};
use reqwest::{Client, Proxy, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

const DEFAULT_TIMEOUT: u64 = 30;
/// const USER_AGENT: &str = concat!("gqlmap/", env!("CARGO_PKG_VERSION"));

const USER_AGENT: &str = concat!("Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.7499.194 Mobile Safari/537.36");

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    headers: HashMap<String, String>,
    debug_mode: bool,
}

impl HttpClient {
    pub fn new(
        proxy: Option<&str>,
        headers: HashMap<String, String>,
        debug_mode: bool,
    ) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT))
            .danger_accept_invalid_certs(true)
            .user_agent(USER_AGENT);

        if let Some(proxy_url) = proxy {
            let proxy = if proxy_url.starts_with("socks") {
                Proxy::all(proxy_url).context("Invalid SOCKS proxy URL")?
            } else {
                Proxy::all(proxy_url).context("Invalid HTTP proxy URL")?
            };
            builder = builder.proxy(proxy);
        }

        let client = builder.build().context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            headers,
            debug_mode,
        })
    }

    fn apply_headers(&self, mut req: reqwest::RequestBuilder, test_name: Option<&str>) -> reqwest::RequestBuilder {
        for (key, value) in &self.headers {
            req = req.header(key, value);
        }

        if self.debug_mode {
            if let Some(name) = test_name {
                req = req.header("X-GQLMap-Test", name);
            }
        }

        req
    }

    pub async fn post_graphql(
        &self,
        url: &str,
        query: &str,
        variables: Option<Value>,
        test_name: Option<&str>,
    ) -> Result<GraphQLResponse> {
        let body = match variables {
            Some(vars) => json!({
                "query": query,
                "variables": vars
            }),
            None => json!({
                "query": query
            }),
        };

        let req = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body);

        let req = self.apply_headers(req, test_name);
        let response = req.send().await.context("Failed to send POST request")?;

        GraphQLResponse::from_response(response, url, "POST", &body).await
    }

    pub async fn post_graphql_batch(
        &self,
        url: &str,
        queries: Vec<Value>,
        test_name: Option<&str>,
    ) -> Result<GraphQLResponse> {
        let req = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&queries);

        let req = self.apply_headers(req, test_name);
        let response = req.send().await.context("Failed to send batch POST request")?;

        GraphQLResponse::from_response(response, url, "POST", &json!(queries)).await
    }

    pub async fn post_urlencoded(
        &self,
        url: &str,
        query: &str,
        test_name: Option<&str>,
    ) -> Result<GraphQLResponse> {
        let params = [("query", query)];

        let req = self.client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params);

        let req = self.apply_headers(req, test_name);
        let response = req.send().await.context("Failed to send URL-encoded POST request")?;

        GraphQLResponse::from_response(response, url, "POST", &json!({"query": query})).await
    }

    pub async fn get_graphql(
        &self,
        url: &str,
        query: &str,
        test_name: Option<&str>,
    ) -> Result<GraphQLResponse> {
        let req = self.client
            .get(url)
            .query(&[("query", query)]);

        let req = self.apply_headers(req, test_name);
        let response = req.send().await.context("Failed to send GET request")?;

        GraphQLResponse::from_response(response, url, "GET", &json!({"query": query})).await
    }

    pub async fn get_html(
        &self,
        url: &str,
        test_name: Option<&str>,
    ) -> Result<HtmlResponse> {
        let req = self.client
            .get(url)
            .header("Accept", "text/html");

        let req = self.apply_headers(req, test_name);
        let response = req.send().await.context("Failed to send HTML GET request")?;

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(HtmlResponse {
            status,
            body,
            url: url.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GraphQLResponse {
    pub status: u16,
    pub body: Value,
    pub curl_command: String,
}

impl GraphQLResponse {
    async fn from_response(response: Response, url: &str, method: &str, body: &Value) -> Result<Self> {
        let status = response.status().as_u16();
        let response_body: Value = response
            .json()
            .await
            .unwrap_or(json!({"error": "Failed to parse response as JSON"}));

        let curl_command = Self::build_curl(url, method, body);

        Ok(Self {
            status,
            body: response_body,
            curl_command,
        })
    }

    fn build_curl(url: &str, method: &str, body: &Value) -> String {
        if method == "GET" {
            format!("curl -X GET '{}'", url)
        } else {
            let body_str = serde_json::to_string(body).unwrap_or_default();
            format!(
                "curl -X POST '{}' -H 'Content-Type: application/json' -d '{}'",
                url, body_str
            )
        }
    }

    pub fn has_data(&self) -> bool {
        self.body.get("data").is_some()
    }

    pub fn has_errors(&self) -> bool {
        self.body.get("errors").is_some()
    }

    pub fn get_data(&self) -> Option<&Value> {
        self.body.get("data")
    }

    pub fn get_errors(&self) -> Option<&Value> {
        self.body.get("errors")
    }

    pub fn get_first_error_message(&self) -> Option<String> {
        self.body
            .get("errors")?
            .as_array()?
            .first()?
            .get("message")?
            .as_str()
            .map(|s| s.to_string())
    }

    pub fn get_extensions(&self) -> Option<&Value> {
        self.body
            .get("errors")?
            .as_array()?
            .first()?
            .get("extensions")
    }
}

#[derive(Debug, Clone)]
pub struct HtmlResponse {
    pub status: u16,
    pub body: String,
    pub url: String,
}
