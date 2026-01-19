use super::{SecurityTest, Severity, TestResult};
use crate::http::HttpClient;
use async_trait::async_trait;

// GET Query Support Test
pub struct GetQuerySupport;

#[async_trait]
impl SecurityTest for GetQuerySupport {
    fn name(&self) -> &'static str { "get_query_support" }
    fn title(&self) -> &'static str { "GET Method Query Support" }
    fn description(&self) -> &'static str { "GraphQL queries accepted via GET parameters" }
    fn impact(&self) -> &'static str { "CSRF vulnerability - queries triggerable from external sites" }
    fn severity(&self) -> Severity { Severity::Medium }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = "query { __typename }";

        let response = client.get_graphql(url, query, Some(self.name())).await?;

        let vulnerable = if let Some(data) = response.get_data() {
            data.get("__typename").is_some()
        } else {
            false
        };

        Ok(TestResult {
            name: self.name().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            impact: self.impact().to_string(),
            severity: self.severity(),
            vulnerable,
            curl_command: format!("curl -G '{}' --data-urlencode 'query={}'", url, query),
        })
    }
}

// GET Mutation Test
pub struct GetMutation;

#[async_trait]
impl SecurityTest for GetMutation {
    fn name(&self) -> &'static str { "get_mutation" }
    fn title(&self) -> &'static str { "GET Method Mutation Support" }
    fn description(&self) -> &'static str { "GraphQL mutations accepted via GET parameters" }
    fn impact(&self) -> &'static str { "CSRF vulnerability - state changes triggerable from external sites" }
    fn severity(&self) -> Severity { Severity::Medium }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = "mutation { __typename }";

        let response = client.get_graphql(url, query, Some(self.name())).await?;

        // Check if mutation was processed (returns data or specific error about mutation not existing)
        let vulnerable = if let Some(data) = response.get_data() {
            data.get("__typename").is_some()
        } else if let Some(msg) = response.get_first_error_message() {
            // If error mentions the mutation doesn't exist, it means mutations ARE processed via GET
            !msg.to_lowercase().contains("get") &&
            !msg.to_lowercase().contains("not allowed") &&
            !msg.to_lowercase().contains("only")
        } else {
            false
        };

        Ok(TestResult {
            name: self.name().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            impact: self.impact().to_string(),
            severity: self.severity(),
            vulnerable,
            curl_command: format!("curl -G '{}' --data-urlencode 'query={}'", url, query),
        })
    }
}

// POST URL-encoded CSRF Test
pub struct PostUrlencoded;

#[async_trait]
impl SecurityTest for PostUrlencoded {
    fn name(&self) -> &'static str { "post_urlencoded" }
    fn title(&self) -> &'static str { "POST URL-encoded Body Support" }
    fn description(&self) -> &'static str { "GraphQL accepts form-encoded POST requests" }
    fn impact(&self) -> &'static str { "CSRF vulnerability - simple form POST without CORS preflight" }
    fn severity(&self) -> Severity { Severity::Medium }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = "query { __typename }";

        let response = client.post_urlencoded(url, query, Some(self.name())).await?;

        let vulnerable = if let Some(data) = response.get_data() {
            data.get("__typename").is_some()
        } else {
            false
        };

        Ok(TestResult {
            name: self.name().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            impact: self.impact().to_string(),
            severity: self.severity(),
            vulnerable,
            curl_command: format!(
                "curl -X POST '{}' -H 'Content-Type: application/x-www-form-urlencoded' -d 'query={}'",
                url, query
            ),
        })
    }
}
