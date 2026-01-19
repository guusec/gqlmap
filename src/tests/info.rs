use super::{SecurityTest, Severity, TestResult};
use crate::http::HttpClient;
use async_trait::async_trait;

// Introspection Test
pub struct Introspection;

#[async_trait]
impl SecurityTest for Introspection {
    fn name(&self) -> &'static str { "introspection" }
    fn title(&self) -> &'static str { "Introspection Enabled" }
    fn description(&self) -> &'static str { "Full schema introspection query allowed" }
    fn impact(&self) -> &'static str { "Information disclosure - complete API schema exposed" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = r#"query {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }"#;

        let response = client.post_graphql(url, query, None, Some(self.name())).await?;

        let vulnerable = if let Some(data) = response.get_data() {
            if let Some(schema) = data.get("__schema") {
                if let Some(types) = schema.get("types") {
                    types.as_array().map(|a| !a.is_empty()).unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            }
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
            curl_command: response.curl_command,
        })
    }
}

// GraphiQL Detection Test
pub struct GraphiQL;

#[async_trait]
impl SecurityTest for GraphiQL {
    fn name(&self) -> &'static str { "graphiql" }
    fn title(&self) -> &'static str { "GraphQL IDE Exposed" }
    fn description(&self) -> &'static str { "GraphQL development IDE accessible in production" }
    fn impact(&self) -> &'static str { "Information disclosure - interactive query interface exposed" }
    fn severity(&self) -> Severity { Severity::Low }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let response = client.get_html(url, Some(self.name())).await?;

        let indicators = [
            "GraphQL Playground",
            "GraphiQL",
            "graphql-playground",
            "graphiql.min.js",
            "graphiql.css",
            "apollo-server",
            "graphql-yoga",
        ];

        let vulnerable = indicators.iter().any(|ind| response.body.contains(ind));

        Ok(TestResult {
            name: self.name().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            impact: self.impact().to_string(),
            severity: self.severity(),
            vulnerable,
            curl_command: format!("curl -H 'Accept: text/html' '{}'", url),
        })
    }
}

// Field Suggestions Test
pub struct FieldSuggestions;

#[async_trait]
impl SecurityTest for FieldSuggestions {
    fn name(&self) -> &'static str { "field_suggestions" }
    fn title(&self) -> &'static str { "Field Suggestions Enabled" }
    fn description(&self) -> &'static str { "Error messages suggest valid field names" }
    fn impact(&self) -> &'static str { "Information disclosure - schema hints in errors" }
    fn severity(&self) -> Severity { Severity::Low }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        // Intentionally misspelled field to trigger suggestion
        let query = r#"query { __schema { directive } }"#;

        let response = client.post_graphql(url, query, None, Some(self.name())).await?;

        let vulnerable = if let Some(msg) = response.get_first_error_message() {
            msg.to_lowercase().contains("did you mean")
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
            curl_command: response.curl_command,
        })
    }
}

// Trace Mode Test
pub struct TraceMode;

#[async_trait]
impl SecurityTest for TraceMode {
    fn name(&self) -> &'static str { "trace_mode" }
    fn title(&self) -> &'static str { "Tracing Enabled" }
    fn description(&self) -> &'static str { "Debug tracing information in responses" }
    fn impact(&self) -> &'static str { "Information disclosure - execution traces exposed" }
    fn severity(&self) -> Severity { Severity::Info }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = "query { __typename }";

        let response = client.post_graphql(url, query, None, Some(self.name())).await?;

        let vulnerable = if let Some(extensions) = response.get_extensions() {
            extensions.get("tracing").is_some()
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
            curl_command: response.curl_command,
        })
    }
}

// Unhandled Errors Test
pub struct UnhandledErrors;

#[async_trait]
impl SecurityTest for UnhandledErrors {
    fn name(&self) -> &'static str { "unhandled_errors" }
    fn title(&self) -> &'static str { "Unhandled Errors Exposed" }
    fn description(&self) -> &'static str { "Exception details visible in error responses" }
    fn impact(&self) -> &'static str { "Information disclosure - stack traces or internal details" }
    fn severity(&self) -> Severity { Severity::Info }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        // Malformed query to trigger exception
        let query = "qwerty { abc }";

        let response = client.post_graphql(url, query, None, Some(self.name())).await?;

        let vulnerable = if let Some(extensions) = response.get_extensions() {
            extensions.get("exception").is_some() || extensions.get("stacktrace").is_some()
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
            curl_command: response.curl_command,
        })
    }
}
