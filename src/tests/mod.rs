mod detection;
mod dos;
mod info;
mod csrf;

pub use detection::*;
pub use dos::*;
pub use info::*;
pub use csrf::*;

use crate::http::HttpClient;
use async_trait::async_trait;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn color(&self) -> &'static str {
        match self {
            Severity::High => "red",
            Severity::Medium => "yellow",
            Severity::Low => "blue",
            Severity::Info => "green",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub name: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub severity: Severity,
    pub vulnerable: bool,
    pub curl_command: String,
}

#[async_trait]
pub trait SecurityTest: Send + Sync {
    fn name(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn impact(&self) -> &'static str;
    fn severity(&self) -> Severity;

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult>;
}

pub fn all_tests() -> Vec<Box<dyn SecurityTest>> {
    vec![
        // DoS tests
        Box::new(dos::AliasOverloading),
        Box::new(dos::BatchQuery),
        Box::new(dos::DirectiveOverloading),
        Box::new(dos::CircularIntrospection),
        Box::new(dos::FieldDuplication),
        Box::new(dos::DepthLimit),
        Box::new(dos::QueryComplexity),
        // Info tests
        Box::new(info::Introspection),
        Box::new(info::GraphiQL),
        Box::new(info::FieldSuggestions),
        Box::new(info::TraceMode),
        Box::new(info::UnhandledErrors),
        // CSRF tests
        Box::new(csrf::GetQuerySupport),
        Box::new(csrf::GetMutation),
        Box::new(csrf::PostUrlencoded),
    ]
}
