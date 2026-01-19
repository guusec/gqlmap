use super::{SecurityTest, Severity, TestResult};
use crate::http::HttpClient;
use crate::schema::fetch_schema;
use async_trait::async_trait;
use serde_json::json;

// Alias Overloading Test
pub struct AliasOverloading;

#[async_trait]
impl SecurityTest for AliasOverloading {
    fn name(&self) -> &'static str { "alias_overloading" }
    fn title(&self) -> &'static str { "Alias Overloading" }
    fn description(&self) -> &'static str { "Multiple field aliases allowed in single query" }
    fn impact(&self) -> &'static str { "Denial of Service via resource exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let aliases: Vec<String> = (0..=100)
            .map(|i| format!("alias{}:__typename", i))
            .collect();
        let query = format!("query {{ {} }}", aliases.join(" "));

        let response = client.post_graphql(url, &query, None, Some(self.name())).await?;

        let vulnerable = if let Some(data) = response.get_data() {
            data.get("alias100").is_some()
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

// Batch Query Test
pub struct BatchQuery;

#[async_trait]
impl SecurityTest for BatchQuery {
    fn name(&self) -> &'static str { "batch_query" }
    fn title(&self) -> &'static str { "Array-based Query Batching" }
    fn description(&self) -> &'static str { "Multiple queries accepted in single request" }
    fn impact(&self) -> &'static str { "Denial of Service via batch resource exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let single_query = json!({ "query": "query { __typename }" });
        let batch: Vec<_> = (0..10).map(|_| single_query.clone()).collect();

        let response = client.post_graphql_batch(url, batch, Some(self.name())).await?;

        let vulnerable = if let Some(arr) = response.body.as_array() {
            arr.len() >= 10
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

// Directive Overloading Test
pub struct DirectiveOverloading;

#[async_trait]
impl SecurityTest for DirectiveOverloading {
    fn name(&self) -> &'static str { "directive_overloading" }
    fn title(&self) -> &'static str { "Directive Overloading" }
    fn description(&self) -> &'static str { "Multiple duplicate directives accepted on field" }
    fn impact(&self) -> &'static str { "Denial of Service via parser resource exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let directives = "@aa".repeat(10);
        let query = format!("query {{ __typename {} }}", directives);

        let response = client.post_graphql(url, &query, None, Some(self.name())).await?;

        let vulnerable = if let Some(errors) = response.get_errors() {
            if let Some(arr) = errors.as_array() {
                arr.len() >= 10
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

// Circular Introspection Test
pub struct CircularIntrospection;

#[async_trait]
impl SecurityTest for CircularIntrospection {
    fn name(&self) -> &'static str { "circular_introspection" }
    fn title(&self) -> &'static str { "Circular Query via Introspection" }
    fn description(&self) -> &'static str { "Deep nested introspection queries allowed" }
    fn impact(&self) -> &'static str { "Denial of Service via recursive resource exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let query = r#"query {
            __schema {
                types {
                    fields {
                        type {
                            fields {
                                type {
                                    fields {
                                        type {
                                            fields {
                                                type { name }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;

        let response = client.post_graphql(url, query, None, Some(self.name())).await?;

        let vulnerable = if let Some(data) = response.get_data() {
            if let Some(schema) = data.get("__schema") {
                if let Some(types) = schema.get("types") {
                    if let Some(arr) = types.as_array() {
                        arr.len() > 25
                    } else {
                        false
                    }
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

// Field Duplication Test
pub struct FieldDuplication;

#[async_trait]
impl SecurityTest for FieldDuplication {
    fn name(&self) -> &'static str { "field_duplication" }
    fn title(&self) -> &'static str { "Field Duplication" }
    fn description(&self) -> &'static str { "Repeated fields accepted in query" }
    fn impact(&self) -> &'static str { "Denial of Service via memory exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let fields = "__typename ".repeat(500);
        let query = format!("query {{ {} }}", fields.trim());

        let response = client.post_graphql(url, &query, None, Some(self.name())).await?;

        let vulnerable = response.has_data() && !response.has_errors();

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

// Depth Limit Test
pub struct DepthLimit;

#[async_trait]
impl SecurityTest for DepthLimit {
    fn name(&self) -> &'static str { "depth_limit" }
    fn title(&self) -> &'static str { "Depth Limit Detection" }
    fn description(&self) -> &'static str { "Server accepts deeply nested queries" }
    fn impact(&self) -> &'static str { "Denial of Service via stack overflow or resource exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        // Try to fetch schema to construct a valid deep query
        let schema = match fetch_schema(client, url).await {
            Ok(s) => s,
            Err(_) => {
                // If we can't fetch schema, we can't easily construct a deep query without guessing.
                // We'll return not vulnerable (or inconclusive) for now.
                return Ok(TestResult {
                    name: self.name().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    impact: self.impact().to_string(),
                    severity: self.severity(),
                    vulnerable: false,
                    curl_command: "Introspection failed, cannot build deep query".to_string(),
                });
            }
        };

        // Find a recursive field loop: T -> ... -> T
        let start_type = if let Some(q) = schema.get_query_type() {
            q
        } else {
             return Ok(TestResult {
                name: self.name().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                impact: self.impact().to_string(),
                severity: self.severity(),
                vulnerable: false,
                curl_command: "No Query type found".to_string(),
            });
        };

        // Simple strategy: Find a field in Query type that returns a type that has a field returning itself.
        // Or Query -> TypeA -> TypeA
        let mut recursive_chain: Option<(String, String)> = None; // (FieldName, FieldName)

        // 1. Check for immediate recursion on Query root fields: Query.me -> User, User.friends -> [User]
        if let Some(fields) = &start_type.fields {
            for field in fields {
                if let Some(base_type_name) = field.field_type.get_base_type_name() {
                    if let Some(base_type) = schema.get_type(base_type_name) {
                        // Check if base_type has a field that returns base_type
                        if let Some(inner_fields) = &base_type.fields {
                            for inner_field in inner_fields {
                                if let Some(inner_base_name) = inner_field.field_type.get_base_type_name() {
                                    if inner_base_name == base_type_name {
                                        // Found recursion: Query.field -> Type, Type.inner_field -> Type
                                        recursive_chain = Some((field.name.clone(), inner_field.name.clone()));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if recursive_chain.is_some() { break; }
            }
        }

        let query_string = if let Some((root_field, recursive_field)) = recursive_chain {
            // Build deep query: root { recursive { recursive { ... } } }
            // Depth 100
            let depth = 64;
            let mut part = String::from("__typename");
            for _ in 0..depth {
                part = format!("{} {{ {} }}", recursive_field, part);
            }
            format!("query {{ {} {{ {} }} }}", root_field, part)
        } else {
             // Fallback: try to find any self-referencing type and access it if we can guess an entry point
             // For now, if no simple recursion found from root, skip.
             return Ok(TestResult {
                name: self.name().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                impact: self.impact().to_string(),
                severity: self.severity(),
                vulnerable: false,
                curl_command: "No simple recursive path found in schema".to_string(),
            });
        };

        let response = client.post_graphql(url, &query_string, None, Some(self.name())).await?;

        // If we get data, it means it executed deep query.
        // If we get specific error "max depth", not vulnerable.
        // If we get timeout or crash, vulnerable.
        // If we get data with correct depth, vulnerable.

        let vulnerable = if let Some(errors) = response.get_errors() {
            // Check if errors mention depth
            let error_str = errors.to_string().to_lowercase();
            !error_str.contains("depth") && !error_str.contains("complexity")
        } else {
            // No errors means it executed
             response.has_data()
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

// Query Complexity Test
pub struct QueryComplexity;

#[async_trait]
impl SecurityTest for QueryComplexity {
    fn name(&self) -> &'static str { "query_complexity" }
    fn title(&self) -> &'static str { "Query Complexity Analysis" }
    fn description(&self) -> &'static str { "Server accepts complex queries (nested lists)" }
    fn impact(&self) -> &'static str { "Denial of Service via CPU/Memory exhaustion" }
    fn severity(&self) -> Severity { Severity::High }

    async fn run(&self, client: &HttpClient, url: &str) -> anyhow::Result<TestResult> {
        let schema = match fetch_schema(client, url).await {
            Ok(s) => s,
            Err(_) => return Ok(TestResult {
                name: self.name().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                impact: self.impact().to_string(),
                severity: self.severity(),
                vulnerable: false,
                curl_command: "Introspection failed".to_string(),
            }),
        };

        // Strategy: Find nested lists to explode complexity
        // Query -> List<A> -> List<B> -> List<C>
        let query_type = if let Some(q) = schema.get_query_type() { q } else {
             return Ok(TestResult {
                name: self.name().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                impact: self.impact().to_string(),
                severity: self.severity(),
                vulnerable: false,
                curl_command: "No Query type".to_string(),
            });
        };

        let mut query_struct: Option<(String, String, String)> = None; // RootField, Level1Field, Level2Field

        if let Some(fields) = &query_type.fields {
            for field in fields {
                if field.field_type.is_list() {
                    if let Some(base_name) = field.field_type.get_base_type_name() {
                        if let Some(type_obj) = schema.get_type(base_name) {
                            if let Some(inner_fields) = &type_obj.fields {
                                for inner in inner_fields {
                                    if inner.field_type.is_list() {
                                         // Found double nesting: Root -> List -> List
                                         // Try one more level
                                         if let Some(inner_base) = inner.field_type.get_base_type_name() {
                                             if let Some(inner_type) = schema.get_type(inner_base) {
                                                 if let Some(level2_fields) = &inner_type.fields {
                                                     for l2 in level2_fields {
                                                          // Just take the first scalar or object, doesn't need to be list for 3rd level to still be expensive
                                                          query_struct = Some((field.name.clone(), inner.name.clone(), l2.name.clone()));
                                                          break;
                                                     }
                                                 }
                                             }
                                         }
                                    }
                                    if query_struct.is_some() { break; }
                                }
                            }
                        }
                    }
                }
                if query_struct.is_some() { break; }
            }
        }

        let query = if let Some((f1, f2, f3)) = query_struct {
             // Construct expensive query
             format!("query {{ {} {{ {} {{ {} }} }} }}", f1, f2, f3)
        } else {
            // Fallback: alias overloading is already a test, so if we can't find nested lists, we skip
            return Ok(TestResult {
                name: self.name().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                impact: self.impact().to_string(),
                severity: self.severity(),
                vulnerable: false,
                curl_command: "No nested lists found for complexity test".to_string(),
            });
        };

        let response = client.post_graphql(url, &query, None, Some(self.name())).await?;

        // Vulnerable if it executes without error "complexity" or "cost"
        let vulnerable = if let Some(errors) = response.get_errors() {
            let error_str = errors.to_string().to_lowercase();
            !error_str.contains("complexity") && !error_str.contains("cost") && !error_str.contains("score")
        } else {
            response.has_data()
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