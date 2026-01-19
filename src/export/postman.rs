use crate::schema::{Field, InputValue, Schema, TypeRef};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanCollection {
    pub info: PostmanInfo,
    pub item: Vec<PostmanFolder>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanInfo {
    pub name: String,
    pub schema: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanFolder {
    pub name: String,
    pub item: Vec<PostmanRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanRequest {
    pub name: String,
    pub request: PostmanRequestDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanRequestDetails {
    pub method: String,
    pub header: Vec<PostmanHeader>,
    pub body: PostmanBody,
    pub url: PostmanUrl,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanHeader {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub header_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanBody {
    pub mode: String,
    pub graphql: PostmanGraphQL,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanGraphQL {
    pub query: String,
    pub variables: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostmanUrl {
    pub raw: String,
    pub protocol: String,
    pub host: Vec<String>,
    pub path: Vec<String>,
}

pub struct PostmanExporter {
    schema: Schema,
    base_url: String,
}

impl PostmanExporter {
    pub fn new(schema: Schema, base_url: String) -> Self {
        Self { schema, base_url }
    }

    pub fn export(&self) -> Result<PostmanCollection> {
        let mut folders = Vec::new();

        // Export queries
        if let Some(query_type) = self.schema.get_query_type() {
            if let Some(fields) = &query_type.fields {
                let requests: Vec<PostmanRequest> = fields
                    .iter()
                    .filter(|f| !f.name.starts_with("__"))
                    .map(|f| self.create_request(f, "query"))
                    .collect();

                if !requests.is_empty() {
                    folders.push(PostmanFolder {
                        name: "Queries".to_string(),
                        item: requests,
                    });
                }
            }
        }

        // Export mutations
        if let Some(mutation_type) = self.schema.get_mutation_type() {
            if let Some(fields) = &mutation_type.fields {
                let requests: Vec<PostmanRequest> = fields
                    .iter()
                    .filter(|f| !f.name.starts_with("__"))
                    .map(|f| self.create_request(f, "mutation"))
                    .collect();

                if !requests.is_empty() {
                    folders.push(PostmanFolder {
                        name: "Mutations".to_string(),
                        item: requests,
                    });
                }
            }
        }

        Ok(PostmanCollection {
            info: PostmanInfo {
                name: "GraphQL API".to_string(),
                schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                    .to_string(),
            },
            item: folders,
        })
    }

    fn create_request(&self, field: &Field, operation: &str) -> PostmanRequest {
        let args_str = self.build_args_string(&field.args);
        let selection = self.build_field_selection(&field.field_type, 0, &mut HashSet::new());
        let variables = self.build_variables_json(&field.args);

        let query = if selection.is_empty() {
            format!("{} {{\n  {}{}\n}}", operation, field.name, args_str)
        } else {
            format!(
                "{} {{\n  {}{} {}\n}}",
                operation, field.name, args_str, selection
            )
        };

        let url_parts = parse_url(&self.base_url);

        PostmanRequest {
            name: field.name.clone(),
            request: PostmanRequestDetails {
                method: "POST".to_string(),
                header: vec![PostmanHeader {
                    key: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                    header_type: "text".to_string(),
                }],
                body: PostmanBody {
                    mode: "graphql".to_string(),
                    graphql: PostmanGraphQL {
                        query,
                        variables,
                    },
                },
                url: url_parts,
            },
        }
    }

    fn build_args_string(&self, args: &[InputValue]) -> String {
        if args.is_empty() {
            return String::new();
        }

        let arg_strs: Vec<String> = args
            .iter()
            .map(|arg| format!("{}: ${}", arg.name, arg.name))
            .collect();

        format!("({})", arg_strs.join(", "))
    }

    fn build_variables_json(&self, args: &[InputValue]) -> String {
        if args.is_empty() {
            return "{}".to_string();
        }

        let vars: Vec<String> = args
            .iter()
            .filter_map(|arg| {
                let value = self.build_arg_value(&arg.input_type, 0)?;
                Some(format!("  \"{}\": {}", arg.name, value))
            })
            .collect();

        if vars.is_empty() {
            "{}".to_string()
        } else {
            format!("{{\n{}\n}}", vars.join(",\n"))
        }
    }

    fn build_arg_value(&self, type_ref: &TypeRef, depth: usize) -> Option<String> {
        if depth > 3 {
            return None;
        }

        match type_ref.kind.as_str() {
            "NON_NULL" | "LIST" => {
                if let Some(ref of_type) = type_ref.of_type {
                    self.build_arg_value(of_type, depth)
                } else {
                    None
                }
            }
            "SCALAR" => {
                let name = type_ref.name.as_deref()?;
                Some(
                    match name {
                        "String" | "ID" => "\"\"",
                        "Int" => "0",
                        "Float" => "0.0",
                        "Boolean" => "false",
                        _ => "\"\"",
                    }
                    .to_string(),
                )
            }
            "ENUM" => {
                let name = type_ref.name.as_deref()?;
                if let Some(enum_type) = self.schema.get_type(name) {
                    if let Some(values) = &enum_type.enum_values {
                        if let Some(first) = values.first() {
                            return Some(format!("\"{}\"", first.name));
                        }
                    }
                }
                None
            }
            "INPUT_OBJECT" => {
                let name = type_ref.name.as_deref()?;
                if let Some(input_type) = self.schema.get_type(name) {
                    if let Some(fields) = &input_type.input_fields {
                        let field_strs: Vec<String> = fields
                            .iter()
                            .filter_map(|f| {
                                let value = self.build_arg_value(&f.input_type, depth + 1)?;
                                Some(format!("\"{}\": {}", f.name, value))
                            })
                            .collect();
                        return Some(format!("{{ {} }}", field_strs.join(", ")));
                    }
                }
                Some("{}".to_string())
            }
            _ => None,
        }
    }

    fn build_field_selection(
        &self,
        type_ref: &TypeRef,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> String {
        if depth > 2 {
            return String::new();
        }

        let base_name = match type_ref.get_base_type_name() {
            Some(name) => name,
            None => return String::new(),
        };

        let scalar_types = ["String", "Int", "Float", "Boolean", "ID"];
        if scalar_types.contains(&base_name) {
            return String::new();
        }

        if let Some(t) = self.schema.get_type(base_name) {
            if t.kind == "ENUM" || t.kind == "SCALAR" {
                return String::new();
            }
        }

        if visited.contains(base_name) {
            return String::new();
        }
        visited.insert(base_name.to_string());

        let object_type = match self.schema.get_type(base_name) {
            Some(t) if t.kind == "OBJECT" || t.kind == "INTERFACE" => t,
            _ => {
                visited.remove(base_name);
                return String::new();
            }
        };

        let fields = match &object_type.fields {
            Some(f) => f,
            None => {
                visited.remove(base_name);
                return String::new();
            }
        };

        let indent = "  ".repeat(depth + 2);
        let field_strs: Vec<String> = fields
            .iter()
            .filter(|f| !f.name.starts_with("__"))
            .take(10)
            .map(|f| {
                let sub_selection = self.build_field_selection(&f.field_type, depth + 1, visited);
                if sub_selection.is_empty() {
                    format!("{}{}", indent, f.name)
                } else {
                    format!("{}{} {}", indent, f.name, sub_selection)
                }
            })
            .collect();

        visited.remove(base_name);

        if field_strs.is_empty() {
            String::new()
        } else {
            let close_indent = "  ".repeat(depth + 1);
            format!("{{\n{}\n{}}}", field_strs.join("\n"), close_indent)
        }
    }
}

fn parse_url(url: &str) -> PostmanUrl {
    let url_obj = url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());

    let protocol = url_obj.scheme().to_string();
    let host: Vec<String> = url_obj
        .host_str()
        .unwrap_or("localhost")
        .split('.')
        .map(|s| s.to_string())
        .collect();
    let path: Vec<String> = url_obj
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    PostmanUrl {
        raw: url.to_string(),
        protocol,
        host,
        path,
    }
}
