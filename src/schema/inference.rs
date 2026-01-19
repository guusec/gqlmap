use crate::http::HttpClient;
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const SCALAR_TYPES: &[&str] = &["String", "Int", "Float", "Boolean", "ID"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredSchema {
    pub query_type: Option<InferredType>,
    pub mutation_type: Option<InferredType>,
    pub subscription_type: Option<InferredType>,
    pub types: HashMap<String, InferredType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredType {
    pub name: String,
    pub kind: String,
    pub fields: Vec<InferredField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredField {
    pub name: String,
    pub type_name: Option<String>,
    pub is_list: bool,
    pub is_non_null: bool,
    pub args: Vec<InferredArg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredArg {
    pub name: String,
    pub type_name: Option<String>,
}

pub struct SchemaInferrer {
    client: HttpClient,
    url: String,
    wordlist: Vec<String>,
    discovered_types: HashMap<String, InferredType>,
    discovered_fields: HashSet<String>,
    // Regex patterns
    suggestions_regex: Regex,
    field_error_regex: Regex,
    _type_error_regex: Regex,
    _arg_error_regex: Regex,
    // New regexes for robust detection (Clairvoyance logic)
    subselection_regex: Regex,
    must_have_selection_regex: Regex,
    must_not_have_selection_regex: Regex,
    quoted_word_regex: Regex,
}

impl SchemaInferrer {
    pub fn new(client: HttpClient, url: String, wordlist: Vec<String>) -> Self {
        Self {
            client,
            url,
            wordlist,
            discovered_types: HashMap::new(),
            discovered_fields: HashSet::new(),
            // Regex patterns to extract info from GraphQL error messages
            suggestions_regex: Regex::new(r#"Did you mean (.+)""#).unwrap(),
            field_error_regex: Regex::new(
                r#"Cannot query field ["\']?(\w+)["\']? on type ["\']?(\w+)["\']?"#,
            )
            .unwrap(),
            _type_error_regex: Regex::new(r#"Unknown type ["\']?(\w+)["\']?"#).unwrap(),
            _arg_error_regex: Regex::new(
                r#"Unknown argument ["\']?(\w+)["\']? on field ["\']?(\w+)["\']?"#,
            )
            .unwrap(),
            // Matches: Subselection required for type 'now_query' of field 'now'
            subselection_regex: Regex::new(r#"Subselection required for type ["\']?(\w+)["\']? of field ["\']?(\w+)["\']?"#).unwrap(),
            // Matches: Field "user" of type "User" must have a selection of subfields
            must_have_selection_regex: Regex::new(r#"Field ["\']?(\w+)["\']? of type ["\']?(\w+)["\']? must have a selection of subfields"#).unwrap(),
            // Matches: Field "name" must not have a selection since type "String" has no subfields
            must_not_have_selection_regex: Regex::new(r#"Field ["\']?(\w+)["\']? must not have a selection since type ["\']?(\w+)["\']? has no subfields"#).unwrap(),
             // Matches quoted words for suggestion extraction: "word" or 'word'
            quoted_word_regex: Regex::new(r#"["\'](\w+)["\']"#).unwrap(),
        }
    }

    pub async fn infer(&mut self, callback: Option<&dyn Fn(&str)>) -> Result<InferredSchema> {
        // Try to discover Query type fields
        if let Some(cb) = callback {
            cb("Probing Query type...");
        }
        let query_fields = self.probe_root_type("query").await?;
        if !query_fields.is_empty() {
            self.discovered_types.insert(
                "Query".to_string(),
                InferredType {
                    name: "Query".to_string(),
                    kind: "OBJECT".to_string(),
                    fields: query_fields,
                },
            );
        }

        // Try to discover Mutation type fields
        if let Some(cb) = callback {
            cb("Probing Mutation type...");
        }
        let mutation_fields = self.probe_root_type("mutation").await?;
        if !mutation_fields.is_empty() {
            self.discovered_types.insert(
                "Mutation".to_string(),
                InferredType {
                    name: "Mutation".to_string(),
                    kind: "OBJECT".to_string(),
                    fields: mutation_fields,
                },
            );
        }

        // Try to discover Subscription type fields
        if let Some(cb) = callback {
            cb("Probing Subscription type...");
        }
        let subscription_fields = self.probe_root_type("subscription").await?;
        if !subscription_fields.is_empty() {
            self.discovered_types.insert(
                "Subscription".to_string(),
                InferredType {
                    name: "Subscription".to_string(),
                    kind: "OBJECT".to_string(),
                    fields: subscription_fields,
                },
            );
        }

        // Build the schema
        Ok(InferredSchema {
            query_type: self.discovered_types.get("Query").cloned(),
            mutation_type: self.discovered_types.get("Mutation").cloned(),
            subscription_type: self.discovered_types.get("Subscription").cloned(),
            types: self.discovered_types.clone(),
        })
    }

    async fn probe_root_type(&mut self, operation: &str) -> Result<Vec<InferredField>> {
        let mut fields = Vec::new();
        let mut checked_words = HashSet::new();
        let mut words_to_check: Vec<String> = self.wordlist.clone();

        while let Some(word) = words_to_check.pop() {
            if checked_words.contains(&word) {
                continue;
            }
            checked_words.insert(word.clone());

            // Validate field name format
            if !is_valid_graphql_name(&word) {
                continue;
            }

            let query = format!("{} {{ {} }}", operation, word);
            let response = self
                .client
                .post_graphql(&self.url, &query, None, Some("inference"))
                .await;

            let response = match response {
                Ok(r) => r,
                Err(_) => continue,
            };

            let mut found_field: Option<InferredField> = None;

            // Check if field exists (has data)
            if response.has_data() {
                if let Some(data) = response.get_data() {
                    if data.get(&word).is_some() {
                        // Field exists! Try to determine its type
                        let field = self.probe_field(&word, operation).await?;
                        found_field = Some(field);
                    }
                }
            }

            // Check if field exists via specific error messages
            if found_field.is_none() {
                if let Some(errors) = response.get_errors() {
                    if let Some(arr) = errors.as_array() {
                        for error in arr {
                            if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                                // 1. Subselection required (It's an Object)
                                if let Some(cap) = self.subselection_regex.captures(msg) {
                                    if let (Some(type_name), Some(field_name_cap)) = (cap.get(1), cap.get(2)) {
                                        if field_name_cap.as_str() == word {
                                            let type_str = type_name.as_str().to_string();
                                            self.register_type(&type_str);
                                            
                                            let mut field = InferredField {
                                                name: word.clone(),
                                                type_name: Some(type_str),
                                                is_list: false,
                                                is_non_null: false,
                                                args: Vec::new(),
                                            };
                                            field.args = self.probe_field_args(&word, operation).await?;
                                            found_field = Some(field);
                                        }
                                    }
                                }

                                // 2. Must have selection (It's an Object)
                                if found_field.is_none() {
                                    if let Some(cap) = self.must_have_selection_regex.captures(msg) {
                                        if let (Some(field_name_cap), Some(type_name)) = (cap.get(1), cap.get(2)) {
                                            if field_name_cap.as_str() == word {
                                                let type_str = type_name.as_str().to_string();
                                                self.register_type(&type_str);

                                                let mut field = InferredField {
                                                    name: word.clone(),
                                                    type_name: Some(type_str),
                                                    is_list: false,
                                                    is_non_null: false,
                                                    args: Vec::new(),
                                                };
                                                field.args = self.probe_field_args(&word, operation).await?;
                                                found_field = Some(field);
                                            }
                                        }
                                    }
                                }

                                // 3. Must NOT have selection (It's a Scalar, but we know it exists)
                                // We need to re-query as a scalar to confirm, or trust the error.
                                // If we sent `query { word }` and got "Must NOT have selection", 
                                // it implies we sent a selection `word { ... }`.
                                // Wait, `probe_root_type` sends `query { word }`.
                                // If it's a scalar, `query { word }` is correct, and we should get DATA, not an error.
                                // The "Must not have selection" error only happens if we send `query { word { sub } }`.
                                // BUT: If we are here, we might have received a generic error or no data.
                                // Let's check `probe_field` logic.
                            }
                        }
                    }
                }
            }

            if let Some(field) = found_field {
                fields.push(field);
                self.discovered_fields.insert(word.clone());
            }

            // Extract suggestions from error messages
            if let Some(errors) = response.get_errors() {
                if let Some(arr) = errors.as_array() {
                    for error in arr {
                        if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                            // Extract "Did you mean X, Y, Z?"
                            if let Some(cap) = self.suggestions_regex.captures(msg) {
                                if let Some(suggestion_part) = cap.get(1) {
                                    // suggestion_part is like: "user", "users" or "me"
                                    for word_match in self.quoted_word_regex.captures_iter(suggestion_part.as_str()) {
                                        if let Some(w) = word_match.get(1) {
                                            let suggested = w.as_str().to_string();
                                            if !checked_words.contains(&suggested) {
                                                words_to_check.push(suggested);
                                            }
                                        }
                                    }
                                }
                            }

                            // Extract type names from error messages
                            for cap in self.field_error_regex.captures_iter(msg) {
                                if let Some(type_name) = cap.get(2) {
                                    let type_str = type_name.as_str().to_string();
                                    if !self.discovered_types.contains_key(&type_str)
                                        && !SCALAR_TYPES.contains(&type_str.as_str())
                                    {
                                        self.discovered_types.insert(
                                            type_str.clone(),
                                            InferredType {
                                                name: type_str,
                                                kind: "OBJECT".to_string(),
                                                fields: Vec::new(),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(fields)
    }

    async fn probe_field(&mut self, field_name: &str, operation: &str) -> Result<InferredField> {
        let mut field = InferredField {
            name: field_name.to_string(),
            type_name: None,
            is_list: false,
            is_non_null: false,
            args: Vec::new(),
        };

        // Try to determine if it's a scalar or object type
        // by requesting a subfield
        let query = format!("{} {{ {} {{ __typename }} }}", operation, field_name);
        let response = self
            .client
            .post_graphql(&self.url, &query, None, Some("inference"))
            .await?;

        if response.has_data() {
            if let Some(data) = response.get_data() {
                if let Some(field_data) = data.get(field_name) {
                    // Check if it's a list
                    if field_data.is_array() {
                        field.is_list = true;
                        if let Some(first) = field_data.as_array().and_then(|a| a.first()) {
                            if let Some(typename) = first.get("__typename").and_then(|t| t.as_str()) {
                                field.type_name = Some(typename.to_string());
                                self.register_type(typename);
                            }
                        }
                    } else if let Some(typename) =
                        field_data.get("__typename").and_then(|t| t.as_str())
                    {
                        field.type_name = Some(typename.to_string());
                        self.register_type(typename);
                    }
                }
            }
        } else if let Some(errors) = response.get_errors() {
            // Check for "Must not have selection" -> It's a scalar!
             if let Some(arr) = errors.as_array() {
                for error in arr {
                    if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                         if let Some(cap) = self.must_not_have_selection_regex.captures(msg) {
                            if let (Some(field_cap), Some(type_name)) = (cap.get(1), cap.get(2)) {
                                if field_cap.as_str() == field_name {
                                    field.type_name = Some(type_name.as_str().to_string());
                                }
                            }
                         }
                    }
                }
             }
        } 
        
        // If we still don't know the type, try querying as scalar
        if field.type_name.is_none() {
            let query = format!("{} {{ {} }}", operation, field_name);
            let response = self
                .client
                .post_graphql(&self.url, &query, None, Some("inference"))
                .await?;

            if response.has_data() {
                if let Some(data) = response.get_data() {
                    if let Some(value) = data.get(field_name) {
                        field.type_name = Some(infer_scalar_type(value));
                        if value.is_array() {
                            field.is_list = true;
                        }
                    }
                }
            }
        }

        // Probe for arguments
        field.args = self.probe_field_args(field_name, operation).await?;

        Ok(field)
    }

    async fn probe_field_args(
        &self,
        field_name: &str,
        operation: &str,
    ) -> Result<Vec<InferredArg>> {
        let mut args = Vec::new();
        let mut checked_args = HashSet::new();

        // Common argument names to probe
        let mut common_args: Vec<String> = vec![
            "id", "input", "where", "filter", "limit", "offset", "first", "last",
            "after", "before", "orderBy", "order", "sort", "skip", "take", "page",
            "pageSize", "cursor", "data", "name", "email", "query", "search",
        ].into_iter().map(String::from).collect();

        while let Some(arg_name) = common_args.pop() {
            if checked_args.contains(&arg_name) { continue; }
            checked_args.insert(arg_name.clone());

            let query = format!("{} {{ {}({}: null) }}", operation, field_name, arg_name);
            let response = self
                .client
                .post_graphql(&self.url, &query, None, Some("inference"))
                .await;

            if let Ok(resp) = response {
                if let Some(errors) = resp.get_errors() {
                    if let Some(arr) = errors.as_array() {
                        for error in arr {
                            if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                                
                                // Check for argument suggestions "Did you mean..."
                                if let Some(cap) = self.suggestions_regex.captures(msg) {
                                    if let Some(suggestion_part) = cap.get(1) {
                                        for word_match in self.quoted_word_regex.captures_iter(suggestion_part.as_str()) {
                                            if let Some(w) = word_match.get(1) {
                                                let suggested = w.as_str().to_string();
                                                if !checked_args.contains(&suggested) {
                                                    common_args.push(suggested);
                                                }
                                            }
                                        }
                                    }
                                }

                                // If error is about type mismatch, not unknown arg, it exists
                                let is_unknown = msg.to_lowercase().contains("unknown argument")
                                    || msg.to_lowercase().contains("no argument");

                                if !is_unknown
                                    && (msg.contains(&arg_name)
                                        || msg.contains("expected")
                                        || msg.contains("type"))
                                {
                                    args.push(InferredArg {
                                        name: arg_name.clone(),
                                        type_name: extract_type_from_error(msg),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(args)
    }

    fn register_type(&mut self, type_name: &str) {
        if !self.discovered_types.contains_key(type_name)
            && !SCALAR_TYPES.contains(&type_name)
            && !type_name.starts_with("__")
        {
            self.discovered_types.insert(
                type_name.to_string(),
                InferredType {
                    name: type_name.to_string(),
                    kind: "OBJECT".to_string(),
                    fields: Vec::new(),
                },
            );
        }
    }

    pub fn to_introspection_format(&self, schema: &InferredSchema) -> serde_json::Value {
        let mut types = Vec::new();

        // Add scalar types
        for scalar in SCALAR_TYPES {
            types.push(serde_json::json!({
                "kind": "SCALAR",
                "name": scalar,
                "description": null,
                "fields": null,
                "inputFields": null,
                "interfaces": [],
                "enumValues": null,
                "possibleTypes": null
            }));
        }

        // Add discovered types
        for (_, inferred_type) in &schema.types {
            let fields: Vec<serde_json::Value> = inferred_type
                .fields
                .iter()
                .map(|f| {
                    let args: Vec<serde_json::Value> = f
                        .args
                        .iter()
                        .map(|a| {
                            serde_json::json!({
                                "name": a.name,
                                "description": null,
                                "type": {
                                    "kind": "SCALAR",
                                    "name": a.type_name.as_deref().unwrap_or("String"),
                                    "ofType": null
                                },
                                "defaultValue": null
                            })
                        })
                        .collect();

                    let type_ref = if f.is_list {
                        serde_json::json!({
                            "kind": "LIST",
                            "name": null,
                            "ofType": {
                                "kind": if SCALAR_TYPES.contains(&f.type_name.as_deref().unwrap_or("")) { "SCALAR" } else { "OBJECT" },
                                "name": f.type_name.as_deref().unwrap_or("String"),
                                "ofType": null
                            }
                        })
                    } else {
                        serde_json::json!({
                            "kind": if SCALAR_TYPES.contains(&f.type_name.as_deref().unwrap_or("")) { "SCALAR" } else { "OBJECT" },
                            "name": f.type_name.as_deref().unwrap_or("String"),
                            "ofType": null
                        })
                    };

                    serde_json::json!({
                        "name": f.name,
                        "description": null,
                        "args": args,
                        "type": type_ref,
                        "isDeprecated": false,
                        "deprecationReason": null
                    })
                })
                .collect();

            types.push(serde_json::json!({
                "kind": inferred_type.kind,
                "name": inferred_type.name,
                "description": null,
                "fields": if fields.is_empty() { serde_json::Value::Null } else { serde_json::json!(fields) },
                "inputFields": null,
                "interfaces": [],
                "enumValues": null,
                "possibleTypes": null
            }));
        }

        serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": schema.query_type.as_ref().map(|t| serde_json::json!({"name": t.name})),
                    "mutationType": schema.mutation_type.as_ref().map(|t| serde_json::json!({"name": t.name})),
                    "subscriptionType": schema.subscription_type.as_ref().map(|t| serde_json::json!({"name": t.name})),
                    "types": types,
                    "directives": []
                }
            }
        })
    }
}

fn is_valid_graphql_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }

    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn infer_scalar_type(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(_) => "String".to_string(),
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                "Float".to_string()
            } else {
                "Int".to_string()
            }
        }
        serde_json::Value::Bool(_) => "Boolean".to_string(),
        serde_json::Value::Array(arr) => {
            if let Some(first) = arr.first() {
                infer_scalar_type(first)
            } else {
                "String".to_string()
            }
        }
        _ => "String".to_string(),
    }
}

fn extract_type_from_error(msg: &str) -> Option<String> {
    // Try to extract type from error messages like "expected type X"
    let patterns = [
        Regex::new(r#"expected type ["\']?(\w+)["\']?"#).ok()?,
        Regex::new(r#"type ["\']?(\w+)["\']?"#).ok()?,
    ];

    for pattern in patterns {
        if let Some(cap) = pattern.captures(msg) {
            if let Some(m) = cap.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }

    None
}

pub fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).context("Failed to read wordlist file")?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

pub fn default_wordlist() -> Vec<String> {
    vec![
        // Common query fields
        "user",
        "users",
        "me",
        "currentUser",
        "viewer",
        "account",
        "accounts",
        "profile",
        "profiles",
        "post",
        "posts",
        "article",
        "articles",
        "comment",
        "comments",
        "message",
        "messages",
        "notification",
        "notifications",
        "order",
        "orders",
        "product",
        "products",
        "item",
        "items",
        "category",
        "categories",
        "tag",
        "tags",
        "file",
        "files",
        "image",
        "images",
        "document",
        "documents",
        "event",
        "events",
        "task",
        "tasks",
        "project",
        "projects",
        "team",
        "teams",
        "organization",
        "organizations",
        "company",
        "companies",
        "customer",
        "customers",
        "client",
        "clients",
        "invoice",
        "invoices",
        "payment",
        "payments",
        "subscription",
        "subscriptions",
        "plan",
        "plans",
        "setting",
        "settings",
        "config",
        "configuration",
        "permission",
        "permissions",
        "role",
        "roles",
        "group",
        "groups",
        "session",
        "sessions",
        "token",
        "tokens",
        "key",
        "keys",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "log",
        "logs",
        "audit",
        "audits",
        "activity",
        "activities",
        "analytics",
        "stats",
        "statistics",
        "metrics",
        "report",
        "reports",
        "dashboard",
        "search",
        "query",
        "find",
        "get",
        "list",
        "all",
        "node",
        "nodes",
        "edge",
        "edges",
        "connection",
        "connections",
        "health",
        "status",
        "version",
        "info",
        // Common mutation fields
        "createUser",
        "updateUser",
        "deleteUser",
        "login",
        "logout",
        "register",
        "signup",
        "signin",
        "signout",
        "authenticate",
        "authorize",
        "verify",
        "confirm",
        "reset",
        "resetPassword",
        "changePassword",
        "updatePassword",
        "forgotPassword",
        "sendEmail",
        "sendMessage",
        "createPost",
        "updatePost",
        "deletePost",
        "createOrder",
        "updateOrder",
        "deleteOrder",
        "createProduct",
        "updateProduct",
        "deleteProduct",
        "upload",
        "uploadFile",
        "uploadImage",
        "create",
        "update",
        "delete",
        "remove",
        "add",
        "set",
        "save",
        "submit",
        "approve",
        "reject",
        "cancel",
        "refund",
        "subscribe",
        "unsubscribe",
        "follow",
        "unfollow",
        "like",
        "unlike",
        "share",
        "invite",
        "join",
        "leave",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}
