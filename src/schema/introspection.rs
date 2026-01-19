use crate::http::HttpClient;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FULL_INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            ...FullType
        }
        directives {
            name
            description
            locations
            args {
                ...InputValue
            }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                }
            }
        }
    }
}
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    #[serde(rename = "__schema")]
    pub schema: SchemaInner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaInner {
    pub query_type: Option<TypeName>,
    pub mutation_type: Option<TypeName>,
    pub subscription_type: Option<TypeName>,
    pub types: Vec<FullType>,
    pub directives: Vec<Directive>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeName {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullType {
    pub kind: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub fields: Option<Vec<Field>>,
    pub input_fields: Option<Vec<InputValue>>,
    pub interfaces: Option<Vec<TypeRef>>,
    pub enum_values: Option<Vec<EnumValue>>,
    pub possible_types: Option<Vec<TypeRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<InputValue>,
    #[serde(rename = "type")]
    pub field_type: TypeRef,
    pub is_deprecated: bool,
    pub deprecation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputValue {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub input_type: TypeRef,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeRef {
    pub kind: String,
    pub name: Option<String>,
    pub of_type: Option<Box<TypeRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumValue {
    pub name: String,
    pub description: Option<String>,
    pub is_deprecated: bool,
    pub deprecation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directive {
    pub name: String,
    pub description: Option<String>,
    pub locations: Vec<String>,
    pub args: Vec<InputValue>,
}

impl Schema {
    pub fn get_query_type(&self) -> Option<&FullType> {
        let query_name = self.schema.query_type.as_ref()?.name.as_str();
        self.schema.types.iter().find(|t| t.name.as_deref() == Some(query_name))
    }

    pub fn get_mutation_type(&self) -> Option<&FullType> {
        let mutation_name = self.schema.mutation_type.as_ref()?.name.as_str();
        self.schema.types.iter().find(|t| t.name.as_deref() == Some(mutation_name))
    }

    pub fn get_subscription_type(&self) -> Option<&FullType> {
        let sub_name = self.schema.subscription_type.as_ref()?.name.as_str();
        self.schema.types.iter().find(|t| t.name.as_deref() == Some(sub_name))
    }

    pub fn get_type(&self, name: &str) -> Option<&FullType> {
        self.schema.types.iter().find(|t| t.name.as_deref() == Some(name))
    }

    pub fn get_user_types(&self) -> Vec<&FullType> {
        self.schema.types.iter()
            .filter(|t| {
                if let Some(name) = &t.name {
                    !name.starts_with("__")
                } else {
                    false
                }
            })
            .collect()
    }
}

impl TypeRef {
    pub fn get_base_type_name(&self) -> Option<&str> {
        if self.name.is_some() {
            self.name.as_deref()
        } else if let Some(ref of_type) = self.of_type {
            of_type.get_base_type_name()
        } else {
            None
        }
    }

    pub fn is_list(&self) -> bool {
        if self.kind == "LIST" {
            true
        } else if let Some(ref of_type) = self.of_type {
            of_type.is_list()
        } else {
            false
        }
    }

    pub fn is_non_null(&self) -> bool {
        self.kind == "NON_NULL"
    }
}

pub async fn fetch_schema(client: &HttpClient, url: &str) -> Result<Schema> {
    let response = client
        .post_graphql(url, FULL_INTROSPECTION_QUERY, None, Some("introspection"))
        .await
        .context("Failed to fetch introspection")?;

    let data = response
        .get_data()
        .context("No data in introspection response")?;

    let schema: Schema = serde_json::from_value(data.clone())
        .context("Failed to parse introspection response")?;

    Ok(schema)
}

pub async fn fetch_schema_raw(client: &HttpClient, url: &str) -> Result<Value> {
    let response = client
        .post_graphql(url, FULL_INTROSPECTION_QUERY, None, Some("introspection"))
        .await
        .context("Failed to fetch introspection")?;

    Ok(response.body)
}
