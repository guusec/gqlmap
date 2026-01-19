use crate::schema::{Field, InputValue, Schema, TypeRef};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct BrunoExporter {
    schema: Schema,
    base_url: String,
}

impl BrunoExporter {
    pub fn new(schema: Schema, base_url: String) -> Self {
        Self { schema, base_url }
    }

    pub fn export(&self, output_dir: &Path) -> Result<ExportStats> {
        fs::create_dir_all(output_dir).context("Failed to create output directory")?;

        let queries_dir = output_dir.join("queries");
        let mutations_dir = output_dir.join("mutations");
        fs::create_dir_all(&queries_dir)?;
        fs::create_dir_all(&mutations_dir)?;

        // Create bruno.json
        let collection_name = output_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("GraphQL");
        let bruno_json = format!(
            r#"{{
  "version": "1",
  "name": "{}",
  "type": "collection"
}}"#,
            collection_name
        );
        fs::write(output_dir.join("bruno.json"), bruno_json)?;

        let mut stats = ExportStats::default();

        // Export queries
        if let Some(query_type) = self.schema.get_query_type() {
            if let Some(fields) = &query_type.fields {
                for (idx, field) in fields.iter().enumerate() {
                    if field.name.starts_with("__") {
                        continue;
                    }
                    let content = self.generate_bru_file(field, "query", idx + 1);
                    let filename = format!("{}.bru", field.name);
                    fs::write(queries_dir.join(&filename), content)?;
                    stats.queries += 1;
                }
            }
        }

        // Export mutations
        if let Some(mutation_type) = self.schema.get_mutation_type() {
            if let Some(fields) = &mutation_type.fields {
                for (idx, field) in fields.iter().enumerate() {
                    if field.name.starts_with("__") {
                        continue;
                    }
                    let content = self.generate_bru_file(field, "mutation", idx + 1);
                    let filename = format!("{}.bru", field.name);
                    fs::write(mutations_dir.join(&filename), content)?;
                    stats.mutations += 1;
                }
            }
        }

        Ok(stats)
    }

    fn generate_bru_file(&self, field: &Field, operation_type: &str, seq: usize) -> String {
        let args_str = self.build_args_string(&field.args);
        let selection = self.build_field_selection(&field.field_type, 0, &mut HashSet::new());

        let query = if selection.is_empty() {
            format!("{} {{\n  {}{}\n}}", operation_type, field.name, args_str)
        } else {
            format!(
                "{} {{\n  {}{} {}\n}}",
                operation_type, field.name, args_str, selection
            )
        };

        format!(
            r#"meta {{
  name: {}
  type: graphql
  seq: {}
}}

post {{
  url: {}
  body: graphql
  auth: inherit
}}

body:graphql {{
  {}
}}
"#,
            field.name,
            seq,
            self.base_url,
            query.replace('\n', "\n  ")
        )
    }

    fn build_args_string(&self, args: &[InputValue]) -> String {
        if args.is_empty() {
            return String::new();
        }

        let arg_strs: Vec<String> = args
            .iter()
            .filter_map(|arg| {
                let value = self.build_arg_value(&arg.input_type, 0)?;
                Some(format!("{}: {}", arg.name, value))
            })
            .collect();

        if arg_strs.is_empty() {
            String::new()
        } else {
            format!("({})", arg_strs.join(", "))
        }
    }

    fn build_arg_value(&self, type_ref: &TypeRef, depth: usize) -> Option<String> {
        if depth > 3 {
            return None;
        }

        match type_ref.kind.as_str() {
            "NON_NULL" => {
                if let Some(ref of_type) = type_ref.of_type {
                    self.build_arg_value(of_type, depth)
                } else {
                    None
                }
            }
            "LIST" => {
                if let Some(ref of_type) = type_ref.of_type {
                    let inner = self.build_arg_value(of_type, depth + 1)?;
                    Some(format!("[{}]", inner))
                } else {
                    Some("[]".to_string())
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
                        _ => "\"\"", // Custom scalars default to string
                    }
                    .to_string(),
                )
            }
            "ENUM" => {
                let name = type_ref.name.as_deref()?;
                if let Some(enum_type) = self.schema.get_type(name) {
                    if let Some(values) = &enum_type.enum_values {
                        if let Some(first) = values.first() {
                            return Some(first.name.clone());
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
                                Some(format!("{}: {}", f.name, value))
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

        // Skip scalars and enums
        let scalar_types = ["String", "Int", "Float", "Boolean", "ID"];
        if scalar_types.contains(&base_name) {
            return String::new();
        }

        if let Some(t) = self.schema.get_type(base_name) {
            if t.kind == "ENUM" || t.kind == "SCALAR" {
                return String::new();
            }
        }

        // Prevent circular references
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
            .take(10) // Limit fields
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

#[derive(Default)]
pub struct ExportStats {
    pub queries: usize,
    pub mutations: usize,
}
