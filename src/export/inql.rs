use crate::schema::{Field, Schema, TypeRef};
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// InQL-compatible export format
/// Creates a directory structure compatible with Burp Suite's InQL extension
///
/// Structure:
/// output_dir/
/// ├── queries/
/// │   ├── query1.graphql
/// │   └── query2.graphql
/// └── mutations/
///     ├── mutation1.graphql
///     └── mutation2.graphql

pub struct InqlExporter {
    schema: Schema,
    base_url: String,
}

impl InqlExporter {
    pub fn new(schema: Schema, base_url: String) -> Self {
        Self { schema, base_url }
    }

    pub fn export(&self, output_dir: &Path) -> Result<ExportStats> {
        let queries_dir = output_dir.join("queries");
        let mutations_dir = output_dir.join("mutations");

        fs::create_dir_all(&queries_dir)?;
        fs::create_dir_all(&mutations_dir)?;

        let mut stats = ExportStats::default();

        // Export queries
        if let Some(query_type) = self.schema.get_query_type() {
            if let Some(fields) = &query_type.fields {
                for field in fields.iter().filter(|f| !f.name.starts_with("__")) {
                    let content = self.generate_operation(field, "query");
                    let path = queries_dir.join(format!("{}.graphql", field.name));
                    fs::write(path, content)?;
                    stats.queries += 1;
                }
            }
        }

        // Export mutations
        if let Some(mutation_type) = self.schema.get_mutation_type() {
            if let Some(fields) = &mutation_type.fields {
                for field in fields.iter().filter(|f| !f.name.starts_with("__")) {
                    let content = self.generate_operation(field, "mutation");
                    let path = mutations_dir.join(format!("{}.graphql", field.name));
                    fs::write(path, content)?;
                    stats.mutations += 1;
                }
            }
        }

        // Write metadata file
        let metadata = format!(
            "# InQL Export\n# URL: {}\n# Queries: {}\n# Mutations: {}\n",
            self.base_url, stats.queries, stats.mutations
        );
        fs::write(output_dir.join("metadata.txt"), metadata)?;

        Ok(stats)
    }

    fn generate_operation(&self, field: &Field, operation: &str) -> String {
        let selection = self.build_field_selection(&field.field_type, 0, &mut HashSet::new());

        if field.args.is_empty() {
            if selection.is_empty() {
                format!("{} {{\n  {}\n}}\n", operation, field.name)
            } else {
                format!("{} {{\n  {} {}\n}}\n", operation, field.name, selection)
            }
        } else {
            // Build variable definitions
            let var_defs: Vec<String> = field
                .args
                .iter()
                .map(|arg| {
                    let type_str = self.type_ref_to_string(&arg.input_type);
                    format!("${}: {}", arg.name, type_str)
                })
                .collect();

            // Build argument usage
            let arg_usage: Vec<String> = field
                .args
                .iter()
                .map(|arg| format!("{}: ${}", arg.name, arg.name))
                .collect();

            let mut output = String::new();

            // Add variable comment
            output.push_str("# Variables:\n");
            for arg in &field.args {
                let default = self.get_default_value(&arg.input_type);
                output.push_str(&format!("#   {}: {}\n", arg.name, default));
            }
            output.push('\n');

            if selection.is_empty() {
                output.push_str(&format!(
                    "{}({}) {{\n  {}({})\n}}\n",
                    operation,
                    var_defs.join(", "),
                    field.name,
                    arg_usage.join(", ")
                ));
            } else {
                output.push_str(&format!(
                    "{}({}) {{\n  {}({}) {}\n}}\n",
                    operation,
                    var_defs.join(", "),
                    field.name,
                    arg_usage.join(", "),
                    selection
                ));
            }

            output
        }
    }

    fn type_ref_to_string(&self, type_ref: &TypeRef) -> String {
        match type_ref.kind.as_str() {
            "NON_NULL" => {
                if let Some(ref of_type) = type_ref.of_type {
                    format!("{}!", self.type_ref_to_string(of_type))
                } else {
                    "String!".to_string()
                }
            }
            "LIST" => {
                if let Some(ref of_type) = type_ref.of_type {
                    format!("[{}]", self.type_ref_to_string(of_type))
                } else {
                    "[String]".to_string()
                }
            }
            _ => type_ref.name.clone().unwrap_or_else(|| "String".to_string()),
        }
    }

    fn get_default_value(&self, type_ref: &TypeRef) -> String {
        match type_ref.kind.as_str() {
            "NON_NULL" | "LIST" => {
                if let Some(ref of_type) = type_ref.of_type {
                    self.get_default_value(of_type)
                } else {
                    "null".to_string()
                }
            }
            "SCALAR" => {
                let name = type_ref.name.as_deref().unwrap_or("String");
                match name {
                    "String" | "ID" => "\"example\"".to_string(),
                    "Int" => "0".to_string(),
                    "Float" => "0.0".to_string(),
                    "Boolean" => "false".to_string(),
                    _ => "\"\"".to_string(),
                }
            }
            "ENUM" => {
                let name = type_ref.name.as_deref().unwrap_or("");
                if let Some(enum_type) = self.schema.get_type(name) {
                    if let Some(values) = &enum_type.enum_values {
                        if let Some(first) = values.first() {
                            return first.name.clone();
                        }
                    }
                }
                "ENUM_VALUE".to_string()
            }
            "INPUT_OBJECT" => "{...}".to_string(),
            _ => "null".to_string(),
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

        let indent = "    ".repeat(depth + 1);
        let close_indent = "    ".repeat(depth);

        let field_strs: Vec<String> = fields
            .iter()
            .filter(|f| !f.name.starts_with("__"))
            .take(10)
            .map(|f| {
                let sub = self.build_field_selection(&f.field_type, depth + 1, visited);
                if sub.is_empty() {
                    format!("{}{}", indent, f.name)
                } else {
                    format!("{}{} {}", indent, f.name, sub)
                }
            })
            .collect();

        visited.remove(base_name);

        if field_strs.is_empty() {
            String::new()
        } else {
            format!("{{\n{}\n{}}}", field_strs.join("\n"), close_indent)
        }
    }
}

#[derive(Default)]
pub struct ExportStats {
    pub queries: usize,
    pub mutations: usize,
}
