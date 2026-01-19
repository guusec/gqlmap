use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use gqlmap::discovery::{load_wordlist, EndpointDiscovery};
use gqlmap::export::{BrunoExporter, CurlExporter, InqlExporter, PostmanExporter};
use gqlmap::http::HttpClient;
use gqlmap::schema::{default_wordlist, fetch_schema_raw, load_wordlist as load_inference_wordlist, SchemaInferrer};
use gqlmap::tests::{all_tests, is_graphql_endpoint, Severity, TestResult};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_banner() {
    println!("{}", "   __________    __    __  ___          ".bright_magenta());
    println!("{}", "  / ____/ __ \\  / /   /  |/  /___ _____ ".bright_magenta());
    println!("{}", " / / __/ / / / / /   / /|_/ / __ `/ __ \\".bright_magenta());
    println!("{}", "/ /_/ / /_/ / / /___/ /  / / /_/ / /_/ /".bright_magenta());
    println!("{}", "\\____/\\___\\_\\/_____/_/  /_/\\__,_/ .___/ ".bright_magenta());
    println!("{}", "                               /_/      ".bright_magenta());
    println!(
        "  {} {}\n",
        "GraphQL Security Scanner".bold().white(),
        format!("v{}", VERSION).dimmed()
    );
}

#[derive(Parser)]
#[command(name = "gqlmap")]
#[command(author = "giuseppesec")]
#[command(version = VERSION)]
#[command(about = "a cli tool for testing graphql that does more than one thing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run security tests against a GraphQL endpoint
    Scan {
        /// Target GraphQL endpoint URL
        #[arg(short, long)]
        target: String,

        /// Custom HTTP headers (can be repeated)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// HTTP/HTTPS/SOCKS proxy URL
        #[arg(short = 'x', long)]
        proxy: Option<String>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Exclude specific tests (comma-separated)
        #[arg(short, long)]
        exclude: Option<String>,

        /// Enable debug mode (adds test headers)
        #[arg(short, long)]
        debug: bool,

        /// Force scan even if GraphQL not detected
        #[arg(short, long)]
        force: bool,

        /// Discover GraphQL endpoints on domain
        #[arg(long)]
        discover: bool,

        /// Custom wordlist for endpoint discovery
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// List available tests
        #[arg(short, long)]
        list_tests: bool,
    },

    /// Fetch and save introspection schema
    Introspect {
        /// Target GraphQL endpoint URL
        #[arg(short, long)]
        target: String,

        /// Custom HTTP headers
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// HTTP/HTTPS/SOCKS proxy URL
        #[arg(short = 'x', long)]
        proxy: Option<String>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Infer schema when introspection is disabled (clairvoyance mode)
    Infer {
        /// Target GraphQL endpoint URL
        #[arg(short, long)]
        target: String,

        /// Custom HTTP headers
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// HTTP/HTTPS/SOCKS proxy URL
        #[arg(short = 'x', long)]
        proxy: Option<String>,

        /// Wordlist file for field/type discovery
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// Output file path for inferred schema
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export schema to API client formats
    Export {
        #[command(subcommand)]
        format: ExportFormat,
    },
}

#[derive(Subcommand)]
enum ExportFormat {
    /// Export to Bruno collection
    Bruno {
        /// Path to introspection JSON schema file
        #[arg(short, long)]
        schema: PathBuf,

        /// Output directory for Bruno collection
        #[arg(short, long)]
        output: PathBuf,

        /// Base URL for requests
        #[arg(short, long)]
        url: String,
    },

    /// Export to Postman collection
    Postman {
        /// Path to introspection JSON schema file
        #[arg(short, long)]
        schema: PathBuf,

        /// Output JSON file path
        #[arg(short, long)]
        output: PathBuf,

        /// Base URL for requests
        #[arg(short, long)]
        url: String,
    },

    /// Export to executable cURL script
    Curl {
        /// Path to introspection JSON schema file
        #[arg(short, long)]
        schema: PathBuf,

        /// Output shell script path
        #[arg(short, long)]
        output: PathBuf,

        /// Base URL for requests
        #[arg(short, long)]
        url: String,
    },

    /// Export to InQL/Burp format (GraphQL files)
    Inql {
        /// Path to introspection JSON schema file
        #[arg(short, long)]
        schema: PathBuf,

        /// Output directory for GraphQL files
        #[arg(short, long)]
        output: PathBuf,

        /// Base URL for requests
        #[arg(short, long)]
        url: String,
    },
}

fn parse_headers(headers: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for header in headers {
        // Try JSON format first: {"Authorization": "Bearer token"}
        if header.starts_with('{') {
            let parsed: HashMap<String, String> =
                serde_json::from_str(header).context("Invalid JSON header format")?;
            map.extend(parsed);
        } else if let Some((key, value)) = header.split_once(':') {
            // Standard format: "Authorization: Bearer token"
            map.insert(key.trim().to_string(), value.trim().to_string());
        } else {
            bail!("Invalid header format: {}", header);
        }
    }

    Ok(map)
}

fn print_result(result: &TestResult) {
    if !result.vulnerable {
        return;
    }

    let severity = match result.severity {
        Severity::High => format!("[{}]", result.severity).red().bold(),
        Severity::Medium => format!("[{}]", result.severity).yellow().bold(),
        Severity::Low => format!("[{}]", result.severity).blue().bold(),
        Severity::Info => format!("[{}]", result.severity).green().bold(),
    };

    println!(
        "{} {} - {}",
        severity,
        result.title.bold(),
        result.description
    );
    println!("    Impact: {}", result.impact);
    println!("    Verify: {}", result.curl_command.dimmed());
    println!();
}

fn print_results_json(results: &[TestResult]) {
    let output = serde_json::to_string_pretty(results).unwrap_or_default();
    println!("{}", output);
}

async fn run_scan(
    target: String,
    headers: Vec<String>,
    proxy: Option<String>,
    output: String,
    exclude: Option<String>,
    debug: bool,
    force: bool,
    discover: bool,
    wordlist: Option<PathBuf>,
    list_tests: bool,
) -> Result<()> {
    let tests = all_tests();

    if list_tests {
        println!("Available security tests:\n");
        for test in &tests {
            println!(
                "  {} [{}] - {}",
                test.name(),
                test.severity(),
                test.description()
            );
        }
        return Ok(());
    }

    print_banner();

    let headers_map = parse_headers(&headers)?;
    let client = HttpClient::new(proxy.as_deref(), headers_map, debug)?;

    let excluded: Vec<&str> = exclude
        .as_deref()
        .map(|e| e.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();

    // Determine target URLs
    let targets: Vec<String> = if discover {
        println!("{} Discovering GraphQL endpoints...\n", "[*]".cyan());

        let custom_paths = wordlist
            .map(|p| load_wordlist(p.to_str().unwrap()))
            .transpose()?;

        let discovery = EndpointDiscovery::new(&target, custom_paths)?;
        let found = discovery.discover(&client).await;

        if found.is_empty() {
            println!("{} No GraphQL endpoints found", "[-]".red());
            return Ok(());
        }

        println!("{} Found {} endpoint(s):\n", "[+]".green(), found.len());
        for url in &found {
            println!("    {}", url);
        }
        println!();

        found
    } else {
        vec![target]
    };

    for url in targets {
        println!("{} Target: {}\n", "[*]".cyan(), url);

        // Check if GraphQL endpoint
        if !force {
            match is_graphql_endpoint(&client, &url).await {
                Ok(true) => {
                    println!("{} GraphQL endpoint detected\n", "[+]".green());
                }
                Ok(false) => {
                    println!(
                        "{} GraphQL not detected at this URL (use -f to force)",
                        "[-]".red()
                    );
                    continue;
                }
                Err(e) => {
                    println!("{} Detection failed: {}", "[-]".red(), e);
                    continue;
                }
            }
        }

        // Run tests
        let mut results = Vec::new();
        let active_tests: Vec<_> = tests
            .iter()
            .filter(|t| !excluded.contains(&t.name()))
            .collect();

        println!(
            "{} Running {} security tests...\n",
            "[*]".cyan(),
            active_tests.len()
        );

        for test in active_tests {
            match test.run(&client, &url).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    if debug {
                        eprintln!("{} Test {} failed: {}", "[-]".red(), test.name(), e);
                    }
                }
            }
        }

        // Sort by severity
        results.sort_by(|a, b| {
            let severity_order = |s: &Severity| match s {
                Severity::High => 0,
                Severity::Medium => 1,
                Severity::Low => 2,
                Severity::Info => 3,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        // Output results
        match output.as_str() {
            "json" => print_results_json(&results),
            _ => {
                let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

                if vulnerable_count == 0 {
                    println!("{} No vulnerabilities found", "[+]".green());
                } else {
                    println!(
                        "{} Found {} issue(s):\n",
                        "[!]".yellow(),
                        vulnerable_count
                    );
                    for result in &results {
                        print_result(result);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_introspect(
    target: String,
    headers: Vec<String>,
    proxy: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    print_banner();

    let headers_map = parse_headers(&headers)?;
    let client = HttpClient::new(proxy.as_deref(), headers_map, false)?;

    println!("{} Fetching introspection from {}...\n", "[*]".cyan(), target);

    let schema = fetch_schema_raw(&client, &target).await?;

    let json_output = serde_json::to_string_pretty(&schema)?;

    match output {
        Some(path) => {
            std::fs::write(&path, &json_output)?;
            println!("{} Schema saved to {}", "[+]".green(), path.display());
        }
        None => {
            println!("{}", json_output);
        }
    }

    Ok(())
}

async fn run_infer(
    target: String,
    headers: Vec<String>,
    proxy: Option<String>,
    wordlist: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    print_banner();

    let headers_map = parse_headers(&headers)?;
    let client = HttpClient::new(proxy.as_deref(), headers_map, false)?;

    println!(
        "{} Inferring schema from {} (introspection disabled mode)...\n",
        "[*]".cyan(),
        target
    );

    // Load wordlist
    let words = match wordlist {
        Some(path) => {
            println!(
                "{} Loading wordlist from {}...",
                "[*]".cyan(),
                path.display()
            );
            load_inference_wordlist(path.to_str().unwrap())?
        }
        None => {
            println!("{} Using built-in wordlist ({} words)...", "[*]".cyan(), default_wordlist().len());
            default_wordlist()
        }
    };

    let mut inferrer = SchemaInferrer::new(client, target.clone(), words);

    let callback = |msg: &str| {
        println!("{} {}", "[*]".cyan(), msg);
    };

    let schema = inferrer.infer(Some(&callback)).await?;

    // Count discovered items
    let query_fields = schema.query_type.as_ref().map(|t| t.fields.len()).unwrap_or(0);
    let mutation_fields = schema.mutation_type.as_ref().map(|t| t.fields.len()).unwrap_or(0);
    let total_types = schema.types.len();

    println!();
    println!(
        "{} Discovered: {} query fields, {} mutation fields, {} types",
        "[+]".green(),
        query_fields,
        mutation_fields,
        total_types
    );

    // Convert to introspection format
    let introspection_format = inferrer.to_introspection_format(&schema);
    let json_output = serde_json::to_string_pretty(&introspection_format)?;

    match output {
        Some(path) => {
            std::fs::write(&path, &json_output)?;
            println!("{} Inferred schema saved to {}", "[+]".green(), path.display());
        }
        None => {
            println!("\n{}", json_output);
        }
    }

    Ok(())
}

async fn run_export_bruno(schema_path: PathBuf, output: PathBuf, url: String) -> Result<()> {
    print_banner();

    println!("{} Loading schema from {}...", "[*]".cyan(), schema_path.display());

    let schema_content = std::fs::read_to_string(&schema_path)
        .context("Failed to read schema file")?;

    let schema_json: Value = serde_json::from_str(&schema_content)
        .context("Failed to parse schema JSON")?;

    // Handle both {"data": {...}} and direct schema format
    let schema_data = if let Some(data) = schema_json.get("data") {
        data.clone()
    } else {
        schema_json
    };

    let schema: gqlmap::schema::Schema = serde_json::from_value(schema_data)
        .context("Failed to parse introspection schema")?;

    let exporter = BrunoExporter::new(schema, url);
    let stats = exporter.export(&output)?;

    println!(
        "{} Exported {} queries and {} mutations to {}",
        "[+]".green(),
        stats.queries,
        stats.mutations,
        output.display()
    );

    Ok(())
}

async fn run_export_postman(schema_path: PathBuf, output: PathBuf, url: String) -> Result<()> {
    print_banner();

    println!("{} Loading schema from {}...", "[*]".cyan(), schema_path.display());

    let schema_content = std::fs::read_to_string(&schema_path)
        .context("Failed to read schema file")?;

    let schema_json: Value = serde_json::from_str(&schema_content)
        .context("Failed to parse schema JSON")?;

    let schema_data = if let Some(data) = schema_json.get("data") {
        data.clone()
    } else {
        schema_json
    };

    let schema: gqlmap::schema::Schema = serde_json::from_value(schema_data)
        .context("Failed to parse introspection schema")?;

    let exporter = PostmanExporter::new(schema, url);
    let collection = exporter.export()?;

    let json_output = serde_json::to_string_pretty(&collection)?;
    std::fs::write(&output, json_output)?;

    let query_count: usize = collection.item.iter()
        .filter(|f| f.name == "Queries")
        .map(|f| f.item.len())
        .sum();
    let mutation_count: usize = collection.item.iter()
        .filter(|f| f.name == "Mutations")
        .map(|f| f.item.len())
        .sum();

    println!(
        "{} Exported {} queries and {} mutations to {}",
        "[+]".green(),
        query_count,
        mutation_count,
        output.display()
    );

    Ok(())
}

async fn run_export_curl(schema_path: PathBuf, output: PathBuf, url: String) -> Result<()> {
    print_banner();

    println!("{} Loading schema from {}...", "[*]".cyan(), schema_path.display());

    let schema_content = std::fs::read_to_string(&schema_path)
        .context("Failed to read schema file")?;

    let schema_json: Value = serde_json::from_str(&schema_content)
        .context("Failed to parse schema JSON")?;

    let schema_data = if let Some(data) = schema_json.get("data") {
        data.clone()
    } else {
        schema_json
    };

    let schema: gqlmap::schema::Schema = serde_json::from_value(schema_data)
        .context("Failed to parse introspection schema")?;

    let exporter = CurlExporter::new(schema, url);
    let stats = exporter.export(&output)?;

    println!(
        "{} Exported {} queries and {} mutations to {}",
        "[+]".green(),
        stats.queries,
        stats.mutations,
        output.display()
    );

    Ok(())
}

async fn run_export_inql(schema_path: PathBuf, output: PathBuf, url: String) -> Result<()> {
    print_banner();

    println!("{} Loading schema from {}...", "[*]".cyan(), schema_path.display());

    let schema_content = std::fs::read_to_string(&schema_path)
        .context("Failed to read schema file")?;

    let schema_json: Value = serde_json::from_str(&schema_content)
        .context("Failed to parse schema JSON")?;

    let schema_data = if let Some(data) = schema_json.get("data") {
        data.clone()
    } else {
        schema_json
    };

    let schema: gqlmap::schema::Schema = serde_json::from_value(schema_data)
        .context("Failed to parse introspection schema")?;

    let exporter = InqlExporter::new(schema, url);
    let stats = exporter.export(&output)?;

    println!(
        "{} Exported {} queries and {} mutations to {}",
        "[+]".green(),
        stats.queries,
        stats.mutations,
        output.display()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            headers,
            proxy,
            output,
            exclude,
            debug,
            force,
            discover,
            wordlist,
            list_tests,
        } => {
            run_scan(
                target, headers, proxy, output, exclude, debug, force, discover, wordlist,
                list_tests,
            )
            .await
        }
        Commands::Introspect {
            target,
            headers,
            proxy,
            output,
        } => run_introspect(target, headers, proxy, output).await,
        Commands::Infer {
            target,
            headers,
            proxy,
            wordlist,
            output,
        } => run_infer(target, headers, proxy, wordlist, output).await,
        Commands::Export { format } => match format {
            ExportFormat::Bruno { schema, output, url } => {
                run_export_bruno(schema, output, url).await
            }
            ExportFormat::Postman { schema, output, url } => {
                run_export_postman(schema, output, url).await
            }
            ExportFormat::Curl { schema, output, url } => {
                run_export_curl(schema, output, url).await
            }
            ExportFormat::Inql { schema, output, url } => {
                run_export_inql(schema, output, url).await
            }
        },
    }
}
