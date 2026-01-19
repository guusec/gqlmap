use crate::http::HttpClient;
use crate::tests::is_graphql_endpoint;
use anyhow::Result;
use url::Url;

const DEFAULT_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/playground",
    "/console",
    "/query",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/api/gql",
    "/graph",
    "/api",
];

pub struct EndpointDiscovery {
    base_url: Url,
    paths: Vec<String>,
}

impl EndpointDiscovery {
    pub fn new(base_url: &str, custom_wordlist: Option<Vec<String>>) -> Result<Self> {
        let base_url = Url::parse(base_url)?;

        let paths = match custom_wordlist {
            Some(list) => list,
            None => DEFAULT_PATHS.iter().map(|s| s.to_string()).collect(),
        };

        Ok(Self { base_url, paths })
    }

    pub async fn discover(&self, client: &HttpClient) -> Vec<String> {
        let mut found = Vec::new();

        for path in &self.paths {
            let mut url = self.base_url.clone();
            url.set_path(path);
            let url_str = url.to_string();

            match is_graphql_endpoint(client, &url_str).await {
                Ok(true) => {
                    found.push(url_str);
                }
                _ => {}
            }
        }

        found
    }
}

pub fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let paths: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            if line.starts_with('/') {
                line.to_string()
            } else {
                format!("/{}", line)
            }
        })
        .collect();
    Ok(paths)
}
