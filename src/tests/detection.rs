use crate::http::HttpClient;
use anyhow::Result;

const DETECTION_QUERY: &str = "query { __typename }";

pub async fn is_graphql_endpoint(client: &HttpClient, url: &str) -> Result<bool> {
    let response = client.post_graphql(url, DETECTION_QUERY, None, Some("detection")).await?;

    if let Some(data) = response.get_data() {
        if let Some(typename) = data.get("__typename") {
            if let Some(name) = typename.as_str() {
                let valid_roots = ["Query", "QueryRoot", "query_root", "Root"];
                if valid_roots.contains(&name) {
                    return Ok(true);
                }
            }
        }
    }

    if let Some(errors) = response.get_errors() {
        if let Some(arr) = errors.as_array() {
            for error in arr {
                if error.get("locations").is_some() || error.get("extensions").is_some() {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
