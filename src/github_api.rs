use anyhow::anyhow;
use oauth2::AccessToken;

const GITHUB_API_GATEWAY: &str = "https://api.github.com/";
const USER_AGENT: &str = "rocket-web-oauth2-example";
const MIMETYPE_JSON: &str = "application/vnd.github+json";
const X_GIT_HUB_API_VERSION: &str = "2022-11-28";

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

/// Excerpt User data from the Github API
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub login: String,
    pub avatar_url: String,
    pub name: String,
    pub location: String,
    pub email: String,
}


impl User {
    /// Parse the excerpt user from the github response
    fn parse(doc: Value) -> Option<User> {
        let login = doc.get("login")?.to_string();
        let login = login.trim_matches(|c: char| c == '"' || c.is_whitespace());

        Some(User {
            login: login.to_string(),
            avatar_url: doc.get("avatar_url")?.to_string(),
            name: doc.get("name")?.to_string(),
            location: doc.get("location")?.to_string(),
            email: doc.get("email")?.to_string(),
        })
    }
}

/// A minimal Github API Client to retrieve some userdata from the REST API.
pub struct GithubClient {
    access_token: AccessToken,
    http: reqwest::Client,
}

impl GithubClient {
    pub fn new(token: &AccessToken) -> GithubClient {
        let http = reqwest::Client::new();
        GithubClient {
            access_token: token.clone(),
            http,
        }
    }

    /// Returns information about the currently authenticated user.
    pub async fn get_user(&self) -> Result<User, anyhow::Error> {
        let response = self.http
            .get(format!("{}{}", GITHUB_API_GATEWAY, "user"))
            .header("user-agent", USER_AGENT)
            .header("Accept", MIMETYPE_JSON)
            .header("Authorization", format!("Bearer {}", self.access_token.secret()))
            .header("X-GitHub-Api-Version", X_GIT_HUB_API_VERSION)
            .send()
            .await?;

        let doc = response.json::<Value>().await?;

        let user = User::parse(doc).ok_or(anyhow!("Could not parse response!"))?;
        Ok(user)
    }
}

