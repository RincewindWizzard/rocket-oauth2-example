use anyhow::anyhow;

const GITHUB_API_GATEWAY: &str = "https://api.github.com/";
const USER_AGENT: &str = "rocket-web-oauth2-example";
const MIMETYPE_JSON: &str = "application/vnd.github+json";
const X_GIT_HUB_API_VERSION: &str = "2022-11-28";

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub login: String,
    pub avatar_url: String,
    pub name: String,
    pub location: String,
    pub email: String,
}


impl User {
    fn parse(doc: Value) -> Option<User> {
        Some(User {
            login: doc.get("login")?.to_string(),
            avatar_url: doc.get("avatar_url")?.to_string(),
            name: doc.get("name")?.to_string(),
            location: doc.get("location")?.to_string(),
            email: doc.get("email")?.to_string(),
        })
    }
}


pub struct GithubClient {
    access_token: String,
    http: reqwest::Client,
}

impl GithubClient {
    pub fn new(token: &str) -> GithubClient {
        let http = reqwest::Client::new();
        GithubClient {
            access_token: token.to_string(),
            http,
        }
    }


    pub async fn get_user(&self) -> Result<User, anyhow::Error> {
        let response = self.http
            .get(format!("{}{}", GITHUB_API_GATEWAY, "user"))
            .header("user-agent", USER_AGENT)
            .header("Accept", MIMETYPE_JSON)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("X-GitHub-Api-Version", X_GIT_HUB_API_VERSION)
            .send()
            .await?;

        let doc = response.json::<Value>().await?;

        let user = User::parse(doc).ok_or(anyhow!("Could not parse response!"))?;
        Ok(user)
    }
}

