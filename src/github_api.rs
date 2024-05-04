use crate::auth::User;
use anyhow::anyhow;
use oauth2::AccessToken;

const GITHUB_API_GATEWAY: &str = "https://api.github.com/";
const USER_AGENT: &str = "rocket-web-oauth2-example";
const MIMETYPE_JSON: &str = "application/vnd.github+json";
const X_GIT_HUB_API_VERSION: &str = "2022-11-28";

use serde_json::Value;

impl TryFrom<Value> for User {
    type Error = anyhow::Error;

    fn try_from(doc: Value) -> Result<Self, Self::Error> {
        let login = doc
            .get("login")
            .ok_or(anyhow!("Could not get login name!"))?
            .to_string();

        let login = login.trim_matches(|c: char| c == '"' || c.is_whitespace());

        Ok(User {
            login: login.to_string(),
            avatar_url: doc.get("avatar_url").ok_or(anyhow!("Could not get avatar_url!"))?.to_string(),
            name: doc.get("name").ok_or(anyhow!("Could not get name!"))?.to_string(),
            location: doc.get("location").ok_or(anyhow!("Could not get location!"))?.to_string(),
            email: doc.get("email").ok_or(anyhow!("Could not get email!"))?.to_string(),
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

        let user = User::try_from(doc)?;
        Ok(user)
    }
}

