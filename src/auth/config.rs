use crate::auth::OAuth;
use serde_derive::Deserialize;


/// Configuration for OAuth. Can be parsed from Figment.
#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_uri: String,
}

/// Creates a new OAuth client from OAuthConfig.
impl TryFrom<OAuthConfig> for OAuth {
    type Error = anyhow::Error;

    fn try_from(oauth_config: OAuthConfig) -> Result<Self, Self::Error> {
        Ok(OAuth::new(
            oauth2::ClientId::new(oauth_config.client_id),
            Some(oauth2::ClientSecret::new(oauth_config.client_secret)),
            oauth2::AuthUrl::new(oauth_config.auth_url)?,
            Some(oauth2::TokenUrl::new(oauth_config.token_url)?),
        ).set_redirect_uri(oauth2::RedirectUrl::new(oauth_config.redirect_uri)?))
    }
}

