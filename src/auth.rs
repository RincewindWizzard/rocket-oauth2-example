
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use oauth2::reqwest::async_http_client;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::State;
use serde_derive::Deserialize;
use crate::{SessionData};
use crate::github_api::GithubClient;
use crate::session::Session;

pub type OAuth = oauth2::basic::BasicClient;


#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_uri: String,
}

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


#[get("/auth/github?<code>&<state>")]
pub async fn github_callback(oauth: &State<OAuth>, session: Session<SessionData>, code: &str, state: &str) -> Redirect
{
    let (csrf_token, pkce_verifier) = {
        let mut session_data = session.get_value().await;
        (session_data.csrf_token.take(), session_data.pkce_verifier.take())
    };


    match csrf_token {
        None => {
            warn!("[{}] No known csrf_token!", session.get_id());
            return Redirect::to("/");
        }
        Some(csrf_token) => {
            if state != csrf_token.secret() {
                warn!("[{}] csrf_token mismatch!", session.get_id());
                return Redirect::to("/");
            }
        }
    }


    match pkce_verifier {
        None => {
            warn!("[{}] Could not validate pkce_verifier!", session.get_id());
            return Redirect::to("/");
        }
        Some(pkce_verifier) => {
            let token = oauth
                .exchange_code(AuthorizationCode::new(code.to_string()))
                .set_pkce_verifier(pkce_verifier)
                .request_async(async_http_client)
                .await;

            match token {
                Err(e) => {
                    warn!("Could not retrieve token: {:?}", e);
                    return Redirect::to("/");
                }
                Ok(token) => {
                    let github = GithubClient::new(&token.access_token());
                    let user = github.get_user().await.ok();

                    {
                        let mut session_data = session.get_value().await;
                        session_data.github_api_token = Some(token);
                        session_data.user = user;
                    }
                }
            }
        }
    }
    Redirect::to("/")
}

#[get("/login/github")]
pub async fn github_login(oauth: &State<OAuth>, session: Session<SessionData>) -> Redirect {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (github_auth_url, csrf_token) = oauth.authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    {
        let mut session_data = session.get_value().await;
        session_data.pkce_verifier = Some(pkce_verifier);
        session_data.csrf_token = Some(csrf_token);
    }

    Redirect::to(github_auth_url.to_string())
}

#[get("/logout")]
pub fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("sid"));
    Redirect::to("/")
}