use anyhow::anyhow;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse};
use oauth2::basic::BasicTokenResponse;
use oauth2::reqwest::async_http_client;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::Redirect;
use rocket::{Request, State};
use serde_derive::{Deserialize, Serialize};
use crate::github_api::GithubClient;
use crate::session::{Session, SessionManager};

pub type OAuth = oauth2::basic::BasicClient;


/// Excerpt User data from the Github API
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub login: String,
    pub avatar_url: String,
    pub name: String,
    pub location: String,
    pub email: String,
}


#[derive(Debug)]
pub struct SessionData {
    pkce_verifier: Option<PkceCodeVerifier>,
    csrf_token: Option<CsrfToken>,
    github_api_token: Option<BasicTokenResponse>,
    user: Option<User>,
}


impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            pkce_verifier: None,
            csrf_token: None,
            github_api_token: None,
            user: None,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User
{
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(session) = request.guard::<Session<SessionData>>().await {
            let user = &session.get_value().await.user;
            match user {
                None => {
                    Outcome::Forward(Status::Forbidden)
                }
                Some(user) => {
                    Outcome::Success(user.clone())
                }
            }
        } else {
            Outcome::Error((Status::InternalServerError, anyhow!("Could not get application state!")))
        }
    }
}

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


/// Redirects th Client to the Github Login Page.
/// Stores the pkce_challenge and csrf_token in the session data.
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


/// Callback after successfully logging in to Github.
/// Checks the  pkce_verifier and  csrf_token from the session.
/// Uses the Github REST API to get the username of the logged in user.
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


/// Removes the session id from the cookie and deletes the session from the session manager.
#[get("/logout")]
pub async fn logout(cookies: &CookieJar<'_>, manager: &State<SessionManager<SessionData>>, session: Session<SessionData>) -> Redirect
{
    cookies.remove_private(Cookie::build("sid"));
    manager.remove_session(session.get_id()).await;
    Redirect::to("/")
}