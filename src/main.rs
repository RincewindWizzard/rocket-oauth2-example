mod github_api;
mod timeout_set;
mod session;
mod config;

#[macro_use]
extern crate rocket;

use crate::session::Session;
use std::sync::Arc;
use std::env;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use rocket::{Config, Request, Rocket, State};
use rocket::figment::Figment;
use rocket::fs::FileServer;
use rocket::fs::relative;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::http::uri::Query;
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use serde::Deserialize;
use oauth2::reqwest::async_http_client;
use crate::github_api::{GithubClient, User};
use std::collections::HashMap;
use oauth2::basic::BasicTokenResponse;
use rocket::futures::lock::Mutex;
use rocket::request::{FromRequest, Outcome};
use uuid::Uuid;
use crate::session::SessionManager;
use crate::timeout_set::TimeoutSet;

const CSRF_TIMEOUT: Duration = Duration::from_secs(60 * 10);

type OAuth = oauth2::basic::BasicClient;

#[derive(Debug, Clone)]
struct SessionData {
    // pkce_verifier: Option<PkceCodeVerifier>,
    csrf_token: Option<CsrfToken>,
    github_api_token: Option<String>,
    visits: i64,
    user: Option<User>,
}

impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            csrf_token: None,
            github_api_token: None,
            visits: 0,
            user: None,
        }
    }
}


#[get("/auth/github?<code>&<state>")]
async fn github_callback(oauth: &State<OAuth>, mut session: Session<SessionData>, code: &str, state: &str) -> Redirect
{
    let token = oauth
        .exchange_code(AuthorizationCode::new(code.to_string()))
        // .set_pkce_verifier(csrf_token)
        .request_async(async_http_client)
        .await;

    let token = match token {
        Err(e) => {
            warn!("Could not retrieve token: {:?}", e);
            return Redirect::to("/");
        }
        Ok(token) => { token.access_token().secret().clone() }
    };


    let github = GithubClient::new(&token);
    let user = github.get_user().await.ok();

    info!("Github token {} for user {} retrieved.", token, user.clone().map(|user| user.login).unwrap_or("".to_string()));

    {
        let mut session_data = session.value.lock().await;
        session_data.github_api_token = Some(token);
        session_data.user = user;
    }

    Redirect::to("/")
}

#[get("/login/github")]
fn github_login(oauth: &State<OAuth>, session: Session<SessionData>) -> Redirect {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (github_auth_url, csrf_token) = oauth.authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Redirect::to(github_auth_url.to_string())
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("sid"));
    Redirect::to("/")
}


#[get("/")]
async fn index(mut session: Session<SessionData>) -> Template {
    let session_data = {
        let mut session_data = session.value.lock().await;
        session_data.visits = session_data.visits + 1;
            session_data.clone()
    };
    info!("Session: {:?}", session_data);

    let username = session_data.user.map(|user| user.login);

    Template::render("index", context! {
        logged_in: username.is_some(),
        username: username.unwrap_or("".to_string()),
    })
}


#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let oauth2 = config::oauth2_client(figment).expect("OAuth2 config could not be loaded!");

    rocket
        .manage::<OAuth>(oauth2)
        .manage::<SessionManager<SessionData>>(SessionManager::default())
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index,  logout, github_login, github_callback])
        .attach(Template::fairing())
}