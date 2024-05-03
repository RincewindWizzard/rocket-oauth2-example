mod github_api;
mod timeout_set;
mod stash;
mod session;

#[macro_use]
extern crate rocket;

use crate::session::Session;
use std::sync::Arc;
use std::env;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use oauth2::basic::BasicClient;
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
use crate::github_api::GithubClient;
use std::collections::HashMap;
use rocket::futures::lock::Mutex;
use rocket::request::{FromRequest, Outcome};
use uuid::Uuid;
use crate::session::SessionManager;
use crate::timeout_set::TimeoutSet;

const CSRF_TIMEOUT: Duration = Duration::from_secs(60 * 10);

#[derive(Debug)]
struct ApplicationState {
    oauth2: BasicClient,
    // sessions: SessionManager<SessionData>,
}


#[derive(Debug)]
struct SessionData {
    // pkce_verifier: Option<PkceCodeVerifier>,
    // csrf_token: Option<CsrfToken>,
    foo: i64,
}

impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            foo: 0,
        }
    }
}


#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("token"));
    cookies.remove_private(Cookie::build("username"));
    Redirect::to("/")
}

#[get("/")]
async fn index(cookies: &CookieJar<'_>, mut session: Session<SessionData>) -> Template {
    let foo = {
        let mut session_data = session.value.lock().await;
        session_data.foo = session_data.foo + 1;
        session_data.foo
    };
    info!("Session: {:?}", foo);

    Template::render("index", context! {
        logged_in: false,
        username: "",
    })
}

#[derive(Debug, Deserialize)]
struct OAuthConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    token_url: String,
}


fn oauth2_client(figment: &Figment) -> Result<BasicClient, anyhow::Error> {
    let conf = figment.find_value("oauth.github")?;
    let conf = conf.as_dict().ok_or(anyhow!("ffo"))?;

    println!("conf: {conf:?}");

    let client_id = conf["client_id"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let client_secret = conf["client_secret"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let auth_url = conf["auth_url"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let redirect_uri = conf["redirect_uri"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let token_url = conf["token_url"].as_str().ok_or(anyhow!("Cannot parse config!"))?;

    Ok(BasicClient::new(
        oauth2::ClientId::new(client_id.to_string()),
        Some(oauth2::ClientSecret::new(client_secret.to_string())),
        oauth2::AuthUrl::new(auth_url.to_string())?,
        Some(oauth2::TokenUrl::new(token_url.to_string())?),
    ).set_redirect_uri(oauth2::RedirectUrl::new(redirect_uri.to_string())?))
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let oauth2 = oauth2_client(figment).expect("OAuth2 config could not be loaded!");

    println!("Oauth2: {:?}", oauth2);


    rocket
        .manage(ApplicationState {
            oauth2,
        })
        .manage::<SessionManager<SessionData>>(SessionManager::default())
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index,  logout])
        .attach(Template::fairing())
}