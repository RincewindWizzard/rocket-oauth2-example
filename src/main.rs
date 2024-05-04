mod github_api;
mod session;
mod config;
mod auth;

#[macro_use]
extern crate rocket;

use crate::auth::OAuthConfig;
use crate::auth::OAuth;
use rocket::fairing::{AdHoc, Fairing, Info, Kind};
use oauth2::{AccessToken, PkceCodeVerifier};
use crate::session::Session;
use std::sync::Arc;
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use anyhow::anyhow;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use rocket::{Build, Config, Data, Orbit, Request, Response, Rocket, State, tokio};
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


const MONTH: Duration = Duration::from_secs(60 * 60 * 24 * 28);


#[derive(Debug)]
struct SessionData {
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

#[get("/")]
async fn index(mut session: Session<SessionData>) -> Template {
    let context = {
        let mut session_data = session.get_value().await;

        let username = session_data.user
            .as_ref()
            .map(|x| x.login.clone())
            .unwrap_or("".to_string());


        context! {
            logged_in: session_data.user.is_some(),
            username: username,
        }
    };

    Template::render("index", context)
}


#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();

    let oauth2 = OAuth::try_from(
        figment
            .find_value("oauth.github")
            .expect("Could not find OAuth config in figment!")
            .deserialize::<OAuthConfig>()
            .expect("Could not parse OAuth config from figment!"))
        .expect("Could not initialize OAuth!");

    let sessions: SessionManager<SessionData> = SessionManager::new(MONTH);
    let session_fairing = sessions.fairing();

    rocket
        .manage::<OAuth>(oauth2)
        .manage::<SessionManager<SessionData>>(sessions)
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index,  auth::logout, auth::github_login, auth::github_callback])
        .attach(Template::fairing())
        .attach(session_fairing)
}