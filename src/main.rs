mod github_api;
mod timeout_set;

#[macro_use]
extern crate rocket;

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
use crate::timeout_set::TimeoutSet;

const CSRF_TIMEOUT: Duration = Duration::from_secs(60 * 10);

#[derive(Debug)]
struct ApplicationState {
    oauth2: BasicClient,
    sessions: Mutex<HashMap<Uuid, Session>>,
}

impl ApplicationState {
    // fn add_session(&mut self, session: Session) {
    //     self.sessions.insert(session.id, session);
    // }

    // fn get_or_create_session(&self, sid: Option<String>) -> &Session {
    //     let sid = sid
    //         .map(|sid| Uuid::parse_str(&sid).ok())
    //         .flatten()
    //         .unwrap_or_else(|| { Uuid::new_v4() });
    //
    //     let mut sessions = &mut self.sessions;
    //
    //     let session = sessions.entry(sid).or_insert_with(|| Session::new());
    //     session
    // }
}

#[derive(Debug, Clone)]
struct Session {
    id: Uuid,
    // pkce_verifier: Option<PkceCodeVerifier>,
    // csrf_token: Option<CsrfToken>,
}

impl Session {
    fn new() -> Session {
        Session {
            id: Uuid::new_v4(),
            // pkce_verifier: None,
            // csrf_token: None,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Session {
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(application_state) = request.guard::<&State<ApplicationState>>().await {
            let sid = request
                .cookies()
                .get_private("sid")
                .map(|c| c.value().to_string())
                .map(|sid| Uuid::parse_str(&*sid).ok())
                .flatten()
                .unwrap_or_else(|| Uuid::new_v4());

            let mut sessions = application_state.sessions.lock().await;

            if !sessions.contains_key(&sid) {
                sessions.insert(sid, Session {
                    id: sid,
                });
            }

            if let Some(session) = sessions.get(&sid) {
                request.cookies().add_private(
                    Cookie::build(("sid", session.id.to_string()))
                        .same_site(SameSite::Lax)
                        .build()
                );

                Outcome::Success((*session).clone())
            } else {
                Outcome::Error((Status::InternalServerError, anyhow!("Could not get the session from application state!")))
            }
        } else {
            Outcome::Error((Status::InternalServerError, anyhow!("Could not get application state!")))
        }
    }
}


#[get("/login/github")]
fn github_login(application_state: &State<ApplicationState>, cookies: &CookieJar<'_>) -> Redirect {
    // let oauth2 = &application_state.oauth2;
    //
    // let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    //
    // let (github_auth_url, csrf_token) = oauth2.authorize_url(CsrfToken::new_random)
    //     .add_scope(Scope::new("user:read".to_string()))
    //     .set_pkce_challenge(pkce_challenge)
    //     .url();
    //
    //
    // application_state.pkce_verifiers.insert(pkce_verifier, CSRF_TIMEOUT);
    //
    // // application_state.csrf_tokens.insert(csrf_token.secret().to_string());
    //
    //
    // // save the csrf token as secret cookie in the client
    // // I am not really sure if this best practice
    // // cookies.add_private(
    // //     Cookie::build(("csrf", pkce_verifier.secret()))
    // //         .same_site(SameSite::Lax)
    // //         .build());
    //
    // Redirect::to(github_auth_url.to_string())
    Redirect::to("/")
}


#[get("/auth/github?<code>&<state>")]
async fn github_callback(application_state: &State<ApplicationState>, cookies: &CookieJar<'_>, code: &str, state: &str) -> Redirect
{
    // let oauth2 = &application_state.oauth2;
    // let csrf_token = application_state.csrf_tokens.pop(&state.to_string()).map(|s| PkceCodeVerifier(s));
    //
    // if let Some(csrf_token) = csrf_token {
    //     let token = oauth2
    //         .exchange_code(AuthorizationCode::new(code.to_string()))
    //         .set_pkce_verifier(csrf_token)
    //         .request_async(async_http_client)
    //         .await;
    //
    //     if let Ok(token) = token {
    //         let token = token.access_token().secret().clone();
    //
    //         cookies.add_private(
    //             Cookie::build(("token", token.clone()))
    //                 .same_site(SameSite::Lax)
    //                 .build()
    //         );
    //
    //         let github = GithubClient::new(&token);
    //         if let Ok(user) = github.get_user().await {
    //             debug!("Welcome {:?}", user);
    //             info!("Welcome {:?}", user.login);
    //             cookies.add_private(
    //                 Cookie::build(("username", user.login))
    //                     .same_site(SameSite::Lax)
    //                     .build()
    //             );
    //         } else {
    //             warn!("Could not retrieve username!");
    //         };
    //     } else {
    //         warn!("Could not retrieve token!");
    //     }
    // }
    //

    Redirect::to("/")
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("token"));
    cookies.remove_private(Cookie::build("username"));
    Redirect::to("/")
}

#[get("/")]
fn index(cookies: &CookieJar<'_>, session: Session) -> Template {
    let logged_in = if let Some(_) = cookies.get_private("token") {
        true
    } else {
        false
    };


    let username = if let Some(cookie) = cookies.get_private("username") {
        let value = cookie.value_trimmed();
        Some(value.to_string())
    } else {
        None
    };

    Template::render("index", context! {
        logged_in: logged_in,
        username: username,
    })
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


#[derive(Debug, Deserialize)]
struct OAuthConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    token_url: String,
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
            sessions: Mutex::new(HashMap::new()),
        })
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index, github_callback, github_login, logout])
        .attach(Template::fairing())
}