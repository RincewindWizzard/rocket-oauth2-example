mod github_api;

#[macro_use]
extern crate rocket;

use std::env;

use anyhow::anyhow;
use oauth2::basic::BasicClient;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use rocket::{Config, State};
use rocket::figment::Figment;
use rocket::fs::FileServer;
use rocket::fs::relative;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::http::uri::Query;
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use serde::Deserialize;
use oauth2::reqwest::async_http_client;
use crate::github_api::GithubClient;

#[derive(Debug)]
struct ApplicationState {
    oauth2: BasicClient,
}


#[get("/login/github")]
fn github_login(state: &State<ApplicationState>, cookies: &CookieJar<'_>) -> Redirect {
    let oauth2 = &state.oauth2;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (github_auth_url, csrf_token) = oauth2.authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Redirect::to(github_auth_url.to_string())
}


#[get("/auth/github?<code>&<state>")]
async fn github_callback(application_state: &State<ApplicationState>, cookies: &CookieJar<'_>, code: &str, state: &str) -> Redirect
{
    let oauth2 = &application_state.oauth2;

    let token = oauth2
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(async_http_client)
        .await;

    if let Ok(token) = token {
        let token = token.access_token().secret().clone();

        cookies.add_private(
            Cookie::build(("token", token.clone()))
                .same_site(SameSite::Lax)
                .build()
        );

        let github = GithubClient::new(&token);
        if let Ok(user) = github.get_user().await {
            debug!("Welcome {:?}", user);
            info!("Welcome {:?}", user.login);
            cookies.add_private(
                Cookie::build(("username", user.login))
                    .same_site(SameSite::Lax)
                    .build()
            );
        } else {
            warn!("Could not retrieve username!");
        };
    } else {
        warn!("Could not retrieve token!");
    }

    Redirect::to("/")
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("token"));
    cookies.remove_private(Cookie::build("username"));
    Redirect::to("/")
}

#[get("/")]
fn index(cookies: &CookieJar<'_>) -> Template {
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
        })
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index, github_callback, github_login, logout])
        .attach(Template::fairing())
}