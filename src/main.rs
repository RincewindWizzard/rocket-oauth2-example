#[macro_use]
extern crate rocket;

use std::env;

use anyhow::anyhow;
use oauth2::basic::BasicClient;
use rocket::Config;
use rocket::figment::Figment;
use rocket::fs::{FileServer, relative};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use serde::Deserialize;

struct ApplicationState {
    oauth2: BasicClient,
}

#[get("/login/github")]
fn github_login(cookies: &CookieJar<'_>) -> Redirect {
    // oauth2.get_redirect(cookies, &["user:read"]).unwrap()
    Redirect::to("/")
}

#[get("/auth/github")]
fn github_callback(cookies: &CookieJar<'_>) -> Redirect
{
    // cookies.add_private(
    //     Cookie::build(("token", token.access_token().to_string()))
    //         .same_site(SameSite::Lax)
    //         .build()
    // );
    Redirect::to("/")
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("token"));
    Redirect::to("/")
}

#[get("/")]
fn index(cookies: &CookieJar<'_>) -> Template {
    let logged_in = if let Some(_) = cookies.get("token") {
        true
    } else {
        false
    };
    Template::render("index", context! {
        logged_in: logged_in,
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


    rocket
        .manage(ApplicationState {
            oauth2,
        })
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index, github_callback, github_login, logout])
        .attach(Template::fairing())
}