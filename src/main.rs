use std::fmt::format;
use reqwest::{Client};
use rocket::fs::{FileServer, relative};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json::{json, Value};

#[macro_use]
extern crate rocket;

struct GitHub;

const GITHUB_ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Clone)]
struct AppState {
    client: Client,
}

#[get("/login/github")]
fn github_login(oauth2: OAuth2<GitHub>, cookies: &CookieJar<'_>) -> Redirect {
    oauth2.get_redirect(cookies, &["user:read"]).unwrap()
}

#[get("/auth/github")]
async fn github_callback(token: TokenResponse<GitHub>, cookies: &CookieJar<'_>) -> Redirect {
    let code = token.access_token().to_string();
    let token = github_get_access_token(code).await;
    cookies.add_private(
        Cookie::build(("token", token))
            .same_site(SameSite::Lax)
            .build()
    );
    Redirect::to("/")
}

async fn github_get_access_token(code: String) -> String {
    let client = reqwest::Client::new();
    let doc = client
        .post(GITHUB_ACCESS_TOKEN_URL)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body(json!({
            "client_id": "7adc7fd9713d21632430",
            "client_secret": "9158e79f814e20b708b309e85ca2fa59dc3623d3",
            "code": code
        }).to_string())
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();

    debug!("{:?}", doc);
    doc["access_token"]
        .as_str().unwrap().to_string()
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::build("token"));
    Redirect::to("/")
}

async fn get_username(client: &Client, token: &str) -> Option<String> {
    let response = client
        .get("https://api.github.com/user")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await;

    let curl = format!(r#"
    curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer {token}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        https://api.github.com/user
    "#);
    debug!("{}", curl);

    debug!("Got a response with {:?}", response);

    match response {
        Ok(response) => {
            let doc = response.json::<Value>().await;

            if let Ok(doc) = doc {
                let username = &doc["login"];
                Some(username.as_str().unwrap().to_string())
            } else {
                None
            }
        }
        Err(err) => {
            warn!("Failed to send request: {}", err);
            None
        }
    }
}

#[get("/")]
async fn index(cookies: &CookieJar<'_>, state: &rocket::State<AppState>) -> Template {
    /*let username = if let Some(token) = cookies.get("token") {
        debug!("Token: {}", token.value());

        get_username(&state.client, token.value()).await
    } else {
        None
    };*/

    let logged_in = cookies.get("token").is_some();
    let username = "unknown";
    /*let username = if let Some(username) = username {
        username
    } else {
        "".to_string()
    };*/


    Template::render("index", context! {
        logged_in:  logged_in,
        username: username,
    })
}


#[launch]
fn rocket() -> _ {
    stderrlog::new()
        .module(module_path!())
        .verbosity(log::Level::Debug) // show warnings and above
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init().expect("Could not setup logging!");

    let client = Client::new();
    let app_state = AppState { client };

    debug!("Starting App!");
    rocket::build()
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index, github_callback, github_login, logout])
        .manage(app_state)
        .attach(OAuth2::<GitHub>::fairing("github"))
        .attach(Template::fairing())
}