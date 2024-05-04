mod github_api;
mod session;
mod auth;

#[macro_use]
extern crate rocket;

use crate::auth::OAuthConfig;
use crate::auth::OAuth;
use oauth2::{PkceCodeVerifier};
use crate::session::Session;
use std::env;
use std::time::{Duration};
use oauth2::{CsrfToken};
use rocket::{tokio};
use rocket::fs::FileServer;
use rocket::fs::relative;
use rocket_dyn_templates::{context, Template};
use crate::github_api::{User};
use oauth2::basic::BasicTokenResponse;
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
async fn index(session: Session<SessionData>) -> Template {
    let context = {
        let session_data = session.get_value().await;

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