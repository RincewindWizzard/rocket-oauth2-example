mod github_api;
mod session;
mod auth;

#[macro_use]
extern crate rocket;


use crate::auth::AuthSession;
use crate::auth::OAuthConfig;
use crate::auth::OAuth;
use crate::auth::User;
use std::env;
use std::time::{Duration};

use rocket::{tokio};
use rocket::fs::FileServer;
use rocket::fs::relative;
use rocket_dyn_templates::{context, Template};


use crate::session::SessionManager;


const MONTH: Duration = Duration::from_secs(60 * 60 * 24 * 28);


#[get("/")]
async fn index_user(user: User) -> Template {
    Template::render("index", context! {
            logged_in: true,
            username: user.login,
        })
}

#[get("/", rank = 2)]
async fn index() -> Template {
    Template::render("index", context! {
            logged_in: false,
            username: "",
        })
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

    let sessions: SessionManager<AuthSession> = SessionManager::new(MONTH);
    let session_fairing = sessions.fairing();

    rocket
        .manage::<OAuth>(oauth2)
        .manage::<SessionManager<AuthSession>>(sessions)
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index_user, index,  auth::logout, auth::github_login, auth::github_callback])
        .attach(Template::fairing())
        .attach(session_fairing)
}