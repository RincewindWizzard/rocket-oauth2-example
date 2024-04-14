use rocket::fs::{FileServer, relative};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use rocket_oauth2::{OAuth2, TokenResponse};

#[macro_use]
extern crate rocket;

struct GitHub;

#[get("/login/github")]
fn github_login(oauth2: OAuth2<GitHub>, cookies: &CookieJar<'_>) -> Redirect {
    oauth2.get_redirect(cookies, &["user:read"]).unwrap()
}

#[get("/auth/github")]
fn github_callback(token: TokenResponse<GitHub>, cookies: &CookieJar<'_>) -> Redirect
{
    cookies.add_private(
        Cookie::build(("token", token.access_token().to_string()))
            .same_site(SameSite::Lax)
            .build()
    );
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


#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![index, github_callback, github_login, logout])
        .attach(OAuth2::<GitHub>::fairing("github"))
        .attach(Template::fairing())
}