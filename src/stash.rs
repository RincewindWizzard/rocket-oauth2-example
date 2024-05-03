use anyhow::anyhow;
use oauth2::basic::BasicClient;
use rocket::figment::Figment;
use rocket::http::CookieJar;
use rocket::response::Redirect;
use rocket::State;
use rocket_dyn_templates::{context, Template};
use serde_derive::Deserialize;
use crate::{ApplicationState, Session};

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


// #[get("/")]
// fn index(cookies: &CookieJar<'_>, mut session: &Session) -> Template {
//     let logged_in = if let Some(_) = cookies.get_private("token") {
//         true
//     } else {
//         false
//     };
//
//
//     let username = if let Some(cookie) = cookies.get_private("username") {
//         let value = cookie.value_trimmed();
//         Some(value.to_string())
//     } else {
//         None
//     };
//
//
//     info!("Session: {:?}", session);
//     // session.value = session.value + 1;
//
//     Template::render("index", context! {
//         logged_in: logged_in,
//         username: username,
//     })
// }

