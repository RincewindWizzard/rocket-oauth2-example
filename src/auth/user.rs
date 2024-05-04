use crate::auth::AuthSession;
use anyhow::anyhow;
use rocket::http::Status;
use rocket::Request;
use rocket::request::{FromRequest, Outcome};
use serde_derive::{Deserialize, Serialize};
use crate::session::Session;


/// Excerpt User data from the Github API
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub login: String,
    pub avatar_url: String,
    pub name: String,
    pub location: String,
    pub email: String,
}


#[rocket::async_trait]
impl<'r> FromRequest<'r> for User
{
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(session) = request.guard::<Session<AuthSession>>().await {
            let user = &session.get_value().await.user;
            match user {
                None => {
                    Outcome::Forward(Status::Forbidden)
                }
                Some(user) => {
                    Outcome::Success(user.clone())
                }
            }
        } else {
            Outcome::Error((Status::InternalServerError, anyhow!("Could not get application state!")))
        }
    }
}
