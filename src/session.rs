use rocket::futures::lock::MutexGuard;

use rocket::http::SameSite;
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::anyhow;
use rocket::futures::lock::Mutex;
use rocket::{Request, State};
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};
use uuid::Uuid;


#[derive(Debug)]
pub struct SessionManager<T> {
    sessions: Mutex<HashMap<Uuid, Session<T>>>,
}

#[derive(Debug, Clone)]
pub struct Session<T> {
    id: Uuid,
    value: Arc<Mutex<T>>,
}

impl<T> Session<T> {
    pub fn get_id(&self) -> Uuid {
        self.id
    }
    pub async fn get_value<'a>(&'a self) -> MutexGuard<'a, T> {
        self.value.lock().await
    }
}

impl<T> Default for SessionManager<T> {
    fn default() -> Self {
        SessionManager {
            sessions: Default::default(),
        }
    }
}


impl<T> SessionManager<T>
    where T: Default
{
    async fn get_session(&self, sid: Uuid) -> Session<T> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.entry(sid).or_insert_with(|| Session {
            id: sid,
            value: Arc::new(Mutex::new(T::default())),
        });

        Session {
            id: session.id,
            value: session.value.clone(),
        }
    }
}

impl<T> Default for Session<T>
    where T: Default
{
    fn default() -> Self {
        Session {
            id: Uuid::new_v4(),
            value: Arc::new(Mutex::new(T::default())),
        }
    }
}


#[rocket::async_trait]
impl<'r, T> FromRequest<'r> for Session<T>
    where T: Sync + Send + Default + 'r + 'static
{
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(session_manager) = request.guard::<&State<SessionManager<T>>>().await {
            let sid = request
                .cookies()
                .get_private("sid")
                .map(|c| c.value().to_string())
                .map(|sid| Uuid::parse_str(&*sid).ok())
                .flatten()
                .unwrap_or_else(|| {
                    Uuid::new_v4()
                });

            let session = session_manager.get_session(sid).await;

            request.cookies().add_private(
                Cookie::build(("sid", session.id.to_string()))
                    .same_site(SameSite::Lax)
                    .build());
            Outcome::Success(session)
        } else {
            Outcome::Error((Status::InternalServerError, anyhow!("Could not get application state!")))
        }
    }
}