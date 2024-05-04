use std::time::{Duration, Instant};
use rocket::futures::lock::MutexGuard;

use rocket::http::{CookieJar, SameSite};
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
    last_access: Instant,
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

impl<T> From<Uuid> for Session<T>
    where T: Default
{
    fn from(sid: Uuid) -> Self {
        Session {
            id: sid,
            last_access: Instant::now(),
            value: Arc::new(Mutex::new(T::default())),
        }
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
        let session = sessions.entry(sid).or_insert_with(|| Session::from(sid));
        session.last_access = Instant::now();

        Session {
            id: session.id,
            last_access: session.last_access,
            value: session.value.clone(),
        }
    }

    pub async fn remove_expired_sessions(&self, timeout: Duration) {
        let mut remove = vec![];
        let mut sessions = self.sessions.lock().await;
        for (sid, session) in sessions.iter() {
            if Instant::now() > session.last_access + timeout {
                remove.push(sid.clone());
            }
        }

        for sid in remove {
            sessions.remove(&sid);
        }
    }
}

impl<T> Default for Session<T>
    where T: Default
{
    fn default() -> Self {
        Session {
            id: Uuid::new_v4(),
            last_access: Instant::now(),
            value: Arc::new(Mutex::new(T::default())),
        }
    }
}

/// This trait is used to store and retrieve session ids
trait SessionIdStore {
    fn get_session_id(&self) -> Uuid;
    fn set_session_id(&self, sid: &Uuid);
}

/// Implements SessionIdStore for cookies.
/// The value is stored in "sid".
impl SessionIdStore for CookieJar<'_> {
    fn get_session_id(&self) -> Uuid {
        self
            .get_private("sid")
            .map(|c| c.value().to_string())
            .map(|sid| Uuid::parse_str(&*sid).ok())
            .flatten()
            .unwrap_or_else(|| {
                let sid = Uuid::new_v4();
                self.add_private(
                    Cookie::build(("sid", sid.to_string()))
                        .same_site(SameSite::Lax)
                        .build());
                sid
            })
    }

    fn set_session_id(&self, sid: &Uuid) {
        self.add_private(
            Cookie::build(("sid", sid.to_string()))
                .same_site(SameSite::Lax)
                .build());
    }
}

#[rocket::async_trait]
impl<'r, T> FromRequest<'r> for Session<T>
    where T: Sync + Send + Default + 'r + 'static
{
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(session_manager) = request.guard::<&State<SessionManager<T>>>().await {
            let sid = request.cookies().get_session_id();
            let session = session_manager.get_session(sid).await;
            Outcome::Success(session)
        } else {
            Outcome::Error((Status::InternalServerError, anyhow!("Could not get application state!")))
        }
    }
}