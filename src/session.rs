use std::time::{Duration};
use rocket::futures::lock::MutexGuard;
use crate::tokio::time::Instant;
use rocket::http::{CookieJar, SameSite};
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::anyhow;
use rocket::futures::lock::Mutex;
use rocket::{Orbit, Request, Rocket, State, tokio};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};
use uuid::Uuid;

/// Thread safe (and cloneable via Arc) manager for client sessions.
/// Supports expiration for stale sessions.
#[derive(Debug)]
pub struct SessionManager<T> {
    sessions: Arc<Mutex<HashMap<Uuid, Session<T>>>>,
    expiration: Option<Duration>,
}

/// This is a reference object and can be cloned.
/// If you want to access the content you have to acquire a lock with get_value.
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

    /// Acquires a lock for the content.
    pub async fn get_value<'a>(&'a self) -> MutexGuard<'a, T> {
        self.value.lock().await
    }
}

/// Creates a new session from an Uuid.
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

/// Creates an empty session manager with no expiration.
impl<T> Default for SessionManager<T> {
    fn default() -> Self {
        SessionManager {
            sessions: Default::default(),
            expiration: None,
        }
    }
}

/// Creates a shallow copy of the session manager for usage in multiple threads/owners.
impl<T> Clone for SessionManager<T> {
    fn clone(&self) -> Self {
        SessionManager {
            sessions: self.sessions.clone(),
            expiration: self.expiration,
        }
    }
}

/// Thread safe (and cloneable via Arc) manager for client sessions.
/// Supports expiration for stale sessions.
impl<T> SessionManager<T>
    where T: Default
{
    pub fn new(expiration: Duration) -> SessionManager<T> {
        let mut session_manager = SessionManager::default();
        session_manager.expiration = Some(expiration);
        session_manager
    }

    /// Gets a session from the memory.
    pub async fn get_session(&self, sid: Uuid) -> Session<T> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.entry(sid).or_insert_with(|| Session::from(sid));
        session.last_access = Instant::now();

        Session {
            id: session.id,
            last_access: session.last_access,
            value: session.value.clone(),
        }
    }

    /// Removes a session.
    pub async fn remove_session(&self, sid: Uuid) {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(&sid);
    }

    /// Returns the instant when the next session will expire.
    /// Returns max duration if no sessions are present.
    pub async fn get_next_expiration(&self) -> Instant {
        if let Some(timeout) = self.expiration {
            let mut next_expiration = Instant::now() + timeout;
            let sessions = self.sessions.lock().await;
            for (_, session) in sessions.iter() {
                if session.last_access + timeout < next_expiration {
                    next_expiration = session.last_access + timeout;
                }
            }
            next_expiration
        } else {
            Instant::now() + Duration::from_nanos(u64::MAX)
        }
    }


    /// Removes all expired sessions.
    /// Beware that it acquires a lock until the operation is done.
    pub async fn remove_expired_sessions(&self) {
        if let Some(timeout) = self.expiration {
            let mut remove = vec![];
            let mut sessions = self.sessions.lock().await;
            for (sid, session) in sessions.iter() {
                if Instant::now() > session.last_access + timeout {
                    remove.push(sid.clone());
                }
            }

            for sid in remove {
                info!("Removed session \"{sid}\"");
                sessions.remove(&sid);
            }
        }
    }

    pub fn fairing(&self) -> SessionManager<T> {
        self.clone()
    }
}

/// To avoid memory leaks, expired sessions regularly need to be removed.
/// This is done in this fairing, which spawns an async loop calling [`SessionManager::remove_expired_sessions`](struct.SessionManager.html#method.remove_expired_sessions) at regular intervals.
/// TODO: it might be necessary to gracefully stop the loop on_shutdown
#[rocket::async_trait]
impl<T> Fairing for SessionManager<T>
    where T: Send + Default + 'static
{
    fn info(&self) -> Info {
        Info {
            name: "SessionManager Expiration loop",
            kind: Kind::Liftoff | Kind::Request,
        }
    }

    async fn on_liftoff(&self, _rocket: &Rocket<Orbit>) {
        if let Some(_) = self.expiration {
            let manager = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep_until(manager.get_next_expiration().await).await;
                    manager.remove_expired_sessions().await;
                }
            });
        }
    }
}

/// Creates a new Session with a random session id.
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
    /// Get the session id from cookie field "sid".
    fn get_session_id(&self) -> Uuid {
        self
            .get_private("sid")
            .map(|c| c.value().to_string())
            .map(|sid| Uuid::parse_str(&*sid).ok())
            .flatten()
            .unwrap_or_else(|| {
                let sid = Uuid::new_v4();
                self.set_session_id(&sid);
                sid
            })
    }

    // Sets the session id in the cookie field "sid".
    fn set_session_id(&self, sid: &Uuid) {
        self.add_private(
            Cookie::build(("sid", sid.to_string()))
                .same_site(SameSite::Lax)
                .build());
    }
}

/// Reads the session id from the cookie "sid" and retrieves the session from the session manager.
/// If no session id is found a new session is created.
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