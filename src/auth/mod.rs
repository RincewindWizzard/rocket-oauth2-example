mod routes;
mod config;
mod user;
mod session_data;

pub use routes::{logout, github_login, github_callback};
pub use config::OAuthConfig;

pub type OAuth = oauth2::basic::BasicClient;

pub use user::User;
pub use session_data::AuthSession;