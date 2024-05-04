use crate::auth::User;
use oauth2::{CsrfToken, PkceCodeVerifier};
use oauth2::basic::BasicTokenResponse;

#[derive(Debug)]
pub struct AuthSession {
    pub(crate) pkce_verifier: Option<PkceCodeVerifier>,
    pub(crate) csrf_token: Option<CsrfToken>,
    pub(crate) github_api_token: Option<BasicTokenResponse>,
    pub(crate) user: Option<User>,
}


impl Default for AuthSession {
    fn default() -> Self {
        AuthSession {
            pkce_verifier: None,
            csrf_token: None,
            github_api_token: None,
            user: None,
        }
    }
}