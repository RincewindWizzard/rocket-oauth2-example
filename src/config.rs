use anyhow::anyhow;
use oauth2::basic::BasicClient;
use rocket::figment::Figment;

pub fn oauth2_client(figment: &Figment) -> Result<BasicClient, anyhow::Error> {
    let conf = figment.find_value("oauth.github")?;
    let conf = conf.as_dict().ok_or(anyhow!("ffo"))?;

    println!("conf: {conf:?}");

    let client_id = conf["client_id"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let client_secret = conf["client_secret"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let auth_url = conf["auth_url"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let redirect_uri = conf["redirect_uri"].as_str().ok_or(anyhow!("Cannot parse config!"))?;
    let token_url = conf["token_url"].as_str().ok_or(anyhow!("Cannot parse config!"))?;

    Ok(BasicClient::new(
        oauth2::ClientId::new(client_id.to_string()),
        Some(oauth2::ClientSecret::new(client_secret.to_string())),
        oauth2::AuthUrl::new(auth_url.to_string())?,
        Some(oauth2::TokenUrl::new(token_url.to_string())?),
    ).set_redirect_uri(oauth2::RedirectUrl::new(redirect_uri.to_string())?))
}