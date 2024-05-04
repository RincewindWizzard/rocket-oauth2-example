# rocket-oauth2-example

This is an example web server using [Rocket](https://rocket.rs/) to serve a website that supports login with github.
It includes [Bulma](https://bulma.io/) in its static path and uses [Handlebars Templates](https://handlebarsjs.com/).

You have
to [register your own application on Github](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)
and insert your application credential into [Rocket.toml](Rocket.toml).

    [default.oauth.github]
    client_id = "<client_id>"
    client_secret = "<client_secret>"
    auth_url = "https://github.com/login/oauth/authorize"
    redirect_uri = "https://<your_domain>/auth/github"
    token_url = "https://github.com/login/oauth/access_token"

Your application has to run on your domain otherwise redirection from github wont work.
You can forward from your server to your local dev machine using [Tailscale](https://tailscale.com/)
and [nginx](https://nginx.org/en/) or you use [Ngrok](https://ngrok.com/).