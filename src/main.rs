use app_error::{AppError, SpotifyError};
use async_redis_session::RedisSessionStore;
use async_session::{async_trait, log::debug, Session, SessionStore};
use axum::{
    body::{Bytes, Empty},
    extract::{Extension, FromRequest, Query, RequestParts, TypedHeader},
    handler::get,
    response::{IntoResponse, Redirect},
    AddExtensionLayer, Json, Router,
};
use headers::HeaderValue;
use hyper::{
    header::{self, SET_COOKIE},
    Body, HeaderMap, Response, StatusCode,
};
use rspotify::{
    clients::{BaseClient, OAuthClient},
    model::{AdditionalType, PlayableItem},
    scopes, AuthCodeSpotify, Config as rspotify_config, Credentials, OAuth, Token,
};
use serde::{Deserialize, Serialize};
use std::{env, fmt::Debug, fs, net::SocketAddr, path::PathBuf};
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
mod app_error;
static COOKIE_NAME: &str = "SESSION";

#[derive(Debug, Deserialize)]
struct Config {
    client_id: String,
    client_secret: String,
    callback_url: String,
    radisserver_url: String,
}

#[tokio::main]
async fn main() {
    let set_header_service = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://tweetdeck.twitter.com"),
        ))
        .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        ))
        .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET"),
        ));

    let cofig_path = get_config_path().expect("Could not find config file");
    let config_string = fs::read_to_string(cofig_path).expect("Unable to read config.toml");
    let config: Config = toml::from_str(&config_string).expect("Unable to parse config.toml");
    let redis_session_store = RedisSessionStore::new(config.radisserver_url).unwrap();
    //initilize Spotify Client
    let credentials = Credentials {
        id: config.client_id,
        secret: Some(config.client_secret),
    };

    let oauth = OAuth {
        redirect_uri: config.callback_url,
        scopes: scopes!("user-read-currently-playing", "user-read-playback-state"),
        ..Default::default()
    };
    let config = rspotify_config {
        token_refreshing: true,
        ..Default::default()
    };
    let spotify_client = AuthCodeSpotify::with_config(credentials, oauth, config);
    let url = spotify_client.get_authorize_url(false).unwrap();
    println!("{}", url);

    // build our application with a route
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .layer(AddExtensionLayer::new(redis_session_store))
        .layer(AddExtensionLayer::new(spotify_client))
        .layer(set_header_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3333));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    token: Token,
}

async fn index(user: User) -> Result<impl IntoResponse, AppError> {
    let spotify = AuthCodeSpotify::from_token(user.token);
    let result = spotify
        .current_playback(
            None,
            Some(&vec![AdditionalType::Track, AdditionalType::Episode]),
        )
        .await?;
    let playing_context = match result {
        Some(result) => result,
        None => return Err(SpotifyError::NotFoundPlayingItem.into()),
    };
    let item = match playing_context.item {
        Some(item) => item,
        None => return Err(SpotifyError::NotFoundPlayingItem.into()),
    };
    match item {
        PlayableItem::Track(track) => Ok((StatusCode::OK, Json(track)).into_response()),
        PlayableItem::Episode(episode) => Ok((StatusCode::OK, Json(episode)).into_response()),
    }
}
async fn login_handler(Extension(spotify_client): Extension<AuthCodeSpotify>) -> Redirect {
    Redirect::permanent(
        spotify_client
            .get_authorize_url(false)
            .unwrap()
            .parse()
            .unwrap(),
    )
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
}

async fn callback_handler(
    Query(query): Query<AuthRequest>,
    Extension(store): Extension<RedisSessionStore>,
    Extension(spotify_client): Extension<AuthCodeSpotify>,
) -> impl IntoResponse {
    let code = query.code.clone();
    let mut spotify = spotify_client.clone();
    debug!("code: {}", code);
    spotify.request_token(&code).await.unwrap();
    let token = spotify.get_token().lock().await.unwrap().clone();
    let token = match token {
        Some(token) => token,
        None => {
            return (
                HeaderMap::new(),
                Redirect::found("/login".parse().unwrap()).into_response(),
            )
        }
    };
    let mut session = Session::new();
    let user = User { token };
    session.insert("spotify_token", user).unwrap();
    let cookie = store.store_session(session).await.unwrap().unwrap();
    let cookie = format!("{}={}; SameSite=none; Path=/; secure", COOKIE_NAME, cookie);
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());
    (
        headers,
        Redirect::found("/".parse().unwrap()).into_response(),
    )
}

fn get_config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    match env::current_exe() {
        Ok(mut path) => {
            path.pop();
            path.push("config.toml");
            Ok(path)
        }
        Err(_) => Err("error occurred while getting current_exe"
            .to_string()
            .into()),
    }
}
struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    type Body = Empty<Bytes>;
    type BodyError = <Self::Body as axum::body::HttpBody>::Error;

    fn into_response(self) -> Response<Self::Body> {
        Redirect::found("/login".parse().unwrap()).into_response()
    }
}

#[async_trait]
impl<B> FromRequest<B> for User
where
    B: Send,
{
    type Rejection = AuthRedirect;
    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        dbg!(&req.headers());
        let Extension(store) = Extension::<RedisSessionStore>::from_request(req)
            .await
            //todo: handle error
            .expect("Unable to get session store");
        let cookies = TypedHeader::<headers::Cookie>::from_request(req)
            .await
            //todo: handle error
            .expect("could not get cookies");
        let cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;
        let session = store
            .load_session(cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;
        let user = session.get::<User>("spotify_token").ok_or(AuthRedirect)?;
        Ok(user)
    }
}
