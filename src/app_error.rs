use std::convert::Infallible;

use axum::{
    body::{Bytes, Full},
    response::IntoResponse,
};
use hyper::{Response, StatusCode};
use rspotify::ClientError;

pub enum AppError {
    SpotifyError(SpotifyError),
    ClientError(ClientError),
}

impl From<ClientError> for AppError {
    fn from(error: ClientError) -> Self {
        AppError::ClientError(error)
    }
}

impl From<SpotifyError> for AppError {
    fn from(error: SpotifyError) -> Self {
        AppError::SpotifyError(error)
    }
}

impl IntoResponse for AppError {
    type Body = Full<Bytes>;
    type BodyError = Infallible;
    fn into_response(self) -> Response<Self::Body> {
        match self {
            AppError::SpotifyError(SpotifyError::NotFoundPlayingItem) => {
                (StatusCode::NO_CONTENT, "Not playing").into_response()
            }
            AppError::SpotifyError(SpotifyError::NoCredentials) => {
                (StatusCode::INTERNAL_SERVER_ERROR,"Internal server error").into_response()
            }
            AppError::ClientError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}

pub enum SpotifyError {
    #[warn(dead_code)]
    NotFoundPlayingItem,
    #[warn(dead_code)]
    NoCredentials,
}
