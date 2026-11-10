use crate::backend::ApiState;
use crate::routes::auth::session::get_session;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;

use secretpass_core::InternalError;
use std::task::{Context, Poll};
use tower_cookies::Cookies;
use tower_layer::Layer;
use tower_service::Service;

#[derive(Clone)]
pub struct AuthLayer {
    state: ApiState,
}

impl AuthLayer {
    pub fn new(state: ApiState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    state: ApiState,
}

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();

        Box::pin(async move {
            let cookies = match req.extensions().get::<Cookies>().cloned() {
                Some(cookies) => cookies,
                None => {
                    return Ok(InternalError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error loading authentication, please raise a support ticket if the issue persists",
                    )
                        .into_response());
                }
            };

            let package = match get_session(&state, &cookies).await {
                Ok(package) => package,
                Err(err) => {
                    return Ok(err.into_response());
                }
            };

            let package = Arc::new(package);

            req.extensions_mut().insert(package.user.clone());
            req.extensions_mut().insert(package.session.clone());
            req.extensions_mut().insert(package.passkeys.clone());
            req.extensions_mut().insert(package);

            inner.call(req).await
        })
    }
}
