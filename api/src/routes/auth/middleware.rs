use crate::backend::ApiState;
use crate::routes::auth::session::get_session;
use axum::body::Body;
use axum::extract::Request;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;

use std::task::{Context, Poll};
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
            let headers = req.headers();
            let path = req.uri().path();

            let session = match get_session(&state, path, headers).await {
                Ok(package) => package,
                Err(err) => {
                    return Ok(err.into_response());
                }
            };

            let session = Arc::new(session);
            let user = Arc::new(session.user.clone());
            let passkeys = Arc::new(session.passkeys.clone());

            req.extensions_mut().insert(user);
            req.extensions_mut().insert(passkeys);
            req.extensions_mut().insert(session);

            inner.call(req).await
        })
    }
}
