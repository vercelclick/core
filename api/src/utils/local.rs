use crate::constants::{CLOUD_PROXY_BASE_URL, PROXY_REQUEST_HEADER, SESSION_COOKIE_NAME};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode, Uri};
use axum::response::Response;
use futures_util::future::BoxFuture;
use reqwest::header::COOKIE;
use reqwest::{Client, RequestBuilder};
use secretpass_core::enums::OperationMode;
use secretpass_core::{InternalError, InternalResult, source};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::str::FromStr;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use tower_cookies::Cookies;
use tower_layer::Layer;
use tower_service::Service;

static REQWEST_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

#[derive(Debug, Clone)]
pub(crate) struct CloudProxy {
    proxied: bool,
    uri: Uri,
    mode: OperationMode,
    method: Method,
    session_cookie: Option<String>,
}

impl CloudProxy {
    fn new(
        uri: Uri,
        mode: OperationMode,
        method: Method,
        session_cookie: Option<String>,
        proxied: bool,
    ) -> Self {
        let uri = Uri::from_str(&format!("{}{}", CLOUD_PROXY_BASE_URL, uri.path())).unwrap();

        CloudProxy {
            uri,
            mode,
            method,
            proxied,
            session_cookie,
        }
    }

    pub fn is_local(&self) -> bool {
        self.mode == OperationMode::Local
    }

    pub fn is_proxied(&self) -> bool {
        self.proxied
    }

    fn builder(&self) -> RequestBuilder {
        let builder = REQWEST_CLIENT
            .request(self.method.clone(), &self.uri.to_string())
            .header(PROXY_REQUEST_HEADER, "true");

        if let Some(cookies) = self.session_cookie.clone() {
            builder.header(COOKIE, cookies)
        } else {
            builder
        }
    }

    pub async fn send_json<I: Serialize, O>(self, json: &I) -> InternalResult<O>
    where
        O: DeserializeOwned,
    {
        self.proxy_inner::<O>(self.builder().json(json)).await
    }

    async fn proxy_inner<T>(&self, builder: RequestBuilder) -> InternalResult<T>
    where
        T: DeserializeOwned,
    {
        let response = builder.send().await.map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::BAD_GATEWAY,
                "Error proxying request to cloud backend",
                err,
            )
        })?;

        let path = self.uri.path();

        let status = response.status();
        if !status.is_success() {
            let error: InternalError = response.json().await.map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Error<{status}> parsing proxied<{path}> request error"),
                    err,
                )
            })?;
            return Err(error);
        }

        let payload: T = response.json().await.map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error parsing proxied<{path}> cloud response"),
                err,
            )
        })?;

        Ok(payload)
    }
}

#[derive(Clone)]
pub struct CloudProxyLayer {
    mode: OperationMode,
}

impl CloudProxyLayer {
    pub fn new(mode: OperationMode) -> Self {
        CloudProxyLayer { mode }
    }
}

impl<S> Layer<S> for CloudProxyLayer {
    type Service = CloudProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CloudProxyService {
            inner,
            mode: self.mode,
        }
    }
}

#[derive(Clone)]
pub struct CloudProxyService<S> {
    inner: S,
    mode: OperationMode,
}

impl<S> Service<Request<Body>> for CloudProxyService<S>
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
        let mode = self.mode;

        Box::pin(async move {
            let session_cookie = match req.extensions().get::<Cookies>().cloned() {
                Some(some_cookies) => some_cookies.get(SESSION_COOKIE_NAME).map(|c| c.to_string()),
                None => None,
            };

            let is_proxied = req
                .headers()
                .get(PROXY_REQUEST_HEADER)
                .map(|value| value == "true")
                .unwrap_or(false);

            let proxy = CloudProxy::new(
                req.uri().clone(),
                mode,
                req.method().clone(),
                session_cookie,
                is_proxied,
            );
            req.extensions_mut().insert(proxy);

            inner.call(req).await
        })
    }
}
