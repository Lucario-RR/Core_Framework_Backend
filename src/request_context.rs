use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub async fn inject_request_context(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4().simple()));

    let ip_address = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        });

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    request.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
        ip_address,
        user_agent,
    });

    let mut response = next.run(request).await;
    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", header_value);
    }

    response
}
