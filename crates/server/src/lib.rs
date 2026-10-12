pub mod bridge;
pub mod ratelimit;
pub mod routing;
pub mod tls;
pub mod transport;

use axum::{extract::State, http::StatusCode, routing::get, Router};
use relay_wire::EULA_VERSION;

use crate::transport::{ws_handler, AppState};

/// Whether `VRC_WE_ACCEPT_EULA` names the EULA version this release requires.
pub fn eula_accepted(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.trim() == EULA_VERSION)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .route("/pair", get(bridge::pair_page))
        .with_state(state)
}

/// `ok`, or 503 with the reason while the certificate is unhealthy.
async fn health(State(state): State<AppState>) -> (StatusCode, String) {
    match state.cert.as_ref().map(|cert| cert.check()) {
        Some(Err(reason)) => (StatusCode::SERVICE_UNAVAILABLE, reason),
        _ => (StatusCode::OK, "ok".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_required_eula_version_is_accepted() {
        assert!(eula_accepted(Some(EULA_VERSION)));
        assert!(eula_accepted(Some(&format!(" {EULA_VERSION}\n"))));
        assert!(!eula_accepted(None));
        assert!(!eula_accepted(Some("")));
        assert!(!eula_accepted(Some("true")));
        assert!(!eula_accepted(Some("2000-01")));
    }

    #[tokio::test]
    async fn health_reports_an_unhealthy_certificate_with_its_reason() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;
        let get = |state: AppState| async move {
            let resp = build_router(state)
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        };
        assert_eq!(
            get(AppState::permissive("plain")).await,
            (StatusCode::OK, "ok".into())
        );
        let cert = std::sync::Arc::new(crate::tls::CertHealth::default());
        let (status, body) = get(AppState::permissive("tls").with_cert_health(cert)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "no certificate yet");
    }
}
