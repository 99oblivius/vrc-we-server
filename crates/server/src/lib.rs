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
        .route("/.well-known/vrc-we", get(version))
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .route("/pair", get(bridge::pair_page))
        .with_state(state)
}

/// What this build is, answered where a person or a monitor looks.
#[derive(serde::Serialize)]
struct Build {
    /// `pass` or `fail`, as the health-check response format has it.
    status: &'static str,
    #[serde(rename = "serviceId")]
    service_id: &'static str,
    version: &'static str,
    wire: u32,
    #[serde(rename = "minClient")]
    min_client: u32,
    #[serde(rename = "minRelay")]
    min_relay: u32,
    eula: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

fn build(status: &'static str, output: Option<String>) -> Build {
    Build {
        status,
        service_id: "vrc-we-server",
        version: env!("APP_VERSION"),
        wire: relay_wire::WIRE_VERSION,
        min_client: relay_wire::MIN_CLIENT_WIRE,
        min_relay: relay_wire::MIN_RELAY_WIRE,
        eula: EULA_VERSION,
        output,
    }
}

/// The health-check response format: `status` and the build behind it. 503
/// while the certificate is unhealthy, with the reason.
async fn health(State(state): State<AppState>) -> (StatusCode, axum::Json<Build>) {
    match state.cert.as_ref().map(|cert| cert.check()) {
        Some(Err(reason)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(build("fail", Some(reason))),
        ),
        _ => (StatusCode::OK, axum::Json(build("pass", None))),
    }
}

/// The same build, where a client or an operator discovers it without asking
/// for health.
async fn version() -> axum::Json<Build> {
    axum::Json(build("pass", None))
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
        let (status, body) = get(AppState::permissive("plain")).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("health is json");
        assert_eq!(json["status"], "pass");
        assert_eq!(json["serviceId"], "vrc-we-server");
        assert_eq!(json["version"], env!("APP_VERSION"));
        assert_eq!(json["wire"], relay_wire::WIRE_VERSION);
        assert_eq!(json["minClient"], relay_wire::MIN_CLIENT_WIRE);
        assert_eq!(json["eula"], EULA_VERSION);

        let cert = std::sync::Arc::new(crate::tls::CertHealth::default());
        let (status, body) = get(AppState::permissive("tls").with_cert_health(cert)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_str(&body).expect("health is json");
        assert_eq!(json["status"], "fail");
        assert_eq!(json["output"], "no certificate yet");
    }

    #[tokio::test]
    async fn the_discovery_document_names_the_build_without_a_certificate() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;
        let resp = build_router(AppState::permissive("tls"))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/vrc-we")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&body).unwrap()).unwrap();
        assert_eq!(json["status"], "pass");
        assert_eq!(json["version"], env!("APP_VERSION"));
    }
}
