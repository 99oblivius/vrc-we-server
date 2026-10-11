pub mod bridge;
pub mod ratelimit;
pub mod routing;
pub mod tls;
pub mod transport;

use axum::{routing::get, Router};
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

async fn health() -> &'static str {
    "ok"
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
}
