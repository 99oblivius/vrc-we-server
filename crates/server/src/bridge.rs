use axum::http::header;
use axum::response::IntoResponse;

const PAGE: &str = include_str!("../assets/pair.html");

pub async fn pair_page() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                 base-uri 'none'; form-action 'none';",
            ),
        ],
        PAGE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_router;
    use crate::transport::AppState;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn router() -> axum::Router {
        let state = AppState::permissive("bridge-test");
        build_router(state)
    }

    #[tokio::test]
    async fn pair_returns_html_with_security_headers() {
        let resp = router()
            .oneshot(Request::builder().uri("/pair").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers().clone();
        assert!(h
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
        let csp = h
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));

        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("vrc-we://pair/"));
        assert!(html.contains("window.location.hash"));
        // Security-adjacent: the page must constrain the pairing token to a safe charset.
        assert!(
            html.contains("[A-Za-z0-9_-]+"),
            "embedded page must validate the token charset"
        );
    }
}
