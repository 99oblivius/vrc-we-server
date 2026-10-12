use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve::ListenerExt;
use relay_wire::EULA_VERSION;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use server::routing::RoutingTable;
use server::tls::{AcmeSettings, CertHealth};
use server::transport::AppState;
use server::{build_router, eula_accepted, ratelimit::RateLimiter};

const DEV_BIND: &str = "127.0.0.1:8443";
const TLS_BIND: &str = "0.0.0.0:443";
const SERVER_ID: &str = "vrc-we-server";
const EULA_URL: &str = "https://github.com/99oblivius/vrc-we-server/blob/main/EULA.md";

/// Container liveness probe: the distroless image has no shell, so the
/// healthcheck runs the relay binary itself: a real GET against `/health`,
/// over TLS for the first domain when TLS is on, where it fails until a
/// certificate is deployed and while that certificate is unhealthy.
/// Exit 0 = healthy.
fn run_healthcheck() -> i32 {
    use std::io::{Read, Write};
    let first_domain = std::env::var("VRC_WE_TLS_DOMAINS").ok().and_then(|v| {
        v.split(',')
            .map(str::trim)
            .find(|d| !d.is_empty())
            .map(String::from)
    });
    let tls_on = first_domain.is_some();
    let default_port = if tls_on { 443 } else { 8443 };
    let port: u16 = std::env::var("VRC_WE_BIND")
        .ok()
        .and_then(|b| b.rsplit(':').next().and_then(|p| p.parse().ok()))
        .unwrap_or(default_port);
    if let Some(domain) = first_domain {
        return if server::tls::https_healthy(port, &domain) {
            0
        } else {
            1
        };
    }
    let addr = format!("127.0.0.1:{port}");
    let mut stream = match std::net::TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let _ =
        stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return 1;
    }
    if buf.starts_with(b"HTTP/1.1 200") || buf.starts_with(b"HTTP/1.0 200") {
        0
    } else {
        1
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(run_healthcheck());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    if !eula_accepted(std::env::var("VRC_WE_ACCEPT_EULA").ok().as_deref()) {
        tracing::error!(
            "this release requires accepting EULA version {EULA_VERSION} ({EULA_URL}): \
             set VRC_WE_ACCEPT_EULA={EULA_VERSION}"
        );
        std::process::exit(1);
    }

    if let Err(e) = serve().await {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    rustls_acme::futures_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let state = AppState::new(RoutingTable::new(), SERVER_ID, RateLimiter::from_env()?);
    let settings = AcmeSettings::from_env()?;
    let cert = settings.as_ref().map(|_| Arc::new(CertHealth::default()));
    let app = build_router(match &cert {
        Some(cert) => state.with_cert_health(cert.clone()),
        None => state,
    });

    match settings.zip(cert) {
        Some((settings, cert)) => {
            let addr: SocketAddr = std::env::var("VRC_WE_BIND")
                .unwrap_or_else(|_| TLS_BIND.into())
                .parse()?;
            tracing::info!(
                %addr,
                domains = ?settings.domains,
                "vrc-we-server listening on TLS; clients can connect once the certificate is ready"
            );
            let acceptor = settings.into_acceptor(cert);
            axum_server::bind(addr)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        None => {
            let addr: SocketAddr = std::env::var("VRC_WE_BIND")
                .unwrap_or_else(|_| DEV_BIND.into())
                .parse()?;
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    if e.raw_os_error() == Some(10013) {
                        // WSAEACCES: the port sits in a Windows excluded
                        // range (Hyper-V/WSL/WinNAT) or a firewall blocks
                        // it. The `netsh` hint is the common remedy.
                        tracing::error!(
                            %addr,
                            "bind failed with 10013 (WSAEACCES): check \
                             `netsh int ipv4 show excludedportrange protocol=tcp` \
                             and your firewall, or set VRC_WE_BIND to a free port"
                        );
                    }
                    return Err(e.into());
                }
            };
            tracing::info!(
                %addr,
                "vrc-we-server listening on plain HTTP: serve it behind a TLS-terminating proxy"
            );
            // tokio-tungstenite sets TCP_NODELAY on client connects only;
            // server-accepted sockets keep Nagle, which stalls the small
            // 20 Hz wire frames behind a 40 ms delayed-ack window. axum-server
            // already sets it on the TLS path; mirror it here.
            let listener = listener.tap_io(|stream: &mut tokio::net::TcpStream| {
                if let Err(e) = stream.set_nodelay(true) {
                    tracing::warn!(?e, "set_nodelay failed");
                }
            });
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}
