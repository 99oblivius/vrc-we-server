use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls_acme::caches::DirCache;
use rustls_acme::rustls;
use rustls_acme::{AcmeConfig, CertCache, EventError, EventOk};
use thiserror::Error;

#[derive(Debug)]
pub struct AcmeSettings {
    pub domains: Vec<String>,
    pub email: String,
    pub cache_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("VRC_WE_TLS_DOMAINS names no domain")]
    NoDomains,
    #[error("VRC_WE_TLS_EMAIL must be set when VRC_WE_TLS_DOMAINS is")]
    NoEmail,
    #[error("VRC_WE_TLS_CACHE {0:?} is not writable ({1}): mount a volume the relay can write to")]
    CacheNotWritable(PathBuf, std::io::Error),
}

impl AcmeSettings {
    pub fn from_env() -> Result<Option<Self>, TlsError> {
        let Some(domains_raw) = std::env::var("VRC_WE_TLS_DOMAINS")
            .ok()
            .filter(|v| !v.trim().is_empty())
        else {
            return Ok(None);
        };
        let domains: Vec<String> = domains_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if domains.is_empty() {
            return Err(TlsError::NoDomains);
        }
        let email = std::env::var("VRC_WE_TLS_EMAIL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or(TlsError::NoEmail)?;
        let cache_dir = std::env::var("VRC_WE_TLS_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./acme-cache"));
        let probe = cache_dir.join(".write-probe");
        std::fs::create_dir_all(&cache_dir)
            .and_then(|()| std::fs::write(&probe, b""))
            .and_then(|()| std::fs::remove_file(&probe))
            .map_err(|e| TlsError::CacheNotWritable(cache_dir.clone(), e))?;
        Ok(Some(Self {
            domains,
            email,
            cache_dir,
        }))
    }

    /// The TLS acceptor, with the certificate's life logged as it goes:
    /// loaded from the cache, or ordered from Let's Encrypt's production
    /// directory, then renewed. Until one is deployed the listener answers
    /// only Let's Encrypt's challenge, and every client handshake fails.
    /// `health` follows the certificate for `/health`.
    pub fn into_acceptor(self, health: Arc<CertHealth>) -> rustls_acme::axum::AxumAcceptor {
        let certs = WatchedCertCache {
            dir: DirCache::new(self.cache_dir.clone()),
            health: health.clone(),
        };
        let mut state = AcmeConfig::new(self.domains.clone())
            .contact_push(format!("mailto:{}", self.email))
            .cache_compose(certs, DirCache::new(self.cache_dir))
            .directory_lets_encrypt(true)
            .state();
        let rustls_config = state.default_rustls_config();
        let acceptor = state.axum_acceptor(rustls_config);

        tokio::spawn(async move {
            use futures_util::StreamExt;
            let mut ready = false;
            let mut retries = OrderRetries::default();
            while let Some(event) = state.next().await {
                let err = match event {
                    Ok(ok) => {
                        let valid_until = health.valid_until();
                        if let Some(line) = cert_progress(&ok, ready, valid_until.as_deref()) {
                            tracing::info!("certificate: {line}");
                        }
                        if matches!(ok, EventOk::DeployedCachedCert | EventOk::DeployedNewCert) {
                            ready = true;
                            retries.succeeded();
                            health.deployed();
                            let _ = health.check();
                        }
                        continue;
                    }
                    Err(err) => err,
                };
                let failure = match &err {
                    EventError::CertCacheStore(_) | EventError::AccountCacheStore(_) => {
                        Failure::CacheStore
                    }
                    EventError::Order(_) => Failure::Order,
                    _ => Failure::Other,
                };
                let (tail, pause) = on_failure(failure, ready, &mut retries);
                if ready || failure == Failure::CacheStore {
                    tracing::warn!("certificate: {err}; {tail}");
                } else {
                    tracing::error!("certificate: {err}; {tail}");
                }
                if ready && failure == Failure::Order {
                    health.renewal_failed();
                    let _ = health.check();
                }
                if let Some(pause) = pause {
                    tokio::time::sleep(pause).await;
                }
            }
        });

        acceptor
    }
}

/// Whether the relay on local `port` answers `GET /health` with 200 over
/// TLS for `domain`: the health check with TLS on. Without a deployed
/// certificate the handshake fails; with one, `/health` reports
/// `CertHealth`. Only the certificate's presence is asked, so it is not
/// verified.
pub fn https_healthy(port: u16, domain: &str) -> bool {
    use rustls::pki_types::ServerName;
    use std::io::{Read, Write};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let Ok(builder) = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
    else {
        return false;
    };
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let Ok(name) = ServerName::try_from(domain.to_string()) else {
        return false;
    };
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(config), name) else {
        return false;
    };
    let Ok(socket) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
    let mut tls = rustls::StreamOwned::new(conn, socket);
    let request = format!("GET /health HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n");
    if tls.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = Vec::new();
    let mut chunk = [0u8; 256];
    while !head.windows(2).any(|w| w == b"\r\n") {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    head.starts_with(b"HTTP/1.1 200") || head.starts_with(b"HTTP/1.0 200")
}

/// Accepts any certificate while still checking the handshake's signatures.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Pauses after consecutive failed orders: two quick retries while a host
/// fixes the setup, then hourly, then every six hours until an order
/// succeeds. Each is at least 12 minutes, which keeps under Let's Encrypt's
/// five failed authorizations per name and hour.
const ORDER_RETRY_GAPS: [Duration; 4] = [
    Duration::from_secs(12 * 60),
    Duration::from_secs(12 * 60),
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
];

/// Consecutive failed orders; a deployed certificate resets the count.
#[derive(Debug, Default)]
struct OrderRetries {
    failed: usize,
}

impl OrderRetries {
    /// Records a failed order and returns the pause before the next.
    fn failed(&mut self) -> Duration {
        self.failed += 1;
        ORDER_RETRY_GAPS[(self.failed - 1).min(ORDER_RETRY_GAPS.len() - 1)]
    }

    fn succeeded(&mut self) {
        self.failed = 0;
    }
}

/// `12 min`, `1 h`, `6 h`.
fn span(d: Duration) -> String {
    let minutes = d.as_secs() / 60;
    if minutes.is_multiple_of(60) {
        format!("{} h", minutes / 60)
    } else {
        format!("{minutes} min")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    CacheStore,
    Order,
    Other,
}

/// How the relay answers a failed certificate step, given whether a
/// certificate was already deployed: the log line's tail, and the pause
/// before the next order. A restart retries at once.
fn on_failure(
    failure: Failure,
    ready: bool,
    retries: &mut OrderRetries,
) -> (String, Option<Duration>) {
    match (failure, ready) {
        (Failure::CacheStore, _) => ("not kept, the next start orders again".into(), None),
        (Failure::Order, false) => {
            let gap = retries.failed();
            (
                format!(
                    "clients cannot connect yet; next attempt in {}, or fix the setup and restart to retry now",
                    span(gap)
                ),
                Some(gap),
            )
        }
        (Failure::Order, true) => {
            let gap = retries.failed();
            (
                format!(
                    "the current certificate stays in use; renewal retried in {}",
                    span(gap)
                ),
                Some(gap),
            )
        }
        (Failure::Other, false) => ("retrying, clients cannot connect yet".into(), None),
        (Failure::Other, true) => ("retrying".into(), None),
    }
}

/// The log line for a certificate event, given whether a certificate was
/// already deployed and the end of the latest one seen.
fn cert_progress(event: &EventOk, ready: bool, valid_until: Option<&str>) -> Option<String> {
    let until = valid_until.map_or(String::new(), |t| format!(", valid until {t}"));
    match event {
        EventOk::AccountCacheStore => Some("Let's Encrypt account created; ordering".into()),
        EventOk::DeployedCachedCert => Some(format!(
            "loaded from the cache{until}; ready, clients can connect"
        )),
        EventOk::DeployedNewCert if ready => Some("renewed".into()),
        EventOk::DeployedNewCert => {
            Some("issued by Let's Encrypt; ready, clients can connect".into())
        }
        EventOk::CertCacheStore => Some(format!("kept in the cache{until}")),
    }
}

/// Consecutive failed renewals that mark the relay unhealthy: the fifth is
/// the attempt after the first 6-hour pause (`ORDER_RETRY_GAPS`). The
/// current certificate keeps serving until it expires.
const UNHEALTHY_AFTER_FAILED_RENEWALS: usize = 5;

/// The deployed certificate as `/health` reports it.
#[derive(Debug, Default)]
pub struct CertHealth {
    state: std::sync::Mutex<CertState>,
}

#[derive(Debug, Default)]
struct CertState {
    /// The latest certificate's end: Unix seconds, and as written in it.
    not_after: Option<(i64, String)>,
    deployed: bool,
    failed_renewals: usize,
    /// Why a deployed certificate was last reported unhealthy; each change
    /// is logged once.
    unhealthy: Option<String>,
}

impl CertHealth {
    fn lock(&self) -> std::sync::MutexGuard<'_, CertState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records the end of the certificate in a stored PEM bundle.
    fn record(&self, pem: &[u8]) {
        if let Some(end) = not_after(pem) {
            self.lock().not_after = Some(end);
        }
    }

    fn deployed(&self) {
        let mut state = self.lock();
        state.deployed = true;
        state.failed_renewals = 0;
    }

    fn renewal_failed(&self) {
        self.lock().failed_renewals += 1;
    }

    fn valid_until(&self) -> Option<String> {
        self.lock()
            .not_after
            .as_ref()
            .map(|(_, shown)| shown.clone())
    }

    /// Healthy, or why not. A deployed certificate turning unhealthy, or
    /// back, is logged once.
    pub fn check(&self) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        self.check_at(now)
    }

    fn check_at(&self, now: i64) -> Result<(), String> {
        let mut state = self.lock();
        let verdict = verdict(&state, now);
        if state.deployed {
            let reason = verdict.as_ref().err().cloned();
            if reason != state.unhealthy {
                match &reason {
                    Some(reason) => tracing::error!("health: unhealthy: {reason}"),
                    None => tracing::info!("health: healthy again"),
                }
                state.unhealthy = reason;
            }
        }
        verdict
    }
}

fn verdict(state: &CertState, now: i64) -> Result<(), String> {
    if !state.deployed {
        return Err("no certificate yet".into());
    }
    if let Some((end, shown)) = &state.not_after {
        if now >= *end {
            return Err(format!(
                "the certificate expired {shown}, clients cannot connect: fix port 443 and restart the relay"
            ));
        }
    }
    if state.failed_renewals >= UNHEALTHY_AFTER_FAILED_RENEWALS {
        let until = state
            .not_after
            .as_ref()
            .map_or(String::new(), |(_, shown)| {
                format!(" until it expires {shown}")
            });
        return Err(format!(
            "certificate renewal failed {} times in a row: fix port 443 and restart the relay; clients can connect{until}",
            state.failed_renewals
        ));
    }
    Ok(())
}

/// The end of the first certificate in a PEM bundle; the bundle
/// `rustls-acme` stores starts with the private key.
fn not_after(pem: &[u8]) -> Option<(i64, String)> {
    x509_parser::pem::Pem::iter_from_buffer(pem)
        .filter_map(Result::ok)
        .find(|block| block.label == "CERTIFICATE")
        .and_then(|block| {
            let end = block.parse_x509().ok()?.validity().not_after;
            Some((end.timestamp(), end.to_string()))
        })
}

/// The certificate cache: `DirCache`, recording each certificate it loads
/// or stores in `CertHealth`.
struct WatchedCertCache {
    dir: DirCache<PathBuf>,
    health: Arc<CertHealth>,
}

#[async_trait::async_trait]
impl CertCache for WatchedCertCache {
    type EC = std::io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let pem = self.dir.load_cert(domains, directory_url).await?;
        if let Some(pem) = &pem {
            self.health.record(pem);
        }
        Ok(pem)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.health.record(cert);
        self.dir.store_cert(domains, directory_url, cert).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = env_lock();
        let snapshot: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, original) in snapshot {
            match original {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn from_env_is_none_when_unset() {
        with_env(
            &[
                ("VRC_WE_TLS_DOMAINS", None),
                ("VRC_WE_TLS_EMAIL", None),
                ("VRC_WE_TLS_CACHE", None),
            ],
            || {
                assert!(AcmeSettings::from_env().unwrap().is_none());
            },
        );
    }

    #[test]
    fn from_env_is_none_when_empty() {
        with_env(
            &[
                ("VRC_WE_TLS_DOMAINS", Some(" ")),
                ("VRC_WE_TLS_EMAIL", None),
            ],
            || {
                assert!(AcmeSettings::from_env().unwrap().is_none());
            },
        );
    }

    #[test]
    fn from_env_requires_email() {
        with_env(
            &[
                ("VRC_WE_TLS_DOMAINS", Some("example.com")),
                ("VRC_WE_TLS_EMAIL", None),
            ],
            || match AcmeSettings::from_env() {
                Err(TlsError::NoEmail) => {}
                other => panic!("expected NoEmail, got {other:?}"),
            },
        );
    }

    #[test]
    fn from_env_parses_multiple_domains() {
        let tmp = tempfile::tempdir().unwrap();
        with_env(
            &[
                (
                    "VRC_WE_TLS_DOMAINS",
                    Some("relay.example.com, alt.example.com"),
                ),
                ("VRC_WE_TLS_EMAIL", Some("admin@example.com")),
                ("VRC_WE_TLS_CACHE", Some(tmp.path().to_str().unwrap())),
            ],
            || {
                let s = AcmeSettings::from_env().unwrap().unwrap();
                assert_eq!(s.domains, vec!["relay.example.com", "alt.example.com"]);
                assert_eq!(s.email, "admin@example.com");
            },
        );
    }

    #[test]
    fn the_log_says_ready_once_then_renewals_with_the_end_date() {
        let until = Some("Jan 10 00:00:00 2027 +00:00");
        assert_eq!(
            cert_progress(&EventOk::DeployedNewCert, false, None).unwrap(),
            "issued by Let's Encrypt; ready, clients can connect"
        );
        assert_eq!(
            cert_progress(&EventOk::DeployedCachedCert, false, until).unwrap(),
            "loaded from the cache, valid until Jan 10 00:00:00 2027 +00:00; ready, clients can connect"
        );
        assert_eq!(
            cert_progress(&EventOk::DeployedNewCert, true, until).unwrap(),
            "renewed"
        );
        assert_eq!(
            cert_progress(&EventOk::CertCacheStore, true, until).unwrap(),
            "kept in the cache, valid until Jan 10 00:00:00 2027 +00:00"
        );
    }

    /// Serves one TLS connection with `config` on a local port: completes
    /// the handshake if the config can, then answers the request with
    /// `response`.
    fn serve_once(config: rustls::ServerConfig, response: &'static [u8]) -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut request = Vec::new();
            let mut chunk = [0u8; 256];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tls.write_all(response);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });
        port
    }

    fn self_signed() -> rustls::ServerConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
        .unwrap()
    }

    #[test]
    fn a_relay_answering_ok_over_tls_is_healthy() {
        let port = serve_once(
            self_signed(),
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        );
        assert!(https_healthy(port, "relay.test"));
    }

    #[test]
    fn a_relay_reporting_its_certificate_unhealthy_is_not() {
        let port = serve_once(
            self_signed(),
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        );
        assert!(!https_healthy(port, "relay.test"));
    }

    #[test]
    fn the_acme_acceptor_before_its_first_certificate_is_not_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AcmeConfig::new(["relay.test"])
            .cache(DirCache::new(tmp.path().to_path_buf()))
            .directory_lets_encrypt(true)
            .state();
        let config =
            Arc::try_unwrap(state.default_rustls_config()).unwrap_or_else(|a| (*a).clone());
        assert!(!https_healthy(serve_once(config, b""), "relay.test"));
    }

    #[test]
    fn a_closed_port_is_not_ready() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(!https_healthy(port, "relay.test"));
    }

    #[cfg(unix)]
    #[test]
    fn a_cache_the_relay_cannot_write_refuses_to_start() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(tmp.path().join("root-probe"), b"").is_ok() {
            return; // root ignores permissions; nothing to observe
        }
        with_env(
            &[
                ("VRC_WE_TLS_DOMAINS", Some("relay.example.com")),
                ("VRC_WE_TLS_EMAIL", Some("admin@example.com")),
                ("VRC_WE_TLS_CACHE", Some(tmp.path().to_str().unwrap())),
            ],
            || match AcmeSettings::from_env() {
                Err(TlsError::CacheNotWritable(..)) => {}
                other => panic!("expected CacheNotWritable, got {other:?}"),
            },
        );
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn failed_orders_retry_twice_after_12_min_then_hourly_then_every_6_h() {
        let mut retries = OrderRetries::default();
        let tails: Vec<(String, Option<Duration>)> = (0..6)
            .map(|_| on_failure(Failure::Order, false, &mut retries))
            .collect();
        let pauses: Vec<u64> = tails
            .iter()
            .map(|(_, p)| p.unwrap().as_secs() / 60)
            .collect();
        assert_eq!(pauses, [12, 12, 60, 360, 360, 360]);
        assert!(tails[0].0.contains("next attempt in 12 min"));
        assert!(tails[2].0.contains("next attempt in 1 h"));
        assert!(tails[3].0.contains("next attempt in 6 h"));
        for gap in ORDER_RETRY_GAPS {
            assert!(
                gap * 5 >= Duration::from_secs(3600),
                "{gap:?} under the failure limit"
            );
        }
    }

    #[test]
    fn a_deployed_certificate_restarts_the_schedule() {
        let mut retries = OrderRetries::default();
        for _ in 0..4 {
            retries.failed();
        }
        retries.succeeded();
        let (tail, pause) = on_failure(Failure::Order, true, &mut retries);
        assert_eq!(pause, Some(Duration::from_secs(12 * 60)));
        assert_eq!(
            tail,
            "the current certificate stays in use; renewal retried in 12 min"
        );
    }

    #[test]
    fn only_failed_orders_pause() {
        let mut retries = OrderRetries::default();
        assert_eq!(on_failure(Failure::CacheStore, false, &mut retries).1, None);
        assert_eq!(on_failure(Failure::Other, true, &mut retries).1, None);
        assert_eq!(retries.failed, 0);
    }

    /// A bundle shaped like the one `rustls-acme` stores: the private key,
    /// then the certificate, ending 2027-01-10.
    fn stored_bundle() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["relay.test".into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2027, 1, 10);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        format!("{}\n{}", key.serialize_pem(), cert.pem()).into_bytes()
    }

    const JAN_10_2027: i64 = 1_799_539_200;

    #[test]
    fn the_end_date_is_read_from_the_stored_certificate() {
        let (end, shown) = not_after(&stored_bundle()).unwrap();
        assert_eq!(end, JAN_10_2027);
        assert!(shown.contains("2027"), "{shown}");
        assert_eq!(not_after(b"not a certificate"), None);
    }

    #[test]
    fn health_follows_the_certificate_through_failed_renewals_and_expiry() {
        let health = CertHealth::default();
        let day = 86_400;
        assert_eq!(health.check_at(0), Err("no certificate yet".into()));
        health.record(&stored_bundle());
        health.deployed();
        assert_eq!(health.check_at(JAN_10_2027 - 30 * day), Ok(()));
        for _ in 0..UNHEALTHY_AFTER_FAILED_RENEWALS - 1 {
            health.renewal_failed();
        }
        assert_eq!(
            health.check_at(JAN_10_2027 - 29 * day),
            Ok(()),
            "still retrying"
        );
        health.renewal_failed();
        let reason = health.check_at(JAN_10_2027 - 29 * day).unwrap_err();
        assert!(reason.contains("renewal failed 5 times"), "{reason}");
        assert!(
            reason.contains("clients can connect until it expires"),
            "{reason}"
        );
        let reason = health.check_at(JAN_10_2027).unwrap_err();
        assert!(reason.contains("expired"), "{reason}");
        health.deployed();
        health.record(&stored_bundle());
        assert_eq!(
            health.check_at(JAN_10_2027 - 29 * day),
            Ok(()),
            "a renewal heals it"
        );
    }
}
