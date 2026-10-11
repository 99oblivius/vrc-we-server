use std::path::PathBuf;

use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use thiserror::Error;

#[derive(Debug)]
pub struct AcmeSettings {
    pub domains: Vec<String>,
    pub email: String,
    pub cache_dir: PathBuf,
    pub production: bool,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("VRC_WE_TLS_DOMAINS names no domain")]
    NoDomains,
    #[error("VRC_WE_TLS_EMAIL must be set when VRC_WE_TLS_DOMAINS is")]
    NoEmail,
    #[error("cache dir {0:?} is not writable: {1}")]
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
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| TlsError::CacheNotWritable(cache_dir.clone(), e))?;
        let production = std::env::var("VRC_WE_TLS_PROD").ok().as_deref() == Some("1");
        Ok(Some(Self {
            domains,
            email,
            cache_dir,
            production,
        }))
    }

    pub fn into_acceptor(self) -> rustls_acme::axum::AxumAcceptor {
        let mut state = AcmeConfig::new(self.domains.clone())
            .contact_push(format!("mailto:{}", self.email))
            .cache(DirCache::new(self.cache_dir))
            .directory_lets_encrypt(self.production)
            .state();
        let rustls_config = state.default_rustls_config();
        let acceptor = state.axum_acceptor(rustls_config);

        tokio::spawn(async move {
            use futures_util::StreamExt;
            while let Some(event) = state.next().await {
                match event {
                    Ok(ok) => tracing::info!(?ok, "acme event"),
                    Err(err) => tracing::error!(?err, "acme error"),
                }
            }
        });

        acceptor
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
                ("VRC_WE_TLS_PROD", None),
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
    fn from_env_parses_multiple_domains_and_prod_flag() {
        let tmp = tempfile::tempdir().unwrap();
        with_env(
            &[
                (
                    "VRC_WE_TLS_DOMAINS",
                    Some("relay.example.com, alt.example.com"),
                ),
                ("VRC_WE_TLS_EMAIL", Some("admin@example.com")),
                ("VRC_WE_TLS_CACHE", Some(tmp.path().to_str().unwrap())),
                ("VRC_WE_TLS_PROD", Some("1")),
            ],
            || {
                let s = AcmeSettings::from_env().unwrap().unwrap();
                assert_eq!(s.domains, vec!["relay.example.com", "alt.example.com"]);
                assert_eq!(s.email, "admin@example.com");
                assert!(s.production);
            },
        );
    }
}
