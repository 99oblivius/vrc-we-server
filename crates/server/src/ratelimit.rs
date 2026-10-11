use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use ipnet::IpNet;
use parking_lot::Mutex;
use thiserror::Error;

/// Idle per-IP entries are pruned once the table grows past `max_entries`.
const IDLE_TTL: Duration = Duration::from_secs(300);

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("VRC_WE_RELAY_TRUSTED_PROXIES entry {0:?} is not an IP address or CIDR range")]
    BadProxy(String),
    #[error("VRC_WE_RELAY_TRUSTED_PROXIES entry {0:?} trusts every address")]
    CatchAll(String),
}

/// Parses a comma- or whitespace-separated list of addresses and CIDR ranges.
/// A range of prefix length 0 is refused: it would let any client forge its
/// address.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpNet>, RateLimitError> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let net = s
                .parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| RateLimitError::BadProxy(s.to_string()))?;
            if net.prefix_len() == 0 {
                return Err(RateLimitError::CatchAll(s.to_string()));
            }
            Ok(net)
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Sustained inbound byte ceiling per source IP.
    pub max_bytes_per_sec: u64,
    /// Token-bucket depth: how large a momentary burst is tolerated.
    pub max_burst_bytes: u64,
    /// New connections/sec from one IP that, if sustained across the window,
    /// trip the penalty throttle.
    pub conn_rate_per_ip: u64,
    pub conn_window: Duration,
    /// Penalty duration once tripped.
    pub conn_throttle: Duration,
    /// Connections/sec allowed from a throttled IP.
    pub conn_throttle_rate: u64,
    /// Proxies whose `X-Forwarded-For` entries are believed. Empty ⇒ the
    /// socket peer address, headers ignored.
    pub trusted_proxies: Vec<IpNet>,
    pub max_entries: usize,
}

impl RateLimitConfig {
    pub fn from_env() -> Result<Self, RateLimitError> {
        let trusted_proxies = parse_trusted_proxies(
            &std::env::var("VRC_WE_RELAY_TRUSTED_PROXIES").unwrap_or_default(),
        )?;
        Ok(Self {
            max_bytes_per_sec: env_u64("VRC_WE_RELAY_MAX_BYTES_PER_SEC", 10_000_000),
            max_burst_bytes: env_u64("VRC_WE_RELAY_MAX_BURST_BYTES", 20_000_000),
            conn_rate_per_ip: env_u64("VRC_WE_RELAY_CONN_RATE_PER_IP", 20),
            conn_window: Duration::from_secs(env_u64("VRC_WE_RELAY_CONN_WINDOW_SECS", 5)),
            conn_throttle: Duration::from_secs(env_u64("VRC_WE_RELAY_CONN_THROTTLE_SECS", 60)),
            conn_throttle_rate: env_u64("VRC_WE_RELAY_CONN_THROTTLE_RATE", 1).max(1),
            trusted_proxies,
            max_entries: env_u64("VRC_WE_RELAY_MAX_IP_ENTRIES", 100_000) as usize,
        })
    }

    fn conn_trip_threshold(&self) -> u64 {
        self.conn_rate_per_ip
            .saturating_mul(self.conn_window.as_secs().max(1))
    }

    fn throttle_min_interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.conn_throttle_rate.max(1) as f64)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnDecision {
    Allow,
    Reject { retry_after_secs: u64 },
}

struct IpState {
    window_start: Instant,
    window_count: u64,
    throttled_until: Option<Instant>,
    last_throttle_allow: Instant,
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl IpState {
    fn new(now: Instant, burst: f64) -> Self {
        Self {
            window_start: now,
            window_count: 0,
            throttled_until: None,
            last_throttle_allow: now - Duration::from_secs(3600),
            tokens: burst,
            last_refill: now,
            last_seen: now,
        }
    }
}

pub struct RateLimiter {
    cfg: RateLimitConfig,
    state: Mutex<HashMap<IpAddr, IpState>>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Result<Self, RateLimitError> {
        RateLimitConfig::from_env().map(Self::new)
    }

    /// Limits so high they never trip — for tests and local dev.
    pub fn permissive() -> Self {
        Self::new(RateLimitConfig {
            max_bytes_per_sec: u64::MAX / 2,
            max_burst_bytes: u64::MAX / 2,
            conn_rate_per_ip: u64::MAX / 16,
            conn_window: Duration::from_secs(1),
            conn_throttle: Duration::from_secs(1),
            conn_throttle_rate: u64::MAX / 16,
            trusted_proxies: Vec::new(),
            max_entries: 100_000,
        })
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.cfg
    }

    /// The address the limits apply to. It starts at the socket peer and
    /// walks `X-Forwarded-For` from the right while the current address is a
    /// trusted proxy. Each trusted proxy appended the address it saw, so every
    /// entry read was written by a trusted proxy; entries a client wrote lie
    /// left of the first untrusted address and are never read. An unparseable
    /// entry stops the walk at the trusted proxy that wrote it.
    pub fn client_ip(&self, headers: &HeaderMap, socket: IpAddr) -> IpAddr {
        let mut client = socket.to_canonical();
        if !self.trusts(client) {
            return client;
        }
        let mut hops = Vec::new();
        for value in headers.get_all("x-forwarded-for") {
            let Ok(value) = value.to_str() else {
                return client;
            };
            hops.extend(value.split(','));
        }
        for hop in hops.into_iter().rev() {
            let Ok(ip) = hop.trim().parse::<IpAddr>() else {
                break;
            };
            client = ip.to_canonical();
            if !self.trusts(client) {
                break;
            }
        }
        client
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.cfg.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    pub fn check_connection(&self, ip: IpAddr) -> ConnDecision {
        self.check_connection_at(ip, Instant::now())
    }

    fn check_connection_at(&self, ip: IpAddr, now: Instant) -> ConnDecision {
        let mut state = self.state.lock();
        if state.len() > self.cfg.max_entries {
            state.retain(|_, s| {
                now.duration_since(s.last_seen) < IDLE_TTL
                    || s.throttled_until.is_some_and(|t| t > now)
            });
        }
        let burst = self.cfg.max_burst_bytes as f64;
        let entry = state.entry(ip).or_insert_with(|| IpState::new(now, burst));
        entry.last_seen = now;

        if let Some(until) = entry.throttled_until {
            if now < until {
                if now.duration_since(entry.last_throttle_allow) >= self.cfg.throttle_min_interval()
                {
                    entry.last_throttle_allow = now;
                    return ConnDecision::Allow;
                }
                return ConnDecision::Reject {
                    retry_after_secs: until.duration_since(now).as_secs().max(1),
                };
            }
            entry.throttled_until = None;
            entry.window_start = now;
            entry.window_count = 0;
        }

        if now.duration_since(entry.window_start) >= self.cfg.conn_window {
            entry.window_start = now;
            entry.window_count = 0;
        }
        entry.window_count += 1;
        if entry.window_count > self.cfg.conn_trip_threshold() {
            entry.throttled_until = Some(now + self.cfg.conn_throttle);
            entry.last_throttle_allow = now;
            return ConnDecision::Reject {
                retry_after_secs: self.cfg.conn_throttle.as_secs().max(1),
            };
        }
        ConnDecision::Allow
    }

    /// Charge `bytes` against the IP's token bucket. `false` ⇒ over the byte
    /// rate; the caller must shed the connection (no buffering).
    pub fn consume(&self, ip: IpAddr, bytes: usize) -> bool {
        self.consume_at(ip, bytes, Instant::now())
    }

    fn consume_at(&self, ip: IpAddr, bytes: usize, now: Instant) -> bool {
        let mut state = self.state.lock();
        let burst = self.cfg.max_burst_bytes as f64;
        let entry = state.entry(ip).or_insert_with(|| IpState::new(now, burst));
        entry.last_seen = now;
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.last_refill = now;
        entry.tokens = (entry.tokens + elapsed * self.cfg.max_bytes_per_sec as f64).min(burst);
        if entry.tokens >= bytes as f64 {
            entry.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RateLimitConfig {
        RateLimitConfig {
            max_bytes_per_sec: 1000,
            max_burst_bytes: 2000,
            conn_rate_per_ip: 20,
            conn_window: Duration::from_secs(5),
            conn_throttle: Duration::from_secs(60),
            conn_throttle_rate: 1,
            trusted_proxies: Vec::new(),
            max_entries: 100_000,
        }
    }

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    fn walker(proxies: &str) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            trusted_proxies: parse_trusted_proxies(proxies).unwrap(),
            ..cfg()
        })
    }

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn without_trusted_proxies_the_header_is_ignored() {
        let rl = walker("");
        let h = forwarded(&["1.2.3.4"]);
        assert_eq!(rl.client_ip(&h, addr("9.9.9.9")), addr("9.9.9.9"));
    }

    #[test]
    fn an_untrusted_socket_cannot_forge_its_address() {
        let rl = walker("10.0.0.1");
        let h = forwarded(&["1.2.3.4"]);
        assert_eq!(rl.client_ip(&h, addr("9.9.9.9")), addr("9.9.9.9"));
    }

    #[test]
    fn the_walk_stops_at_the_first_untrusted_address() {
        // Client 1.2.3.4, which wrote 6.6.6.6 itself, reached proxy 10.0.0.1
        // through CDN edge 173.245.48.7.
        let rl = walker("10.0.0.1, 173.245.48.0/20");
        let h = forwarded(&["6.6.6.6, 1.2.3.4", "173.245.48.7"]);
        assert_eq!(rl.client_ip(&h, addr("10.0.0.1")), addr("1.2.3.4"));
    }

    #[test]
    fn an_unparseable_or_missing_entry_stops_at_the_trusted_proxy() {
        let rl = walker("10.0.0.1");
        let h = forwarded(&["garbage"]);
        assert_eq!(rl.client_ip(&h, addr("10.0.0.1")), addr("10.0.0.1"));
        assert_eq!(
            rl.client_ip(&HeaderMap::new(), addr("10.0.0.1")),
            addr("10.0.0.1")
        );
    }

    #[test]
    fn mapped_ipv4_sockets_match_ipv4_ranges() {
        let rl = walker("10.0.0.0/8");
        let h = forwarded(&["1.2.3.4"]);
        assert_eq!(rl.client_ip(&h, addr("::ffff:10.0.0.1")), addr("1.2.3.4"));
    }

    #[test]
    fn trusted_proxies_parse_addresses_and_ranges_and_refuse_catch_alls() {
        assert_eq!(
            parse_trusted_proxies(" 10.0.0.1,2001:db8::/32\n")
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            parse_trusted_proxies("0.0.0.0/0"),
            Err(RateLimitError::CatchAll(_))
        ));
        assert!(matches!(
            parse_trusted_proxies("::/0"),
            Err(RateLimitError::CatchAll(_))
        ));
        assert!(matches!(
            parse_trusted_proxies("10.0.0.300"),
            Err(RateLimitError::BadProxy(_))
        ));
    }

    #[test]
    fn byte_bucket_allows_burst_then_refills() {
        let rl = RateLimiter::new(cfg());
        let t0 = Instant::now();
        // Burst capacity is 2000 bytes.
        assert!(rl.consume_at(ip(), 2000, t0));
        // Immediately over: bucket empty.
        assert!(!rl.consume_at(ip(), 1, t0));
        // After 1s, ~1000 bytes refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.consume_at(ip(), 1000, t1));
        assert!(!rl.consume_at(ip(), 1, t1));
    }

    #[test]
    fn connection_gate_trips_after_sustained_burst_then_penalizes() {
        let rl = RateLimiter::new(cfg());
        let t0 = Instant::now();
        // Threshold is 20*5 = 100 within the window; 100 allowed, 101st trips.
        for i in 0..100 {
            assert_eq!(
                rl.check_connection_at(ip(), t0 + Duration::from_millis(i)),
                ConnDecision::Allow,
                "conn {i} should be allowed"
            );
        }
        let tripped = rl.check_connection_at(ip(), t0 + Duration::from_millis(100));
        assert!(
            matches!(tripped, ConnDecision::Reject { .. }),
            "101st must trip"
        );
        // While throttled, at most 1/sec is allowed.
        let t_pen = t0 + Duration::from_millis(200);
        assert!(matches!(
            rl.check_connection_at(ip(), t_pen),
            ConnDecision::Reject { .. }
        ));
        // 1s after the last allowed, one gets through.
        let t_next = t_pen + Duration::from_millis(1100);
        assert_eq!(rl.check_connection_at(ip(), t_next), ConnDecision::Allow);
    }

    #[test]
    fn many_ips_each_below_threshold_are_not_throttled() {
        let rl = RateLimiter::new(cfg());
        let t0 = Instant::now();
        // A reconnect storm: 1000 distinct IPs each opening 2 connections.
        for n in 0..1000u32 {
            let addr: IpAddr = format!("10.{}.{}.{}", n / 256, n % 256, 1).parse().unwrap();
            assert_eq!(rl.check_connection_at(addr, t0), ConnDecision::Allow);
            assert_eq!(rl.check_connection_at(addr, t0), ConnDecision::Allow);
        }
    }
}
