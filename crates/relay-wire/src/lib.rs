use serde::{Deserialize, Serialize};

use crate::version::VersionRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteTag(pub [u8; 16]);

/// The client↔relay wire. Bump it on any change to `ClientFrame` or
/// `ServerFrame`; raise a minimum below only to drop an older version.
pub const WIRE_VERSION: u32 = 2;
/// The oldest relay wire a client accepts.
pub const MIN_RELAY_WIRE: u32 = 2;
/// The oldest client wire a relay accepts.
pub const MIN_CLIENT_WIRE: u32 = 2;

pub const CLIENT_WIRE: VersionRange = VersionRange {
    version: WIRE_VERSION,
    min: MIN_RELAY_WIRE,
};
pub const RELAY_WIRE: VersionRange = VersionRange {
    version: WIRE_VERSION,
    min: MIN_CLIENT_WIRE,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientFrame {
    /// A client's first frame: the relay closes a connection whose first
    /// frame is anything else, or whose range it refuses.
    Hello {
        wire: VersionRange,
    },
    Register {
        tag: RouteTag,
    },
    Send {
        tag: RouteTag,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
    Unregister {
        tag: RouteTag,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerFrame {
    /// A relay's first frame. `protocol_version` and `min_client_version`
    /// form its `RELAY_WIRE`; a relay that predates the minimum sends none,
    /// which reads as 0.
    Hello {
        server_id: String,
        protocol_version: u32,
        app_version: String,
        #[serde(default)]
        min_client_version: u32,
    },
    Recv {
        tag: RouteTag,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
    Error {
        tag: Option<RouteTag>,
        reason: String,
    },
    PeerArrived {
        tag: RouteTag,
    },
    PeerGone {
        tag: RouteTag,
    },
    /// The relay is shedding this connection for exceeding a rate limit. The
    /// client should surface it and back off for `retry_after_secs` rather than
    /// reconnecting immediately. Sent immediately before the socket is closed.
    RateLimited {
        retry_after_secs: u64,
    },
}

pub const NO_RECIPIENT_REASON: &str = "no recipient registered for this tag";
/// The relay refused a `Register`: the connection holds as many tags as it
/// may.
pub const TAG_LIMIT_REASON: &str = "too many tags registered on this connection";
/// The relay refused a `Register`: the tag has as many holders as it may.
pub const TAG_FULL_REASON: &str = "too many holders registered on this tag";

/// A `Send` payload is one Noise message, which Noise's 2-byte length field
/// caps at 65 535 bytes. The relay closes a connection that sends a larger
/// one.
pub const MAX_PAYLOAD_BYTES: usize = 65_535;

/// The EULA version this release requires. The client records the version
/// its user accepted; the relay starts only when `VRC_WE_ACCEPT_EULA` names
/// this one.
pub const EULA_VERSION: &str = "2026-10";
/// The text of EULA version `EULA_VERSION`, shown by the client.
pub const EULA: &str = include_str!("../../../EULA.md");

pub mod transport {
    pub const KEEPALIVE_INTERVAL_SECS: u64 = 30;
    /// No inbound frame of any kind (data, ping, or the automatic pong) for
    /// this long means the other end is hung or gone: 1.5 keep-alive
    /// intervals tolerates scheduling while two missed pings kill. Both the
    /// relay and the client hold their connections to it.
    pub const INBOUND_IDLE_DEADLINE_SECS: u64 = KEEPALIVE_INTERVAL_SECS * 3 / 2;
}

pub mod version {
    use serde::{Deserialize, Serialize};

    /// One end of a link: the version it speaks and the oldest version it
    /// accepts from the other end. Invariant: `min <= version`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct VersionRange {
        pub version: u32,
        pub min: u32,
    }

    /// Which end of a link is too old for the other.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VersionRefusal {
        /// The remote speaks `remote`, below this end's minimum `min`.
        RemoteTooOld { remote: u32, min: u32 },
        /// This end speaks `local`, below the remote's minimum `min`.
        LocalTooOld { local: u32, min: u32 },
    }

    impl VersionRange {
        /// The link works iff each end speaks at least the other's minimum.
        /// Both ends evaluate it on the same two ranges and reach the same
        /// verdict; with `min <= version` on each end, at most one end is
        /// too old.
        pub fn check(self, remote: VersionRange) -> Result<(), VersionRefusal> {
            if remote.version < self.min {
                return Err(VersionRefusal::RemoteTooOld {
                    remote: remote.version,
                    min: self.min,
                });
            }
            if self.version < remote.min {
                return Err(VersionRefusal::LocalTooOld {
                    local: self.version,
                    min: remote.min,
                });
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn r(version: u32, min: u32) -> VersionRange {
            VersionRange { version, min }
        }

        #[test]
        fn overlapping_ranges_link_in_both_directions() {
            assert_eq!(r(3, 2).check(r(2, 1)), Ok(()));
            assert_eq!(r(2, 1).check(r(3, 2)), Ok(()));
        }

        #[test]
        fn the_newer_ends_minimum_decides_and_both_ends_name_the_same_side() {
            let new = r(4, 3);
            let old = r(2, 1);
            assert_eq!(
                new.check(old),
                Err(VersionRefusal::RemoteTooOld { remote: 2, min: 3 })
            );
            assert_eq!(
                old.check(new),
                Err(VersionRefusal::LocalTooOld { local: 2, min: 3 })
            );
        }

        #[test]
        fn a_minimum_equal_to_the_remote_version_admits_it() {
            assert_eq!(r(5, 5).check(r(5, 5)), Ok(()));
            assert_eq!(r(5, 4).check(r(4, 4)), Ok(()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eula_text_is_the_required_version() {
        assert!(EULA.contains(&format!("**Version {EULA_VERSION}**")));
    }
}
