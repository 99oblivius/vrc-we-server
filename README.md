# vrc-we-server

The relay for [vrc-WiredExpressions](https://github.com/99oblivius), a desktop app that controls VRChat avatar expressions locally and, with consent, between paired friends. Clients that can't reach each other directly meet on a relay, which forwards their end-to-end encrypted traffic.

This repository is the relay's complete source and the source of the `99oblivius/vrc-we-server` Docker image, so anyone can check what a relay does with the traffic it carries.

## What a relay sees

A relay is a routing-only fabric. Clients register opaque 16-byte routing tags on one WebSocket each; the relay forwards each payload to the other holders of its tag.

- **It cannot read or forge traffic.** Every payload is a Noise message encrypted between the two clients. The relay never holds a key.
- **It stores nothing.** Routing state lives in memory and ends with the connection. The relay writes no client IP address to its logs, at any level.
- **It does see metadata:**
  - the source address of every connection, and which tags each connection registers;
  - each client registers every contact's long-lived tag on one connection, so an operator could intersect tag sets across connections and infer who is paired with whom;
  - how much traffic flows, and when.
- **Its operator can deny service:** drop or delay frames, close connections, or withdraw a pairing request still waiting for an answer.

The client's [EULA](EULA.md) tells its users that every relay they use sees this metadata.

## Quick start

```bash
curl -O https://raw.githubusercontent.com/99oblivius/vrc-we-server/main/compose.yml
export VRC_WE_ACCEPT_EULA=2026-10           # the EULA version you accept
export VRC_WE_TLS_DOMAINS=relay.example.com # a DNS name pointing at this host
export VRC_WE_TLS_EMAIL=you@example.com     # the Let's Encrypt account contact
docker compose up -d
```

The relay obtains a certificate in-process through Let's Encrypt, on port 443. It starts on Let's Encrypt's **staging** directory, whose certificates clients do not trust. Once `docker compose logs` shows a certificate issued, switch to production:

```bash
export VRC_WE_TLS_PROD=1
docker compose up -d
```

Clients then connect to `relay.example.com`.

## Hosting

### Directly

Port 443 reaches the relay, which terminates TLS itself, as in the quick start. Leave `VRC_WE_RELAY_TRUSTED_PROXIES` unset: the relay then rate-limits by each connection's own source address, which cannot be forged.

### Behind your own reverse proxy

Leave the TLS variables empty; the relay serves plain HTTP on port 8443 and the proxy terminates TLS. The proxy must:

- forward WebSocket upgrades on `/ws`;
- allow idle connections of at least 60 s (keep-alive pings run every 30 s);
- append the address that connected to it to `X-Forwarded-For`, for example nginx's `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

Set `VRC_WE_RELAY_TRUSTED_PROXIES` to the proxy's address. Starting from the connection's source address, the relay reads one more `X-Forwarded-For` entry from the right for as long as the current address is trusted; the first untrusted address is the client. A client can only write entries the walk never reaches.

Behind a CDN such as Cloudflare, also list [the CDN's ranges](https://www.cloudflare.com/ips/), and make sure your proxy does not itself replace the connecting address with a client-supplied header for this host. Nginx Proxy Manager, for example, trusts `X-Real-IP` from CDN and private ranges by default; add `set_real_ip_from 127.0.0.1/32;` to the host's advanced configuration to turn that off for the relay.

A missing range fails safe: that proxy's traffic is rate-limited as one client. `0.0.0.0/0` and `::/0` are refused at startup.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VRC_WE_ACCEPT_EULA` | unset (required) | The [EULA](EULA.md) version you accept, e.g. `2026-10`. The relay refuses to start unless it names the version the release requires. |
| `VRC_WE_BIND` | `0.0.0.0:8443` (image) / `127.0.0.1:8443` (plain, outside the image) / `0.0.0.0:443` (TLS, outside the image) | Listen address. |
| `VRC_WE_TLS_DOMAINS` | unset | Comma-separated domains to obtain certificates for. Set, it enables in-process TLS. |
| `VRC_WE_TLS_EMAIL` | unset (required with TLS) | Let's Encrypt account contact. |
| `VRC_WE_TLS_PROD` | `0` | `1` uses Let's Encrypt's production directory instead of staging. |
| `VRC_WE_TLS_CACHE` | `/var/lib/vrc-we/acme` (image) / `./acme-cache` | Where certificates are kept. Mount a volume here. |
| `VRC_WE_RELAY_TRUSTED_PROXIES` | unset | Addresses and CIDR ranges of your own reverse proxies, comma-separated (see [Hosting](#behind-your-own-reverse-proxy)). |
| `VRC_WE_RELAY_MAX_BYTES_PER_SEC` | `10000000` | Sustained inbound bytes per second, per client address. |
| `VRC_WE_RELAY_MAX_BURST_BYTES` | `20000000` | Token-bucket depth: the largest momentary burst tolerated. |
| `VRC_WE_RELAY_CONN_RATE_PER_IP` | `20` | New connections per second from one address that, sustained across the window, trip the penalty. |
| `VRC_WE_RELAY_CONN_WINDOW_SECS` | `5` | Window for the connection rate. |
| `VRC_WE_RELAY_CONN_THROTTLE_SECS` | `60` | Penalty duration. |
| `VRC_WE_RELAY_CONN_THROTTLE_RATE` | `1` | Connections per second allowed from a penalized address. |
| `VRC_WE_RELAY_MAX_IP_ENTRIES` | `100000` | Per-address state table size; idle entries are pruned past it. |
| `RUST_LOG` | `info` | Log filter. |

### Limits and endpoints

- `/ws` is the relay, `/health` answers `ok`, and `/pair` serves the static page that turns an invite link into a `vrc-we://` deep link. The invite token stays in the URL fragment, which browsers never send to the server.
- A payload is one Noise message, at most 65 535 bytes; a larger one closes the connection.
- A connection holds at most 1024 tags, and a tag at most 8 connections.
- A recipient that falls 256 frames behind is disconnected rather than silently missing a frame; the client reconnects and re-synchronizes.
- Over the byte budget, the relay sends `RateLimited` and closes the connection; over the connection rate, it answers HTTP 429 with `Retry-After`.
- The image is distroless, runs as non-root, and checks its own health (`--healthcheck`). The compose file adds a read-only root filesystem, dropped capabilities, `no-new-privileges`, a 256 MB memory cap and rotated logs.

### Versions

The client and the relay each state the wire version they speak and the oldest they accept; a link works when each speaks at least the other's minimum. The relay closes a connection whose first frame is not a hello it accepts.

## Building

```bash
cargo test --workspace
VRC_WE_ACCEPT_EULA=2026-10 cargo run -p server   # plain HTTP on 127.0.0.1:8443
docker build -t vrc-we-server:local .            # needs BuildKit (docker buildx)
```

Rust 1.85 or newer. To run a local image, set `image: vrc-we-server:local` in `compose.yml`.

## License

The relay is source-available under the [PolyForm Shield License 1.0.0](LICENSE), with an Additional Permission. In short, and the license's text is authoritative:

- you may use, change and run it for any purpose that does not compete with vrc-WiredExpressions;
- you may run relays for other people, and gate access by any criteria you choose, as long as you do not sell access to them; donations and supporter memberships are fine;
- relays are for use with the vrc-WiredExpressions client.

Running the relay also means accepting the [EULA](EULA.md). Third-party crates and their licenses are listed in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt); the image carries all three files in `/usr/share/doc/vrc-we-server/`.

Contributions are welcome under the terms in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

oblivius · projects@oblivius.dev · https://github.com/99oblivius
