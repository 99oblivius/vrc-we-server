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

The relay runs from the `99oblivius/vrc-we-server` image. Pick a DNS name that points at the host, and give the relay the host's public port 443: it obtains its certificate in-process through Let's Encrypt, which checks it there. If another service already holds port 443, run the relay [behind that service's proxy](#behind-your-own-reverse-proxy) instead. Both forms below set up the same container, and `podman` and `podman compose` take them unchanged.

### Compose

Save this as `compose.yml` and run `docker compose up -d`:

```yaml
services:
  relay:
    image: 99oblivius/vrc-we-server:latest     # or pin a release, e.g. :2026.1
    restart: unless-stopped
    ports:
      - "443:8443"
    environment:
      VRC_WE_ACCEPT_EULA: "2026-10"            # the EULA version you accept
      VRC_WE_TLS_DOMAINS: "relay.example.com"  # a DNS name pointing at this host
      VRC_WE_TLS_EMAIL: "you@example.com"      # the Let's Encrypt account contact
    volumes:
      - acme-cache:/var/lib/vrc-we/acme
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  acme-cache:
```

The repository's [`compose.yml`](compose.yml) is the same file with every setting annotated, reading its values from the environment.

### docker run

```bash
docker run -d --name vrc-we-server --restart unless-stopped \
  -p 443:8443 \
  -e VRC_WE_ACCEPT_EULA=2026-10 \
  -e VRC_WE_TLS_DOMAINS=relay.example.com \
  -e VRC_WE_TLS_EMAIL=you@example.com \
  -v vrc-we-acme:/var/lib/vrc-we/acme \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 256m --log-opt max-size=10m --log-opt max-file=3 \
  99oblivius/vrc-we-server:latest
```

### First start

The relay loads its certificate from the volume, or orders one from Let's Encrypt, which reaches it on port 443. Until the certificate is ready, clients cannot connect. The logs (`docker compose logs`, or `docker logs vrc-we-server`) report each step and say when clients can connect, and the container turns healthy at the same moment. The logs give the certificate's end date. It is renewed in place, starting 30 days before it expires, which again needs port 443.

If an order fails, the log quotes Let's Encrypt's reason, for example a timeout when port 443 does not reach the host. The relay retries after 12 minutes, twice, then after an hour, then every 6 hours until it succeeds; Let's Encrypt blocks a name for an hour after five failures. Fix the setup and restart the relay to retry at once. A failed renewal keeps the current certificate in use; after five in a row, the attempt that follows the first 6-hour wait, the container turns unhealthy and the log says why, while clients keep connecting until the certificate expires. An expired certificate is unhealthy too.

Clients then connect to `relay.example.com`.

## Hosting

### Directly

Port 443 reaches the relay, which terminates TLS itself, as in the quick start. Leave `VRC_WE_RELAY_TRUSTED_PROXIES` unset: the relay then rate-limits by each connection's own source address, which cannot be forged.

### Behind your own reverse proxy

Leave the TLS variables empty: the relay serves plain HTTP on port 8443, and the proxy terminates TLS. Clients only connect over TLS, so publish the port to the proxy alone, for example `127.0.0.1:8443:8443` (`-p 127.0.0.1:8443:8443`). The proxy must:

- forward WebSocket upgrades on `/ws` and keep idle connections open for at least 60 s;
- append the address that connected to it to `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).

Set `VRC_WE_RELAY_TRUSTED_PROXIES` to the proxy's address, and to [your CDN's ranges](https://www.cloudflare.com/ips/) if one sits in front. The relay reads `X-Forwarded-For` only as far as these addresses wrote it, so a client cannot forge its own. A missing range fails safe: that traffic is rate-limited as one client. `0.0.0.0/0` and `::/0` are refused.

Nginx Proxy Manager trusts `X-Real-IP` from CDN and private ranges by default; add `set_real_ip_from 127.0.0.1/32;` to the host's advanced configuration so it keeps the address that connected.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VRC_WE_ACCEPT_EULA` | unset (required) | The [EULA](EULA.md) version you accept, e.g. `2026-10`. The relay refuses to start unless it names the version the release requires. |
| `VRC_WE_BIND` | `0.0.0.0:8443` (image) / `127.0.0.1:8443` (plain, outside the image) / `0.0.0.0:443` (TLS, outside the image) | Listen address. |
| `VRC_WE_TLS_DOMAINS` | unset | Comma-separated domains to obtain certificates for. Set, it enables in-process TLS. |
| `VRC_WE_TLS_EMAIL` | unset (required with TLS) | Let's Encrypt account contact. |
| `VRC_WE_TLS_CACHE` | `/var/lib/vrc-we/acme` (image) / `./acme-cache` | Where certificates are kept. Mount a volume here; the relay refuses to start if it cannot write to it (the image runs as uid 65532). |
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

- `/ws` is the relay, `/health` answers `ok` (or 503 with the reason while the certificate is unhealthy), and `/pair` serves the static page that turns an invite link into a `vrc-we://` deep link. The invite token stays in the URL fragment, which browsers never send to the server.
- A payload is one Noise message, at most 65 535 bytes; a larger one closes the connection.
- A connection holds at most 1024 tags, and a tag at most 8 connections.
- A recipient that falls 256 frames behind is disconnected rather than silently missing a frame; the client reconnects and re-synchronizes.
- Over the byte budget, the relay sends `RateLimited` and closes the connection; over the connection rate, it answers HTTP 429 with `Retry-After`.
- The image is distroless, runs as non-root, and checks its own health (`--healthcheck`, a request to `/health`, over TLS when TLS is on): healthy once a certificate is deployed, unhealthy while renewal keeps failing or once it expired. The compose file adds a read-only root filesystem, dropped capabilities, `no-new-privileges`, a 256 MB memory cap and rotated logs.

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
