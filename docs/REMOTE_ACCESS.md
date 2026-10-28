# Remote Access

This document explains how to reach GhostDrive from a phone or another
machine, what each option does and does not protect, and what GhostDrive
deliberately refuses to do. It pairs with the operator endpoints described
below and with the honest-adversary framing of
[THREAT_MODEL.md](THREAT_MODEL.md).

Endpoints referenced here:

- `GET /api/remote/status` and `POST /api/remote/rescan` — full access status
  (bind address, port, URLs, Tailscale detection, checklist steps).
- `GET /api/pairing/status` — the same payload, answerable while the vault
  is **locked** (pairing needs no vault access; `vault_unlocked: false`).
- `GET /api/pairing/qr.png` — a PNG QR code of the best URL (or `?url=`).
- `GET /metrics` — Prometheus text exposition (see §7).

---

## 1. Why GhostDrive binds 127.0.0.1

The web server starts with `host="127.0.0.1"` (`ghostdrive/web/server.py`).
Nothing on your LAN or the internet can connect unless you deliberately open
a path. The rationale is simple: the UI can list filenames, download files,
and — while unlocked — drive destructive operations. An exposed port is an
exposed vault UI. The default posture is loopback-only, and it stays that
way unless *you* change it.

## 2. The Tailscale story (recommended)

[Tailscale](https://tailscale.com) builds a private WireGuard mesh between
your own devices. No inbound ports, no public exposure, no cloud relay of
your data — just your machines talking to each other.

1. Install Tailscale on the GhostDrive machine
   (Windows default: `C:\Program Files\Tailscale\tailscale.exe`).
2. Run `tailscale up` and sign in with your account.
3. Find this machine's Tailscale IP: `tailscale ip -4` → e.g. `100.64.0.5`.
4. Install Tailscale on the phone and join the same tailnet.
5. Open `http://<ts-ip>:<port>/` in the phone browser — or scan the QR code
   (§3). The port is whatever the launcher picked (8000 and up);
   `GET /api/remote/status` reports the configured one.

GhostDrive detects the CLI for you: `/api/remote/status` reports
`tailscale.running`, the `100.x` address, and `ready_for_phone`. Detection
only *reads* `tailscale ip -4` with a 5 s timeout; the app never runs
`tailscale up`, never signs in, and never modifies your tailnet.

## 3. QR pairing flow

1. On the desktop, make sure GhostDrive is running (unlock optional —
   pairing status and the QR code work while locked).
2. Scan `GET /api/pairing/qr.png` (or open it on the desktop and scan from
   the phone). Without a `url` parameter the code encodes the Tailscale URL
   when available, else the loopback URL. Only `http://`/`https://` URLs
   without embedded credentials are encoded; anything else is a 400.
3. On the phone, the URL opens the same GhostDrive UI.
4. Unlock the vault with your passphrase on the phone.

Pairing transports **a URL, nothing else** — no keys, no tokens, no trust.
The phone stays untrusted until the passphrase is typed.

## 4. WireGuard alternative

You can skip Tailscale and run plain WireGuard: point-to-point tunnels, your
own key exchange, your own endpoints. Once the phone has a route to the
machine, open `http://<tunnel-ip>:<port>/` exactly as above. GhostDrive does
not detect plain WireGuard — `ready_for_phone` will be false — but the QR
code and every URL still work. (Tor is a third option; latency makes the UI
sluggish, and the plumbing lives in `ghostdrive/utils/tor_manager.py`.)

## 5. Firewall notes

- The Windows firewall prompt for Python/uvicorn applies to the *loopback*
  listener too; allow it on private networks only.
- If you use Tailscale, the tailnet itself is the boundary — you usually do
  **not** need to open any OS firewall port.
- If you run Prometheus on another box, explicitly allow its IP to the
  `/metrics` port (or tunnel it the same way); do not expose the port broadly.
- A LAN-facing bind (`0.0.0.0`) is a manual, deliberate act this app never
  performs for you; if you do it, you own the exposure.

## 6. What is encrypted in transit (honest)

GhostDrive serves **plain HTTP** — no TLS termination in the app.

- **Loopback** (`127.0.0.1`): traffic never leaves the machine.
- **Tailscale / WireGuard**: the wire between your devices is
  ChaCha20-Poly1305-encrypted; the HTTP inside it is not.
- **Plain LAN (no tunnel)**: the entire conversation — filenames, file
  downloads, and the unlock flow — crosses your network in the clear,
  readable by anyone who can sniff the segment. Use a tunnel, or consciously
  accept the trust you are placing in that LAN.

## 7. `/metrics` exposure

`GET /metrics` speaks Prometheus text format 0.0.4 and exposes **metadata
only**: file counts and total bytes, trash count, backend counts/health,
alert counts by severity, last restore-drill result and timestamp,
durability state, sync configuration, and uptime. It never exposes file
names, paths, or content.

Metadata still describes your vault (how much you store, whether drills
pass), so treat the endpoint as sensitive: firewall it, or disable it with
the `metrics_enabled` setting (stored in the vault; a locked vault serves
only the minimal three-line set — `ghostdrive_up`, `ghostdrive_vault_unlocked 0`,
uptime — regardless).

## 8. What GhostDrive deliberately does not do

- **No public port.** The app never binds `0.0.0.0` on its own and never
  publishes an inbound endpoint.
- **No cloud relay.** There is no GhostDrive account system or rendezvous
  server; pairing is a URL, not a handshake through us.
- **No tunnels by the app.** GhostDrive does not create, relay, or
  hole-punch tunnels; Tailscale/WireGuard are external, operator-owned
  tools that we merely *detect*.
- **No TLS of its own.** The app will not pretend to encrypt what it does
  not; encrypt the transport yourself (§6).
- **No automatic firewall changes or third-party tool configuration.**
  We read `tailscale ip -4`; we never run configuration commands.

If a feature would require any of the above, it does not belong in
GhostDrive — see the threat model for why.
