# nanotun self-hosted gateway

**English** · [简体中文](README.zh-CN.md)

Give a small team secure access to machines you own — and take it back when someone leaves.

You run the gateway on your own server; your teammates get a virtual subnet where they can
reach your GPU hosts, staging boxes and office LAN, and route egress through an IP that is
yours alone. Access is granted per user, gated by ACLs, recorded in an audit log, and
revoking it actually revokes it.

Most teams solve this today by pasting a config link into a group chat. That link can't be
recalled, keeps working after someone leaves, and tells you nothing about who used what.

Typical users:

- Teams that need to reach self-hosted inference, GPU servers, or data that must stay in one
  jurisdiction
- Teams whose shared commercial VPN egress IPs keep getting flagged by upstream APIs
- Anyone who wants a private network without handing the control plane to a vendor

## How it works

`nanotun` is a self-hosted "mesh networking" server: it runs on a machine with a public
ingress, and after clients log in with a username + PSK (pre-shared key), they can reach
each other over a TUN virtual interface, forming a mesh subnet.

No external control plane / account system is required; all users, devices, and ACL rules
live in a local SQLite database (`[store].db_path`), managed by the `nanotun-admin` CLI.

## Quick start

The server runs on **Linux only** (needs TUN + iptables + systemd), supports amd64 and
arm64, and needs neither Go nor a compiler.

### One command

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

[`install.sh`](scripts/install.sh) does four things in order; if any step fails it stops and tells you why:

0. **Pick a language** — English or Chinese. English is the default; you are asked once, up
   front, and only when a terminal is attached (see below)
1. **Check the environment** — whether this machine can run it (see below); if not, it
   downloads and installs nothing, leaving no half-installed system behind
2. **Download** — auto-detects the architecture, verifies SHA256, extracts to `/opt/nanotun/`
3. **Install** ([`install-self-hosted.sh`](scripts/install-self-hosted.sh)) — systemd units,
   IP forwarding, REALITY / hy2 keys and self-signed certs, opens ufw, the first VPN admin
4. **Setup wizard** ([`setup.sh`](scripts/setup.sh)) — see below

When it finishes you can use it: the wizard asks for the client dial address, sets the Web
admin username and password, creates the first VPN user, and prints two QR codes.

> **About the client, up front.** What this repository ships is the **server**. Those two QR
> codes are meant to be scanned by a nanotun client, and the clients (macOS / Windows /
> Android / OpenWrt) are **not publicly distributed** — their code isn't here either. So: you
> can stand the server up right now and administer it from the Web console and the CLI, but
> without a client in hand there's nothing to scan those QR codes with. Contact the maintainer
> if you need one.
>
> This is stated up front because it's worth knowing *before* you spend time installing —
> rather than at the moment the wizard hands you a QR code.

> **Don't write it as `curl … | sudo bash`.** Ubuntu / Debian's sudo has `use_pty` on by
> default, which opens a separate pty for the command; layered with a pipe holding sudo's
> stdin, the wizard is suspended by job control the moment it asks a question — the prompt
> shows up but Enter does nothing (reproduced twice, both hanging, on a fresh Ubuntu 26.04).
> Written as `bash -c "$(curl …)"`, bash's stdin is the terminal itself, so the problem
> doesn't exist. Even if you do use the pipe form it won't hang: `install.sh` recognizes the
> combination, finishes installing the system, skips the wizard, and reminds you to run
> `sudo nanotun-setup`.

**Unattended** (CI / cloud-init): give the wizard everything it would ask up front, in one command —

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \
  && sudo NANOTUN_WEB_ADMIN_PASSWORD='your-password' bash nanotun-install.sh \
      --dial-host vpn.example.com --user alice --web-admin ops --yes
```

> **Here you must write to disk first, not `curl … | bash`.** In the pipe form, when curl
> fails bash receives an empty script — it dutifully runs those zero lines and then
> **exits 0**. `bash -c "$(curl …)"` is the same. A human watching won't care (nothing
> happened on screen), but cloud-init / Ansible / CI only look at the exit code: they treat
> "not a single byte downloaded" as a successful install and move on, while that machine has
> nothing on it. Writing to disk first lets `&&` honestly block on curl's failure.
>
> Land it in the current directory rather than `/tmp`: `/tmp` is world-writable, and in the
> instant between finishing the download and sudo running it, another user on the machine can
> swap the file out — and the next step is root running it.

After this one command the Web admin can log in with `ops` and that password directly — you
can install without `--web-admin` too, it just leaves the admin account uncreated, while
`/setup` is open to the whole internet until one exists (whoever opens it first is the admin).

Any argument `install.sh` doesn't recognize is passed through verbatim to the wizard, so
[`setup.sh`](scripts/setup.sh)'s options can all be given this way.

**Language.** Everything the install chain prints — the environment check, the installer, the
setup wizard, and the `nanotun-*` commands it leaves behind — comes in English or Chinese.
English is the default. With a terminal attached you are asked once before anything else
happens; without one (CI, cloud-init, `curl … | bash`) nothing is asked and English is used,
so an unattended install never blocks on the question.

```bash
sudo bash -c "$(curl -fsSL …/install.sh)" --lang zh      # or: NANOTUN_LANG=zh
```

`--lang` wins over `NANOTUN_LANG`, which wins over the choice remembered in
`/etc/nanotun/lang`. The choice is written there at install time, so `nanotun-setup`,
`nanotun-uninstall` and `nanotun-set-suffix` later default to the same language without being
told again; either knob still overrides it per run. `nanotun-admin` and the Web console read
the same `NANOTUN_LANG` (the console also has its own language switcher), so one decision
covers the whole chain.

**For production, pin the version** rather than drifting with latest. Put the same tag in both
the URL and `NANOTUN_VERSION` and the whole install is pinned — script, environment check and
release tarball all come from that tag:

```bash
sudo NANOTUN_VERSION=v1.0.0 bash -c "$(curl -fsSL \
  https://raw.githubusercontent.com/nanotun/server/v1.0.0/scripts/install.sh)"
```

Setting only `NANOTUN_VERSION` and leaving the URL on `main` works too and pins the tarball just
the same; the difference is that **the script itself** follows the trunk. Changes on `main` don't
go through the release gate — one push affects every new install — so use the form above if that
matters to you.

> Pinning all three requires a tag ≥ v0.1.25: the "when `NANOTUN_VERSION` is a tag, take the
> environment check from that tag too" coupling landed in v0.1.25. On earlier tags that
> `install.sh` doesn't have it, so the check still comes from `main` — script and tarball pinned,
> environment check not. Override explicitly with `NANOTUN_BRANCH`.

**If github.com is unreachable** (blocked, restricted egress), you don't have to give up the
one-liner — point the two download prefixes at a mirror. They're full prefixes, so both
path-style and ghproxy-style (URL-appending) mirrors fit:

```bash
sudo NANOTUN_GH_BASE=https://<your-mirror>/https://github.com/nanotun/server \
     NANOTUN_RAW_BASE=https://<your-mirror>/https://raw.githubusercontent.com/nanotun/server/main/scripts \
     bash -c "$(curl -fsSL https://<your-mirror>/https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

`NANOTUN_GH_BASE` covers the release tarball, `NANOTUN_RAW_BASE` the environment check. On a
download failure the error names the prefix you supplied instead of vaguely blaming github.com.

**If this machine has no `curl`** (minimal images like Debian netinst often ship only `wget`),
you don't need to install curl first — fetch the script with wget and the script's own downloads
fall back to wget too:

```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh)"
```

With neither present it says up front which one to install, instead of reporting "network is
down" on the first network call.

To control every step yourself, download the tar for your architecture from
[Releases](https://github.com/nanotun/server/releases), extract it and run
`sudo ./scripts/install-self-hosted.sh` — that's step 3 above, ships with the release, and
needs no network. `install.sh` merely also handles "getting it onto this machine".

### Check whether this machine will work first

After buying a VPS and wanting to scope it out, or troubleshooting after an install fails,
run the environment check on its own. It installs nothing:

```bash
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/preflight.sh | bash
```

It lists every problem at once, ending with a paste-ready fix command (with the right package
names for your distro), no need to install anything to re-run. After installing, a copy is on
disk too: `nanotun-preflight`.

> The one thing it does write: it tries to set `net.ipv4.ip_forward` to 1 — because what it needs
> to establish is precisely whether this machine *lets you* change it, and a read-only check can't
> answer that (getting it wrong costs you an `exit 60` from nanotund after the install). Installing
> sets it anyway. If you want it to touch nothing at all, add `--dry-run`:
> `curl -fsSL .../preflight.sh | bash -s -- --dry-run`. That's the path
> `install.sh --check-only` takes.

It checks whether systemd is running, whether `/dev/net/tun` exists, whether
`iptables`/`ip6tables`/`ip`/`openssl` are present, whether `ip_forward` can be set to 1, and
whether 8443/tcp, 443/udp, 7443/tcp are free. **The two most common pitfalls** are cheap
VPSes using OpenVZ / LXC virtualization that can't get a TUN device (switch to KVM), and
distros like Alpine that don't use systemd (go the Docker route).

### Which distros are supported, and down to which version

**It doesn't care about the distro — it cares about the handful of things above.** The binary
is statically compiled (`CGO_ENABLED=0`), linking neither glibc nor musl, so the distro and
version are meaningless to the program itself.

**The hard requirement is systemd ≥ 235.** The unit files use `RuntimeDirectoryPreserve=`, a
directive that only arrived in systemd 235 (October 2017); lower versions ignore that line,
so the `/run/nanotun` the two services share gets wiped by the other on each restart, and the
control socket vanishes with it — the symptom is the Web admin constantly saying "runtime data
unavailable". Translated to distros, that's the lower bounds in the table below.

Every row was installed from a bare system to wizard-complete in a container, not inferred
from version numbers:

| Distro | Minimum | Tested | Notes |
| --- | --- | --- | --- |
| Ubuntu | 18.04 | 18.04 / 20.04 / 26.04 | 18.04's systemd is 237, just above the threshold |
| Debian | 10 | 11 / 13 | 10's repos are archived and won't install packages, so it wasn't tested live; it's the same generation as 18.04, component versions map one-to-one |
| RHEL family | 8 | Rocky 8 / 9 | The firewall is firewalld; the script opens it automatically |
| Alpine | — | Explicitly blocked | Uses OpenRC instead of systemd; go the Docker route |

Distros not listed aren't necessarily unsupported: Fedora, Alma, openSUSE, Arch are the same
path as long as systemd is running, and preflight recognizes their package managers too. When
in doubt, run that read-only check command above — it gives you the answer for this machine,
more accurate than any compatibility list.

**But still prefer a version that receives security updates.** Ubuntu 18.04 and Debian 10 are
both EOL: nanotun installs and runs on them, but that machine's kernel and OpenSSL are no
longer patched by anyone — and it's about to open ports to the internet.

Older distros differ from newer ones in three places, all handled by the install scripts;
listed here only so you don't have to rediscover them while troubleshooting: OpenSSL 1.1.1
(Ubuntu ≤ 20.04 / Debian 11 / RHEL 8) writes duplicate extensions when generating certs which
Go rejects; mawk 1.3.3 (Ubuntu 18.04 / Debian 10) doesn't understand character classes like
`[[:space:]]`; the legacy iptables that older versions default to needs to write
`/run/xtables.lock`, while the systemd sandbox mounts `/run` read-only.

Alpine, Devuan and the like that don't use systemd, plus container environments without even
an init, take the [Docker deployment](docs/DOCKER.md) route: that path doesn't require systemd
on the host, and the distro matters even less.

### Setup wizard

**Installed doesn't mean clients can connect** — there are still three things only you know the
answer to: which address the client should dial, the Web admin password, and the QR codes for
users. The last step of the command above is exactly this; to run it on its own:

```bash
sudo nanotun-setup
```

It probes and writes the dial address (`server_dial_host`), **creates the Web admin on the
spot** (username and password you set now, password entered twice, hidden), creates the first
VPN user, and prints two QR codes directly in the terminal:

- **profile QR** — the server address and transport config, no PSK. But with hy2 mTLS on (the
  install default) it embeds a client certificate — that's not a login credential, yet it is
  the key to the QUIC door, so give it to the person themselves and don't post it publicly
- **credentials QR** — username + PSK, secret, handed one-to-one to the person only

Don't skip the admin-account step: before the first admin exists, the `/setup` page is open to
the whole internet — **whoever opens it first becomes the admin**. The wizard creates it, and
this door closes automatically (afterward visiting `/setup` redirects to the login page).

Re-running is safe (doesn't reset PSKs, doesn't touch config, skips if an admin already
exists); use it later to add users and re-issue QR codes. Automated deploys do it all in one
command:

```bash
sudo NANOTUN_WEB_ADMIN_PASSWORD='...' nanotun-setup \
     --dial-host vpn.example.com --user alice --web-admin ops --yes
```

The password only comes from the environment variable, not a command-line argument — argv is
visible to all users on the machine (`ps`) and lands in shell history too. Under `--yes`, if
`--web-admin` is given but no password, the wizard generates a random one and prints it on
screen (only once).

The VPN account and the Web admin are **two separate things**, the easiest to confuse: the
former is the username + PSK for client login (the PSK is generated by the server, not
chosen); the latter is for logging into the admin panel in a browser, with a password you set.
Admin accounts can also be added anytime from the CLI:

```bash
sudo nanotun-admin webadmin create <name>     # prompts for the password twice, no echo
sudo nanotun-admin webadmin list              # see who the admins are
```

Forgot the admin password, or got locked out by too many wrong attempts? Recover from the server:

```bash
sudo nanotun-admin webadmin reset-password <name>   # change the password, also clears the failure lock
sudo nanotun-admin webadmin unlock <name>           # unlock only, password untouched
```

Once the client scans both codes it can connect. The rest of user management goes through the
Web admin or the CLI below.

### Run with Docker

If you're already comfortable with containers, this route works too:

```bash
curl -fsSLO https://raw.githubusercontent.com/nanotun/server/main/docker/docker-compose.yml \
  && docker compose up -d && docker compose logs -f     # the first-boot PSK is printed in the logs
```

The image is `ghcr.io/nanotun/server` (amd64 + arm64 multi-arch). It's a VPN gateway with hard
requirements on `/dev/net/tun`, `CAP_NET_ADMIN`, host `sysctl`, and the firewall; those host
kernel params can't be set from inside the container, you must set them yourself — **the two
lines above finishing doesn't mean clients can connect**; see [`docs/DOCKER.md`](docs/DOCKER.md)
for the step-by-step gotchas. There's no `nanotun-setup` in the container; set the dial address
and users in the Web admin, or `docker compose exec nanotun nanotun-admin ...`.

### Build from source (for development)

```bash
git clone https://github.com/nanotun/server.git && cd server
go build ./...

# Local non-root test run: config.toml pins [store].db_path to the production
# absolute path /var/lib/nanotun/nanotun.db; use the config_no_tun.toml one
# (db_path is data/nanotun.db, and it needs neither root nor TUN).
cd cmd/nanotund && go build -o nanotund . && ./nanotund -config config_no_tun.toml

# Verify your own changes in a container:
cd docker && docker compose -f docker-compose.dev.yml up --build
```

## Create users and devices with the admin CLI

`nanotun-setup` does exactly the steps below; use the CLI directly when you want manual control
or to script it. Full commands are in [`cmd/nanotun-admin/README.md`](cmd/nanotun-admin/README.md);
the most common workflow (after the 0013 credentials split, **dual QR**: profile without PSK +
credentials issued separately):

```bash
# On a machine with nanotun installed you can omit --db-path: when it can't find
# data/nanotun.db in the current directory it auto-uses /var/lib/nanotun/nanotun.db
# and says so. To pin it, set NANOTUN_DB — commands in docs, scripts, and tickets
# shouldn't depend on "which directory you run from".
export NANOTUN_DB=/var/lib/nanotun/nanotun.db

# 1) Create a user: the PSK is echoed in plaintext only this once, and a credential_id (UUID v4) is assigned.
nanotun-admin user create alice --admin --exit-allowed=true

# 2) Client profile QR (server node / routes, no PSK; with hy2 mTLS on it embeds a client cert,
#    so it's "for the person" not "post anywhere"). --dial-host, if omitted, uses the stored server_dial_host.
nanotun-admin profile show alice --dial-host vpn.example.com --format qr

# 3) Client credentials QR (generated from the PSK plaintext + UUID, **plaintext obtainable only this once**).
#    The user scans the nanotun-cred://v1?d=... QR into the Apple client Keychain; the Profile list
#    then goes "bind credentials" and picks this UUID. Later reset-psk re-issues a new QR, and the
#    client overwrites automatically by UUID.
nanotun-admin credentials show alice --psk '<the plaintext echoed at create time>' \
    --format qr-png --output alice-cred.png

# The PSK being lost isn't fatal, but rotating it kicks that user's online sessions:
nanotun-admin --yes credentials show alice --rotate-psk --format qr
```

For Docker deployments prefix everything with `docker compose exec nanotun` (the image has
`NANOTUN_DB` already pinned).

## Server processes and ports

After install, systemd manages the services (`systemctl status nanotun` / `nanotun-web`); for
Docker it's the container itself. To run in the foreground by hand (troubleshooting):
`sudo nanotund -config /etc/nanotun/config.toml`.

The VPN data plane listens on `[server].listen_addr` (default `127.0.0.1:8080`, loopback only),
speaking WebSocket Binary + custom link frames (see `util/link_frame.go`). Production clients
(iOS/Android) enter via Hysteria 2 (`[hysteria]`, :443/udp) or Xray REALITY (`[reality]`,
:8443/tcp); after the handshake the server loopback-bridges them to the data-plane port, and
clients never connect to 8080 directly. Only if you want clients to dial the data plane
directly via wss:// do you change `listen_addr` to `:8080` (all interfaces) and open the firewall.

## Protocol and session semantics

- The client's first frame sends `LinkTypeLoginReq`, fields in `util/protocol.go`. The `Token`
  field carries the PSK plaintext, which the server verifies with argon2id.
- On success the server sends `LinkTypeLoginResp(code=0, session_id, takeover_secret)` +
  `LinkTypeConvSaltMsg` (with virtual IP / DNS).
- Each session has a unique `connIDStr` (16B hex), used for "hot-swap takeover": the client can
  send a `Purpose=takeover` LoginReq over another transport to take over the original session;
  after the server verifies PSK + secret it seamlessly transfers the vIP / TunChan.
- `Code*` error codes (`util/login_codes.go`) are defined in the `util` package; the client
  shows UI hints by `Code` + `clientLoginMessageForCode`.

## Security defaults

- PSKs are hashed with `argon2id` (t=3 / m=64MB / p=2); `auth.argon2Sema` caps concurrency to
  prevent a DoS from blowing up memory.
- The concurrent session count is **unlimited** by default; you can set a global cap
  `[server].max_sessions_per_user` (>0 takes effect), or override per account with
  `user set-max-sessions <username> <n>` (>0 overrides global, -1 unlimited for that account,
  0 follows global); exceeding it kicks the oldest by `createdAt`, and changes apply to future
  logins only.
- With `[server].jump_host_firewall=true`, it attaches ipset + iptables on Linux per
  `[server].jump_host_allowed_ips`, allowing only source IPv4 addresses in the list to connect
  (127.0.0.1 is added automatically).
- All login failures / kicks / config reloads / ACL drops are written to `audit_logs`,
  auto-pruned after 30 days (see `cmd/nanotund/audit_gc.go`).
- Revocation has two layers: `user disable <user>` seals all devices, `user reset-psk <user>`
  (also via `credentials show <user> --rotate-psk`) invalidates the old credential; both cause
  online sessions to be actively kicked by the server within
  ≤ `[server].user_invalidate_interval_sec` (default 10s) (close code = 905).
  The historical per-profile `pid` blacklist (P2#14) was removed in 0014 (2026-05-25) along
  with the credentials split — the profile QR no longer contains the PSK, so leaking it can't
  log in, making per-QR revocation redundant.

## Profile QR vs Credentials QR — the dual-QR design (since 0013)

Since 0013 (2026-05-25) nanotun splits the client import QR **into two**, to stop putting the
PSK and server config into the same shareable URL:

| QR type | URL prefix | Content | Security level |
| --- | --- | --- | --- |
| profile QR | `nanotun://v1` | server host / transport (WS, Hysteria, REALITY) / nodes config; with hy2 mTLS on it also contains a client cert and private key | **for the person** — no PSK, useless for login on its own; but that cert is the key to the QUIC door, and making it public strips a layer that blocks scanning |
| credentials QR | `nanotun-cred://v1` | `credential_id` (UUID v4) + `username` + `psk` + `created_at` | **secret** — passed locally one-to-one only, the client stores it in the Keychain |

Workflow:
- **First issuance**: the admin exports both QRs for the user. The client scans profile first
  (pick server), then credentials (inject the credential). Both go only to the person: the
  profile has no PSK and can sync via cloud to the same person's multiple devices, but the
  client cert it embeds isn't suitable for public posting or mass distribution; credentials go offline.
- **Multiple devices**: the same user logs in on a new device by scanning the **same**
  credentials QR; the `credential_id` stays the same, and `nanotun-admin device list` counts
  each device_uuid separately.
- **Credential rotation**: `nanotun-admin user reset-psk <user>` or
  `credentials show <user> --rotate-psk` generates a new PSK while **keeping** `credential_id`
  unchanged. The client scans the new credentials QR once more and, indexed by `credential_id`,
  overwrites the local old PSK automatically — no need to delete the old entry by hand; sessions
  on the old PSK are kicked by the server with Close(905) within ≤ 10s.
- **Ops list**: `nanotun-admin credentials list [--json]` prints all users who have been issued
  credentials (including disabled ones), with `credential_id` + last rotate time;
  `user show --json` exposes `credential_id` / `credential_created_at` from the user's perspective.

CLI quick reference:
```bash
# Profile QR (server config + client cert, for the person)
nanotun-admin profile show <user> --format qr      # terminal QR
nanotun-admin profile show <user> --format qr-png --output profile.png

# Credentials QR (secret credential; the rotate path equals user reset-psk)
nanotun-admin credentials show <user> --psk PLAIN  --format qr
nanotun-admin credentials show <user> --rotate-psk --format qr
nanotun-admin credentials list [--json]
```

Same in the Web admin: the `/users` list shows the first 8 chars of `credential_id`; creating a
user / resetting the PSK both go via a PRG redirect to `/users/{id}/created` or
`/users/{id}/reset-psk-result`, and a stale or refreshed token counts as already shown once,
avoiding an accidental repeat rotate.

## Optional modules

- **Magic DNS** (P2#11) with `[server.magic_dns].enabled=true`, the server runs a built-in stub
  DNS on the TUN gateway IP's :53, resolving `<device>.<user>.<suffix>` to a vIP. `listen_port`
  must = 53, otherwise the server skips prepending the gateway DNS to the client (to avoid
  pointing the client's DNS at an unreachable port). See the `cmd/nanotund/config.toml`
  comments for a config example. The suffix `<suffix>` defaults to `lan` and can be customized
  **at install time**: `--magic-suffix nanotun` or the env var `NANOTUN_MAGIC_SUFFIX=nanotun`
  (one-shot install `install.sh` / offline `install-self-hosted.sh` / same var for Docker;
  only takes effect when `config.toml` is first written). To change the suffix on an
  **already-installed** machine use `sudo nanotun-set-suffix <suffix>` (installed as a command
  with the package; in the release it's `scripts/set-magic-suffix.sh`) — backup → rewrite →
  restart → auto-rollback on failure; the `nanotun-setup` wizard also has an optional step for
  it. At runtime the suffix is read only from `config.toml`; `nanotun-admin setting set
  magic_suffix` is not the entry point (hard-blocked with guidance).
- **Subnet route advertise** (P2#12, **data plane landed SR-M1**) clients can advertise a local
  subnet, which the admin approves via `nanotun-admin route approve <device_id> <cidr>`. After
  approval, as long as the advertising device is online and the requester→advertiser ACL allows
  it, traffic to that CIDR is really delivered by the server to the advertiser's session, then
  forwarded / NAT'd into its LAN by the advertiser's host (requires the advertiser client to
  support SR-M2 LAN forwarding). See `docs/DESIGN_SUBNET_ROUTES.md`.

## Observability / monitoring

- **`/health`** (default `127.0.0.1:8081`) JSON liveness probe, usable directly by k8s
  liveness/readiness.
- **`/metrics`** (same port) Prometheus text format (OpenMetrics 0.0.4 compatible), exposing:
  active sessions, ACL drops (by kind), lease GC counts, Magic DNS egress distribution, subnet
  route accept/reject counts, login rate-limit hits, etc. Scrape example:
  ```yaml
  scrape_configs:
    - job_name: nanotun
      static_configs: [{targets: ['127.0.0.1:8081']}]
      metrics_path: /metrics
  ```

## systemd integration

`cmd/nanotund/nanotun.service` uses `Type=notify` + `WatchdogSec=30s`:
- Startup: systemd marks it `active` only after the server calls `sd_notify READY=1`, letting
  dependent units order correctly;
- Heartbeat: the server sends `WATCHDOG=1` every 15s; if stuck for 30s systemd auto-SIGTERMs
  and restarts;
- Shutdown: `sd_notify STOPPING=1` makes `systemctl status` show `deactivating`.

Non-systemd deployments (running `./nanotund` directly): with `NOTIFY_SOCKET` empty → all
no-ops, not affecting dev / container scenarios.

## Config validation

```bash
# Default lenient: unknown fields only WARN, the server keeps starting (backward compat).
./nanotund -config config.toml

# strict: any unknown field is a fatal exit (good for CI / upgrade flows).
NANOTUN_CONFIG_STRICT=1 ./nanotund -config config.toml

# Don't start the server, just validate:
nanotun-admin config lint config.toml
# Exit codes: 0=OK / 3=unknown field / 4=TOML syntax error / 1=I/O error
```

## Testing

```bash
# Unit + integration tests (fully local, no external services)
go test -count=1 ./...

# Server package only, verbose
go test -v -count=1 -timeout 120s ./cmd/nanotund/

# Benchmarks
go test -bench="BenchmarkLoginFlow" -benchtime=10s -count=1 ./cmd/nanotund/
```

The three-machine behavioral regression and the **release gate** are in
[`docs/RELEASE.md`](docs/RELEASE.md). A green merge only passes CI; releasing must go through:

```bash
./scripts/e2e/run.sh 00 10 20 30 40 50 60 70
./scripts/release/stamp-e2e.sh
./scripts/release/cut.sh v0.1.0
git push origin v0.1.0     # triggers CI to build the Release tar + GHCR image
```

The three-machine e2e can't run in GitHub Actions, so the gate stays local: `cut.sh` writes
the e2e stamp into an annotated tag, and the workflow only accepts that kind of tag — a
hand-made `git tag` push can't ship a release.

## Upgrade / deploy

**Docker**: `docker compose pull && docker compose up -d`. The config isn't overwritten;
template changes are saved to `config.toml.dist` for diffing.

**Bare metal**: re-run `install.sh`, adding `--no-setup` when upgrading — that step is the
first-run wizard, which a machine that's already serving doesn't need to go through again:

```bash
sudo NANOTUN_VERSION=v1.0.0 bash -c "$(curl -fsSL \
  https://raw.githubusercontent.com/nanotun/server/v1.0.0/scripts/install.sh)" --no-setup
```

You can also download the new tar and run `install-self-hosted.sh` directly (that one never
enters the wizard). The scripts are idempotent and **won't touch** an already-effective
`config.toml` or the keys — re-signing keys would kick off all existing clients. See the script
header comments and [`docs/UPGRADE_M0.md`](docs/UPGRADE_M0.md).

Leaving `--no-setup` off breaks nothing either: the wizard recognizes an already-configured
machine — it defaults the dial address to the current value, and skips the web admin and the VPN
user when they already exist. You just walk through the questions for nothing.

Upgrading across several versions at once uses the same method, no need to climb version by
version. Tested going straight from v0.1.0 to v0.1.16: `server_id`, the REALITY private key,
the two certs, users and ACLs are all preserved verbatim, and already-issued profile QRs keep
working (a field-by-field comparison shows only that on-demand-signed client cert differs, the
other 18 items identical, and the old cert still verifies under the upgraded CA).

**But one thing the upgrade won't do for you**: the client cert embedded in the profile has its
validity fixed **at the moment it was signed**. The default went 90 days → 10 years → 100 years,
but each change only affects newly signed ones; QRs issued by old versions still expire on their
original schedule, and upgrading doesn't retroactively extend them. If you're upgrading
from an early version, re-issue `profile show` for existing users to swap to a long-lived cert —
otherwise you think "everything's a hundred years now" while clients drop offline en masse on the
originally scheduled day.

The same applies to the **client CA** on disk: it's only minted when missing, so a machine
installed before the 100-year change still carries the older, shorter CA — and the issuer clamps
every leaf to the CA's `NotAfter`, so freshly issued client certs silently inherit that shorter
expiry. `profile show` says so when the remaining life drops under 180 days.

**Backup**: `nanotun-admin backup <path>` (hot-consistent, via `VACUUM INTO`; without a path it
names by timestamp) grabs the SQLite DB; also store `/etc/nanotun` alongside it — the REALITY
private key and hy2 password are in there, and losing them means clients must re-onboard.

**What to do if the database is lost**: the service won't stop just because the DB is gone — it
rebuilds an empty one and starts as usual, so don't count on "the service crashed" to alert
you. Recovery is copying the backup back:

```bash
sudo systemctl stop nanotun nanotun-web
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db restore /path/to/backup.db
sudo systemctl start nanotun nanotun-web
```

Use `restore` rather than `cp`: it first verifies the source is a complete nanotun DB (a
half-downloaded backup, a wrong tar.gz, a 0-byte cron artifact are all kept out), keeps a copy
of the current DB as `.pre-restore-<timestamp>` before overwriting, and **flatly refuses while
the service is still running**.

That last one matters most. `cp` overwrites in place with the inode unchanged, so the server's
"reopen if the DB file is swapped" fallback misses it: forget to stop one service then cp, and
that process keeps serving with a DB whose bytes were swapped out from under it, silently,
while the other service can't start and the log only has a `database is locked`. In
non-interactive scenarios (ssh, scripts) remember `--yes` — without a TTY it can't ask anyone
and will do nothing and exit non-zero.

The install wizard writes a line `NANOTUN_WEB_ALLOW_SETUP=0` into `/etc/nanotun/web.env`,
keeping the closed state of /setup outside the database. Otherwise once the DB is gone, /setup
reopens to the whole internet, and whoever opens it first becomes this machine's admin.

**Only the wizard writes this line.** A machine installed skipping the wizard, with the admin
account created via `nanotun-admin webadmin create`, doesn't have this line — on that machine
"there's already an admin so /setup is closed" is only recorded in the DB, and it's gone once
the DB is lost. Tested: delete the DB and restart, both services are active, and `/setup`
returns 200 with the create-admin form. If uneasy, add that line yourself and restart
`nanotun-web` (`nanotun-web` also warns about this on every startup).

To really re-bootstrap an admin account, use the CLI:

```bash
sudo nanotun-admin webadmin create <name>
```

Same for container deploys, except the line goes in the compose `environment:` (see
`docker/docker-compose.yml`) — volume loss is the most common container mishap, and the compose
file, not being with the volume, is still alive at that point.

**What to do if the whole machine is gone**: the above is for "DB lost, machine still there",
when `/etc/nanotun` is intact and just restoring the DB is enough. Moving to a new machine
needs one more step — bring the identity along, otherwise the new machine generates a fresh set
of REALITY private key and certs, no old client can connect, and the server log looks perfectly
normal.

```bash
# 1) Install on the new machine as usual (the version needn't match the old one, newer is fine)
curl -fsSL https://raw.githubusercontent.com/nanotun/server/main/scripts/install.sh -o nanotun-install.sh \
  && sudo bash nanotun-install.sh --yes --dial-host <new-address>

# 2) Stop the services, put the backup back — both are needed: /etc/nanotun is identity, the DB is users and settings
#    Restore the DB with restore not cp, reasons in the previous section (it verifies the source, keeps a copy of the old DB, refuses if the service isn't stopped)
sudo systemctl stop nanotun nanotun-web
sudo tar -xzf etc-nanotun.tar.gz -C /etc
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db restore backup.db --yes
sudo systemctl start nanotun nanotun-web

# 3) If the new machine's IP changed, the dial address restored from backup still points at the old machine
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db setting set server_dial_host <new-address>

# 4) If the backup has no Web admin, create one now (reason below)
sudo nanotun-admin --db-path /var/lib/nanotun/nanotun.db webadmin create <name>
```

Step 4 is easy to miss: when the new machine was installed the wizard wrote
`/etc/nanotun/web.env` (`ALLOW_SETUP=0`), and step 2's tar extraction **won't** delete files
not in the archive, so that line stays — thus /setup is closed and the DB has no admin, and no
one can get into the panel. The service is active, the log is clean, the page opens fine, and
not a single symptom points to the cause, which is why `nanotun-web` says it outright in the
startup log (`journalctl -u nanotun-web`).

Tested across distros too (source machine Ubuntu 26.04 → new machine Ubuntu 20.04): after
restore the cert fingerprint, REALITY private key, and user list are byte-for-byte identical to
the source.

Step 3's address change can't save already-issued client configs — they have the old address
written in. **So the dial address should be a domain, not an IP, from the start**: swapping
machines then means changing one DNS record and clients touch nothing.

**Uninstall**: installed as a command, so it works from any directory.

```bash
sudo nanotun-uninstall --dry-run    # see which files it would touch first
sudo nanotun-uninstall              # stop services, remove the program, keep config and DB
sudo nanotun-uninstall --purge      # delete config, certs, DB too
```

It's [`scripts/uninstall.sh`](scripts/uninstall.sh) from the release; running that directly
works too if you still have the extracted directory.

By default it keeps `/etc/nanotun` and the DB, so a reinstall picks up where it left off;
`--purge` requires you to type `purge` to confirm, because users, devices, PSKs, and approved
subnet routes all go together, and already-issued client configs are invalidated with them.

Don't `rm -rf /etc/nanotun /var/lib/nanotun` by hand: these two directories are **shared with
the client**, and the client's device identity `/etc/nanotun/device_id` is in there. Deleting
it makes the client re-register with a new UUID, and the UUID is the stable key for approvals
and egress selection — the old device row still holds the fixed vIP, the new device can't pin
it, and to clients that already chose this egress it simply disappears. The uninstall script
deletes by a file manifest and doesn't touch these.

The database schema migrates automatically at startup; there's no separate migrate command.

Historical versions once relied on a centralized auth backend (`legacy_backend` mode); the
current codebase has removed that path entirely, and all deployments go self-hosted PSK. For
historical attribution, see `docs/POSTMORTEM-20260521-db-path-migration.md`.

## License

This project is open-sourced under [Apache License 2.0](LICENSE). `third_party/xtls-reality`
is vendored third-party code retaining its own license (see `LICENSE` and `LICENSE-Go` in that
directory).
