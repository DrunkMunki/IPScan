# IPScan

Company-internal Windows IP and TCP port scanner for IT security teams.

Built with **Tauri 2 + Rust + React**. Inspired by the workflows of Angry IP Scanner and RustScan, implemented as a greenfield app (not a GPL fork).

## Features (MVP)

- Host discovery over CIDR / IP ranges / lists (**ARP-first on LAN**, ICMP + broader TCP probes)
- Async TCP connect port scanning with concurrency controls
- Dedicated **Port scan** mode for deep scans on specific IPs/ranges (presets: extended common, 1–1024, 1–10000, full 1–65535, custom)
- Optional **Identify services** (banners, HTTP Server/title/version, SMB dialect/signing, TLS cert CN)
- Optional **Vuln check** mode / chained checks (lightweight exposure assessment)
- **Ping** mode — wrapping browser-style tabs for continuous ICMP, CSV IP import, Export/Load DB (`%AppData%\ipscan\ping.db`), latency/drop charts
- Optional UDP scan for common services (DNS/NTP/SNMP/NetBIOS/SSDP/…) — reports ports that reply
- Hostname via reverse DNS with **NetBIOS** fallback for Windows hosts
- MAC address via Windows ARP (**same L2/subnet only**) + manufacturer via embedded OUI DB (nmap mac-prefixes, ~52k vendors)
- Allowlist gate (targets must fall inside authorized CIDRs)
- Authorized-use confirmation before scan start
- Live results grid, filters, risk notes (RDP/SMB/Telnet/FTP)
- Saved scan profiles
- CSV / JSON export
- Local audit log (default `%AppData%\com.onyx.ipscan\audit.log`); path configurable and stored in `HKCU\Software\Onyx\IPScan\AuditLogPath`

## Prerequisites (Windows)

- Node.js 20+
- Rust stable (`rustup`)
- Visual Studio 2022 Build Tools with **Desktop development with C++**
- WebView2 Runtime (usually preinstalled on Windows 10/11)

## Develop

```bash
npm install
npm run tauri:dev
```

Do **not** double-click `ipscan.exe` while developing unless Vite is running (`npm run tauri:dev`). A bare debug/dev binary expects `http://localhost:1420`.

## Build Windows installers

```bash
npm run tauri:build
```

Artifacts are written to:

- `src-tauri/target/release/ipscan.exe` (standalone, UI embedded)
- `src-tauri/target/release/bundle/nsis/`
- `src-tauri/target/release/bundle/msi/`

Always prefer `npm run tauri:build` (or at least `cargo build --release` with default features) for a runnable `.exe`.

## Authorized use

This tool is intended for **authorized internal assessments only**. Configure the allowlist to your company ranges before scanning. Do not point it at networks you do not own or administer.
