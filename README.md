# LAN-CAP

> Local-first LAN discovery, inventory, and security console — no admin/root required, no cloud account, no telemetry.

[![Node.js](https://img.shields.io/badge/Node.js-22.5+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-19.2.8-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.21.2-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Features in Detail](#features-in-detail)
- [API Reference](#api-reference)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

LAN-CAP is a comprehensive network reconnaissance and security auditing tool that runs entirely on your local machine. It discovers all devices on your subnet, fingerprints them, monitors for threats like MAC clones, audits your router security, and visualizes your network topology in an interactive 3D view.

**Key Principles:**
- **Local-first**: All data stays on your machine - no cloud sync, no telemetry
- **No privileges required**: Works without administrator/root access
- **Read-only by design**: Router security checks are read-only and LAN-side only
- **Privacy-focused**: Binds to loopback by default
- **Self-contained**: Pure Node.js + React, no Python or external binaries required

## Features

### Discovery & Inventory
- **Network Scanning**: Bounded ping sweep with ARP cache integration and configurable worker pool
- **Auto-detection**: Automatically detects your subnet and network interfaces
- **Device Classification**: Identifies device types (phones, computers, TVs, cameras, printers, IoT, routers)
- **Service Probing**: Scans common ports (SSH, HTTP/HTTPS, SMB, RTSP, IPP) to label services
- **Persistent Inventory**: Tracks first/last seen times, notes, favorites, and trust status
- **Vendor Identification**: OUI-based MAC vendor lookup from local database

### Fingerprinting & Identification
- **HTTP/HTTPS Analysis**: Extracts server headers, page titles, auth realms, and TLS certificate info
- **SSDP/UPnP Discovery**: Queries UPnP devices for model and manufacturer details
- **OS Fingerprinting**: Infers OS family/version from service banners and TTL values
- **AI-Powered Guesses**: Optional integration with local Ollama or OpenAI for uncertain identifications
- **Evidence Tracking**: Shows confidence scores and supporting evidence for each identification

### Security & Monitoring
- **Watchdog Mode**: Continuous ARP monitoring for network changes
- **MAC Clone Detection**: Sophisticated correlation-based detection with scoring system
- **Trusted MAC List**: Lock known MACs to prevent false positives
- **Router Security Audit**: LAN-side read-only checks for common router vulnerabilities
- **Threat Dashboard**: Visual alerts for suspicious and likely clone devices
- **Stability Testing**: Repeated ping probes to measure packet loss and jitter

### Visualization & UI
- **3D Topology View**: Interactive SVG-based 3D network map with orbit controls
- **Color-Coded Orbits**: Devices grouped by category (Personal, Media, Smart Home, Network, Other)
- **Device Details Panel**: Comprehensive view of each device's information
- **Responsive Design**: Works on desktop and tablet browsers
- **Dark Theme**: Optimized for network security work

### Diagnostic Tools
- **Speed Test**: Network throughput testing via UPnP IGD
- **DNS Benchmark & Lookup**: Test and compare DNS resolvers
- **Ping & Traceroute**: Network connectivity diagnostics
- **Wi-Fi Scanner**: View nearby networks and connection info
- **DHCP Lease Recovery**: Read-only inspection of DHCP leases
- **Custom Port Scanner**: Scan specific ports on targets
- **Hidden Camera Detection**: Heuristic scanning for RTSP/IP camera streams
- **Network Health Check**: Quick overview of network status

## Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **Node.js** | 22.5+ | 24 LTS | `node:sqlite` used for clone detection (graceful degradation on older versions) |
| **npm** | 10+ | Latest | Comes with Node.js |
| **OS** | Windows, macOS, Linux | Any | Cross-platform compatible |
| **Privileges** | None required | None required | No admin/root needed |
| **Browser** | Modern browser with ES6 support | Chrome/Edge/Firefox latest | For the dashboard |

**Note:** Python is not used - all functionality is implemented in Node.js and React.

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/sipun1220/lan-cap.git
cd lan-cap

# Install all dependencies (server + client)
npm run install:all
```

### Manual Install

```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

## Usage

### Development Mode (Hot Reload)

Run both API server and React dev server with automatic restart:

```bash
npm run dev
```

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5174
- Press `Ctrl+C` to stop both

The dev runner includes stale port cleanup for a smooth experience.

### Production Mode (Single Process)

Build the client and serve everything from the Express server:

```bash
# Build the React frontend
npm run build

# Start the production server
npm start
```

- **Application**: http://localhost:5174

The Express server serves static files from `client/dist` and the API on the same port.

### First Scan

1. Open the dashboard in your browser
2. Navigate to the **Scan** or **Inventory** view
3. The app will auto-detect your network interface and CIDR
4. Click **Start Scan** to discover devices
5. View results in the list, grid, or **3D Topology** view

## Configuration

Create a `.env` file in the `server/` directory to customize settings:

```bash
cp server/.env.example server/.env
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | API bind address. Use `0.0.0.0` for LAN access (see security warning below) |
| `PORT` | `5174` | API server port |
| `LAN_CAP_DB` | `server/data/lan-cap.sqlite` | Path to SQLite database for clone detection logs |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint for local LLM fingerprinting |
| `OLLAMA_MODEL` | `llama3.1` | Ollama model to use |
| `OPENAI_API_KEY` | (none) | OpenAI API key for cloud-based fingerprinting fallback |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model to use |

### LAN Access Warning

⚠️ **By default, the server only binds to `127.0.0.1` (localhost).** 

If you set `HOST=0.0.0.0` to access from other devices on your LAN:
- **Anyone on your network can access the console** without authentication
- They can trigger scans and view your entire device inventory
- Only do this on trusted networks
- Consider using a firewall or VPN if needed

## Architecture

### Project Structure

```
lan-cap/
├── client/                    # React 19 + Vite frontend
│   ├── src/
│   │   ├── App.jsx           # Main app, views, scanning, watchdog UI
│   │   ├── ToolsView.jsx     # Diagnostics and router security tools
│   │   ├── topo.jsx          # 3D topology engine (SVG-based)
│   │   ├── App.css           # Theme and 3D map styles
│   │   └── main.jsx          # Entry point
│   ├── index.html
│   └── package.json
│
├── server/                    # Express API backend
│   ├── server.js            # Main server, routes, scanning logic
│   ├── db.js                # SQLite observation log for clone detection
│   ├── detector.js          # MAC clone scoring algorithm
│   ├── os-fingerprint.js    # OS detection from banners/TTL
│   ├── router-security.js   # Router security audit (read-only)
│   ├── tools.js             # Network diagnostic utilities
│   ├── discovery-names.js   # Reverse DNS and naming
│   ├── oui.json             # MAC vendor OUI database
│   ├── test.js              # Backend self-tests
│   ├── data/                # Runtime data (gitignored)
│   │   ├── devices.json     # Persistent device inventory
│   │   ├── notes.json       # Names, notes, favorites, hidden
│   │   ├── trusted.json     # Trusted MAC addresses
│   │   ├── history.json     # Scan history
│   │   └── lan-cap.sqlite   # Clone detection observations
│   └── package.json
│
├── scripts/
│   └── dev.js               # Dev runner with port cleanup
├── package.json             # Root scripts
└── README.md
```

### Technology Stack

**Backend:**
- Node.js (CommonJS) with Express 4
- Native Node modules: `child_process`, `dns`, `net`, `os`, `fs`
- SQLite via `node:sqlite` (built-in, Node 22.5+)
- CORS for cross-origin requests

**Frontend:**
- React 19 with Hooks
- Vite 8 for bundling and dev server
- Custom SVG-based 3D rendering (no Three.js/WebGL)
- Pure CSS with CSS variables for theming

**Scanning:**
- Native `ping` command via `child_process`
- ARP table parsing
- Raw TCP port checks with Node.js `net` module
- HTTP/HTTPS probes

## Features in Detail

### 3D Topology View

The topology visualizes your network as a constellation with the router/gateway at the center.

**Orbits (by device type):**
| Orbit | Color | Device Types |
|-------|-------|--------------|
| Personal | Blue/Cyan | Phones, tablets, computers/laptops |
| Media | Magenta/Purple | TVs, speakers, gaming consoles |
| Smart Home | Green/Teal | Cameras, smart plugs, IoT devices |
| Network | Orange/Yellow | Routers, switches, access points |
| Other | Gray | Unknown or unclassified devices |

**Controls:**
- **Drag**: Orbit the camera (yaw and pitch)
- **Scroll**: Zoom in/out
- **Click/Enter/Space**: Select and inspect a device
- **Orbit/Still**: Toggle auto-rotation
- **Reset**: Return to default view
- **Reduced Motion**: Respects `prefers-reduced-motion` system setting

**Visual States:**
- Online devices glow in their orbit color
- Offline devices are dimmed and rendered with dashed strokes
- Depth affects perspective scale, opacity, label priority, and draw order

### MAC Clone Detection

LAN-CAP uses correlation-based scoring across multiple signals over time:

| Signal | Points | Explanation |
|--------|--------|-------------|
| 2+ IPs on one MAC | +20 | Same MAC seen with different IP addresses |
| 2+ IPs active within 10 min | +30 | Multiple IPs recently active |
| 3+ IPs within one hour | +10 | Spreading across many IPs |
| One IP answered for another MAC | +30 | IP conflict or spoofing indicator |
| Same MAC via 2+ APs (BSSIDs) | +50 | MAC seen on different access points |
| Trusted MAC on unexpected IP | +40 | Trusted device moved unexpectedly |

**Threat Levels:**
- **0-30**: Normal
- **31-60**: Suspicious
- **61-100**: Likely clone

**Notes:**
- Randomized private MACs (common on iOS/Android) are capped at "suspicious" to reduce false positives
- Observations older than 4 days are automatically pruned
- All correlation happens locally from ARP/watch data

### Router Security Audit

Performs read-only, LAN-side checks on your default gateway:

**Checks Include:**
- Management ports (80, 443, 8080, 8443, etc.)
- HTTP/HTTPS behavior and redirects
- UPnP IGD availability
- NAT-PMP/PCP support
- Vendor identification via HTTP headers, TLS certificates, UPnP
- Known risk pattern detection

**Important:** 
- CVE matches are labeled as `possible` since firmware version cannot be reliably determined from LAN only
- External/WAN exposure tests are **deliberately excluded**
- Default credential testing is **deliberately excluded**
- Only checks the gateway or addresses within the local subnet

### Device Fingerprinting

LAN-CAP extracts identity without privileged access:

| Method | What it finds | Example |
|--------|---------------|---------|
| HTTP Headers | Server software, frameworks | `Server: nginx/1.18.0` |
| HTTP Content | Page titles, auth realms | `<title>HP LaserJet Pro</title>` |
| TLS Certificates | Subject/Issuer CN fields | Often contains model numbers |
| SSDP/UPnP | Manufacturer, model name, device type | From `device.xml` descriptions |
| Service Banners | Protocol-specific info | SSH version strings |
| TTL Analysis | OS family hints | Different TTL values per OS |

### Data Storage

All data is stored locally in `server/data/`:

| File | Purpose | Retention |
|------|---------|-----------|
| `devices.json` | Persistent device inventory with metadata | Until manually removed |
| `notes.json` | User notes, display names, favorites, hidden flags | Permanent |
| `trusted.json` | Locked MAC addresses for clone detection | Permanent |
| `history.json` | Previous scan results | Permanent |
| `lan-cap.sqlite` | MAC↔IP sighting log for correlation | 4 days (auto-pruned) |

The old `lan-scanner.sqlite` filename is automatically adopted if `lan-cap.sqlite` doesn't exist.

## API Reference

Base URL: `http://localhost:5174` (or your configured host:port)

### Health & Interfaces

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Server health check with platform info |
| `GET` | `/api/interfaces` | Network interfaces, recommended CIDR, Wi-Fi info |

### Discovery & Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/arp` | Current ARP cache entries |
| `POST` | `/api/scans` | Start network scan. Body: `{cidr, timeout, workers, arpOnly, resolveNames, serviceScan}` |
| `GET` | `/api/scans/:id` | Get scan status and results |
| `GET` | `/api/scans/:id/events` | Server-Sent Events stream for scan progress |
| `DELETE` | `/api/scans/:id` | Cancel running scan |
| `GET` | `/api/scans/:id/export?format=json\|csv` | Export scan results |

### Inventory & Device Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/devices` | Get persistent inventory with online status, timestamps |
| `GET` | `/api/storage` | Storage usage and retention information |
| `GET` | `/api/vendor/:mac` | Look up vendor by MAC address |
| `GET` | `/api/notes` | Get all notes/favorites/hidden flags |
| `PUT` | `/api/notes/:ip` | Update notes for a device. Body: `{name, note, favorite, hidden}` |

### Identification & Fingerprinting

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/identify` | Fingerprint a device. Body: `{ip}` |
| `POST` | `/api/ai-guess` | Get AI identification guess. Body: `{ip}` |

### Monitoring & Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/watch` | Start background ARP monitoring |
| `GET` | `/api/watch` | Get watchdog status |
| `DELETE` | `/api/watch` | Stop watchdog |
| `GET` | `/api/threats` | Get detected threats |
| `GET` | `/api/clones` | Get MAC clone detection results |
| `GET` | `/api/trusted` | Get trusted MAC list |
| `POST` | `/api/trusted` | Add trusted MAC. Body: `{mac}` |
| `DELETE` | `/api/trusted/:mac` | Remove trusted MAC |
| `POST` | `/api/stability` | Run stability probe. Body: `{ip, count}` |

### Router Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/router-security` | Get last router security scan results |
| `POST` | `/api/router-security/scan` | Start router security audit |
| `GET` | `/api/router-security/scan/:id` | Get router scan status/results |

### Diagnostics & Tools

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/tools/health` | Network health check |
| `POST` | `/api/tools/ping` | Ping a host. Body: `{host, count}` |
| `POST` | `/api/tools/traceroute` | Traceroute to host. Body: `{host}` |
| `POST` | `/api/tools/dns-benchmark` | Benchmark DNS resolvers |
| `POST` | `/api/tools/dns-lookup` | DNS lookup. Body: `{name, server}` |
| `GET` | `/api/tools/wifi` | Wi-Fi network information |
| `GET` | `/api/tools/dhcp` | DHCP lease information (read-only) |
| `GET` | `/api/tools/hidden-cameras` | Scan for potential hidden cameras |
| `POST` | `/api/speedtest` | Start speed test via UPnP |
| `GET` | `/api/speedtest/:id` | Get speed test results |
| `DELETE` | `/api/speedtest/:id` | Cancel speed test |
| `POST` | `/api/ping` | Quick ping check |
| `POST` | `/api/ports` | Port scan. Body: `{ip, ports}` |
| `GET` | `/api/wan` | WAN/UPnP IGD information |

## Security

### Built-in Security Measures

- **Loopback binding by default**: Server only listens on `127.0.0.1` unless explicitly configured otherwise
- **CORS restrictions**: Only allows requests from loopback and RFC1918 (private) origins; public web origins are rejected
- **Security headers**: Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cross-Origin-Resource-Policy`
- **No X-Powered-By**: Server header disabled
- **Input validation**: Targets are validated before executing commands
- **Safe command execution**: Uses `execFile` with argument arrays (no shell interpolation)
- **Read-only router checks**: No configuration changes, no credential attempts
- **Local-only storage**: All data stays on your machine

### Security Best Practices

1. **Keep default binding**: Only use `HOST=0.0.0.0` on fully trusted LANs
2. **Firewall protection**: If exposing to LAN, ensure your firewall is configured appropriately
3. **Regular updates**: Keep Node.js and dependencies updated
4. **Review inventory**: Periodically check for unknown devices
5. **Use watchdog**: Enable monitoring to detect new devices
6. **Trust carefully**: Only mark known devices as trusted

### Known Limitations

- **Client isolation**: Guest Wi-Fi networks often block device-to-device discovery
- **Privacy MACs**: iOS/Android randomized MACs cannot be reliably identified by OUI alone
- **Firmware detection**: Router firmware versions cannot be proven from LAN-side only (CVE matches are marked "possible")
- **Large subnets**: Auto-detect refuses ranges larger than 8192 hosts without explicit CIDR
- **AP visibility**: In multi-AP deployments with same subnet, you can only see your own AP details

## Troubleshooting

### Common Issues

#### Port already in use
```bash
# The dev script auto-cleans ports, but manually:
# Windows
netstat -ano | findstr :5173
taskkill /PID <pid> /F

# macOS/Linux
lsof -ti:5173 | xargs kill -9
```

#### Scan finds no devices
- Check you're on the correct network interface
- Verify firewall isn't blocking ping/ARP
- Try with `arpOnly: true` to use only ARP cache
- Some networks have client isolation enabled
- Ensure you're not on a guest network

#### Node version issues
```bash
node --version  # Should be >= 22.5
```
If using older Node, clone detection will degrade gracefully but still function.

#### Permission issues on Linux/macOS
Ping usually works without root on modern systems. If issues persist, check your network configuration.

#### Database locked errors
Close any other instances of LAN-CAP and restart the server.

### Logs and Debugging

- Server logs appear in the terminal running `npm run dev` or `npm start`
- Check `server/data/` for all stored information
- Use browser DevTools (Network/Console) for frontend issues

### Testing

Run the backend self-tests:

```bash
npm test
```

Tests cover: CIDR parsing, OUI lookups, MAC clone detector, SQLite operations, and router security checks.

Lint the frontend:

```bash
npm run lint
```

Build to verify production readiness:

```bash
npm run build
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Guidelines:**
- Keep changes local-first and privacy-focused
- No external telemetry or cloud dependencies
- Maintain read-only security posture for router checks
- Follow existing code style
- Add tests for new functionality
- Update documentation as needed

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OUI database sourced from IEEE MAC address assignments
- Built with Node.js, Express, React, and Vite
- SVG-based 3D rendering implemented from scratch
- Inspired by network security tools focused on local-first privacy

---

**Made with privacy in mind. Your network, your data.**
