# LAN-CAP Complete User Manual

This manual provides detailed instructions for installing, configuring, and using all features of LAN-CAP.

## Table of Contents

- [Getting Started](#getting-started)
- [Interface Overview](#interface-overview)
- [Scanning Your Network](#scanning-your-network)
- [Managing the Inventory](#managing-the-inventory)
- [3D Topology View](#3d-topology-view)
- [Device Identification](#device-identification)
- [Watchdog & MAC Clone Detection](#watchdog--mac-clone-detection)
- [Router Security Audit](#router-security-audit)
- [Diagnostic Tools](#diagnostic-tools)
- [Settings & Configuration](#settings--configuration)
- [Data Management](#data-management)
- [Advanced Usage](#advanced-usage)
- [Appendix](#appendix)

## Getting Started

### First Launch

1. Start the application (see [Installation](README.md#installation) in README)
2. Open your browser to the provided URL
3. The dashboard will load and attempt to detect your network interfaces
4. You'll be presented with the main dashboard view

### Understanding the Network Context

Before scanning, LAN-CAP needs to know which network to scan:
- It automatically detects your active network interface
- It calculates the CIDR range (usually /24 for home networks)
- It identifies your gateway/router
- It shows your own device as "Self"

## Interface Overview

The LAN-CAP interface consists of several main views accessible from the navigation:

| View | Purpose |
|------|---------|
| **Dashboard/Inventory** | Main device list with filtering, sorting, and quick actions |
| **Topology** | Interactive 3D visualization of your network |
| **Scan** | Network scanning controls and history |
| **Watchdog** | Monitoring status and threat detection |
| **Router Security** | Gateway audit and findings |
| **Tools** | Diagnostic utilities (ping, DNS, speed test, etc.) |

### Device Card Information

Each device in the inventory displays:
- **Icon**: Based on device type (phone, computer, TV, camera, printer, etc.)
- **Name/Label**: Custom name or auto-detected
- **IP Address**: Current IP on the network
- **MAC Address**: Hardware address
- **Vendor**: Manufacturer from OUI lookup
- **Status**: Online/Offline indicator
- **Type**: Classified device category
- **First/Last Seen**: Timestamps

## Scanning Your Network

### Starting a Scan

1. Navigate to the **Scan** view or click **Scan** from the dashboard
2. Configure scan options:
   - **CIDR**: Network range to scan (auto-detected by default)
   - **Resolve Names**: Enable reverse DNS lookups (slower but more informative)
   - **Service Scan**: Probe common ports for service identification
   - **ARP Only**: Use only existing ARP cache (fastest, no active ping)
3. Click **Start Scan**

### Scan Progress

During scanning, you'll see:
- Progress percentage
- Number of hosts discovered
- Current phase (ARP discovery, ping sweep, service probing, etc.)
- Option to cancel

### Scan Options Explained

| Option | Default | Description |
|--------|---------|-------------|
| `arpOnly` | false | Skip active ping, only read ARP cache. Faster but may miss sleeping devices |
| `resolveNames` | false | Perform reverse DNS lookups. Can be slow on some networks |
| `serviceScan` | true | Probe common ports to identify services and refine device types |
| `timeout` | varies | Timeout for individual probes |
| `workers` | auto | Number of concurrent scan workers (higher = faster but more network load) |

### Tips for Effective Scanning

- **Home networks**: Default settings usually work well
- **Large networks**: Increase workers cautiously
- **Sleeping devices**: They may not respond to ping; try multiple scans or keep watchdog running
- **Guest networks**: Often have client isolation - devices won't see each other
- **VPNs**: May interfere with network detection

## Managing the Inventory

### Device Actions

Click on any device to open the detail panel with these actions:

| Action | Description |
|--------|-------------|
| **Rename** | Give the device a custom display name |
| **Add Note** | Add personal notes about the device |
| **Favorite** | Mark as favorite (appears at top) |
| **Hide/Unhide** | Hide devices from main view |
| **Identify** | Run fingerprinting to determine device details |
| **AI Guess** | Get AI-powered identification (requires Ollama or OpenAI) |
| **Trust** | Mark MAC as trusted for clone detection |
| **Ping** | Quick connectivity test |
| **Port Scan** | Custom port scanning |

### Organizing Your Inventory

- **Favorites**: Click the star icon to prioritize important devices
- **Hidden devices**: Toggle "Show Hidden" to view hidden entries
- **Notes**: Use notes to track device purposes, locations, or ownership
- **Sorting**: Sort by name, IP, last seen, type, or status

### Understanding Device Status

- **Online** (green indicator): Device responded recently
- **Offline** (gray indicator): Not seen in recent scans
- **Self** (blue badge): Your own computer running LAN-CAP
- **Gateway** (orange badge): Your router/default gateway

## 3D Topology View

### Navigation

| Input | Action |
|-------|--------|
| Mouse drag | Rotate the view (orbit) |
| Mouse wheel/scroll | Zoom in and out |
| Click on node | Select device and open details |
| Enter/Space (on focused node) | Select device |

### View Controls

Located at the top/bottom of the topology view:
- **Orbit/Still**: Toggle automatic rotation
- **Reset**: Return camera to default position and zoom
- **Orbit Settings**: Adjust rotation speed (if available)

### Reading the Topology

- **Center node**: Router/gateway is at the origin
- **Orbits**: Devices arranged by category in concentric tilted rings
- **Size**: Indicates relative importance or category
- **Glow**: Online devices have glowing nodes
- **Dashed outline**: Offline devices
- **Labels**: Shown based on zoom level and depth (closer devices labeled first)
- **Colors**: Match device category (see color scheme in README)

### Accessibility

- Respects `prefers-reduced-motion` - auto-rotation disabled automatically
- Keyboard navigation supported for node selection
- SVG-based, works without WebGL

## Device Identification

### Automatic Fingerprinting

LAN-CAP automatically collects evidence during scans:
1. **Service discovery** probes open ports
2. **HTTP probing** fetches headers and pages from web servers
3. **TLS inspection** examines certificates on HTTPS
4. **SSDP/UPnP** queries for device descriptions
5. **OS fingerprinting** analyzes TTL and banners

### Manual Identification

1. Click on a device → **Identify**
2. LAN-CAP will probe the device with various methods
3. Results show:
   - **Detected Type**: Inferred device category
   - **Model/Name**: Extracted from evidence
   - **Manufacturer**: From evidence or OUI
   - **Confidence**: Percentage based on evidence quality
   - **Evidence**: List of sources (HTTP headers, TLS cert, SSDP, etc.)
   - **OS Guess**: Inferred operating system

### AI-Powered Identification

For ambiguous devices, use AI guessing:

**Setup for local Ollama (recommended):**
1. Install [Ollama](https://ollama.com/)
2. Pull a model: `ollama pull llama3.1`
3. Ensure Ollama runs on `http://localhost:11434`
4. LAN-CAP will auto-detect it

**Setup for OpenAI:**
1. Add `OPENAI_API_KEY` to `server/.env`
2. Optionally set `OPENAI_MODEL` (default: gpt-4o-mini)

**Using AI Guess:**
1. Open device details → **AI Guess**
2. The AI analyzes collected evidence and suggests identification
3. Review the reasoning and accept/update if appropriate

## Watchdog & MAC Clone Detection

### Enabling Watchdog

1. Navigate to **Watchdog** view
2. Click **Start Watchdog**
3. The watchdog continuously monitors ARP table changes
4. All sightings are logged to SQLite for correlation

### Understanding Clone Detection

MAC cloning occurs when the same MAC address appears with different IP addresses, which can indicate:
- DHCP IP changes (normal for many devices)
- MAC spoofing (potential attack)
- Network bridging issues
- Virtual machines

LAN-CAP scores based on correlation over time.

### Viewing Threats

The **Watchdog** and **Inventory** views show threat indicators:

| Badge | Level | Meaning |
|-------|-------|---------|
| Normal | 0-30 | Expected behavior |
| Suspicious | 31-60 | Unusual patterns, worth investigating |
| Likely Clone | 61-100 | Strong indicators of cloning/spoofing |

### Managing Trust

To reduce false positives for known devices:

1. Open device details
2. Click **Trust** / **Mark as Trusted**
3. Trusted MACs get +40 points if seen on unexpected IPs but you can track them
4. Manage trusted list from Watchdog view or API

### Privacy MAC Handling

Modern phones randomize MAC addresses:
- iOS uses randomized MACs for Wi-Fi probing
- Android has MAC randomization features
- LAN-CAP caps confidence for randomized/private MACs
- Look for "locally administered" MAC flag (second hex digit odd)

## Router Security Audit

### Running an Audit

1. Navigate to **Router Security** view
2. Click **Scan Router**
3. LAN-CAP will:
   - Discover default gateway
   - Probe management interfaces
   - Check UPnP/NAT-PMP
   - Fingerprint router software
   - Analyze for known issues

### Understanding Results

Results include:
- **Gateway Info**: IP, vendor, detected model
- **Open Management Ports**: Web, SSH, telnet interfaces found
- **UPnP Status**: Whether UPnP IGD is enabled
- **Findings**: Security issues with severity levels
- **Recommendations**: Suggested actions
- **CVE Matches**: Possible vulnerabilities (marked as "possible")

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **Info** | Informational finding | Review for awareness |
| **Low** | Minor issue | Consider addressing |
| **Medium** | Notable concern | Should be investigated |
| **High** | Serious issue | Address promptly |

### Important Notes

- **Read-only**: No changes are made to your router
- **LAN-side only**: Cannot test from outside your network
- **Firmware unknown**: CVEs are speculative without exact firmware version
- **Safe by design**: No default credential testing, no exploitation attempts

## Diagnostic Tools

Access all tools from the **Tools** view.

### Health Check
Quick overview of network connectivity and interface status.

### Ping
Test connectivity to any host:
1. Enter hostname or IP
2. Set number of pings (default: 4)
3. View results with packet loss and round-trip times

### Traceroute
Trace network path to destination:
- Shows each hop with IP and response time
- Helps diagnose routing issues
- Uses system traceroute/tracert

### DNS Benchmark
Compare performance of DNS resolvers:
- Tests common public DNS (Google, Cloudflare, Quad9, etc.)
- Measures response times
- Helps choose fastest DNS for your location

### DNS Lookup
Query DNS records for a domain:
- Supports various record types
- Can use specific DNS servers

### Wi-Fi Scanner
View wireless network information:
- Current connected network (SSID, BSSID, signal strength)
- Available networks (where supported)
- Note: Requires platform support

### DHCP Information
View DHCP lease details (read-only):
- Current lease information
- DHCP server details
- Renewal times

### Speed Test
Test internet throughput via UPnP IGD:
- Requires UPnP enabled on router
- Measures download/upload speeds
- Results shown with timestamps

### Hidden Cameras
Heuristic scan for RTSP/IP camera streams:
- Scans common RTSP ports (554, 8554)
- Attempts basic detection
- Results are probabilistic, not definitive

### Custom Port Scan
Scan specific ports on a target:
1. Enter target IP
2. Specify ports (comma-separated or ranges)
3. View open/closed/filtered status

## Settings & Configuration

### Environment Configuration

Edit `server/.env` for advanced configuration:

```env
# Server binding
HOST=127.0.0.1
PORT=5174

# Clone detection database
LAN_CAP_DB=server/data/lan-cap.sqlite

# Local LLM (Ollama)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1

# OpenAI fallback
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```

### Network Interface Selection

LAN-CAP auto-selects the best interface, but you can influence detection. The API returns available interfaces at `/api/interfaces`.

### Scan Defaults

Adjust scan behavior through the UI or API. Worker count and timeouts are automatically optimized but can be customized.

## Data Management

### Viewing Storage Usage

Navigate to Storage info or check via API: `GET /api/storage`

Shows:
- File sizes for all data files
- Record counts
- Retention status for SQLite log

### Manual Data Cleanup

All data files in `server/data/` can be safely deleted to reset:
- `devices.json` - clears inventory
- `notes.json` - clears names/notes/favorites
- `trusted.json` - clears trust list
- `history.json` - clears scan history
- `lan-cap.sqlite` - clears clone detection history

**Warning:** Deleting is permanent and cannot be undone.

### Backup

To backup your configuration and inventory:
```bash
# Copy the entire data directory
cp -r server/data/ backup/
```

### Data Retention

- **Inventory/Notes/Trusted/History**: Kept indefinitely until manually removed
- **SQLite observations**: Automatically pruned after 4 days (configurable in code)
- **Old filename migration**: `lan-scanner.sqlite` automatically renamed/adopted as `lan-cap.sqlite`

## Advanced Usage

### Running on Multiple Networks

LAN-CAP works on the network it's connected to. To scan a different network:
1. Connect to that network
2. Restart LAN-CAP or it will auto-detect
3. Trigger a new scan

### API Usage

You can interact with LAN-CAP programmatically via its REST API. See [API Reference](README.md#api-reference) in README.

Example using curl:
```bash
# Get all devices
curl http://localhost:5174/api/devices

# Start a scan
curl -X POST http://localhost:5174/api/scans \
  -H "Content-Type: application/json" \
  -d '{"cidr":"192.168.1.0/24","serviceScan":true}'
```

### Headless/Automated Scanning

Use the API for automation:
1. Start server in production mode
2. Schedule scans via cron/Task Scheduler calling the API
3. Parse results from JSON responses

### Custom OUI Database

Update vendor database:
1. Edit `server/oui.json` or run `node build-oui.js` in server directory
2. Restart server

## Appendix

### Glossary

- **ARP**: Address Resolution Protocol - maps IP to MAC addresses
- **CIDR**: Classless Inter-Domain Routing notation (e.g., /24)
- **MAC**: Media Access Control address (hardware address)
- **OUI**: Organizationally Unique Identifier - first 3 bytes of MAC
- **SSDP**: Simple Service Discovery Protocol (UPnP)
- **TTL**: Time To Live - used in OS fingerprinting
- **UPnP**: Universal Plug and Play

### Keyboard Shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `Tab` | General | Navigate UI elements |
| `Enter/Space` | Topology nodes | Select node |
| `Esc` | Modals | Close dialogs |

### System Requirements Notes

- **Windows**: Uses `arp -a`, `ping`, `tracert` natively
- **macOS**: Uses `arp -an`, `ping`, `traceroute` natively
- **Linux**: Uses `ip neigh`/`arp`, `ping`, `traceroute` natively

### Getting Help

- Check the [README](README.md) for quick reference
- Review this manual for detailed usage
- Look at server logs for errors
- Check GitHub issues for known problems

---

*LAN-CAP - Local-first network security for everyone*
