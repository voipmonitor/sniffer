<p align="center">
  <img src="https://www.voipmonitor.org/img/voipmonitor-logo.svg" alt="VoIPmonitor Logo" width="400">
</p>

<h3 align="center">Open Source Network Packet Sniffer for VoIP/RTC Traffic Analysis</h3>

<p align="center">
  <a href="https://github.com/voipmonitor/sniffer/releases"><img src="https://img.shields.io/github/v/release/voipmonitor/sniffer?style=flat-square&color=00A7E3" alt="Release"></a>
  <a href="https://github.com/voipmonitor/sniffer/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-GPL--2.0-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/voipmonitor/sniffer/stargazers"><img src="https://img.shields.io/github/stars/voipmonitor/sniffer?style=flat-square&color=f78d1d" alt="Stars"></a>
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Platform">
</p>

<p align="center">
  <a href="https://www.voipmonitor.org/">Website</a> •
  <a href="https://www.voipmonitor.org/doc/">Documentation</a> •
  <a href="https://www.voipmonitor.org/demo">Live Demo</a> •
  <a href="https://www.voipmonitor.org/download">Download</a> •
</p>

---

## What is VoIPmonitor?

**VoIPmonitor** is an open source network packet sniffer with commercial frontend for SIP, RTP, RTCP, SDRS, WebRTC, T.38, MGCP, Skinny(SCCP), and other VoIP protocols running on Linux.

It is designed for VoIP troubleshooting and monitoring. VoIPmonitor captures, decodes, and analyzes VoIP traffic, saving call metadata to a database and optionally storing full packet captures and audio recordings. The sniffer is engineered for high-performance environments, capable of processing **10 Gbit traffic** and handling **100,000+ concurrent calls** on a single server.

**Trusted by 1,000+ telecom operators, ITSPs, and contact centers worldwide.**
Representative vendor in [Gartner's Market Guide for Unified Communications Monitoring](https://www.gartner.com/doc/3487617/market-guide-unified-communications-monitoring).

---

## Key Features

### Protocol Support
- **SIP** - Full message parsing, call correlation, and ladder diagrams
- **RTP/RTCP** - Audio stream capture, quality analysis, and RTCP-XR
- **WebRTC** - Browser-based real-time communication analysis
- **SIPREC** - Session Recording Server (RFC 7866/7865)
- **MGCP** - Media Gateway Control Protocol
- **SKINNY/SCCP** - Cisco proprietary signaling
- **T.38** - FAX over IP with PDF conversion
- **Diameter, SS7, SCTP** - Extended protocol support

### Quality Metrics (ITU-T G.107 E-model)
- **MOS** (Mean Opinion Score) - Voice quality prediction on 1-5 scale
- **Jitter** - Packet arrival time variation
- **Packet Loss** - Impact on call clarity
- **R-Factor** - Transmission rating factor
- **Delay/Latency** - End-to-end delay measurement

### Codec Support
G.711, G.722, G.723, G.726, G.729a, OPUS, AMR, AMR-WB, iLBC, Speex, GSM, Silk, iSAC, MP4A-LATM

### Advanced Capabilities
- **TLS/SRTP Decryption** - Full support for encrypted VoIP traffic
- **DPDK Acceleration** - Kernel-bypass for 10 Gbit line-rate capture
- **ARM Architecture** - Native support for ARM-based servers
- **Serialized Storage** - Optimized format for cost-effective HDD storage
- **Horizontal Scaling** - Distributed sniffers with central database

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Network Traffic                              │
│            (SPAN/RSPAN/ERSPAN/TAP/SBC Mirroring)                    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     VoIPmonitor Sniffer (GPL)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ SIP Parser  │  │ RTP Decoder │  │ Quality     │  │ Audio       │ │
│  │             │  │             │  │ Analysis    │  │ Recording   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
    ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
    │ MySQL/MariaDB │   │ PCAP Storage  │   │ Audio Files   │
    │   (CDRs)      │   │ (SIP/RTP)     │   │ (WAV/OGG)     │
    └───────────────┘   └───────────────┘   └───────────────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    VoIPmonitor WEB GUI (Commercial)                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Dashboards  │  │ Analytics   │  │ Alerting    │  │ Billing     │ │
│  │ & Reports   │  │ & OLAP      │  │ & Fraud     │  │ Engine      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Download Static Binary (Recommended)

No dependencies required - works on any Linux distribution:

```bash
# 64-bit
wget https://www.voipmonitor.org/current-stable-sniffer-static-64bit.tar.gz
tar xzf current-stable-sniffer-static-64bit.tar.gz
cd voipmonitor-*

# Run sniffer
./voipmonitor -i eth0
```

### Build from Source

```bash
git clone https://github.com/voipmonitor/sniffer.git
cd sniffer
./configure
make
make install
```

### Basic Configuration

Create `/etc/voipmonitor.conf`:

```ini
# Network interface to sniff
interface = eth0

# MySQL database connection
mysqlhost = localhost
mysqldb = voipmonitor
mysqlusername = voipmonitor
mysqlpassword = secret

# Enable audio recording
audio_recording = yes
savesip = yes
savertp = yes
```

Start the sniffer:

```bash
voipmonitor --config /etc/voipmonitor.conf
```

---

## Installation Guides

Detailed installation guides for popular distributions:

| Distribution | Guide |
|--------------|-------|
| Debian 13 | [Installation Guide](https://www.voipmonitor.org/doc/Debian_13) |
| Debian 12 | [Installation Guide](https://www.voipmonitor.org/doc/Debian_12) |
| Ubuntu 24.04 LTS | [Installation Guide](https://www.voipmonitor.org/doc/Ubuntu_24.04_LTS) |
| Ubuntu 22.04 LTS | [Installation Guide](https://www.voipmonitor.org/doc/Ubuntu_22.04_LTS) |
| Rocky Linux 10 | [Installation Guide](https://www.voipmonitor.org/doc/Rocky_10) |
| Rocky Linux 9 | [Installation Guide](https://www.voipmonitor.org/doc/Rocky_9) |
| AlmaLinux 10 | [Installation Guide](https://www.voipmonitor.org/doc/Almalinux_10) |
| AlmaLinux 9 | [Installation Guide](https://www.voipmonitor.org/doc/Almalinux_9.5) |

---

## VoIPmonitor WEB GUI

The **commercial WEB GUI** transforms raw sniffer data into actionable insights with:

<p align="center">
  <img src="https://www.voipmonitor.org/img/analytics/dashboard2.webp" alt="VoIPmonitor Dashboard" width="800">
</p>

### Features
- **Real-time Dashboards** - 2D/3D visualizations, live call monitoring, NOC views
- **CDR Analysis** - Search, filter, and drill-down into any call
- **SIP Ladder Diagrams** - Interactive message sequence visualization
- **Audio Playback** - Waveform display with spectral analysis
- **Quality Reports** - MOS, jitter, packet loss trending and comparisons
- **OLAP Analytics** - Instant insights from millions of records
- **Alerting** - KPI thresholds, fraud detection, trend anomaly detection
- **Billing Engine** - Flexible price tables, revenue/cost tracking
- **AI Transcription** - OpenAI Whisper integration for call-to-text

### Try It

- **[Live Demo](https://www.voipmonitor.org/demo)** - Explore the GUI instantly, no registration required
- **[30-Day Trial](https://www.voipmonitor.org/pricing)** - Full-featured trial license
- **[Cloud Option](https://cloud.voipmonitor.org/)** - Start in minutes, we handle everything

---

## Tested Compatibility

VoIPmonitor works with any system using supported protocols. Tested with:

| Category | Platforms |
|----------|-----------|
| **SIP Proxies** | Kamailio, OpenSIPS |
| **Media Servers** | FreeSWITCH, Asterisk |
| **Enterprise PBX** | Cisco, Avaya, Genesys, Mitel |
| **SBCs** | AudioCodes, Ribbon, Oracle SBC, Cisco CUBE, Sangoma, Dialogic |
| **UCaaS/CCaaS** | NetSapiens, BroadSoft, Odin/Ooma |

### Capture Methods
- SPAN/RSPAN/ERSPAN port mirroring
- Network TAP
- SBC-native packet duplication
- Direct deployment on SBC/PBX

---

## Performance

| Metric | Capability |
|--------|------------|
| Concurrent Calls | 100,000+ |
| Calls Per Second | 50,000+ |
| Network Throughput | 10 Gbit |
| CDR Writes/Second | 50,000 |

Engineered for carrier-grade deployments with multi-core optimization, DPDK kernel-bypass support, and serialized I/O storage format.

---

## Documentation

- **[Sniffer Manual](https://www.voipmonitor.org/doc/Sniffer_manual)** - Complete sniffer configuration reference
- **[WEB GUI Manual](https://www.voipmonitor.org/doc/WEB_GUI_Manual)** - GUI features and usage
- **[Configuration Options](https://www.voipmonitor.org/doc/Configuration)** - All configuration parameters
- **[FAQ](https://www.voipmonitor.org/doc/FAQ)** - Frequently asked questions

---

## Support

- **Commercial Support** - Included with WEB GUI license
- **Email**: [support@voipmonitor.org](mailto:support@voipmonitor.org)
- **Sales**: [info@voipmonitor.org](mailto:info@voipmonitor.org)
- **GitHub Issues** - For sniffer bug reports and feature requests

---

## License

The **sniffer** is released under the **GNU General Public License v2.0** (GPL-2.0).

The **WEB GUI** is commercial software available with monthly, quarterly, or annual subscriptions.
See [pricing](https://www.voipmonitor.org/pricing) for details.

---

## About

VoIPmonitor is developed by **Martin Vit** in Prague, Czech Republic.

- Website: [www.voipmonitor.org](https://www.voipmonitor.org/)
- GitHub: [github.com/voipmonitor](https://github.com/voipmonitor)
