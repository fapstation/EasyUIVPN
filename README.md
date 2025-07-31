# EasyUIVPN Management Interface

🚀 **Lightweight** • 🔒 **Secure** • 🎨 **Modern UI** • 📱 **Mobile Friendly**

🌐 **[Live Demo](https://demo.easyuivpn.com)** | 📱 **Mobile Friendly** | 🎨 **Modern Dark UI**

![EasyUIVPN Dashboard](https://via.placeholder.com/800x400/0f0f23/10b981?text=EasyUIVPN+Dashboard)

## 🚀 Quick Install

**One-line installation (recommended):**
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh --default
```

**Interactive installation:**
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh
```

**Custom port installation:**
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh --port 8080 --default
```

## 🔄 Update & Uninstall

**Update to latest version:**
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh --update
```

**Completely uninstall:**
```bash
sudo bash install.sh --uninstall
```

## ✨ Features

### 🔐 Security First
- **System Authentication**: Uses your server's existing user accounts (no separate database)
- **CSRF Protection**: Built-in protection against cross-site request forgery
- **Rate Limiting**: Prevents brute force login attempts
- **Session Management**: Secure session handling with automatic timeouts
- **Input Validation**: All user inputs are validated and sanitized
- **Audit Logging**: All actions are logged for security monitoring

### 🎯 OpenVPN Management
- **Client Certificate Management**: Create, revoke, and download client certificates
- **Real-time Connection Status**: See who's connected with live status indicators
- **QR Code Generation**: Mobile-friendly configuration import
- **Bandwidth Monitoring**: Track data usage per client
- **Configuration Editor**: Browser-based OpenVPN config editing (advanced users)

### 📊 Monitoring & Statistics
- **Live Connection Status**: Real-time updates every 30 seconds
- **Bandwidth Statistics**: Upload/download tracking for all clients
- **Connection History**: 7-day connection history (configurable retention)
- **Server Statistics**: Client counts, usage metrics, and more

### 🖥️ Modern UI/UX
- **Dark Theme**: Easy on the eyes with a professional dark interface
- **Responsive Design**: Works perfectly on mobile, tablet, and desktop
- **Real-time Updates**: Live status updates without page refreshes
- **Intuitive Navigation**: Clean and simple user interface
- **Accessibility**: WCAG compliant design

### ⚡ Lightweight & Efficient
- **Minimal Resources**: Runs smoothly on 512MB RAM / 1 CPU core
- **No Docker Required**: Native Python application
- **Fast Installation**: One-command setup script
- **Small Footprint**: Less than 50MB total installation size

## 🚀 Quick Installation

### Prerequisites
- Linux server (Debian/Ubuntu or CentOS/RHEL/Fedora)
- OpenVPN server already installed (supports multiple installation methods)
- Root or sudo access

### Supported OpenVPN Installations
EasyUIVPN automatically detects and supports:
- **[Angristan's OpenVPN script](https://github.com/angristan/openvpn-install)** (recommended)
- **Standard package installations** with EasyRSA (`apt install openvpn easy-rsa`)
- **Manual OpenVPN configurations** (limited functionality)

📖 **See [COMPATIBILITY.md](COMPATIBILITY.md) for detailed compatibility information**

### Automatic Compatibility Detection
EasyUIVPN automatically detects your OpenVPN installation type during setup and adapts accordingly.

### 🚀 One-Line Installation
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh --default
```

### Installation Options
```bash
# Interactive installation with custom options
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh

# Custom port installation
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh && sudo bash install.sh --port 8080 --default
```

### Installation Options
```bash
# Available installation flags:
sudo bash install.sh --help

Options:
  --default       Unattended installation with defaults
  --port PORT     Set custom web interface port (default: 8094)
  --no-firewall   Skip firewall configuration
  --ssl           Generate self-signed SSL certificate
  -h, --help      Show help message
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/fapstation/EasyUIVPN.git
cd EasyUIVPN

# Make the installer executable and run it
chmod +x install.sh
sudo ./install.sh
```

## 📋 Detailed Setup Guide

### 1. Install OpenVPN Server First
Choose one of the following installation methods:

#### Option A: Angristan's Script (Recommended)
```bash
curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
sudo ./openvpn-install.sh
```

#### Option B: Standard Package Installation
**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install openvpn easy-rsa
```

**CentOS/RHEL/Fedora:**
```bash
# CentOS/RHEL 8+
sudo dnf install openvpn easy-rsa

# CentOS/RHEL 7
sudo yum install epel-release
sudo yum install openvpn easy-rsa
```

### 2. Install EasyUIVPN
Run the EasyUIVPN installer:
```bash
curl -O https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/install.sh
sudo bash install.sh
```

### 3. Access the Web Interface
- Open your browser and navigate to: `http://YOUR_SERVER_IP:8094`
- Login with your system user credentials (same as SSH)

## 🎯 Usage Guide

### Creating VPN Clients
1. Navigate to the **Clients** section
2. Click **"New Client"**
3. Enter a descriptive name (e.g., "john-laptop", "mary-phone")
4. Click **"Create Client"**
5. Download the `.ovpn` file or scan the QR code

### Mobile Setup
1. Install OpenVPN Connect on your mobile device:
   - [Android](https://play.google.com/store/apps/details?id=net.openvpn.openvpn)
   - [iOS](https://apps.apple.com/app/openvpn-connect/id590379981)
2. Use the QR code feature for easy import
3. Toggle the connection in the app

### Revoking Certificates
1. Go to the **Clients** section
2. Find the client you want to revoke
3. Click the **"Revoke"** button
4. Confirm the action

⚠️ **Important**: Revoked certificates cannot be restored. The client will need a new certificate to reconnect.

## ⚙️ Configuration

### Environment Variables
Create `/opt/easyuivpn/.env` to customize settings:
```bash
SECRET_KEY=your-secret-key-here
PORT=8094
DEBUG=false
LOG_LEVEL=info
```

### OpenVPN Integration
EasyUIVPN automatically detects most OpenVPN configurations. If you have a custom setup, you may need to adjust these paths in `app.py`:

```python
CONFIG = {
    'OPENVPN_DIR': '/etc/openvpn',
    'CLIENT_DIR': '/etc/openvpn/clients',
    'SERVER_CONFIG': '/etc/openvpn/server.conf',
    'STATUS_LOG': '/var/log/openvpn/status.log',
}
```

## 🛡️ Security Considerations

### Production Deployment
For production use, consider these additional security measures:

1. **Use HTTPS**: Set up a reverse proxy with SSL/TLS
2. **Restrict Access**: Use firewall rules to limit web interface access
3. **Regular Updates**: Keep the system and EasyUIVPN updated
4. **Monitor Logs**: Regularly check logs for suspicious activity
5. **Strong Passwords**: Use strong system passwords for authentication

### Reverse Proxy with Nginx
Example Nginx configuration for SSL termination:
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:8094;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔧 Service Management

### Systemd Commands
```bash
# Start the service
sudo systemctl start easyuivpn

# Stop the service
sudo systemctl stop easyuivpn

# Restart the service
sudo systemctl restart easyuivpn

# Check service status
sudo systemctl status easyuivpn

# View logs
sudo journalctl -u easyuivpn -f
```

### File Locations
- **Application**: `/opt/easyuivpn/`
- **Data**: `/var/lib/easyuivpn/`
- **Logs**: `/var/log/easyuivpn/`
- **Service**: `/etc/systemd/system/easyuivpn.service`

## 🐛 Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check the service status
sudo systemctl status easyuivpn

# View detailed logs
sudo journalctl -u easyuivpn -n 50

# Check permissions
ls -la /opt/easyuivpn/
```

#### Can't Access Web Interface
```bash
# Check if the service is running
sudo systemctl status easyuivpn

# Check firewall rules
sudo ufw status
sudo iptables -L

# Test local access
curl http://localhost:8094
```

#### Authentication Issues
```bash
# Verify user exists and can authenticate
id username
sudo -u username -i

# Check sudoers configuration
sudo visudo -f /etc/sudoers.d/easyuivpn
```

### Log Locations
- **Application Logs**: `journalctl -u easyuivpn`
- **OpenVPN Logs**: `/var/log/openvpn/`
- **System Logs**: `/var/log/syslog` or `/var/log/messages`

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/fapstation/EasyUIVPN.git
cd EasyUIVPN

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
export DEBUG=true
python app.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Angristan](https://github.com/angristan/openvpn-install) for the excellent OpenVPN installation script
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Font Awesome](https://fontawesome.com/) for the icons
- The OpenVPN community for the amazing VPN software

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/fapstation/EasyUIVPN/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fapstation/EasyUIVPN/discussions)
- **Documentation**: [Project Wiki](https://github.com/fapstation/EasyUIVPN/wiki)

## 🗺️ Roadmap

- [ ] Multi-language support
- [ ] 2FA authentication support
- [ ] Email notifications for connections
- [ ] Advanced bandwidth controls
- [ ] Client-specific routing rules
- [ ] API endpoints for automation
- [ ] Docker deployment option
- [ ] Backup/restore functionality

---

**Made with ❤️ for the OpenVPN community** 