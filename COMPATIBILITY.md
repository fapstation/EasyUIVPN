# EasyUIVPN Compatibility Guide

## 📋 Supported OpenVPN Installation Types

EasyUIVPN automatically detects your OpenVPN installation type and adapts its functionality accordingly. Here's what's supported:

## 🚀 Angristan Script Installation

**Status: ✅ Full Compatibility**

The Angristan OpenVPN script is the **recommended** installation method for EasyUIVPN.

### Features Available:
- ✅ **Client Creation**: Fully automated via Angristan script
- ✅ **Client Revocation**: Complete certificate revocation with CRL updates
- ✅ **Configuration Management**: Full server configuration editing
- ✅ **Real-time Monitoring**: All connection tracking features
- ✅ **QR Code Generation**: Mobile client setup
- ✅ **Bandwidth Tracking**: Complete statistics and monitoring

### Installation:
```bash
# Install Angristan OpenVPN
curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
sudo ./openvpn-install.sh

# Then install EasyOVPN
curl -O https://raw.githubusercontent.com/fapstation/EasyOVPN/main/install.sh
sudo bash install.sh --default
```

### Auto-Detection:
EasyUIVPN detects Angristan installations by looking for:
- `/usr/local/bin/openvpn-install.sh`
- `/root/openvpn-install.sh`

---

## 🔑 Standard EasyRSA Installation

**Status: ✅ Full Compatibility**

Standard package manager installations with EasyRSA are fully supported.

### Features Available:
- ✅ **Client Creation**: Automated using EasyRSA commands
- ✅ **Client Revocation**: Certificate revocation with CRL generation
- ✅ **Configuration Management**: Full server configuration editing
- ✅ **Real-time Monitoring**: All connection tracking features
- ✅ **QR Code Generation**: Mobile client setup
- ✅ **Bandwidth Tracking**: Complete statistics and monitoring

### Installation Examples:

#### Debian/Ubuntu:
```bash
# Install OpenVPN and EasyRSA
sudo apt update
sudo apt install openvpn easy-rsa

# Configure OpenVPN server (manual setup required)
sudo make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
sudo ./easyrsa init-pki
sudo ./easyrsa build-ca
sudo ./easyrsa gen-req server nopass
sudo ./easyrsa sign-req server server
sudo ./easyrsa gen-dh

# Install EasyOVPN
curl -O https://raw.githubusercontent.com/fapstation/EasyOVPN/main/install.sh
sudo bash install.sh --default
```

#### CentOS/RHEL/Fedora:
```bash
# Install OpenVPN and EasyRSA
sudo dnf install openvpn easy-rsa  # or 'yum' on older systems

# Configure OpenVPN server (manual setup required)
sudo make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
sudo ./easyrsa init-pki
sudo ./easyrsa build-ca
sudo ./easyrsa gen-req server nopass
sudo ./easyrsa sign-req server server
sudo ./easyrsa gen-dh

# Install EasyOVPN
curl -O https://raw.githubusercontent.com/fapstation/EasyOVPN/main/install.sh
sudo bash install.sh --default
```

### Auto-Detection:
EasyUIVPN detects EasyRSA installations by looking for:
- `/etc/openvpn/easy-rsa/`
- `/usr/share/easy-rsa/`
- `easyrsa` command in system PATH
- PKI directory with CA certificate

### Requirements:
- EasyRSA must be installed and initialized
- PKI structure must exist with CA certificate
- OpenVPN server must be configured and running

---

## 🔧 Manual/Custom Installations

**Status: ⚠️ Limited Compatibility**

Manual OpenVPN installations without proper certificate management tools have limited functionality.

### Features Available:
- ✅ **Real-time Monitoring**: Connection status and bandwidth tracking
- ✅ **Configuration Management**: Server configuration editing
- ✅ **Statistics**: Connection history and server statistics
- ❌ **Client Creation**: Not available (no certificate management tools)
- ❌ **Client Revocation**: Not available (no certificate management tools)
- ❌ **QR Code Generation**: Only for existing clients

### What EasyUIVPN Can Do:
- Monitor existing client connections
- Display bandwidth usage and statistics
- Allow manual configuration editing
- Track connection history

### What EasyUIVPN Cannot Do:
- Create new client certificates automatically
- Revoke existing certificates automatically
- Generate new .ovpn configuration files

### Auto-Detection:
EasyUIVPN detects manual installations when:
- OpenVPN server configuration exists
- No Angristan script found
- No EasyRSA tools found

### Recommendations:
If you have a manual installation, consider:
1. **Installing EasyRSA** to enable client management:
   ```bash
   # Debian/Ubuntu
   sudo apt install easy-rsa
   
   # CentOS/RHEL/Fedora
   sudo dnf install easy-rsa
   ```

2. **Migrating to Angristan script** for full automation

---

## 🔍 Installation Type Detection

EasyUIVPN performs automatic detection during startup:

### Detection Process:
1. **Check for Angristan script** in common locations
2. **Check for EasyRSA** installation and PKI setup
3. **Check for basic OpenVPN** configuration files
4. **Display detected type** in dashboard

### Detection During Installation:
EasyUIVPN performs compatibility detection during the installation process and displays:
- 🚀 **ANGRISTAN OPENVPN INSTALLATION DETECTED** (100% compatibility)
- 🔑 **STANDARD OPENVPN WITH EASYRSA DETECTED** (95% compatibility)
- 🔧 **MANUAL OPENVPN INSTALLATION DETECTED** (50% compatibility)

### Detection Logs:
After installation, check the application logs:
```bash
# View EasyUIVPN logs
sudo journalctl -u easyvpn -f

# Look for detection messages like:
# "Detected Angristan installation with script: /usr/local/bin/openvpn-install.sh"
# "Detected EasyRSA installation: /etc/openvpn/easy-rsa"
```

### Dashboard Indicator:
The dashboard displays your installation type with appropriate icons:
- 🚀 **Angristan OpenVPN Installation**
- 🔑 **Standard OpenVPN with EasyRSA**
- 🔧 **Manual OpenVPN Installation**
- ❓ **Unknown Installation Type**

---

## 🛠️ Troubleshooting Common Issues

### Issue: "Client creation not available"
**Cause**: EasyUIVPN couldn't detect certificate management tools

**Solutions**:
1. Install EasyRSA: `sudo apt install easy-rsa`
2. Initialize PKI if using EasyRSA
3. Check that required tools are in expected locations

### Issue: "Certificate files not found"
**Cause**: PKI directory structure is non-standard

**Solutions**:
1. Check PKI directory exists: `/etc/openvpn/easy-rsa/pki/`
2. Verify CA certificate exists: `ca.crt`
3. Ensure proper permissions on certificate directories

### Issue: "Unknown installation type"
**Cause**: EasyUIVPN couldn't identify your OpenVPN setup

**Solutions**:
1. Ensure OpenVPN is properly installed and configured
2. Check that server configuration file exists
3. Install missing certificate management tools

### Issue: ".ovpn files not generated correctly"
**Cause**: Server configuration parsing issues

**Solutions**:
1. Verify server configuration syntax
2. Check that server IP address is correctly detected
3. Ensure certificate files have proper permissions

---

## 📞 Getting Help

If you encounter compatibility issues:

1. **Check Installation Type**: Visit the dashboard to see detected type
2. **View Logs**: `sudo journalctl -u easyvpn -f`
3. **Test Components**: Verify OpenVPN server is running
4. **Report Issues**: Include installation type and error logs

### Community Support:
- GitHub Issues: Report compatibility problems
- Documentation: Check installation guides
- Discussions: Ask questions about specific setups

---

## 🔄 Migration Between Types

### From Manual to EasyRSA:
1. Install EasyRSA: `sudo apt install easy-rsa`
2. Initialize PKI structure
3. Restart EasyUIVPN: `sudo systemctl restart easyvpn`

### From EasyRSA to Angristan:
1. Backup existing clients
2. Run Angristan script
3. Migrate client configurations
4. Restart EasyUIVPN

### Best Practices:
- Always backup client configurations before migration
- Test new setup with a single client first
- Keep old certificates until migration is confirmed working

This compatibility guide ensures you understand exactly what features are available with your specific OpenVPN installation type. 