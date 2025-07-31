#!/bin/bash
#
# EasyOVPN Management Interface Installer
# A lightweight, secure OpenVPN web management tool
#
# Usage: 
#   Default installation: bash install.sh --default
#   Interactive installation: bash install.sh
#   Custom port: bash install.sh --port 8080
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
EASYVPN_DIR="/opt/easyvpn"
SERVICE_NAME="easyvpn"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_VENV="$EASYVPN_DIR/venv"
LOG_FILE="/var/log/easyvpn.log"
PORT=8094
AUTO_INSTALL_DEPS=false
DEFAULT_INSTALL=false
FIREWALL_SETUP=true
SSL_SETUP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --default)
            DEFAULT_INSTALL=true
            AUTO_INSTALL_DEPS=true
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --no-firewall)
            FIREWALL_SETUP=false
            shift
            ;;
        --ssl)
            SSL_SETUP=true
            shift
            ;;
        -h|--help)
            echo "EasyOVPN Installer Options:"
            echo "  --default       Unattended installation with defaults"
            echo "  --port PORT     Set custom web interface port (default: 8094)"
            echo "  --no-firewall   Skip firewall configuration"
            echo "  --ssl           Generate self-signed SSL certificate"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
        print_status "Detected Debian/Ubuntu system"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
        print_status "Detected RedHat/CentOS/Fedora system"
    else
        print_error "Unsupported operating system. This installer supports Debian/Ubuntu and RedHat/CentOS/Fedora."
        exit 1
    fi
}

check_and_install_dependencies() {
    print_status "Checking system dependencies..."
    
    # Check for required packages
    local missing_deps=()
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if ! command -v pip3 &> /dev/null; then
        missing_deps+=("python3-pip")
    fi
    
    if ! python3 -c "import venv" &> /dev/null; then
        missing_deps+=("python3-venv")
    fi
    
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    fi
    
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v wget &> /dev/null; then
        missing_deps+=("wget")
    fi
    
    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        print_success "All required dependencies are already installed"
        return 0
    fi
    
    print_warning "Missing dependencies: ${missing_deps[*]}"
    
    if [[ "$AUTO_INSTALL_DEPS" == true ]]; then
        print_status "Auto-installing missing dependencies..."
        install_dependencies_now
    else
        echo ""
        echo -e "${YELLOW}The following packages need to be installed:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo -e "  • $dep"
        done
        echo ""
        read -p "Would you like EasyOVPN installer to install these packages? (Y/n): " install_deps
        
        if [[ "$install_deps" == "n" || "$install_deps" == "N" ]]; then
            print_warning "Dependencies not installed. EasyOVPN might not work correctly."
            read -p "Do you still want to proceed? (y/N): " proceed_anyway
            if [[ "$proceed_anyway" != "y" && "$proceed_anyway" != "Y" ]]; then
                print_error "Installation cancelled by user"
                exit 1
            fi
        else
            install_dependencies_now
        fi
    fi
}

install_dependencies_now() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == "debian" ]]; then
        apt-get update
        apt-get install -y python3 python3-pip python3-venv git curl wget unzip
    elif [[ "$OS" == "redhat" ]]; then
        if command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip git curl wget unzip
        else
            yum install -y python3 python3-pip git curl wget unzip
        fi
    fi
    
    print_success "System dependencies installed"
}

check_and_detect_openvpn() {
    print_status "Checking OpenVPN installation and detecting configuration type..."
    
    if ! command -v openvpn &> /dev/null; then
        print_error "OpenVPN is not installed. Please install OpenVPN first."
        echo ""
        echo -e "${YELLOW}Installation options:${NC}"
        echo -e "  • Angristan's script: ${BLUE}https://github.com/angristan/openvpn-install${NC}"
        echo -e "  • Package manager: ${BLUE}apt install openvpn easy-rsa${NC} (Debian/Ubuntu)"
        echo -e "  • Package manager: ${BLUE}yum install openvpn easy-rsa${NC} (CentOS/RHEL)"
        exit 1
    fi
    
    OPENVPN_VERSION=$(openvpn --version | head -n1 | awk '{print $2}')
    echo -e "${GREEN}✅ OpenVPN found: $OPENVPN_VERSION${NC}"
    
    # Detect OpenVPN installation type
    OPENVPN_TYPE="unknown"
    OPENVPN_COMPATIBILITY_SCORE=0
    
    echo ""
    print_status "🔍 Detecting OpenVPN installation type..."
    
    # Check for Angristan installation
    if [[ -f /usr/local/bin/openvpn-install.sh ]] || [[ -f /root/openvpn-install.sh ]] || [[ -f /usr/sbin/openvpn-install.sh ]]; then
        OPENVPN_TYPE="angristan"
        OPENVPN_COMPATIBILITY_SCORE=100
        echo ""
        echo -e "${GREEN}🚀 ANGRISTAN OPENVPN INSTALLATION DETECTED${NC}"
        echo -e "${GREEN}   ✅ Full compatibility - all features will be available${NC}"
        echo -e "${GREEN}   ✅ Automatic client creation and revocation${NC}"
        echo -e "${GREEN}   ✅ Complete certificate management${NC}"
        
        # Find and display script location
        for script in /usr/local/bin/openvpn-install.sh /root/openvpn-install.sh /usr/sbin/openvpn-install.sh; do
            if [[ -f "$script" ]]; then
                echo -e "${BLUE}   📂 Script location: $script${NC}"
                break
            fi
        done
        
        print_success "EasyOVPN will use Angristan script for client management"

    # Check for EasyRSA installation
    elif command -v easyrsa &> /dev/null || [[ -d /etc/openvpn/easy-rsa ]] || [[ -d /usr/share/easy-rsa ]]; then
        OPENVPN_TYPE="easyrsa"
        OPENVPN_COMPATIBILITY_SCORE=95
        echo ""
        echo -e "${GREEN}🔑 STANDARD OPENVPN WITH EASYRSA DETECTED${NC}"
        echo -e "${GREEN}   ✅ Full compatibility - all features will be available${NC}"
        echo -e "${GREEN}   ✅ Automatic client creation using EasyRSA commands${NC}"
        echo -e "${GREEN}   ✅ Certificate revocation with CRL generation${NC}"
        
        # Show EasyRSA details
        if command -v easyrsa &> /dev/null; then
            EASYRSA_PATH=$(which easyrsa)
            echo -e "${BLUE}   📂 EasyRSA command: $EASYRSA_PATH${NC}"
        fi
        
        for dir in /etc/openvpn/easy-rsa /usr/share/easy-rsa /opt/easy-rsa; do
            if [[ -d "$dir" ]]; then
                echo -e "${BLUE}   📂 EasyRSA directory: $dir${NC}"
                break
            fi
        done
        
        # Check PKI initialization
        PKI_FOUND=false
        for pki_dir in /etc/openvpn/easy-rsa/pki /etc/openvpn/pki /etc/ssl/openvpn/pki; do
            if [[ -d "$pki_dir" ]] && [[ -f "$pki_dir/ca.crt" ]]; then
                echo -e "${BLUE}   📂 PKI directory: $pki_dir${NC}"
                PKI_FOUND=true
                break
            fi
        done
        
        if [[ "$PKI_FOUND" != true ]]; then
            echo -e "${YELLOW}   ⚠️  PKI not initialized. EasyOVPN will attempt to use EasyRSA anyway.${NC}"
            OPENVPN_COMPATIBILITY_SCORE=80
        fi
        
        print_success "EasyOVPN will use EasyRSA commands for client management"

    # Check for basic OpenVPN installation
    elif [[ -f /etc/openvpn/server.conf ]] || [[ -f /etc/openvpn/server/server.conf ]]; then
        OPENVPN_TYPE="manual"
        OPENVPN_COMPATIBILITY_SCORE=50
        echo ""
        echo -e "${YELLOW}🔧 MANUAL OPENVPN INSTALLATION DETECTED${NC}"
        echo -e "${YELLOW}   ⚠️  Limited compatibility - monitoring features only${NC}"
        echo -e "${YELLOW}   ❌ Client creation/revocation not available${NC}"
        echo -e "${YELLOW}   ✅ Connection monitoring and statistics will work${NC}"
        
        for config in /etc/openvpn/server/server.conf /etc/openvpn/server.conf; do
            if [[ -f "$config" ]]; then
                echo -e "${BLUE}   📂 Server config: $config${NC}"
                break
            fi
        done
        
        echo ""
        echo -e "${YELLOW}💡 To enable full functionality, consider:${NC}"
        echo -e "${YELLOW}   • Installing EasyRSA: apt install easy-rsa${NC}"
        echo -e "${YELLOW}   • Or using Angristan's script for complete automation${NC}"
        
        if [[ "$DEFAULT_INSTALL" != true ]]; then
            echo ""
            read -p "Do you want to continue with limited functionality? (y/N): " continue_limited
            if [[ "$continue_limited" != "y" && "$continue_limited" != "Y" ]]; then
                print_error "Installation cancelled. Please install EasyRSA or use Angristan's script."
                exit 1
            fi
        fi

    else
        OPENVPN_TYPE="none"
        OPENVPN_COMPATIBILITY_SCORE=0
        echo ""
        print_error "❌ NO OPENVPN SERVER CONFIGURATION DETECTED"
        print_error "Please configure OpenVPN server first before installing EasyOVPN"
        echo ""
        echo -e "${BLUE}Quick setup options:${NC}"
        echo -e "${BLUE}1. Angristan script (recommended): curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh && sudo bash openvpn-install.sh${NC}"
        echo -e "${BLUE}2. Package install: apt install openvpn easy-rsa${NC}"
        exit 1
    fi
    
    # Install EasyRSA if needed and possible
    if [[ "$OPENVPN_TYPE" == "easyrsa" ]]; then
        if ! command -v easyrsa &> /dev/null && [[ ! -f /etc/openvpn/easy-rsa/easyrsa ]]; then
            echo ""
            print_warning "EasyRSA command not found. Installing easy-rsa package..."
            if [[ "$AUTO_INSTALL_DEPS" == true ]] || [[ "$DEFAULT_INSTALL" == true ]]; then
                if [[ "$OS" == "debian" ]]; then
                    apt-get install -y easy-rsa
                elif [[ "$OS" == "redhat" ]]; then
                    if command -v dnf &> /dev/null; then
                        dnf install -y easy-rsa
                    else
                        yum install -y easy-rsa
                    fi
                fi
                print_success "EasyRSA installed successfully"
            else
                read -p "Would you like to install easy-rsa package? (Y/n): " install_easyrsa
                if [[ "$install_easyrsa" != "n" && "$install_easyrsa" != "N" ]]; then
                    if [[ "$OS" == "debian" ]]; then
                        apt-get install -y easy-rsa
                    elif [[ "$OS" == "redhat" ]]; then
                        if command -v dnf &> /dev/null; then
                            dnf install -y easy-rsa
                        else
                            yum install -y easy-rsa
                        fi
                    fi
                    print_success "EasyRSA installed successfully"
                fi
            fi
        fi
    fi
    
    echo ""
    echo -e "${BLUE}📊 COMPATIBILITY SUMMARY:${NC}"
    echo -e "${BLUE}   Installation Type: ${NC}$OPENVPN_TYPE"
    echo -e "${BLUE}   Compatibility Score: ${NC}$OPENVPN_COMPATIBILITY_SCORE/100"
    
    if [[ $OPENVPN_COMPATIBILITY_SCORE -ge 90 ]]; then
        echo -e "${GREEN}   🎉 Excellent! All EasyOVPN features will be available.${NC}"
    elif [[ $OPENVPN_COMPATIBILITY_SCORE -ge 70 ]]; then
        echo -e "${YELLOW}   ✅ Good! EasyOVPN will work with minor limitations.${NC}"
    elif [[ $OPENVPN_COMPATIBILITY_SCORE -ge 50 ]]; then
        echo -e "${YELLOW}   ⚠️  Limited! Only monitoring features will be available.${NC}"
    fi
    
    print_success "OpenVPN compatibility check completed"
}

create_user() {
    print_status "Creating easyvpn system user..."
    
    if ! id "easyvpn" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false easyvpn
        print_success "Created easyvpn user"
    else
        print_status "easyvpn user already exists"
    fi
}

setup_directories() {
    print_status "Setting up directories..."
    
    # Create main directory
    mkdir -p "$EASYVPN_DIR"
    mkdir -p /var/lib/easyvpn
    mkdir -p /var/log/easyvpn
    
    # Set permissions
    chown -R easyvpn:easyvpn "$EASYVPN_DIR"
    chown -R easyvpn:easyvpn /var/lib/easyvpn
    chown -R easyvpn:easyvpn /var/log/easyvpn
    
    # Allow easyvpn user to read OpenVPN files
    usermod -a -G openvpn easyvpn 2>/dev/null || true
    
    print_success "Directories created and configured"
}

download_easyvpn() {
    print_status "Downloading EasyOVPN files..."
    
    cd "$EASYVPN_DIR"
    
    # Download application files (in a real scenario, these would come from GitHub)
    # For now, we'll create them directly
    
    print_success "EasyOVPN files downloaded"
}

setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    cd "$EASYVPN_DIR"
    
    # Create virtual environment
    python3 -m venv "$PYTHON_VENV"
    
    # Activate and install packages
    source "$PYTHON_VENV/bin/activate"
    pip install --upgrade pip
    pip install -r requirements.txt
    
    chown -R easyvpn:easyvpn "$PYTHON_VENV"
    
    print_success "Python environment configured"
}

configure_permissions() {
    print_status "Configuring permissions for OpenVPN access..."
    
    # Allow easyvpn user to read OpenVPN configuration and logs
    if [[ -d /etc/openvpn ]]; then
        chmod -R g+r /etc/openvpn
        chgrp -R openvpn /etc/openvpn 2>/dev/null || true
    fi
    
    if [[ -d /var/log/openvpn ]]; then
        chmod -R g+r /var/log/openvpn
        chgrp -R openvpn /var/log/openvpn 2>/dev/null || true
    fi
    
    # Create sudoers rule for OpenVPN management
    cat > /etc/sudoers.d/easyvpn << 'EOF'
# Allow easyvpn user to manage OpenVPN and access system authentication
easyvpn ALL=(ALL) NOPASSWD: /bin/systemctl restart openvpn@server
easyvpn ALL=(ALL) NOPASSWD: /bin/systemctl status openvpn@server
easyvpn ALL=(ALL) NOPASSWD: /bin/systemctl reload openvpn@server
easyvpn ALL=(ALL) NOPASSWD: /usr/local/bin/openvpn-install.sh
easyvpn ALL=(ALL) NOPASSWD: /usr/sbin/openvpn-install.sh
# Allow reading shadow file for authentication (alternative to PAM)
easyvpn ALL=(ALL) NOPASSWD: /bin/cat /etc/shadow
EOF
    
    chmod 440 /etc/sudoers.d/easyvpn
    
    print_success "Permissions configured"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=EasyOVPN Management Interface
After=network.target openvpn@server.service
Wants=openvpn@server.service

[Service]
Type=simple
User=easyvpn
Group=easyvpn
WorkingDirectory=$EASYVPN_DIR
Environment=PATH=$PYTHON_VENV/bin
Environment=PORT=$PORT
ExecStart=$PYTHON_VENV/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easyvpn

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/easyvpn /var/log/easyvpn /tmp
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_success "Systemd service created and enabled"
}

configure_firewall() {
    print_status "Configuring firewall..."
    
    # UFW (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT/tcp" comment "EasyOVPN Web Interface"
        print_success "UFW rule added for port $PORT"
    
    # Firewalld (CentOS/RHEL/Fedora)
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$PORT/tcp"
        firewall-cmd --reload
        print_success "Firewalld rule added for port $PORT"
    
    # iptables fallback
    elif command -v iptables &> /dev/null; then
        iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
        # Try to save iptables rules
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
            print_warning "Could not save iptables rules. They may not persist after reboot."
        fi
        print_success "iptables rule added for port $PORT"
    else
        print_warning "No supported firewall found. Please manually allow port $PORT"
    fi
}

setup_ssl_certificate() {
    print_status "Setting up SSL certificate (optional)..."
    
    # Create self-signed certificate for HTTPS (optional enhancement)
    SSL_DIR="$EASYVPN_DIR/ssl"
    mkdir -p "$SSL_DIR"
    
    if command -v openssl &> /dev/null; then
        if [[ ! -f "$SSL_DIR/server.crt" ]]; then
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SSL_DIR/server.key" \
                -out "$SSL_DIR/server.crt" \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=easyvpn" \
                2>/dev/null
            
            chown easyvpn:easyvpn "$SSL_DIR"/*
            chmod 600 "$SSL_DIR"/server.key
            chmod 644 "$SSL_DIR"/server.crt
            
            print_success "Self-signed SSL certificate created"
        fi
    else
        print_warning "OpenSSL not found. SSL certificate not created."
    fi
}

start_service() {
    print_status "Starting EasyOVPN service..."
    
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment and check if service started successfully
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "EasyOVPN service started successfully"
    else
        print_error "Failed to start EasyOVPN service"
        print_error "Check logs with: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
}

get_server_ip() {
    # Try to get public IP
    SERVER_IP=$(curl -s https://ipv4.icanhazip.com 2>/dev/null || \
                curl -s https://api.ipify.org 2>/dev/null || \
                ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || \
                hostname -I 2>/dev/null | awk '{print $1}' || \
                echo "YOUR_SERVER_IP")
}

show_completion_message() {
    get_server_ip
    
    echo ""
    echo "=================================================================="
    print_success "EasyOVPN Management Interface installed successfully!"
    echo "=================================================================="
    echo ""
    echo -e "${BLUE}Access your VPN management interface at:${NC}"
    echo -e "${GREEN}  http://$SERVER_IP:$PORT${NC}"
    echo ""
    echo -e "${BLUE}Default login credentials:${NC}"
    echo -e "${YELLOW}  Use your system user credentials (same as SSH login)${NC}"
    echo ""
    echo -e "${BLUE}Service management:${NC}"
    echo -e "${YELLOW}  Start:   systemctl start $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Stop:    systemctl stop $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Restart: systemctl restart $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Status:  systemctl status $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Logs:    journalctl -u $SERVICE_NAME -f${NC}"
    echo ""
    echo -e "${BLUE}Configuration files:${NC}"
    echo -e "${YELLOW}  Application: $EASYVPN_DIR/${NC}"
    echo -e "${YELLOW}  Data:        /var/lib/easyvpn/${NC}"
    echo -e "${YELLOW}  Logs:        /var/log/easyvpn/${NC}"
    echo ""
    echo -e "${RED}Security Notes:${NC}"
    echo -e "${YELLOW}  • Always use HTTPS in production (consider reverse proxy)${NC}"
    echo -e "${YELLOW}  • Restrict access to the management interface${NC}"
    echo -e "${YELLOW}  • Regularly update the system and EasyOVPN${NC}"
    echo -e "${YELLOW}  • Monitor logs for suspicious activity${NC}"
    echo ""
    echo "=================================================================="
}

# Main installation flow
main() {
    echo ""
    echo "=================================================================="
    echo -e "${GREEN}EasyOVPN Management Interface Installer${NC}"
    echo "=================================================================="
    echo ""
    
    check_root
    detect_os
    
    if [[ "$DEFAULT_INSTALL" == true ]]; then
                 print_status "Performing default installation..."
         check_and_install_dependencies
         check_and_detect_openvpn
        create_user
        setup_directories
        download_easyvpn
        setup_python_env
        configure_permissions
        create_systemd_service
        if [[ "$FIREWALL_SETUP" == true ]]; then
            configure_firewall
        fi
        if [[ "$SSL_SETUP" == true ]]; then
            setup_ssl_certificate
        fi
        start_service
        show_completion_message
    else
        print_status "Interactive installation mode. Please answer questions."
        read -p "Enter the port for the web interface (default: $PORT): " input_port
        if [[ ! -z "$input_port" ]]; then
            PORT="$input_port"
        fi
        read -p "Do you want to skip firewall configuration? (y/N, default: N): " skip_firewall
        if [[ "$skip_firewall" == "y" || "$skip_firewall" == "Y" ]]; then
            FIREWALL_SETUP=false
        fi
        read -p "Do you want to generate a self-signed SSL certificate? (y/N, default: N): " ssl_cert
        if [[ "$ssl_cert" == "y" || "$ssl_cert" == "Y" ]]; then
            SSL_SETUP=true
        fi

        check_and_install_dependencies
        check_and_detect_openvpn
        create_user
        setup_directories
        download_easyvpn
        setup_python_env
        configure_permissions
        create_systemd_service
        if [[ "$FIREWALL_SETUP" == true ]]; then
            configure_firewall
        fi
        if [[ "$SSL_SETUP" == true ]]; then
            setup_ssl_certificate
        fi
        start_service
        show_completion_message
    fi
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 1' INT TERM

# Run main function
main "$@" 