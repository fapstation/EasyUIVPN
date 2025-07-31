#!/bin/bash
#
# EasyUIVPN Management Interface Installer
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
EASYVPN_DIR="/opt/easyuivpn"
SERVICE_NAME="easyuivpn"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_VENV="$EASYVPN_DIR/venv"
LOG_FILE="/var/log/easyuivpn.log"
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
            echo "EasyUIVPN Installer Options:"
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
    
    # Check for venv module - this is the critical fix
    if ! python3 -c "import venv" &> /dev/null; then
        # Try to determine the right venv package name
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if [[ "$OS" == "debian" ]]; then
            missing_deps+=("python${PYTHON_VERSION}-venv")
        else
            missing_deps+=("python3-venv")
        fi
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
        read -p "Would you like EasyUIVPN installer to install these packages? (Y/n): " install_deps
        
        if [[ "$install_deps" == "n" || "$install_deps" == "N" ]]; then
            print_warning "Dependencies not installed. EasyUIVPN might not work correctly."
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
        # Install basic packages first
        apt-get install -y python3 python3-pip git curl wget unzip
        
        # Install the correct venv package
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3")
        if ! python3 -c "import venv" &> /dev/null; then
            print_status "Installing Python venv package for version $PYTHON_VERSION..."
            apt-get install -y "python${PYTHON_VERSION}-venv" || apt-get install -y python3-venv
        fi
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
    print_status "Checking OpenVPN installation..."
    
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
    
    echo ""
    print_status "🔍 Checking for client management tools..."
    
    # Check what client management tools are available
    HAS_CLIENT_TOOLS=false
    CLIENT_TOOLS_INFO=""
    
    # Check for Angristan script
    for script in /usr/local/bin/openvpn-install.sh /root/openvpn-install.sh /usr/sbin/openvpn-install.sh; do
        if [[ -f "$script" ]]; then
            HAS_CLIENT_TOOLS=true
            CLIENT_TOOLS_INFO="✅ Found OpenVPN management script: $script"
            break
        fi
    done
    
    # Check for EasyRSA if no script found
    if [[ "$HAS_CLIENT_TOOLS" != true ]]; then
        if command -v easyrsa &> /dev/null || [[ -d /etc/openvpn/easy-rsa ]] || [[ -d /usr/share/easy-rsa ]]; then
            HAS_CLIENT_TOOLS=true
            if command -v easyrsa &> /dev/null; then
                CLIENT_TOOLS_INFO="✅ Found EasyRSA: $(which easyrsa)"
            else
                for dir in /etc/openvpn/easy-rsa /usr/share/easy-rsa /opt/easy-rsa; do
                    if [[ -d "$dir" ]] && [[ -f "$dir/easyrsa" ]]; then
                        CLIENT_TOOLS_INFO="✅ Found EasyRSA: $dir"
                        break
                    fi
                done
            fi
        fi
    fi
    
    # Show results
    echo ""
    if [[ "$HAS_CLIENT_TOOLS" == true ]]; then
        echo -e "${GREEN}🎉 FULL OPENVPN SETUP DETECTED${NC}"
        echo -e "${GREEN}   $CLIENT_TOOLS_INFO${NC}"
        echo -e "${GREEN}   ✅ Client creation and management available${NC}"
        echo -e "${GREEN}   ✅ Complete EasyUIVPN functionality${NC}"
        OPENVPN_COMPATIBILITY_SCORE=100
    else
        echo -e "${YELLOW}⚠️  BASIC OPENVPN INSTALLATION${NC}"
        echo -e "${YELLOW}   ✅ OpenVPN server is running${NC}"
        echo -e "${YELLOW}   ❌ No client management tools found${NC}"
        echo -e "${YELLOW}   📊 EasyUIVPN will work in monitoring mode only${NC}"
        OPENVPN_COMPATIBILITY_SCORE=50
        
        echo ""
        echo -e "${YELLOW}💡 To enable client management, install:${NC}"
        echo -e "${YELLOW}   • EasyRSA: apt install easy-rsa${NC}"
        echo -e "${YELLOW}   • Or use Angristan's script for full automation${NC}"
        
        if [[ "$DEFAULT_INSTALL" != true ]]; then
            echo ""
            read -p "Continue with monitoring-only functionality? (y/N): " continue_limited
            if [[ "$continue_limited" != "y" && "$continue_limited" != "Y" ]]; then
                print_error "Installation cancelled. Install EasyRSA or Angristan script for full functionality."
                exit 1
            fi
        fi
    fi
    
    echo ""
    echo -e "${BLUE}📊 SETUP SUMMARY:${NC}"
    echo -e "${BLUE}   OpenVPN Version: ${NC}$OPENVPN_VERSION"
    echo -e "${BLUE}   Client Management: ${NC}$([ "$HAS_CLIENT_TOOLS" == true ] && echo "Available" || echo "Not Available")"
    echo -e "${BLUE}   EasyUIVPN Features: ${NC}$([ "$HAS_CLIENT_TOOLS" == true ] && echo "Full" || echo "Monitoring Only")"
    
    print_success "OpenVPN check completed"
}

create_user() {
    print_status "Creating easyuivpn system user..."
    
    if ! id "easyuivpn" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false easyuivpn
        print_success "Created easyuivpn user"
    else
        print_status "easyuivpn user already exists"
    fi
}

setup_directories() {
    print_status "Setting up directories..."
    
    # Create main directory
    mkdir -p "$EASYVPN_DIR"
    mkdir -p /var/lib/easyuivpn
    mkdir -p /var/log/easyuivpn
    
    # Set permissions
    chown -R easyuivpn:easyuivpn "$EASYVPN_DIR"
    chown -R easyuivpn:easyuivpn /var/lib/easyuivpn
    chown -R easyuivpn:easyuivpn /var/log/easyuivpn
    
    # Allow easyuivpn user to read OpenVPN files
    usermod -a -G openvpn easyuivpn 2>/dev/null || true
    
    print_success "Directories created and configured"
}

download_easyuivpn() {
    print_status "Downloading EasyUIVPN files..."
    
    cd "$EASYVPN_DIR"
    
    # Download main application files from GitHub
    curl -sSL -o app.py https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/app.py
    curl -sSL -o stats.py https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/stats.py
    curl -sSL -o requirements.txt https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/requirements.txt
    
    # Create templates directory and download templates
    mkdir -p templates
    curl -sSL -o templates/base.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/base.html
    curl -sSL -o templates/login.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/login.html
    curl -sSL -o templates/dashboard.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/dashboard.html
    curl -sSL -o templates/clients.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/clients.html
    curl -sSL -o templates/create_client.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/create_client.html
    curl -sSL -o templates/settings.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/settings.html
    curl -sSL -o templates/qrcode.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/qrcode.html
    curl -sSL -o templates/error.html https://raw.githubusercontent.com/fapstation/EasyUIVPN/main/templates/error.html
    
    # Verify critical files were downloaded
    if [[ ! -f app.py ]]; then
        print_error "Failed to download app.py"
        exit 1
    fi
    
    if [[ ! -f requirements.txt ]]; then
        print_error "Failed to download requirements.txt"
        exit 1
    fi
    
    print_success "EasyUIVPN files downloaded"
}

setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    cd "$EASYVPN_DIR"
    
    # Test venv capability before creating
    if ! python3 -c "import venv" &> /dev/null; then
        print_error "Python venv module not available. Please install python3-venv package."
        echo ""
        echo -e "${YELLOW}Quick fix:${NC}"
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3.12")
        echo -e "${BLUE}apt install python${PYTHON_VERSION}-venv${NC}"
        exit 1
    fi
    
    # Create virtual environment with better error handling
    if ! python3 -m venv "$PYTHON_VENV"; then
        print_error "Failed to create Python virtual environment"
        print_error "This usually means the python3-venv package is not installed"
        echo ""
        echo -e "${YELLOW}Please run:${NC}"
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3.12")
        echo -e "${BLUE}apt install python${PYTHON_VERSION}-venv${NC}"
        echo -e "${BLUE}Then re-run this installer${NC}"
        exit 1
    fi
    
    # Activate and install packages
    source "$PYTHON_VENV/bin/activate"
    
    # Upgrade pip first
    if ! pip install --upgrade pip; then
        print_warning "Failed to upgrade pip, continuing anyway..."
    fi
    
    # Install requirements
    if [[ -f requirements.txt ]]; then
        if ! pip install -r requirements.txt; then
            print_error "Failed to install Python requirements"
            exit 1
        fi
    else
        print_warning "requirements.txt not found, skipping Python package installation"
    fi
    
    chown -R easyuivpn:easyuivpn "$PYTHON_VENV"
    
    print_success "Python environment configured"
}

configure_permissions() {
    print_status "Configuring permissions for OpenVPN access..."
    
    # Allow easyuivpn user to read OpenVPN configuration and logs
    if [[ -d /etc/openvpn ]]; then
        chmod -R g+r /etc/openvpn
        chgrp -R openvpn /etc/openvpn 2>/dev/null || true
    fi
    
    if [[ -d /var/log/openvpn ]]; then
        chmod -R g+r /var/log/openvpn
        chgrp -R openvpn /var/log/openvpn 2>/dev/null || true
    fi
    
    # Create sudoers rule for OpenVPN management
    cat > /etc/sudoers.d/easyuivpn << 'EOF'
# Allow easyuivpn user to manage OpenVPN and access system authentication
easyuivpn ALL=(ALL) NOPASSWD: /bin/systemctl restart openvpn@server
easyuivpn ALL=(ALL) NOPASSWD: /bin/systemctl status openvpn@server
easyuivpn ALL=(ALL) NOPASSWD: /bin/systemctl reload openvpn@server
easyuivpn ALL=(ALL) NOPASSWD: /usr/local/bin/openvpn-install.sh
easyuivpn ALL=(ALL) NOPASSWD: /usr/sbin/openvpn-install.sh
# Allow reading shadow file for authentication (alternative to PAM)
easyuivpn ALL=(ALL) NOPASSWD: /bin/cat /etc/shadow
EOF
    
    chmod 440 /etc/sudoers.d/easyuivpn
    
    print_success "Permissions configured"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=EasyUIVPN Management Interface
After=network.target openvpn@server.service
Wants=openvpn@server.service

[Service]
Type=simple
User=easyuivpn
Group=easyuivpn
WorkingDirectory=$EASYVPN_DIR
Environment=PATH=$PYTHON_VENV/bin
Environment=PORT=$PORT
ExecStart=$PYTHON_VENV/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easyuivpn

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/easyuivpn /var/log/easyuivpn /tmp
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
        ufw allow "$PORT/tcp" comment "EasyUIVPN Web Interface"
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
                -subj "/C=US/ST=State/L=City/O=Organization/CN=easyuivpn" \
                2>/dev/null
            
            chown easyuivpn:easyuivpn "$SSL_DIR"/*
            chmod 600 "$SSL_DIR"/server.key
            chmod 644 "$SSL_DIR"/server.crt
            
            print_success "Self-signed SSL certificate created"
        fi
    else
        print_warning "OpenSSL not found. SSL certificate not created."
    fi
}

start_service() {
    print_status "Starting EasyUIVPN service..."
    
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment and check if service started successfully
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "EasyUIVPN service started successfully"
    else
        print_error "Failed to start EasyUIVPN service"
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

setup_autostart() {
    print_status "Setting up autostart configuration..."
    
    # Check if systemctl is available (systemd system)
    if command -v systemctl &> /dev/null; then
        if [[ "$DEFAULT_INSTALL" == true ]]; then
            # Auto-enable in default installation
            systemctl enable "$SERVICE_NAME"
            print_success "EasyUIVPN enabled for autostart"
        else
            # Ask user in interactive installation
            echo ""
            echo -e "${BLUE}Autostart Configuration:${NC}"
            echo -e "${YELLOW}Would you like EasyUIVPN to start automatically at boot?${NC}"
            echo -e "${GREEN}This ensures your VPN management interface is always available.${NC}"
            echo ""
            read -p "Enable autostart? (Y/n): " enable_autostart
            
            if [[ "$enable_autostart" != "n" && "$enable_autostart" != "N" ]]; then
                systemctl enable "$SERVICE_NAME"
                print_success "EasyUIVPN enabled for autostart"
            else
                print_status "Autostart not configured. You can enable it later with: systemctl enable $SERVICE_NAME"
            fi
        fi
    else
        print_warning "Systemd not detected. Manual autostart configuration may be required."
    fi
}

show_completion_message() {
    get_server_ip
    
    echo ""
    echo "=================================================================="
    print_success "EasyUIVPN Management Interface installed successfully!"
    echo "=================================================================="
    echo ""
    # Get both internal and external IP addresses
    INTERNAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "localhost")
    EXTERNAL_IP=$(curl -s --max-time 5 https://ipv4.icanhazip.com 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "Unknown")
    
    echo -e "${BLUE}Access Information:${NC}"
    if [[ "$EXTERNAL_IP" != "Unknown" && "$EXTERNAL_IP" != "" ]]; then
        echo -e "${GREEN}  External Access: http://$EXTERNAL_IP:$PORT${NC}"
    fi
    echo -e "${GREEN}  Internal Access: http://$INTERNAL_IP:$PORT${NC}"
    echo -e "${GREEN}  Local Access: http://localhost:$PORT${NC}"
    echo -e "${YELLOW}  Username: Use your system user credentials (e.g., root, admin)${NC}"
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo -e "${YELLOW}  Start:   systemctl start $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Stop:    systemctl stop $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Status:  systemctl status $SERVICE_NAME${NC}"
    echo -e "${YELLOW}  Logs:    journalctl -u $SERVICE_NAME -f${NC}"
    echo ""
    echo -e "${BLUE}Configuration files:${NC}"
    echo -e "${YELLOW}  Application: $EASYVPN_DIR/${NC}"
    echo -e "${YELLOW}  Data:        /var/lib/easyuivpn/${NC}"
    echo -e "${YELLOW}  Logs:        /var/log/easyuivpn/${NC}"
    echo ""
    echo -e "${BLUE}Update Information:${NC}"
    echo -e "${YELLOW}  Current Version: 1.0.0${NC}"
    echo -e "${YELLOW}  Check updates at: https://github.com/fapstation/EasyUIVPN/releases${NC}"
    echo ""
    
    echo -e "${RED}Security Notes:${NC}"
    echo -e "${YELLOW}  • Change default passwords for all user accounts${NC}"
    echo -e "${YELLOW}  • Consider setting up a firewall if not already configured${NC}"
    echo -e "${YELLOW}  • Always use HTTPS in production (consider reverse proxy)${NC}"
    echo -e "${YELLOW}  • Restrict access to the management interface${NC}"
    echo -e "${YELLOW}  • Regularly update the system and EasyUIVPN${NC}"
    echo -e "${YELLOW}  • Monitor logs for suspicious activity${NC}"
    echo ""
    echo "=================================================================="
}

# Main installation flow
main() {
    echo ""
    echo "=================================================================="
    echo -e "${GREEN}EasyUIVPN Management Interface Installer${NC}"
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
        download_easyuivpn
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
        setup_autostart
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
        download_easyuivpn
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
        setup_autostart
        show_completion_message
    fi
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 1' INT TERM

# Run main function
main "$@" 