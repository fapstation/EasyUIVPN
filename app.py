#!/usr/bin/env python3
"""
EasyUIVPN - Simple and Secure OpenVPN Web Management Interface
A lightweight, security-focused OpenVPN management tool for small servers.
"""

import os
import sys
import logging
import subprocess
import json
import secrets
import hashlib
import pwd
import crypt
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.security import check_password_hash
import qrcode
import io
import base64
from stats import get_stats_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configuration
CONFIG = {
    'OPENVPN_DIR': '/etc/openvpn',
    'CLIENT_DIR': '/etc/openvpn/client',
    'SERVER_CONFIG': '/etc/openvpn/server/server.conf',
    'STATUS_LOG': '/var/log/openvpn/openvpn-status.log',
    'STATS_FILE': '/var/lib/easyvpn/stats.json',
    'DATA_DIR': '/var/lib/easyvpn',
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_TIMEOUT': 300,  # 5 minutes
    'OPENVPN_SCRIPT': '/usr/local/bin/openvpn-install.sh',
    'INSTALLATION_TYPE': 'unknown',  # Will be detected
    'EASYRSA_DIR': None,
    'CA_DIR': None,
    'CAN_CREATE_CLIENTS': False  # Will be set based on available tools
}

# Auto-detect OpenVPN configuration paths and installation type
def detect_openvpn_paths():
    """Auto-detect OpenVPN installation paths and type"""
    possible_configs = [
        '/etc/openvpn/server/server.conf',
        '/etc/openvpn/server.conf',
    ]
    
    possible_client_dirs = [
        '/etc/openvpn/client',
        '/etc/openvpn/clients', 
        '/root',  # Angristan script default
    ]
    
    possible_status_logs = [
        '/var/log/openvpn/openvpn-status.log',
        '/var/log/openvpn/status.log',
        '/etc/openvpn/server/openvpn-status.log',
    ]
    
    # Find server config
    for config_path in possible_configs:
        if os.path.exists(config_path):
            CONFIG['SERVER_CONFIG'] = config_path
            break
    
    # Find client directory
    for client_dir in possible_client_dirs:
        if os.path.exists(client_dir):
            # Check if it contains .ovpn files
            try:
                if any(f.endswith('.ovpn') for f in os.listdir(client_dir)):
                    CONFIG['CLIENT_DIR'] = client_dir
                    break
            except PermissionError:
                continue
    
    # Find status log
    for status_log in possible_status_logs:
        if os.path.exists(status_log):
            CONFIG['STATUS_LOG'] = status_log
            break
    
    # Detect installation type
    detect_installation_type()
    
    logger.info(f"OpenVPN installation detected: type={CONFIG['INSTALLATION_TYPE']}, config={CONFIG['SERVER_CONFIG']}, clients={CONFIG['CLIENT_DIR']}, status={CONFIG['STATUS_LOG']}")

def detect_installation_type():
    """Detect OpenVPN installation type - simplified approach"""
    # Just check if we can manage clients - don't overcomplicate it
    CONFIG['INSTALLATION_TYPE'] = 'openvpn'
    
    # Check if we have any way to create clients
    can_create_clients = False
    
    # Check for Angristan script (if it exists, we can use it)
    angristan_script_paths = [
        '/usr/local/bin/openvpn-install.sh',
        '/root/openvpn-install.sh',
        '/usr/sbin/openvpn-install.sh',
    ]
    
    for script_path in angristan_script_paths:
        if os.path.exists(script_path):
            CONFIG['OPENVPN_SCRIPT'] = script_path
            can_create_clients = True
            logger.info(f"Found OpenVPN management script: {script_path}")
            break
    
    # Check for EasyRSA (alternative way to create clients)
    if not can_create_clients:
        try:
            result = subprocess.run(['which', 'easyrsa'], capture_output=True, text=True)
            if result.returncode == 0:
                can_create_clients = True
                logger.info("Found EasyRSA for client management")
        except:
            pass
        
        # Also check common EasyRSA directories
        easyrsa_paths = [
            '/etc/openvpn/easy-rsa',
            '/usr/share/easy-rsa',
            '/opt/easy-rsa',
        ]
        
        for easyrsa_dir in easyrsa_paths:
            easyrsa_executable = os.path.join(easyrsa_dir, 'easyrsa')
            if os.path.exists(easyrsa_executable):
                CONFIG['EASYRSA_DIR'] = easyrsa_dir
                can_create_clients = True
                logger.info(f"Found EasyRSA installation: {easyrsa_dir}")
                break
    
    # Set capabilities based on what we found
    CONFIG['CAN_CREATE_CLIENTS'] = can_create_clients
    
    if can_create_clients:
        logger.info("OpenVPN client management available")
    else:
        logger.warning("No client management tools found - monitoring only")
        CONFIG['INSTALLATION_TYPE'] = 'monitoring_only'

# Initialize paths
detect_openvpn_paths()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1, max=255)])

class ClientForm(FlaskForm):
    client_name = StringField('Client Name', validators=[DataRequired(), Length(min=1, max=50)])

class ConfigForm(FlaskForm):
    config_content = TextAreaField('Configuration', validators=[DataRequired()])

def verify_system_user(username, password):
    """Verify user credentials against system users with enhanced security"""
    try:
        # Get user info
        user_info = pwd.getpwnam(username)
        
        # Read shadow file for password hash (requires root or appropriate permissions)
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    if line.startswith(f"{username}:"):
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            stored_hash = parts[1]
                            # Verify password using crypt
                            return crypt.crypt(password, stored_hash) == stored_hash
        except PermissionError:
            logger.warning("Cannot read /etc/shadow, falling back to less secure method")
            # Fallback: attempt to use su command (less secure)
            try:
                result = subprocess.run(['su', '-c', 'echo "authenticated"', username], 
                                      input=password, text=True, capture_output=True, timeout=5)
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
                
    except KeyError:
        logger.warning(f"User {username} not found")
    except Exception as e:
        logger.error(f"Authentication error: {e}")
    
    return False

def requires_auth(f):
    """Decorator to require authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_connected_clients():
    """Get list of currently connected clients with statistics integration"""
    connected = []
    stats_manager = get_stats_manager()
    
    try:
        if os.path.exists(CONFIG['STATUS_LOG']):
            with open(CONFIG['STATUS_LOG'], 'r') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Try different parsing methods for different OpenVPN status formats
                connected = _parse_openvpn_status_v3(lines) or _parse_openvpn_status_v2(lines)
                
                # Update statistics for connected clients
                for client in connected:
                    stats_manager.record_connection(
                        client['name'],
                        client['real_address'],
                        client['virtual_address'],
                        client['bytes_sent'],
                        client['bytes_received']
                    )
                
                # Update concurrent connections count
                stats_manager.update_concurrent_connections(len(connected))
                
    except Exception as e:
        logger.error(f"Error reading status log: {e}")
    
    return connected

def _parse_openvpn_status_v3(lines):
    """Parse OpenVPN status format version 3"""
    connected = []
    try:
        in_client_list = False
        for line in lines:
            line = line.strip()
            if line.startswith('CLIENT_LIST'):
                in_client_list = True
                continue
            elif line.startswith('ROUTING_TABLE') or line.startswith('GLOBAL_STATS'):
                in_client_list = False
                continue
            elif in_client_list and line and not line.startswith('#'):
                parts = line.split('\t')
                if len(parts) >= 5:
                    connected.append({
                        'name': parts[0],
                        'real_address': parts[1].split(':')[0],  # Remove port
                        'virtual_address': parts[2],
                        'bytes_received': int(parts[3]) if parts[3].isdigit() else 0,
                        'bytes_sent': int(parts[4]) if parts[4].isdigit() else 0,
                        'connected_since': parts[5] if len(parts) > 5 else 'Unknown'
                    })
    except Exception as e:
        logger.debug(f"Failed to parse status v3 format: {e}")
        return None
    
    return connected if connected else None

def _parse_openvpn_status_v2(lines):
    """Parse OpenVPN status format version 2 (comma-separated)"""
    connected = []
    try:
        in_client_list = False
        for line in lines:
            line = line.strip()
            if line.startswith('CLIENT_LIST'):
                in_client_list = True
                continue
            elif line.startswith('ROUTING_TABLE'):
                in_client_list = False
                continue
            elif in_client_list and line and not line.startswith('Common Name'):
                parts = line.split(',')
                if len(parts) >= 5:
                    connected.append({
                        'name': parts[0],
                        'real_address': parts[1].split(':')[0],  # Remove port
                        'virtual_address': parts[2],
                        'bytes_received': int(parts[3]) if parts[3].isdigit() else 0,
                        'bytes_sent': int(parts[4]) if parts[4].isdigit() else 0,
                        'connected_since': parts[5] if len(parts) > 5 else 'Unknown'
                    })
    except Exception as e:
        logger.debug(f"Failed to parse status v2 format: {e}")
        return []
    
    return connected

def get_all_clients():
    """Get list of all configured clients"""
    clients = []
    try:
        client_dir = CONFIG['CLIENT_DIR']
        if os.path.exists(client_dir):
            for filename in os.listdir(client_dir):
                if filename.endswith('.ovpn'):
                    client_name = filename[:-5]  # Remove .ovpn extension
                    cert_path = os.path.join(client_dir, f"{client_name}.crt")
                    created_date = 'Unknown'
                    if os.path.exists(cert_path):
                        created_date = datetime.fromtimestamp(os.path.getctime(cert_path)).strftime('%Y-%m-%d %H:%M')
                    
                    clients.append({
                        'name': client_name,
                        'created': created_date,
                        'config_file': filename
                    })
    except Exception as e:
        logger.error(f"Error reading client directory: {e}")
    
    return clients

@app.route('/')
def index():
    if 'authenticated' not in session or not session['authenticated']:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Rate limiting check
        login_key = f"login_attempts_{request.remote_addr}"
        attempts = session.get(login_key, 0)
        
        if attempts >= CONFIG['MAX_LOGIN_ATTEMPTS']:
            flash('Too many login attempts. Please try again later.', 'error')
            return render_template('login.html', form=form)
        
        if verify_system_user(username, password):
            session['authenticated'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            
            # Clear login attempts
            session.pop(login_key, None)
            
            logger.info(f"Successful login for user: {username}")
            return redirect(url_for('dashboard'))
        else:
            # Increment login attempts
            session[login_key] = attempts + 1
            flash('Invalid username or password', 'error')
            # Hash the IP for privacy in logs
            ip_hash = hashlib.sha256(request.remote_addr.encode()).hexdigest()[:8]
            logger.warning(f"Failed login attempt for user: {username} from IP hash: {ip_hash}")
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User logged out: {username}")
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@requires_auth
def dashboard():
    connected_clients = get_connected_clients()
    all_clients = get_all_clients()
    stats_manager = get_stats_manager()
    
    # Mark clients as connected or not
    for client in all_clients:
        client['connected'] = any(c['name'] == client['name'] for c in connected_clients)
    
    # Get enhanced statistics
    server_stats = stats_manager.get_server_stats()
    
    stats = {
        'total_clients': len(all_clients),
        'connected_clients': len(connected_clients),
        'total_bandwidth_sent': sum(c['bytes_sent'] for c in connected_clients),
        'total_bandwidth_received': sum(c['bytes_received'] for c in connected_clients),
        'connections_last_7_days': server_stats.get('connections_last_7_days', 0),
        'unique_clients_last_7_days': server_stats.get('unique_clients_last_7_days', 0),
        'max_concurrent_connections': server_stats['summary'].get('max_concurrent_connections', 0),
        'can_manage_clients': CONFIG['CAN_CREATE_CLIENTS'],
        'installation_type': 'OpenVPN' if CONFIG['CAN_CREATE_CLIENTS'] else 'OpenVPN (Monitoring Only)',
    }
    
    return render_template('dashboard.html', 
                         clients=all_clients, 
                         connected=connected_clients, 
                         stats=stats, 
                         server_stats=server_stats)

@app.route('/api/status')
@requires_auth
def api_status():
    """API endpoint for real-time status updates"""
    connected_clients = get_connected_clients()
    return jsonify({
        'connected_clients': connected_clients,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/clients')
@requires_auth  
def clients():
    all_clients = get_all_clients()
    connected_clients = get_connected_clients()
    
    # Mark clients as connected
    for client in all_clients:
        client['connected'] = any(c['name'] == client['name'] for c in connected_clients)
        
    return render_template('clients.html', clients=all_clients)

@app.route('/clients/create', methods=['GET', 'POST'])
@requires_auth
def create_client():
    form = ClientForm()
    
    if form.validate_on_submit():
        client_name = form.client_name.data
        
        # Validate client name (alphanumeric and hyphens only)
        if not client_name.replace('-', '').replace('_', '').isalnum():
            flash('Client name can only contain letters, numbers, hyphens, and underscores', 'error')
            return render_template('create_client.html', form=form)
        
        # Check if client already exists
        if _client_exists(client_name):
            flash(f'Client "{client_name}" already exists', 'error')
            return render_template('create_client.html', form=form)
        
        try:
            # Use the OpenVPN script to create client
            success = _create_openvpn_client(client_name)
            
            if success:
                flash(f'Client "{client_name}" created successfully', 'success')
                logger.info(f"Created client: {client_name} by user: {session['username']}")
                return redirect(url_for('clients'))
            else:
                flash('Error creating client. Please check server logs.', 'error')
                
        except Exception as e:
            flash(f'Error creating client: {str(e)}', 'error')
            logger.error(f"Exception creating client {client_name}: {e}")
    
    return render_template('create_client.html', form=form)

def _client_exists(client_name):
    """Check if a client certificate already exists"""
    # Check for .ovpn file in client directory
    ovpn_path = os.path.join(CONFIG['CLIENT_DIR'], f"{client_name}.ovpn")
    if os.path.exists(ovpn_path):
        return True
    
    # For EasyRSA installations, also check for certificate files
    if CONFIG['INSTALLATION_TYPE'] == 'easyrsa' and CONFIG['CA_DIR']:
        client_crt_path = os.path.join(CONFIG['CA_DIR'], 'issued', f'{client_name}.crt')
        if os.path.exists(client_crt_path):
            return True
    
    # Check fallback locations
    fallback_locations = [
        os.path.join('/root', f"{client_name}.ovpn"),
        os.path.join('/etc/openvpn/client', f"{client_name}.ovpn"),
        os.path.join('/etc/openvpn/clients', f"{client_name}.ovpn"),
    ]
    
    return any(os.path.exists(path) for path in fallback_locations)

def _create_openvpn_client(client_name):
    """Create OpenVPN client using available tools"""
    if not CONFIG['CAN_CREATE_CLIENTS']:
        logger.error("No client management tools available")
        return False
        
    # Try Angristan script first if available
    if CONFIG.get('OPENVPN_SCRIPT') and os.path.exists(CONFIG['OPENVPN_SCRIPT']):
        return _create_client_angristan(client_name)
    
    # Try EasyRSA if available
    if CONFIG.get('EASYRSA_DIR') or subprocess.run(['which', 'easyrsa'], capture_output=True).returncode == 0:
        return _create_client_easyrsa(client_name)
    
    logger.error("No supported client creation method found")
    return False

def _create_client_angristan(client_name):
    """Create OpenVPN client using Angristan's script"""
    if not CONFIG['OPENVPN_SCRIPT'] or not os.path.exists(CONFIG['OPENVPN_SCRIPT']):
        logger.error("Angristan OpenVPN script not found")
        return False
    
    try:
        # Create client using the script
        env = os.environ.copy()
        env['MENU_OPTION'] = '1'  # Add client option
        env['CLIENT'] = client_name
        env['PASS'] = '1'  # No password
        
        result = subprocess.run([
            CONFIG['OPENVPN_SCRIPT']
        ], input=f"1\n{client_name}\n1\n", text=True, 
          capture_output=True, timeout=60, env=env)
        
        if result.returncode == 0:
            return _client_exists(client_name)
        else:
            logger.error(f"Angristan script failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Client creation timed out")
        return False
    except Exception as e:
        logger.error(f"Exception in Angristan client creation: {e}")
        return False

def _create_client_easyrsa(client_name):
    """Create OpenVPN client using EasyRSA"""
    try:
        # Determine easyrsa command and working directory
        if CONFIG['EASYRSA_DIR']:
            # Validate that EASYRSA_DIR is safe
            if not os.path.abspath(CONFIG['EASYRSA_DIR']).startswith(('/etc/', '/usr/', '/opt/')):
                logger.error("EasyRSA directory not in safe location")
                return False
            easyrsa_cmd = os.path.join(CONFIG['EASYRSA_DIR'], 'easyrsa')
            work_dir = CONFIG['EASYRSA_DIR']
        else:
            easyrsa_cmd = 'easyrsa'
            work_dir = '/etc/openvpn/easy-rsa'
        
        # Validate working directory exists and is safe
        if not os.path.exists(work_dir) or not os.path.abspath(work_dir).startswith(('/etc/', '/usr/', '/opt/')):
            logger.error("EasyRSA working directory not found or not safe")
            return False
        
        # Generate client certificate and key
        logger.info(f"Creating client certificate for {client_name}")
        result = subprocess.run([
            easyrsa_cmd, 'build-client-full', client_name, 'nopass'
        ], cwd=work_dir, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            logger.error(f"EasyRSA client creation failed: {result.stderr}")
            return False
        
        # Generate the .ovpn file
        return _generate_ovpn_file_easyrsa(client_name)
        
    except subprocess.TimeoutExpired:
        logger.error("EasyRSA client creation timed out")
        return False
    except Exception as e:
        logger.error(f"Exception in EasyRSA client creation: {e}")
        return False

def _generate_ovpn_file_easyrsa(client_name):
    """Generate .ovpn configuration file for EasyRSA installation"""
    try:
        # Determine paths
        if CONFIG['CA_DIR']:
            pki_dir = CONFIG['CA_DIR']
        else:
            # Try to find PKI directory
            possible_pki_dirs = [
                '/etc/openvpn/easy-rsa/pki',
                '/etc/openvpn/pki',
                '/etc/ssl/openvpn/pki',
            ]
            pki_dir = None
            for pki in possible_pki_dirs:
                if os.path.exists(pki):
                    pki_dir = pki
                    break
            
            if not pki_dir:
                logger.error("Could not find PKI directory")
                return False
        
        # Read certificate files
        ca_crt_path = os.path.join(pki_dir, 'ca.crt')
        client_crt_path = os.path.join(pki_dir, 'issued', f'{client_name}.crt')
        client_key_path = os.path.join(pki_dir, 'private', f'{client_name}.key')
        tls_auth_path = os.path.join(pki_dir, 'ta.key')
        
        # Check if all files exist
        required_files = [ca_crt_path, client_crt_path, client_key_path]
        for file_path in required_files:
            if not os.path.exists(file_path):
                logger.error(f"Required certificate file not found: {file_path}")
                return False
        
        # Read server configuration to extract settings
        server_ip = "YOUR_SERVER_IP"
        server_port = "1194"
        protocol = "udp"
        
        if os.path.exists(CONFIG['SERVER_CONFIG']):
            try:
                with open(CONFIG['SERVER_CONFIG'], 'r') as f:
                    server_config = f.read()
                    
                # Extract port
                import re
                port_match = re.search(r'^port\s+(\d+)', server_config, re.MULTILINE)
                if port_match:
                    server_port = port_match.group(1)
                
                # Extract protocol
                proto_match = re.search(r'^proto\s+(\w+)', server_config, re.MULTILINE)
                if proto_match:
                    protocol = proto_match.group(1)
                    
            except Exception as e:
                logger.warning(f"Could not parse server config: {e}")
        
        # Try to get server IP (with security validation)
        try:
            result = subprocess.run(['curl', '-s', 'https://ipv4.icanhazip.com'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                detected_ip = result.stdout.strip()
                # Validate it's a valid IP address format
                import ipaddress
                try:
                    ipaddress.ip_address(detected_ip)
                    server_ip = detected_ip
                except ValueError:
                    logger.warning(f"Invalid IP detected from external service: {detected_ip}")
        except Exception as e:
            logger.debug(f"Could not detect server IP: {e}")
            pass
        
        # Read certificate contents
        with open(ca_crt_path, 'r') as f:
            ca_crt = f.read()
        
        with open(client_crt_path, 'r') as f:
            client_crt = f.read()
        
        with open(client_key_path, 'r') as f:
            client_key = f.read()
        
        tls_auth = ""
        if os.path.exists(tls_auth_path):
            with open(tls_auth_path, 'r') as f:
                tls_auth = f.read()
        
        # Generate .ovpn content
        ovpn_content = f"""client
dev tun
proto {protocol}
remote {server_ip} {server_port}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
key-direction 1
verb 3

<ca>
{ca_crt}</ca>

<cert>
{client_crt}</cert>

<key>
{client_key}</key>
"""

        if tls_auth:
            ovpn_content += f"""
<tls-auth>
{tls_auth}</tls-auth>
"""
        
        # Write .ovpn file
        ovpn_path = os.path.join(CONFIG['CLIENT_DIR'], f'{client_name}.ovpn')
        os.makedirs(CONFIG['CLIENT_DIR'], exist_ok=True)
        
        with open(ovpn_path, 'w') as f:
            f.write(ovpn_content)
        
        logger.info(f"Generated .ovpn file: {ovpn_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating .ovpn file: {e}")
        return False

@app.route('/clients/<client_name>/revoke', methods=['POST'])
@requires_auth
def revoke_client(client_name):
    try:
        # Validate CSRF token
        validate_csrf(request.form.get('csrf_token'))
        
        # SECURITY: Validate client name to prevent command injection
        if not client_name.replace('-', '').replace('_', '').isalnum():
            flash('Invalid client name', 'error')
            return redirect(url_for('clients'))
        
        # Revoke client based on installation type
        success = _revoke_openvpn_client(client_name)
        
        if success:
            flash(f'Client "{client_name}" revoked successfully', 'success')
            logger.info(f"Revoked client: {client_name} by user: {session['username']}")
        else:
            flash('Error revoking client. Please check server logs.', 'error')
            
    except Exception as e:
        flash('Error revoking client', 'error')
        logger.error(f"Exception revoking client {client_name}: {e}")
    
    return redirect(url_for('clients'))

def _revoke_openvpn_client(client_name):
    """Revoke OpenVPN client using available tools"""
    if not CONFIG['CAN_CREATE_CLIENTS']:
        logger.error("No client management tools available")
        return False
        
    # Try Angristan script first if available
    if CONFIG.get('OPENVPN_SCRIPT') and os.path.exists(CONFIG['OPENVPN_SCRIPT']):
        return _revoke_client_angristan(client_name)
    
    # Try EasyRSA if available
    if CONFIG.get('EASYRSA_DIR') or subprocess.run(['which', 'easyrsa'], capture_output=True).returncode == 0:
        return _revoke_client_easyrsa(client_name)
    
    logger.error("No supported client revocation method found")
    return False

def _revoke_client_angristan(client_name):
    """Revoke client using Angristan script"""
    try:
        result = subprocess.run([
            CONFIG['OPENVPN_SCRIPT'],
            '--batch',
            '--revoke', client_name
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return True
        else:
            logger.error(f"Angristan revocation failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Exception in Angristan revocation: {e}")
        return False

def _revoke_client_easyrsa(client_name):
    """Revoke client using EasyRSA"""
    try:
        # Determine easyrsa command and working directory
        if CONFIG['EASYRSA_DIR']:
            # Validate that EASYRSA_DIR is safe
            if not os.path.abspath(CONFIG['EASYRSA_DIR']).startswith(('/etc/', '/usr/', '/opt/')):
                logger.error("EasyRSA directory not in safe location")
                return False
            easyrsa_cmd = os.path.join(CONFIG['EASYRSA_DIR'], 'easyrsa')
            work_dir = CONFIG['EASYRSA_DIR']
        else:
            easyrsa_cmd = 'easyrsa'
            work_dir = '/etc/openvpn/easy-rsa'
        
        # Validate working directory exists and is safe
        if not os.path.exists(work_dir) or not os.path.abspath(work_dir).startswith(('/etc/', '/usr/', '/opt/')):
            logger.error("EasyRSA working directory not found or not safe")
            return False
        
        # Revoke the certificate
        logger.info(f"Revoking client certificate for {client_name}")
        result = subprocess.run([
            easyrsa_cmd, 'revoke', client_name
        ], cwd=work_dir, capture_output=True, text=True, timeout=60, input='yes\n')
        
        if result.returncode != 0:
            logger.error(f"EasyRSA revocation failed: {result.stderr}")
            return False
        
        # Generate new CRL
        crl_result = subprocess.run([
            easyrsa_cmd, 'gen-crl'
        ], cwd=work_dir, capture_output=True, text=True, timeout=60)
        
        if crl_result.returncode != 0:
            logger.warning(f"Failed to generate CRL: {crl_result.stderr}")
        
        # Remove the .ovpn file
        ovpn_path = os.path.join(CONFIG['CLIENT_DIR'], f'{client_name}.ovpn')
        if os.path.exists(ovpn_path):
            os.remove(ovpn_path)
            logger.info(f"Removed .ovpn file: {ovpn_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"Exception in EasyRSA revocation: {e}")
        return False

@app.route('/clients/<client_name>/download')
@requires_auth
def download_client(client_name):
    try:
        # Validate client name to prevent path traversal
        if not client_name.replace('-', '').replace('_', '').isalnum():
            flash('Invalid client name', 'error')
            return redirect(url_for('clients'))
        
        config_path = os.path.join(CONFIG['CLIENT_DIR'], f"{client_name}.ovpn")
        
        # Ensure the file is within the client directory
        if not os.path.commonpath([CONFIG['CLIENT_DIR'], config_path]) == CONFIG['CLIENT_DIR']:
            flash('Invalid file path', 'error')
            return redirect(url_for('clients'))
            
        if os.path.exists(config_path):
            return send_file(config_path, as_attachment=True, download_name=f"{client_name}.ovpn")
        else:
            flash('Client configuration not found', 'error')
    except Exception as e:
        flash('Error downloading client config', 'error')
        logger.error(f"Error downloading client {client_name}: {e}")
    
    return redirect(url_for('clients'))

@app.route('/clients/<client_name>/qrcode')
@requires_auth
def client_qrcode(client_name):
    try:
        # Validate client name to prevent path traversal
        if not client_name.replace('-', '').replace('_', '').isalnum():
            flash('Invalid client name', 'error')
            return redirect(url_for('clients'))
        
        config_path = os.path.join(CONFIG['CLIENT_DIR'], f"{client_name}.ovpn")
        
        # Ensure the file is within the client directory
        if not os.path.commonpath([CONFIG['CLIENT_DIR'], config_path]) == CONFIG['CLIENT_DIR']:
            flash('Invalid file path', 'error')
            return redirect(url_for('clients'))
            
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_content = f.read()
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(config_content)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64 for display
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            
            return render_template('qrcode.html', 
                                 client_name=client_name, 
                                 qr_code=img_base64)
        else:
            flash('Client configuration not found', 'error')
    except Exception as e:
        flash(f'Error generating QR code: {str(e)}', 'error')
        logger.error(f"Error generating QR code for {client_name}: {e}")
    
    return redirect(url_for('clients'))

@app.route('/settings', methods=['GET', 'POST'])
@requires_auth
def settings():
    config_form = ConfigForm()
    
    if config_form.validate_on_submit():
        try:
            config_content = config_form.config_content.data
            
            # Basic security validation
            dangerous_patterns = [
                'script-security',
                'system(',
                'shell',
                '../',
                '~/',
                '/etc/passwd',
                '/etc/shadow'
            ]
            
            for pattern in dangerous_patterns:
                if pattern in config_content.lower():
                    flash(f'Configuration contains potentially dangerous directive: {pattern}', 'error')
                    return render_template('settings.html', form=config_form)
            
            # Backup current config
            backup_path = f"{CONFIG['SERVER_CONFIG']}.backup.{int(datetime.now().timestamp())}"
            subprocess.run(['cp', CONFIG['SERVER_CONFIG'], backup_path], check=True)
            
            # Write new config
            with open(CONFIG['SERVER_CONFIG'], 'w') as f:
                f.write(config_content)
            
            flash('Configuration updated successfully. Remember to restart OpenVPN service.', 'success')
            logger.info(f"Config updated by user: {session['username']}")
            
        except Exception as e:
            flash('Error updating configuration', 'error')
            logger.error(f"Error updating config: {e}")
    
    # Load current config
    try:
        with open(CONFIG['SERVER_CONFIG'], 'r') as f:
            config_form.config_content.data = f.read()
    except Exception as e:
        flash(f'Error loading configuration: {str(e)}', 'error')
    
    return render_template('settings.html', form=config_form)

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    # Ensure data directory exists
    os.makedirs(CONFIG['DATA_DIR'], exist_ok=True)
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response
    
    print("Starting EasyOVPN Management Interface...")
    print("Access the web interface at: http://your-server-ip:8094")
    print("Use your system user credentials to login.")
    
    port = int(os.environ.get('PORT', 8094))
    app.run(host='0.0.0.0', port=port, debug=False) 