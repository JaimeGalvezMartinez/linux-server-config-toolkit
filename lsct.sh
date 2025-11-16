#!/bin/bash
# Version 3.2 - november 2025
# Developer: Jaime Galvez (https://github.com/JaimeGalvezMartinez)
# Description: Bash script for configuring a Linux based Server
# If you like my work, please support it with a start in my github´s profile

clear

# === COLORES ===
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if exec in superuser permissions. 
if [ $EUID -ne 0 ]; then
   echo -e "${RED}${BOLD}This script must be run with superuser permissions (sudo su)${NC}"
   exit 1
fi

setup_vaultwarden_in_docker () {


set -e

# Colores
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # Sin color

# Encabezado
echo -e "${RED}${BOLD}==============================================${NC}"
echo -e "${CYAN}${BOLD}🚀 Vaultwarden Installer with HTTPS Proxy${NC}"
echo -e "${RED}${BOLD}==============================================${NC}"
echo -e "${RED}${BOLD}==============================================${NC}"
echo -e "${CYAN}${BOLD} Author: Jaime Galvez Martinez${NC}"
echo -e "${CYAN}${BOLD} GitHub: github.com/JaimeGalvezMartinez${NC}"
echo -e "${RED}${BOLD}==============================================${NC}"
echo ""


# === USER INPUT ===
read -rp "📁 Installation folder (default ~/vaultwarden-docker): " VAULT_DIR
VAULT_DIR=${VAULT_DIR:-$HOME/vaultwarden-docker}

read -rp "🔢 HTTP internal port for Vaultwarden (default 80): " HTTP_PORT_INTERNAL
HTTP_PORT_INTERNAL=${HTTP_PORT_INTERNAL:-80}

read -rp "🔢 HTTP host port to expose (default 8081): " HTTP_PORT_HOST
HTTP_PORT_HOST=${HTTP_PORT_HOST:-8081}

read -rp "🔒 HTTPS host port to expose (default 8445): " HTTPS_PORT
HTTPS_PORT=${HTTPS_PORT:-8445}

# Check for OpenSSL
command -v openssl >/dev/null 2>&1 || {
  echo "⚠️ OpenSSL not found. Installing..."
  sudo apt update && sudo apt install -y openssl
}

# Update and upgrade packages
sudo apt update && sudo apt upgrade -y

# Ensure vault directory exists
mkdir -p "$VAULT_DIR"

echo "✅ OpenSSL installed and vault directory ready at: $VAULT_DIR"


# === TOKEN GENERATION ===
generate_token() {
  # Generates a secure 12-character token (alphanumeric + symbols)
  openssl rand -base64 9 | tr -dc 'A-Za-z0-9@#%&_+=' | head -c 12
}

while true; do
  read -rsp "🗝️  Admin token (leave empty to generate a random one): " ADMIN_TOKEN
  echo
  if [ -z "$ADMIN_TOKEN" ]; then
    ADMIN_TOKEN=$(generate_token)
    echo "🔒 Automatically generated token: $ADMIN_TOKEN"
    echo "⚠️  Please copy and store this token safely."
    break
  else
    read -rsp "🔁 Confirm admin token: " CONFIRM_TOKEN
    echo
    if [ "$ADMIN_TOKEN" == "$CONFIRM_TOKEN" ]; then
      echo "✅ Token confirmed successfully!"
      break
    else
      echo "❌ Tokens do not match. Please try again."
    fi
  fi
done

# === SSL METADATA INPUT ===
echo ""

echo -e "${GREEN}${BOLD}🔧 SSL Certificate Metadata (press Enter to use defaults):${NC}"

read -rp "🌍 Country Code (default ES): " SSL_COUNTRY
SSL_COUNTRY=${SSL_COUNTRY:-ES}

read -rp "🏙️  State or Province (default State): " SSL_STATE
SSL_STATE=${SSL_STATE:-Castilla-La Mancha}

read -rp "🏡 City (default Toledo): " SSL_CITY
SSL_CITY=${SSL_CITY:-Toledo}

read -rp "🏢 Organization (default INTRANET): " SSL_ORG
SSL_ORG=${SSL_ORG:-INTRANET}

# Capture The main IP of the system
SSL_CN=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')

# And main IP saves in the variable SSL_CN 
echo " 🌐 Common Name / Domain: $SSL_CN"

SSL_DIR="$VAULT_DIR/ssl"
NGINX_CONF="$VAULT_DIR/nginx.conf"


# ================= CONFIGURATION SUMMARY =================
echo ""
echo -e "${GREEN}${BOLD}Configuration summary:${NC}"
echo "----------------------------------------------"
echo "📂 Folder:            $VAULT_DIR"
echo "🔢 HTTP internal:     $HTTP_PORT_INTERNAL"
echo "🔢 HTTP host port:    $HTTP_PORT_HOST"
echo "🔒 HTTPS host port:   $HTTPS_PORT"
echo "🗝️  Admin token:      $ADMIN_TOKEN"
echo "⚠️  Please copy and store this token safely."
echo ""
echo "📜 SSL Certificate Info:"
echo "   Country:           $SSL_COUNTRY"
echo "   State:             $SSL_STATE"
echo "   City:              $SSL_CITY"
echo "   Organization:      $SSL_ORG"
echo "   Common Name:       $SSL_CN"
echo "----------------------------------------------"

read -rp "Continue with installation? (y/n): " CONFIRM
[[ "$CONFIRM" =~ ^[yY]$ ]] || { echo -e "${RED}❌ Installation cancelled.${NC}"; exit 1; }

echo -e "${CYAN}${BOLD} ******************************************************${NC}"

# ================= FUNCTIONS =================

install_docker() {
    if ! command -v docker &>/dev/null; then
        echo "🚀 Installing Docker..."
        apt update && apt install -y ca-certificates curl gnupg lsb-release
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
          https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable --now docker
    else
        echo "✅ Docker is already installed."
    fi
}

generate_certificate() {
    echo -e "${GREEN}${BOLD}🔒 Generating self-signed certificate...${NC}"
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/selfsigned.key" \
        -out "$SSL_DIR/selfsigned.crt" \
        -subj "/C=$SSL_COUNTRY/ST=$SSL_STATE/L=$SSL_CITY/O=$SSL_ORG/CN=$SSL_CN"
}

create_nginx_conf() {
      echo -e "${GREEN}${BOLD}🧱 Creating nginx.conf..."
    mkdir -p "$VAULT_DIR"
    cat > "$NGINX_CONF" <<EOF
server {
    listen 443 ssl;
    server_name $SSL_CN;

    ssl_certificate /etc/ssl/private/selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/selfsigned.key;

    location / {
        proxy_pass http://vaultwarden:$HTTP_PORT_INTERNAL;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 80;
    server_name $SSL_CN;
    return 301 https://\$host\$request_uri;
}
EOF
}

create_compose() {
    echo -e "${GREEN}${BOLD}🧱 Creating docker-compose.yml...${NC}"
    mkdir -p "$VAULT_DIR"
    cat > "$VAULT_DIR/docker-compose.yml" <<EOF
services:
  vaultwarden:
    image: vaultwarden/server:latest
    restart: always
    environment:
      - ADMIN_TOKEN=$ADMIN_TOKEN
    volumes:
      - vaultwarden_data:/data

  proxy:
    image: nginx:latest
    restart: always
    depends_on:
      - vaultwarden
    ports:
      - "$HTTPS_PORT:443"
      - "$HTTP_PORT_HOST:80"
    volumes:
      - $SSL_DIR:/etc/ssl/private:ro
      - $NGINX_CONF:/etc/nginx/conf.d/default.conf:ro

volumes:
  vaultwarden_data:
EOF
}

start_containers() {
    echo "🚀 Starting Vaultwarden + Nginx proxy..."
    cd "$VAULT_DIR"
    docker compose up -d
}

# === EXECUTION ===
install_docker
generate_certificate
create_nginx_conf
create_compose
start_containers

echo ""
echo "✅ Installation completed successfully!"
echo "----------------------------------------------"
echo "🌐 Access Vaultwarden at:"
echo "   🔒 HTTPS: https://$SSL_CN:$HTTPS_PORT"
echo "   🔁 HTTP redirect: http://$SSL_CN:$HTTP_PORT_HOST"
echo ""
echo "🗝️  Admin Token: $ADMIN_TOKEN"
echo "⚠️  Please copy and store this token safely. — it will not be shown again!"
echo "----------------------------------------------"

}

setup_autofirmed_https () {

# Script to create a self-signed certificate and automatically configure Apache

echo "=== HTTPS configuration with self-signed certificate ==="

# === Ask for domain ===
read -p "Enter the domain name (e.g., mydomain.com): " DOMAIN

# === Ask for certificate metadata ===
read -p "Country (C) [e.g., ES]: " COUNTRY
read -p "State/Province (ST) [e.g., Toledo]: " STATE
read -p "City/Locality (L) [e.g., Toledo]: " LOCALITY
read -p "Organization (O) [e.g., IES-AZARQUIEL]: " ORGANIZATION
read -p "Organizational Unit (OU) [e.g., IT]: " ORG_UNIT
read -p "Email (e.g., admin@$DOMAIN): " EMAIL

# === Ask for DocumentRoot ===
read -p "Enter the DocumentRoot directory (e.g., /var/www/html): " DOCROOT

# === File paths ===
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
CERT_FILE="$CERT_DIR/${DOMAIN}.crt"
KEY_FILE="$KEY_DIR/${DOMAIN}.key"
VHOST_FILE="/etc/apache2/sites-available/${DOMAIN}-ssl.conf"

# === Create directories if they don't exist ===
sudo mkdir -p $CERT_DIR
sudo mkdir -p $KEY_DIR
sudo mkdir -p $DOCROOT

echo "🔑 Generating self-signed certificate for $DOMAIN ..."

# === Generate self-signed certificate ===
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$DOMAIN/emailAddress=$EMAIL"

# Adjust permissions
sudo chmod 600 "$KEY_FILE"
sudo chmod 644 "$CERT_FILE"

echo "📜 Certificate generated:"
echo "   - Certificate: $CERT_FILE"
echo "   - Private key: $KEY_FILE"

# === Enable Apache SSL module ===
echo "⚙️ Enabling SSL module in Apache..."
sudo a2enmod ssl

# === Create SSL VirtualHost ===
echo "🌐 Creating HTTPS VirtualHost for $DOMAIN ..."

sudo bash -c "cat > $VHOST_FILE" <<EOF
# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName $DOMAIN
    Redirect permanent / https://$DOMAIN/
</VirtualHost>

# VirtualHost on HTTTPS
<VirtualHost *:443>
    ServerName $DOMAIN
    DocumentRoot $DOCROOT

    SSLEngine on
    SSLCertificateFile $CERT_FILE
    SSLCertificateKeyFile $KEY_FILE

    # Protocolos y cifrados seguros
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder on

# deny subdirectory listing
    <Directory $DOCROOT>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Security Modules
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains; preload"
        Header always set Referrer-Policy "no-referrer"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    </IfModule>

    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
</VirtualHost>
EOF


# === Enable VirtualHost ===
echo "✅ Enabling VirtualHost..."
sudo a2ensite "${DOMAIN}-ssl.conf"

# === Reload Apache ===
echo "🔄 Restarting Apache..."
sudo systemctl reload apache2

echo "🎉 Configuration complete. You can now access https://$DOMAIN/"


}


zentyal_80_setup() {

# Zentyal 8.0 Installer for Ubuntu 22.04 LTS =>
# Interactive menu version

# ==========================
# COLORS
# ==========================
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'
NORM='\033[0m'

# ==========================
# CHECK FUNCTIONS
# ==========================

function check_ubuntu {
  echo -e "\n${GREEN} - Checking Ubuntu version...${NC}"
  UBUNTU_VERSION_NUM=$(lsb_release -sr)

  if dpkg --compare-versions "$UBUNTU_VERSION_NUM" lt "22.04"; then
      echo -e "${RED}${BOLD}You are running Ubuntu ${UBUNTU_VERSION_NUM}. Only Ubuntu 22.04 LTS or later is supported.${NC}"
      exit 1
  fi

if ! lsb_release -d | grep -qE "Ubuntu 22\.04(\.[0-9]+)? LTS"; then
    echo -e "${RED}${BOLD}Invalid OS. Ubuntu 22.04.x LTS is required. For Ubuntu 20.04, please, use Zentyal 7.0${NC}"
    exit 1
fi

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_broken_packages {
  echo -e "\n${GREEN} - Checking for broken packages...${NC}"
  if ! dpkg --audit; then
      apt-get -f install
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_available_packages {
  echo -e "\n${GREEN} - Checking for available package updates...${NC}"
  apt-get update -q
  apt-get upgrade -y -q
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_disk_space {
  echo -e "\n${GREEN} - Checking disk space...${NC}"
  REQUIRED_BOOT=51200
  REQUIRED_ROOT=358400
  REQUIRED_VAR=358400

  AVAILABLE_BOOT=$(df /boot | tail -1 | awk '{print $4}')
  AVAILABLE_ROOT=$(df / | tail -1 | awk '{print $4}')
  AVAILABLE_VAR=$(df /var | tail -1 | awk '{print $4}')

  if [ "$AVAILABLE_BOOT" -lt "$REQUIRED_BOOT" ] || [ "$AVAILABLE_ROOT" -lt "$REQUIRED_ROOT" ] || [ "$AVAILABLE_VAR" -lt "$REQUIRED_VAR" ]; then
      echo -e "${RED} Insufficient disk space.${NC}"
      exit 1
  fi

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_connection {
  echo -e "\n${GREEN} - Checking Internet connection...${NC}"
  if ! ping -c 2 google.com > /dev/null; then
      echo -e "${RED} No Internet connection detected.${NC}"
      exit 1
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_nic_names {
  echo -e "\n${GREEN} - Checking network interface names...${NC}"

  if ip -o link show | grep -q '^.*: eth[0-9]:'; then
      echo -e "${YELLOW} Warning: Old-style interface detected (ethX).${NC}"
      echo -e "          Consider using modern predictable names like ens160, enp3s0, etc."
      echo
  else
      echo -e "${GREEN}${BOLD}...OK (modern interface naming detected)${NC}${NORM}"; echo
  fi
}


# ==========================
# INSTALLATION FUNCTIONS
# ==========================

function configure_repos {
  echo -e "\n${GREEN} - Configuring repositories...${NC}"

  # Limpieza de repos previos de Zentyal
  sed -i '/zentyal/d' /etc/apt/sources.list
  rm -f /etc/apt/sources.list.d/zentyal.list

  # Clave y repositorio de Zentyal 8.0
  wget -qO- https://keys.zentyal.org/zentyal-8.0-packages-org.asc | gpg --dearmor -o /usr/share/keyrings/zentyal-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/zentyal-archive-keyring.gpg] http://packages.zentyal.org/zentyal 8.0 main extra" > /etc/apt/sources.list.d/zentyal.list

  # Clave y repositorio de Docker
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list

  sudo add-apt-repository -y ppa:mozillateam/ppa
sudo apt update

  # Preferencia para que Firefox use siempre el PPA
  cat <<EOF >/etc/apt/preferences.d/mozilla-firefox
Package: firefox
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
EOF

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}"; echo
}

function install_zentyal {
# Function to install Zentyal Server

echo -e "\e[33mWarning\e[0m"
echo
echo "It is highly recommended that no additional packages such as MySQL are installed on the server;"
echo "otherwise, the installation may fail and leave the server unstable."

read -rp "Continue with installation? (y/n): " CONFIRM
[[ "$CONFIRM" =~ ^[yY]$ ]] || { echo -e ${RED}${BOLD}"❌ Installation cancelled."; exit 1; }

  echo -e "${GREEN}>>> Starting Zentyal installation...${NC}\n"

  # Update package index
  if ! apt update -y; then
    echo -e "${RED}ERROR: Failed to update package lists.${NC}"
    return 1
  fi

  # Install Zentyal and required core package
  if ! DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends zentyal zenbuntu-core; then
    echo -e "${RED}ERROR: Zentyal installation failed.${NC}"
    return 1
  fi

  # Mark as commercial edition (simulate license)
  touch /var/lib/zentyal/.commercial-edition
  touch /var/lib/zentyal/.license

  echo -e "${GREEN}${BOLD}✔ Zentyal installation completed successfully.${NC}${NORM}\n"

  # Print access information
  echo -e "${GREEN}${BOLD}You can now access the Zentyal Web Interface at:${NC}${NORM}\n"
  echo -e "   * https://<zentyal-ip-address>:8443/\n"

  # If GUI is enabled, run additional setup
  if [[ -n ${ZEN_GUI} ]]; then
    echo -e "${YELLOW}GUI mode detected. Initializing graphical interface...${NC}"
    
    if command -v zentyal_gui &>/dev/null; then
      zentyal_gui
      sleep 10
      systemctl restart zentyal.lxdm
      echo -e "${GREEN}✔ Zentyal GUI initialized and service restarted.${NC}"
    else
      echo -e "${RED}WARNING: zentyal_gui command not found. Skipping GUI setup.${NC}"
    fi
  fi

  return 0
}

function install_graphical_environment {
  echo -e "\n${GREEN} - Installing graphical environment...${NC}"
  apt-get install -y zenbuntu-desktop lxdm
  echo "/usr/sbin/lxdm" > /etc/X11/default-display-manager
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function post_install {
  echo -e "\n${GREEN} - Disabling cloud-init...${NC}"
  touch /etc/cloud/cloud-init.disabled
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

# ==========================
# MAIN MENU
# ==========================

function show_menu {
  clear
  echo -e "${BLUE}${BOLD}===================================================================${NC}"
  echo -e "${CYAN}${BOLD}                        Zentyal 8.0 installer${NC}"
  echo -e "${BLUE}${BOLD}===================================================================${NC}"
  echo "1) Check system requirements"
  echo "2) Configure repositories"
  echo "3) Install Zentyal"
  echo "4) Install graphical environment (optional)"
  echo "5) Post-installation tasks"
  echo "6) Run everything in order"
  echo -e "${RED}${BOLD}0) Exit ${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
}

while true; do
  show_menu
  read -p "Select an option: " option
  case $option in
    1)
      check_ubuntu
      check_broken_packages
      check_available_packages
      check_disk_space
      check_connection
      check_webadmin_port
      check_nic_names
      ;;
    2)
      configure_repos
      ;;
    3)
      install_zentyal
      ;;
    4)
      read -p "Do you want to install the Zentyal graphical environment? (y/n) [n]: " choice
      choice=${choice:-n}
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          install_graphical_environment
      fi
      ;;
    5)
      post_install
      ;;
    6)
      check_ubuntu
      check_broken_packages
      check_available_packages
      check_disk_space
      check_connection
      check_webadmin_port
      check_nic_names
      configure_repos
      install_zentyal
      read -p "Do you want to install the Zentyal graphical environment? (y/n) [n]: " choice
      choice=${choice:-n}
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          install_graphical_environment
      fi
      post_install
      echo -e "\n${GREEN}${BOLD} Zentyal installation completed. Access it at https://<SERVER-IP>:8443 ${NC}${NORM}\n"
      ;;
    0)
      echo "Exiting..."
      return 0
      ;;
    *)
      echo "Invalid option."
      ;;
  esac
  read -p "Press Enter to continue..." enter
done

}

configure_firewall() {

    echo "==============================================================================="
    echo "=========================== FIREWALL SETUP ===================================="
    echo "==============================================================================="

    # Ensure UFW is installed
    if ! command -v ufw &>/dev/null; then
        echo "UFW is not installed. Installing UFW (Uncomplicated Firewall)..."
        sudo apt update && sudo apt install ufw -y
    fi

    # Enable UFW if it's inactive
    if sudo ufw status | grep -q "inactive"; then
        echo "Enabling UFW..."
        sudo ufw enable
    else
        echo "UFW is already active."
    fi

    while true; do
        echo ""
        echo "========================= FIREWALL MENU ========================="
        echo "1) Allow access to a specific port"
        echo "2) Allow access to a specific port from a specific IP"
        echo "3) Delete rule: IP to specific port"
        echo "4) Delete rule by port (no IP)"
        echo "5) Show firewall rules"
        echo "6) Install UFW"
        echo "7) Enable UFW"
        echo "8) Disable UFW"
        echo "9) Delete rule by name (e.g., 'Apache Full')"
        echo -e "${RED}${BOLD}0) Exit"
        echo "================================================================="
        read -rp "Choose an option: " option

        case $option in
            1)
                read -rp "Enter the port to allow (e.g., 80, 443, 22): " port
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    echo "Allowing access to port $port..."
                    sudo ufw allow "$port"
                    echo "Port $port allowed."
                else
                    echo "Invalid port number."
                fi
                ;;
            2)
                read -rp "Enter the port to allow (e.g., 80, 443, 22): " port
                read -rp "Enter the IP address (e.g., 192.168.1.100): " ip
                if [[ "$port" =~ ^[0-9]+$ && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "Allowing access to port $port from $ip..."
                    sudo ufw allow from "$ip" to any port "$port"
                    echo "Access allowed."
                else
                    echo "Invalid port or IP."
                fi
                ;;
            3)
                read -rp "Enter the port (e.g., 22, 80, 443): " port
                read -rp "Enter the IP to remove (e.g., 192.168.1.100): " ip
                if [[ "$port" =~ ^[0-9]+$ && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "Removing rule for port $port from IP $ip..."
                    sudo ufw delete allow from "$ip" to any port "$port"
                    echo "Rule deleted."
                else
                    echo "Invalid port or IP."
                fi
                ;;
            4)
                read -rp "Enter the port to delete (e.g., 80, 443, 22): " port
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    echo "Deleting rule for port $port..."
                    sudo ufw delete allow "$port"
                    echo "Rule for port $port deleted."
                else
                    echo "Invalid port number."
                fi
                ;;
            5)
                echo "Showing current firewall rules..."
                sudo ufw status verbose
                ;;
            6)
                echo "Installing UFW..."
                sudo apt update -y
                sudo apt install ufw -y
                ;;
            7)
                echo "Enabling UFW..."
                sudo ufw enable
                ;;
            8)
                echo "Disabling UFW..."
                sudo ufw disable
                ;;
            9)
                echo "Available application profiles:"
                sudo ufw app list
                read -rp "Enter the rule name to delete (e.g., 'Apache Full'): " rule_name
                if [[ -n "$rule_name" ]]; then
                    echo "Deleting rule: $rule_name"
                    sudo ufw delete allow "$rule_name"
                    echo "Rule '$rule_name' deleted."
                else
                    echo "No rule name entered."
                fi
                ;;
            0)
                echo "Exiting firewall configuration."
                break
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}



install_forwarder_dns() {
    



# Ask the user which type of DNS server they want to install
echo "Select the type of DNS server to install:"
echo "1) Forwarding DNS Server"
echo "2) Caching DNS Server"
read -p "Enter the number of the desired option: " option

# Update packages and install Bind9
sudo apt update && sudo apt install -y bind9

if [ "$option" == "1" ]; then
    # Configure Bind9 as a forwarding DNS server
    sudo bash -c 'cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    
    recursion yes;
    allow-recursion { any; };
    
    forwarders {
    	9.9.9.9;  // Quad9 DNS
        8.8.8.8;  // Google DNS
        8.8.4.4;  // Google Secondary DNS
        1.1.1.1;  // Cloudflare DNS
        1.0.0.1;  // Cloudflare Secondary DNS
	8.26.56.26; // Comodo Secure DNS
 	
    };
    
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
};
EOF'
elif [ "$option" == "2" ]; then
    # Configure Bind9 as a caching DNS server
    sudo bash -c 'cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    
    recursion yes;
    allow-query { any; };
    
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
};
EOF'
else
    echo "Invalid option. Exiting..."
    exit 1
fi

# Restart Bind9 to apply changes
sudo systemctl restart bind9
sudo systemctl enable bind9

# Check the service status
sudo systemctl status bind9 --no-pager

}


configure_network() {
    # Display available network interfaces (excluding lo)
    echo "Available network interfaces:"
    echo "--------------------------------"
    ip -o link show | awk -F': ' '!/ lo:/{print $2}' | while read -r iface; do
        mac=$(cat /sys/class/net/$iface/address)
        echo "Interface: $iface - MAC: $mac"
    done
    echo "--------------------------------"

    # Ask for the network interface
    read -rp "Enter the network interface you want to configure: " interface

    # Check if the interface exists
    if ! ip link show "$interface" &>/dev/null; then
        echo "Error: Interface '$interface' does not exist."
        return 1
    fi

    # Ask whether to configure Static IP or use DHCP
    echo "Do you want to configure a Static IP or use DHCP?"
    echo "1) Static IP"
    echo "2) DHCP (Automatic)"
    read -rp "Select an option (1, 2 or 0): " option
	
    # Initialize variables
    ip_address=""
    cidr=""
    gateway=""
    dns_servers=""

    # Backup current netplan config (if present)
    if [ -d /etc/netplan ]; then
        sudo cp /etc/netplan/01-netcfg.yaml /etc/netplan/01-netcfg.yaml.bak 2>/dev/null
    fi

    if [[ "$option" == "1" ]]; then
        # Static IP configuration
        read -rp "Enter the IP address (e.g., 192.168.1.100): " ip_address
        read -rp "Enter the CIDR prefix (e.g., 24 for 255.255.255.0): " cidr
        read -rp "Enter the gateway (or press Enter to skip): " gateway
        read -rp "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -rp "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        # CIDR validation
        if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 1 ] || [ "$cidr" -gt 32 ]; then
            echo "Error: CIDR prefix must be a number between 1 and 32."
            return 1
        fi

        # Netplan configuration
        if [ -d /etc/netplan ]; then
            # Base netplan config
            sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: no
      addresses:
        - $ip_address/$cidr
EOF

            # Append gateway if provided
            if [[ -n "$gateway" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      gateway4: $gateway
EOF
            fi

            # Append DNS if provided
            if [[ -n "$dns_servers" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
            fi

        else
            # Fallback to ifupdown
            echo "Configuring static IP using ifupdown..."
            sudo tee /etc/network/interfaces > /dev/null <<EOF
auto $interface
iface $interface inet static
    address $ip_address
    netmask 255.255.255.0
    $( [[ -n "$gateway" ]] && echo "gateway $gateway" )
    $( [[ -n "$dns_servers" ]] && echo "dns-nameservers $dns_servers" )
EOF
        fi

    elif [[ "$option" == "2" ]]; then
        # DHCP configuration
        read -rp "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -rp "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        if [ -d /etc/netplan ]; then
            # DHCP Netplan config
            sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: yes
EOF

            if [[ -n "$dns_servers" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
            fi

        else
            # Fallback to ifupdown
            echo "Configuring DHCP using ifupdown..."
            sudo tee /etc/network/interfaces > /dev/null <<EOF
auto $interface
iface $interface inet dhcp
EOF
        fi

    else
        echo "Invalid option. You must choose 1 or 2."
        return 1
    fi

    # Apply changes based on system setup
    if [ -d /etc/netplan ]; then
        sudo chmod 600 /etc/netplan/01-netcfg.yaml
        echo "Applying network configuration with Netplan..."
        sudo netplan apply && echo "✅ Network configuration applied successfully!"
    else
        echo "Applying configuration using ifupdown..."
        sudo ifdown "$interface" && sudo ifup "$interface" && echo "✅ Network configuration applied successfully!"
    fi
}


# Configure gateway server

configure_gateway_server(){


echo "------------------------------------------------"
echo "----------- MAKE GATEWAY ON UBUNTU -------------"
echo "------------------------------------------------"
echo "                                               "

#show network interfaces in the system
 echo "--------------------------------------"
    echo "Network interfaces in your system:"
    echo "--------------------------------------"
    INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
    echo "$INTERFACES"
    echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root. Exit"
  exit 1
fi

read -p "Enter the WAN Interface: " WAN_INTERFACE
read -p "Enter the LAN Interface: " LAN_INTERFACE

# Network Interface Variables

# Update system
echo "Updating the system..."
apt update && apt upgrade -y

# Install iptables if not installed
echo "Installing iptables..."
apt install -y iptables iptables-persistent

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Flush existing iptables rules (optional)
echo "Flushing existing iptables rules..."
iptables -F
iptables -t nat -F

# Configure iptables for NAT
echo "Configuring NAT in iptables..."
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules
echo "Saving iptables rules..."
netfilter-persistent save

# Restart iptables service
echo "Restarting the iptables service..."
systemctl restart netfilter-persistent

# Enable iptables-persistent to start on boot
echo "Enabling iptables-persistent at boot..."
systemctl enable netfilter-persistent

echo "Gateway successfully configured on $WAN_INTERFACE and $LAN_INTERFACE."
}

# Configure DHCP Server
configure_dhcp_server() {
# A tool for creating and managing a DHCP server with MAC filtering in an Ubuntu 20.04 system or later


    echo "================================="
    echo "Configuring DHCP Server..."
    echo "================================="
    echo "1) Assign an IP to a MAC"
    echo "2) Block an IP"
    echo "3) Change Network Configuration"
    echo "4) Install DHCP Server"
    echo -e "${RED}${BOLD}0) Exit"
    read -p "Choose an option: " dhcp_option
    case $dhcp_option in
        1)
            read -p "Enter the MAC address of the device: " mac
            read -p "Enter the IP to assign: " ip
            echo "host device_$mac {
    hardware ethernet $mac;
    fixed-address $ip;
}" >> /etc/dhcp/dhcpd.conf
            echo "Assigned IP $ip to MAC $mac."
            ;;
        2)
            read -p "Enter the IP to block: " ip_blocked
            echo "deny booting from $ip_blocked;" >> /etc/dhcp/dhcpd.conf
            echo "Blocked IP $ip_blocked in the DHCP server."
            ;;
        3)
            echo "Updating network configuration for the DHCP server..."
            read -p "Enter the network (e.g., 192.168.1.0): " network
            read -p "Enter the netmask (e.g., 255.255.255.0): " netmask
            read -p "Enter the range of IPs to assign (e.g., 192.168.1.100 192.168.1.200): " range
            read -p "Enter the gateway: " gateway
            echo "
subnet $network netmask $netmask {
    range $range;
    option routers $gateway;
}" >> /etc/dhcp/dhcpd.conf
            echo "Updated network settings for the DHCP server."
            ;;
        4)
            echo "======================="
            echo "Installing DHCP Server"
            echo "======================="
            
            #show interfaces
            echo ""
            echo "++++++++++++++++++++++++++++++++"
            echo "Available interfaces"
            echo "++++++++++++++++++++++++++++++++"
            INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
            echo "$INTERFACES"
            echo "++++++++++++++++++++++++++++++++"
            echo ""

	  # Ask the user to input the network interface name
  read -p "Enter the network interface for the DHCP server (e.g., ens19): " interface_name
  
  apt update && apt install -y isc-dhcp-server
  if [ $? -ne 0 ]; then
    echo "Error installing the DHCP server."
    exit 1
  fi

  # Configure the network interface
  echo "INTERFACESv4=\"$interface_name\"" > /etc/default/isc-dhcp-server


  # Restart and enable the DHCP service
  systemctl restart isc-dhcp-server
  systemctl enable isc-dhcp-server

  echo "DHCP server configured on interface $interface_name with network 10.33.206.0/24."

# configure_dhcp() {
  # Backup the configuration file
  cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak
  
  read -p "Enter the subnet (e.g., 10.33.206.0): " subnet
  read -p "Enter the subnet mask (e.g., 255.255.255.0): " subnet_mask
  read -p "Enter the starting IP range (e.g., 10.33.206.100): " range_start
  read -p "Enter the ending IP range (e.g., 10.33.206.200): " range_end
  read -p "Enter the router IP (e.g., 10.33.206.1): " router_ip
  read -p "Enter the DNS servers separated by commas (e.g., 8.8.8.8, 8.8.4.4): " dns_servers
  read -p "Enter the domain name (e.g., network.local): " domain_name

  # Write the configuration to dhcpd.conf
  cat <<EOL > /etc/dhcp/dhcpd.conf
# DHCP server configuration
subnet $subnet netmask $subnet_mask {
    range $range_start $range_end;
    option routers $router_ip;
    option subnet-mask $subnet_mask;
    option domain-name-servers $dns_servers;
    option domain-name "$domain_name";
}
EOL
            ;;
        0)
            echo "Exiting DHCP configuration."
            return ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
    # Restart the service after any change
    systemctl restart isc-dhcp-server
    echo "DHCP server configured and restarted."
}


configure_acl(){


# Ask the user what they want to configure
echo "What would you like to configure?"
echo "1) Block Traffic To LAN to WAN Network"
echo " ----------------------------------------"
echo "2) Configure QoS"
echo "-----------------------------------------"
read -p "Choose an option (1 or 2): " OPTION

case $OPTION in
    1)


# Display available network interfaces
echo "Available network interfaces:"
ip link show | awk -F': ' '/^[0-9]+: / {print $2}'

# Ask the user for interfaces and WAN network
echo -e "\nLAN to WAN Traffic Blocking Configuration"
read -p "Enter the WAN interface name: " WAN_IF
read -p "Enter the LAN interface name: " LAN_IF
read -p "Enter the WAN network (e.g., 192.168.1.0/24): " WAN_NET

# Check if interfaces exist
if ! ip link show "$WAN_IF" >/dev/null 2>&1; then
    echo "Error: The WAN interface '$WAN_IF' does not exist."
    exit 1
fi

if ! ip link show "$LAN_IF" >/dev/null 2>&1; then
    echo "Error: The LAN interface '$LAN_IF' does not exist."
    exit 1
fi

# Enable packet forwarding in sysctl
echo "Enabling packet forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Flush previous iptables rules
echo "Flushing previous rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies
echo "Setting default policies..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT  # Allow outgoing traffic from the gateway

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow the gateway itself to access the internet
echo "Allowing the gateway to access the internet..."
iptables -A INPUT -i "$WAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block LAN -> WAN internal network traffic
echo "Configuring firewall rules..."
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -d "$WAN_NET" -j DROP  

# Allow LAN -> Internet traffic
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Enable NAT for internet access
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

# Save iptables rules to persist after reboot
echo "Saving iptables rules..."
iptables-save > /etc/iptables.rules

# Apply rules on startup (Debian/Ubuntu)
echo -e "#!/bin/sh\n/sbin/iptables-restore < /etc/iptables.rules" > /etc/network/if-pre-up.d/iptables
chmod +x /etc/network/if-pre-up.d/iptables

# Display configured rules
echo "Configured rules:"
iptables -L -v -n
echo "Configuration completed."

 ;;

    
    2)
        # Configure QoS on the LAN interface
        echo "Enter the LAN network interface (example: eth0):"
        read LAN_IF
        echo "Enter the bandwidth limit in Kbps (example: 1000):"
        read BANDWIDTH

        # Validate the bandwidth
        if ! [[ "$BANDWIDTH" =~ ^[0-9]+$ ]]; then
            echo "The bandwidth limit must be an integer number."
            exit 1
        fi

        tc qdisc add dev "$LAN_IF" root handle 1: htb default 10
        tc class add dev "$LAN_IF" parent 1: classid 1:1 htb rate "${BANDWIDTH}kbit"
        tc filter add dev "$LAN_IF" protocol ip parent 1:0 prio 1 handle 1 fw flowid 1:1

        # Save the rules to persist after reboot
        echo "tc qdisc add dev $LAN_IF root handle 1: htb default 10" >> /etc/qos.rules
        echo "tc class add dev $LAN_IF parent 1: classid 1:1 htb rate ${BANDWIDTH}kbit" >> /etc/qos.rules
        echo "tc filter add dev $LAN_IF protocol ip parent 1:0 prio 1 handle 1 fw flowid 1:1" >> /etc/qos.rules

        echo "QoS configured with a bandwidth limit of ${BANDWIDTH} Kbps on the interface $LAN_IF"
        ;;
    
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

}

# Change FQDN Name

configure_local_dns_server() {

set -e

# Colors
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
NC="\e[0m"

echo -e "${CYAN}===================================================="
echo -e " 🖥️  Interactive DNS Server Installer with BIND9"
echo -e "====================================================${NC}"

# 1️⃣ Install BIND9 if not installed
if ! command -v named-checkconf &> /dev/null; then
    echo -e "${YELLOW}📦 Installing BIND9...${NC}"
    sudo apt update
    sudo apt install -y bind9 bind9utils bind9-doc
else
    echo -e "${GREEN}✔ BIND9 is already installed${NC}"
fi

# 2️⃣ Ask how many zones to configure
read -rp "👉 How many zones do you want to create? " ZONES

for ((i=1; i<=ZONES; i++)); do
    echo -e "\n${CYAN}=========================="
    echo -e " ⚙️  Zone configuration $i"
    echo -e "==========================${NC}"
    read -rp "➡️  Domain (e.g. mydomain.local): " DOMAIN
    read -rp "➡️  DNS server IP (e.g. 192.168.1.10): " SERVER_IP
    read -rp "➡️  Network for reverse zone (e.g. 192.168.1.0): " NETWORK

    ZONE_FILE="/etc/bind/db.${DOMAIN}"
    REV_ZONE_FILE="/etc/bind/db.${NETWORK}.${DOMAIN}"
    OCTET=$(echo $SERVER_IP | awk -F. '{print $4}')

    echo -e "${YELLOW}📄 Creating configuration files for $DOMAIN...${NC}"

    # 3️⃣ Add zone to named.conf.local
    sudo tee -a /etc/bind/named.conf.local > /dev/null <<EOF

zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};

zone "${NETWORK}.in-addr.arpa" {
    type master;
    file "$REV_ZONE_FILE";
};
EOF

    # 4️⃣ Create forward zone file
    sudo tee $ZONE_FILE > /dev/null <<EOF
;
; Forward zone for $DOMAIN
;
\$TTL    604800
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                         2         ; Serial
                    604800         ; Refresh
                     86400         ; Retry
                   2419200         ; Expire
                    604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMAIN.
ns1     IN      A       $SERVER_IP
www     IN      A       $SERVER_IP
EOF

    # 5️⃣ Create reverse zone file
    sudo tee $REV_ZONE_FILE > /dev/null <<EOF
;
; Reverse zone for $NETWORK
;
\$TTL    604800
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                         2         ; Serial
                    604800         ; Refresh
                     86400         ; Retry
                   2419200         ; Expire
                    604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMAIN.
$OCTET  IN      PTR     ns1.$DOMAIN.
$OCTET  IN      PTR     www.$DOMAIN.
EOF

    # 6️⃣ Verify zone configuration
    echo -e "${YELLOW}🔍 Checking zone files...${NC}"
    sudo named-checkzone $DOMAIN $ZONE_FILE
    sudo named-checkzone ${NETWORK}.in-addr.arpa $REV_ZONE_FILE
    echo -e "${GREEN}✔ Zone $DOMAIN configured successfully${NC}"
done

# 7️⃣ Restart service
echo -e "${YELLOW}🔄 Applying configuration...${NC}"
sudo named-checkconf
sudo systemctl restart bind9
sudo systemctl enable bind9

# 8️⃣ Usage instructions
echo -e "\n${CYAN}===================================================="
echo -e " ✅ All zones have been configured successfully"
echo -e "====================================================${NC}"
echo -e "${GREEN}👉 You can now test your DNS server with:${NC}"
echo -e "   dig @<SERVER_IP> www.<DOMAIN>"
echo -e "   dig @<SERVER_IP> ns1.<DOMAIN>"
echo -e "   nslookup www.<DOMAIN> <SERVER_IP>\n"

echo -e "${YELLOW}💡 Note:${NC} For other clients to use this DNS server, set its IP in their resolv.conf or network settings."


}

# Install samba server

install_samba_server() {

echo "---------------------------------------------------"
echo "----------- Configure Samba Server ----------------"
echo "---------------------------------------------------"
echo ""
# Upgrade system and the dependencias
echo "Upgrade System..."
apt update && apt upgrade -y

# Install Samba
echo "Install Samba..."
apt install samba -y

echo "==============================================================================="
echo ""
# Ask to the user the share folder`s name
read -p "What do you want to call the shared folder? " carpeta_compartida

# Ask to the user if the shared folder will be writable or not
read -p "Do you want the folder to be writable? (y/n): " escribible

# Create the shared folder
ruta_carpeta="/srv/samba/$carpeta_compartida"
mkdir -p "$ruta_carpeta"

# Apply Permissions to the shared folder
chmod 770 "$ruta_carpeta"  #Allows the owner and group to have all permissions, but denies access to others. 
chown nobody:nogroup "$ruta_carpeta"

# Configure Samba
SMB_CONF="/etc/samba/smb.conf"
echo "Configuring Samba..."

# Apply config to the smb.conf file
{
    echo ""
    echo "[$carpeta_compartida]"
    echo "   path = $ruta_carpeta"
    echo "   available = yes"
    echo "   valid users = @sambashare"
    echo "   read only = no"
    echo "   browsable = yes"
    echo "   public = yes"
    if [[ "$escribible" == "y" || "$escribible" == "Y" ]]; then
        echo "   writable = yes"
    else
        echo "   writable = no"
    fi
} >> "$SMB_CONF"

# Esto a lo mejor se cambia
# Create a group for the samba users
groupadd sambashare

# Create a Samba user (if it does not exist)
read -p "Input the Username for Samba: " usuario
useradd -m -G sambashare "$usuario"
echo "$usuario:1234" | chpasswd  # Establecer una contraseña por defecto (puede cambiarse)
smbpasswd -a "$usuario"  # Agregar el usuario a Samba
smbpasswd -e "$usuario"  # Habilitar el usuario en Samba

#Restart Samba service
systemctl restart smbd
systemctl enable smbd

# Verify Samba Service
if systemctl is-active --quiet smbd; then
    echo "The Samba service is runs correctly."
else
    echo "Samba Server not runs."
    exit 1
fi

# Show the shared folder and configuration
echo "====================================================================================="
echo "======= The shared folder '$carpeta_compartida' has been shared correctly. =========="
echo "============= Shared Folder: //$HOSTNAME/$carpeta_compartida ========================"
echo "====================================================================================="
}

backup_or_restore_backup_from_ssh_server() {

# Log file
LOG_FILE="$HOME/backup.log"

# Function to create a backup of a directory
backup() {
    read -r -p "Enter the directory to back up: " BACKUP_DIR
    read -r -p "Enter the local folder to store the backup (If it doesn't exist, it will be created automatically): " DEST_DIR

    if [ ! -d "$BACKUP_DIR" ]; then
        echo "Error: The directory '$BACKUP_DIR' does not exist."
        exit 1
    fi

    mkdir -p "$DEST_DIR"

    BACKUP_FILE="$DEST_DIR/backup_$(date +'%Y%m%d_%H%M%S').tar.xz"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Starting backup..." | tee -a "$LOG_FILE"
    tar -cJf "$BACKUP_FILE" "$BACKUP_DIR"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Backup created: $BACKUP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error creating the backup" | tee -a "$LOG_FILE"
        exit 1
    fi

    read -r -p "Do you want to send the backup to a remote server? (y/n): " RESPONSE
    if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
        send_to_remote "$BACKUP_FILE"
    fi
}

# Function to create a database backup
backup_database() {
    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter database name: " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST
    read -r -p "Enter the local folder to store the backup: " DEST_DIR

    DB_HOST=${DB_HOST:-localhost}
    mkdir -p "$DEST_DIR"

    BACKUP_FILE="$DEST_DIR/db_backup_${DB_NAME}_$(date +'%Y%m%d_%H%M%S').sql.gz"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Starting database backup..." | tee -a "$LOG_FILE"
    mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" | gzip > "$BACKUP_FILE"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database backup created: $BACKUP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error creating the database backup" | tee -a "$LOG_FILE"
        exit 1
    fi

    read -r -p "Do you want to send the backup to a remote server? (y/n): " RESPONSE
    if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
        send_to_remote "$BACKUP_FILE"
    fi
}

# Function to restore a database from a local backup
restore_database() {
    read -r -p "Enter the path to the .sql.gz backup file: " BACKUP_FILE
    if [ ! -f "$BACKUP_FILE" ]; then
        echo "Error: File '$BACKUP_FILE' does not exist."
        exit 1
    fi

    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter the name of the database to restore into (must already exist): " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST

    DB_HOST=${DB_HOST:-localhost}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring database from backup..." | tee -a "$LOG_FILE"
    gunzip -c "$BACKUP_FILE" | mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database '$DB_NAME' successfully restored." | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the database." | tee -a "$LOG_FILE"
        exit 1
    fi
}

# Function to restore a database from a remote server
restore_database_from_remote() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the .sql.gz file on the remote server: " REMOTE_FILE
    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter the target database name (must already exist): " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST

    REMOTE_PORT=${REMOTE_PORT:-22}
    DB_HOST=${DB_HOST:-localhost}

    TEMP_FILE="$HOME/$(basename "$REMOTE_FILE")"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading database backup from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$TEMP_FILE"

    if [ $? -ne 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the file" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring database from $TEMP_FILE..." | tee -a "$LOG_FILE"
    gunzip < "$TEMP_FILE" | mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database successfully restored from $TEMP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the database" | tee -a "$LOG_FILE"
    fi
}

# Function to send a file to a remote server
send_to_remote() {
    FILE_TO_SEND="$1"
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path on the remote server to store the file: " REMOTE_PATH

    REMOTE_PORT=${REMOTE_PORT:-22}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Checking connection to $REMOTE_HOST on port $REMOTE_PORT..." | tee -a "$LOG_FILE"
    if ! nc -z "$REMOTE_HOST" "$REMOTE_PORT"; then
        echo -e "${RED}${BOLD}$(date +"%Y-%m-%d %H:%M:%S") - Error: Could not connect to $REMOTE_HOST on port $REMOTE_PORT." | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Sending file to $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$FILE_TO_SEND" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - File successfully sent" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}${BOLD}$(date +"%Y-%m-%d %H:%M:%S") - Error sending the file" | tee -a "$LOG_FILE"
    fi
}

# Function to restore a file-based backup from a remote server
restore_backup() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the backup file on the remote server: " REMOTE_FILE
    read -r -p "Enter the folder where the backup should be restored: " RESTORE_DIR

    REMOTE_PORT=${REMOTE_PORT:-22}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading backup from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$HOME"

    if [ $? -eq 0 ]; then
        BACKUP_FILENAME=$(basename "$REMOTE_FILE")
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Backup successfully downloaded: $HOME/$BACKUP_FILENAME" | tee -a "$LOG_FILE"

        echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring backup to $RESTORE_DIR..." | tee -a "$LOG_FILE"
        mkdir -p "$RESTORE_DIR"
        tar -xJf "$HOME/$BACKUP_FILENAME" -C "$RESTORE_DIR"

        if [ $? -eq 0 ]; then
            echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoration completed in $RESTORE_DIR" | tee -a "$LOG_FILE"
        else
            echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the backup" | tee -a "$LOG_FILE"
        fi
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the backup" | tee -a "$LOG_FILE"
    fi
}

# Function to download a file from a remote server
download_file() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the file on the remote server: " REMOTE_FILE
    read -r -p "Enter the local folder to save the file: " LOCAL_DIR

    REMOTE_PORT=${REMOTE_PORT:-22}
    mkdir -p "$LOCAL_DIR"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading file from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$LOCAL_DIR"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - File successfully downloaded to $LOCAL_DIR" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the file" | tee -a "$LOG_FILE"
    fi
}

# Main menu
echo "Select an option:"
echo "1) Create a backup of a directory"
echo "2) Restore a backup"
echo "3) Download a file from a remote server"
echo "4) Create a database backup"
echo "5) Restore a database from local backup"
echo "6) Restore a database from remote server"
read -r -p "Enter the option number: " OPTION

case $OPTION in
    1) backup ;;
    2) restore_backup ;;
    3) download_file ;;
    4) backup_database ;;
    5) restore_database ;;
    6) restore_database_from_remote ;;
    *) echo "Invalid option. Exiting..." ;;
esac

}

# Install and configure SFTP Server

install_ftp_server_over_ssh() {


# Prompt user for input

echo "-----------------------------------------------------------------------------------"
read -p "Enter SFTP group name: " SFTP_GROUP
read -p "Enter SFTP username: " SFTP_USER
read -p "Enter SFTP base directory (e.g., /sftp/$SFTP_USER): " SFTP_DIR
read -s -p "Enter password for $SFTP_USER: " PASSWORD
echo ""
echo "-----------------------------------------------------------------------------------"

# Validate input
if [[ -z "$SFTP_GROUP" || -z "$SFTP_USER" || -z "$PASSWORD" ]]; then
    echo "Error: All fields are required. Please restart the script and provide valid inputs."
    exit 1
fi
SFTP_DIR="${SFTP_DIR:-/sftp/$SFTP_USER}"

# Install OpenSSH if not installed
echo "Installing OpenSSH Server..."
apt update && apt install -y openssh-server || { echo "Failed to install OpenSSH Server"; exit 1; }

# Create SFTP group if it doesn't exist
if ! getent group "$SFTP_GROUP" >/dev/null; then
    echo "Creating group $SFTP_GROUP..."
    groupadd "$SFTP_GROUP" || { echo "Failed to create group"; exit 1; }
else
    echo "Group $SFTP_GROUP already exists."
fi

# Create user without SSH access
if id "$SFTP_USER" &>/dev/null; then
    echo "User $SFTP_USER already exists."
else
    echo "Creating user $SFTP_USER..."
    useradd -m -d "$SFTP_DIR" -s /usr/sbin/nologin -G "$SFTP_GROUP" "$SFTP_USER" || { echo "Failed to create user"; exit 1; }
    echo "$SFTP_USER:$PASSWORD" | chpasswd
fi

# Set permissions
echo "Setting permissions for the SFTP directory..."
mkdir -p "$SFTP_DIR/upload"
chown root:root "$SFTP_DIR"
chmod 755 "$SFTP_DIR"
chown "$SFTP_USER:$SFTP_GROUP" "$SFTP_DIR/upload"
chmod 750 "$SFTP_DIR/upload"

# Configure SSH for SFTP
echo "Configuring SSH for SFTP..."
SSHD_CONFIG="/etc/ssh/sshd_config"
if ! grep -q "Match Group $SFTP_GROUP" "$SSHD_CONFIG"; then
    echo "Match Group $SFTP_GROUP
    ChrootDirectory $SFTP_DIR
    ForceCommand internal-sftp
    X11Forwarding no
    AllowTcpForwarding no" >> "$SSHD_CONFIG"
else
    echo "SFTP configuration for group $SFTP_GROUP already exists in $SSHD_CONFIG."
fi

# Restart SSH service
echo "Restarting SSH service..."
systemctl restart ssh || { echo "Failed to restart SSH service"; exit 1; }

# Final message
echo -e "${GREEN}SFTP setup complete. User $SFTP_USER can now connect using SFTP.${NC}"
echo -e "${GREEN}-----------------------------------------------------------------------------------${NC}"
echo -e "${GREEN}To connect using FileZilla:${NC}"
echo -e "${GREEN}- Host: Your server's IP address${NC}"
echo -e "${GREEN}- Username: $SFTP_USER${NC}"
echo -e "${GREEN}- Password: (the one you set)${NC}"
echo -e "${GREEN}- Default Port: 22${NC}"
echo -e "${GREEN}- Protocol: SFTP - SSH File Transfer Protocol${NC}"
echo -e "${GREEN}-----------------------------------------------------------------------------------${NC}"

}
# function to install Apache, PHP, MySQL server, MySQL client, Certbot, Bind9, Nextcloud, and required configurations to set up the server.

nextcloud_install(){

# Interactive menu for capturing values

echo -e "${BLUE}${BOLD}=================================================================${NC}"
    echo -e "${CYAN}${BOLD}================== Nextcloud Installation =======================${NC}"
    echo -e "${BLUE}${BOLD}=================================================================${NC}"
    echo -e "${BLUE}${BOLD}=================================================================${NC}"
    echo -e "${CYAN}${BOLD}================= by Jaime Galvez Martinez  =====================${NC}"
    echo -e "${CYAN}${BOLD}================ GitHub: Jaime Galvez Martinez ==================${NC}"
    echo -e "${BLUE}${BOLD}=================================================================${NC}"
    echo ""

# Check if the user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." 
    exit 1
fi

# Prompt for Nextcloud version
read -p "Which version of Nextcloud would you like to install? (Default: 32.0.0): " NEXTCLOUD_VERSION
NEXTCLOUD_VERSION=${NEXTCLOUD_VERSION:-"32.0.0"}  # Default version if user inputs nothing

# Prompt for database name
read -p "Enter the database name (default: nextcloud_db): " DB_NAME
DB_NAME=${DB_NAME:-"nextcloud_db"}

read -p "Input Database User (Default nextcloud_user): " DB_USER
DB_USER=${DB_USER:-"nextcloud_user"}

while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo "Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo "Error: Passwords do not match. Please try again."
    fi
done

# Prompt for Nextcloud installation path
read -p "Enter the Nextcloud installation path (default: /var/www/html/nextcloud): " NEXTCLOUD_PATH
NEXTCLOUD_PATH=${NEXTCLOUD_PATH:-"/var/www/html/nextcloud"}

# Promt Nextcloud Data Directory
 read -p "Enter the directory where Nextcloud will store data (default: /var/nextcloud/data): " DATA_DIRECTORY
 DATA_DIRECTORY=${DATA_DIRECTORY:-"/var/nextcloud/data"}

# Prompt for domain or IP
read -p "Enter the domain or IP to access Nextcloud: " DOMAIN

# Configuration confirmation
echo -e "${GREEN}${BOLD}========================================================${NC}"
echo -e "${GREEN}${BOLD}============ Configuration Summary =====================${NC}"
echo -e "${GREEN}${BOLD}========================================================${NC}"
echo -e "${GREEN}${BOLD}Nextcloud Version:     ${BOLD}$NEXTCLOUD_VERSION${NC}"
echo -e "${GREEN}${BOLD}Database:              ${BOLD}$DB_NAME${NC}"
echo -e "${GREEN}${BOLD}Database User:         ${BOLD}$DB_USER${NC}"
echo -e "${GREEN}${BOLD}Installation Path:     ${BOLD}$NEXTCLOUD_PATH${NC}"
echo -e "${GREEN}${BOLD}Data Directory:        ${BOLD}$DATA_DIRECTORY${NC}"
echo -e "${GREEN}${BOLD}Domain or IP:          ${BOLD}$DOMAIN${NC}"
echo -e "${GREEN}${BOLD}========================================================${NC}"


echo -e "Do you want to proceed with the installation? (y/n): "

# Confirmation to proceed with the installation
read -n 1 CONFIRM
echo
if [[ "$CONFIRM" != [yY] ]]; then
    echo -e "${RED}${BOLD}Installation canceled."
    exit 1
fi

# Rest of the script for Nextcloud installation
# Update and upgrade packages
echo "========================================================"
echo "=============== Updating system... ====================="
echo "========================================================"
apt update && apt upgrade -y

# Install Apache
echo -e "${GREEN}Installing Apache..."
apt install apache2 -y
ufw allow 'Apache Full'

# Install MariaDB
echo -e "${GREEN}Installing MariaDB..."
apt install mariadb-server -y

# Create database and user for Nextcloud
echo -e "${GREEN}Configuring database for Nextcloud..."
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Setup root user
# mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"

# Install PHP and necessary modules
echo -e "${GREEN}Installing PHP  and modules..."
sudo apt install -y php php-gd php-json php-mbstring php-curl php-xml php-zip php-mysql php-intl php-bz2 php-imagick php-fpm php-cli libapache2-mod-php php-sqlite3 php-pgsql

 # Create Data Directory
    echo -e "${GREEN}Creating Data Directory..."
    if [[ ! -d "$DATA_DIRECTORY" ]]; then
        mkdir -p "$DATA_DIRECTORY"
        echo "Data directory created at: $DATA_DIRECTORY"
    else
        echo "Data directory already exists: $DATA_DIRECTORY"
    fi
    chown -R www-data:www-data "$DATA_DIRECTORY"
    chmod -R 750 "$DATA_DIRECTORY"
    
# Configure PHP for Nextcloud
echo "Configuring PHP..."
PHP_INI_PATH=$(php -r "echo php_ini_loaded_file();")
sed -i "s/memory_limit = .*/memory_limit = 512M/" "$PHP_INI_PATH"
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 512M/" "$PHP_INI_PATH"
sed -i "s/post_max_size = .*/post_max_size = 512M/" "$PHP_INI_PATH"
sed -i "s/max_execution_time = .*/max_execution_time = 300/" "$PHP_INI_PATH"

# Download and configure Nextcloud
echo "Downloading Nextcloud..."
wget https://download.nextcloud.com/server/releases/nextcloud-${NEXTCLOUD_VERSION}.tar.bz2
tar -xjf nextcloud-${NEXTCLOUD_VERSION}.tar.bz2
mv nextcloud $NEXTCLOUD_PATH
chown -R www-data:www-data $NEXTCLOUD_PATH
chmod -R 755 $NEXTCLOUD_PATH

# Enable Nextcloud configuration and necessary Apache modules
a2ensite nextcloud.conf
a2enmod rewrite headers env dir mime setenvif
systemctl restart apache2

# Finish
echo "Nextcloud installation complete."
echo "Please access http://$DOMAIN/nextcloud to complete setup in the browser."
}

moodle_install() {


    # Script that configure moodle 

    echo -e "${GREEN}${BOLD}=============================================="
    echo -e "${GREEN}${BOLD}============== MOODLE SETUP =================="
    echo -e "${GREEN}${BOLD}=============================================="
}


# Prompt for database name
read -p "Enter the database name (default: moodle_db): " DB_NAME
DB_NAME=${DB_NAME:-"moodle_db"}

# Prompt for database user
read -p "Enter the database user name (default: moodle_user): " DB_USER
DB_USER=${DB_USER:-"moodle_user"}

read -p "What will be your data directory? (default: /var/www/moodledata): " data_directory
data_directory=${data_directory:-"/var/www/moodledata"}



# Compare passwords
while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

# Prompt Again for database password
    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    # Prompt for database password
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo -e "${GREEN}${BOLD}Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo -e "${RED}${BOLD}Error: Passwords do not match. Please try again."
    fi
done

# Prompt for installation path
read -p "Enter the moodle installation path (default: /var/www/html/moodle): " MOODLE_PATH
MOODLE_PATH=${MOODLE_PATH:-"/var/www/html/moodle"}


# Prompt for domain or IP
read -p "Enter the domain or IP to access Moodle: " DOMAIN


# Colores
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m' # Sin color

# Configuration confirmation
echo -e ""
echo -e "${GREEN}${BOLD}========================================================${NC}"
echo -e "${GREEN}${BOLD}============ Configuration Summary ====================${NC}"
echo -e "${GREEN}${BOLD}========================================================${NC}"
echo -e ""

echo -e "${GREEN}Database: ${BOLD}$DB_NAME${NC}"
echo -e "${GREEN}Database User: ${BOLD}Root${NC}"
echo -e "${GREEN}Installation Path: ${BOLD}$MOODLE_PATH${NC}"
echo -e "${GREEN}Domain or IP: ${BOLD}$DOMAIN${NC}"
echo -e "${GREEN}Data Directory: ${BOLD}$data_directory${NC}"
echo ""

# Confirmation to proceed with the installation
read -rp "${GREEN}Do you want to proceed with the installation? (y/n): ${NC}" CONFIRM
echo

if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
    echo -e "${RED}Installation canceled.${NC}"
    exit 1
fi

# Rest of the script for Moodle installation
# Update and upgrade packages
echo "========================================================"
echo "=============== Updating system... ====================="
echo "========================================================"
apt update && apt upgrade -y

# Install Apache
echo "Installing Apache..."
apt install apache2 -y
ufw allow 'Apache Full'

# Install MariaDB
echo "Installing MariaDB..."
apt install mariadb-server -y
mysql_secure_installation

# Create database and user for moodle
echo "Configuring database for Moodle.."
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Install PHP and necessary modules
echo "Installing PHP  and modules..."
sudo apt install -y php php-gd php-json php-mbstring php-curl php-xml php-zip php-mysql php-intl php-bz2 php-imagick php-fpm php-cli libapache2-mod-php php-sqlite3 php-pgsql git
sudo apt update
sudo apt install php-curl php-zip

# Configure PHP
echo "Configuring PHP..."
PHP_INI_PATH=$(php -r "echo php_ini_loaded_file();")
sed -i "s/memory_limit = .*/memory_limit = 512M/" "$PHP_INI_PATH"
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 512M/" "$PHP_INI_PATH"
sed -i "s/post_max_size = .*/post_max_size = 512M/" "$PHP_INI_PATH"
sed -i "s/max_execution_time = .*/max_execution_time = 300/" "$PHP_INI_PATH"


# Download and configure Moodle
echo "Downloading Moodle..."
sudo apt install git
sudo apt install php-xml
sudo apt install php-mbstring
sudo apt install php-mysqli

git clone https://github.com/moodle/moodle.git
mv moodle $MOODLE_PATH
chown -R www-data:www-data $MOODLE_PATH
chmod -R 755 $MOODLE_PATH

# Make the Moodle data directory

mkdir $data_directory
chown -R www-data:www-data $data_directory
chmod -R 755 $data_directory

# Restart Apache web server
systemctl restart apache2

# Finish
echo "---------------------------------------------------------------------"
echo "Moodle installation complete."
echo "Please access http://$DOMAIN/moodle to complete setup in the browser."
echo "---------------------------------------------------------------------"
}

wp_install() {

# Enable strict mode: stop script execution if any command fails
set -e

echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo -e "${CYAN}${BOLD}====================== Latest Wordpress Install ===================${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo -e "${CYAN}${BOLD}==================== by: Jaime Galvez Martinez ====================${NC}"
echo -e "${CYAN}${BOLD}=================== GitHub: JaimeGalvezMartinez ===================${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo ""    

# Define variables
WP_URL="https://wordpress.org/latest.tar.gz"
WP_ARCHIVE="latest.tar.gz"
WP_DIR="/var/www/html/wordpress"

# Ask user for database details
read -p "Enter the database name: " DB_NAME
read -p "Enter the database username: " DB_USER
read -s -p "Enter the database password: " DB_PASSWORD

# Prompt again to verify password
read -sp "Re-enter the password to verify: " DB_PASSWORD2
echo


while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo "Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo "Error: Passwords do not match. Please try again."
    fi
done

# Display installation details
echo ""
echo "🔹 WordPress will be installed with the following settings:"
echo "   📂 Download and extraction in: $(pwd)"
echo "   🚀 Installation in: $WP_DIR"
echo "   💾 Database name: $DB_NAME"
echo "   👤 Database user: $DB_USER"
echo ""
read -p "❓ Do you want to continue? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "❌ Installation canceled."
    exit 1
fi

# Update system
echo "🔄 Updating packages..."
sudo apt update && sudo apt upgrade -y

# Install Apache
echo "🌍 Installing Apache..."
sudo apt install -y apache2

echo "💾 Installing MariaDB..."
sudo apt update
sudo apt install -y mariadb-server
sudo systemctl enable --now mariadb

# Configure MARIADB (create DB and user)
echo "🛠 Configuring Mariadb..."
sudo mysql -e "CREATE DATABASE $DB_NAME;"
sudo mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
sudo mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Install PHP and required modules
echo "🐘 Installing PHP and modules..."
sudo apt install -y php libapache2-mod-php php-mysql php-curl php-gd php-mbstring php-xml php-xmlrpc php-soap php-intl php-zip

# Download and extract WordPress in the script's directory
echo "⬇ Downloading WordPress in $(pwd)..."
wget -q $WP_URL -O $WP_ARCHIVE
tar -xzf $WP_ARCHIVE

# Move WordPress to /var/www/html
echo "📂 Moving WordPress to $WP_DIR..."
sudo mv wordpress $WP_DIR

# Set permissions
echo "🔑 Setting permissions..."
sudo chown -R www-data:www-data $WP_DIR
sudo chmod -R 755 $WP_DIR

# Configure wp-config.php automatically
echo "⚙ Configuring WordPress..."
sudo cp $WP_DIR/wp-config-sample.php $WP_DIR/wp-config.php
sudo sed -i "s/database_name_here/$DB_NAME/" $WP_DIR/wp-config.php
sudo sed -i "s/username_here/$DB_USER/" $WP_DIR/wp-config.php
sudo sed -i "s/password_here/$DB_PASS/" $WP_DIR/wp-config.php

echo "------------------------------------------------------------"
echo "-----------------------------------------"
echo ""
echo "   💾 database name: $DB_NAME"
echo "   👤 database user: $DB_USER"
echo ""
echo "-----------------------------------------"
echo "------------------------------------------------------------"

# Cleanup
echo "🧹 Removing installation archive..."
rm -f $WP_ARCHIVE

echo "✅ Installation complete. Access http://your-server/wordpress to finish WordPress setup."

}



configure_prometheus () {


# Variables
PROM_VERSION="2.51.2"
PROM_USER="prometheus"
PROM_DIR="/etc/prometheus"
PROM_DATA_DIR="/var/lib/prometheus"
PROM_BIN_DIR="/usr/local/bin"
NODE_EXPORTER_VERSION="1.7.0"

install_prometheus() {
    echo "Updating system and installing dependencies..."
    apt update && apt install -y wget tar || { echo "Failed to install dependencies"; exit 1; }
    
    echo "Creating Prometheus user..."
    useradd --no-create-home --shell /bin/false $PROM_USER
    
    echo "Creating directories..."
    mkdir -p $PROM_DIR $PROM_DATA_DIR
    chown $PROM_USER:$PROM_USER $PROM_DIR $PROM_DATA_DIR
    
    echo "Downloading Prometheus v$PROM_VERSION..."
    wget https://github.com/prometheus/prometheus/releases/download/v$PROM_VERSION/prometheus-$PROM_VERSION.linux-amd64.tar.gz -O /tmp/prometheus.tar.gz
    
    echo "Extracting Prometheus..."
    tar -xzf /tmp/prometheus.tar.gz -C /tmp/
    cd /tmp/prometheus-$PROM_VERSION.linux-amd64/
    
    echo "Installing Prometheus binaries..."
    mv prometheus promtool $PROM_BIN_DIR/
    chown $PROM_USER:$PROM_USER $PROM_BIN_DIR/prometheus $PROM_BIN_DIR/promtool
    
    echo "Setting up configuration..."
    mv prometheus.yml $PROM_DIR/
    chown $PROM_USER:$PROM_USER $PROM_DIR/prometheus.yml
    
    echo "Creating Prometheus systemd service..."
    cat <<EOF > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus Monitoring System
Wants=network-online.target
After=network-online.target

[Service]
User=$PROM_USER
Group=$PROM_USER
Type=simple
ExecStart=$PROM_BIN_DIR/prometheus \\
    --config.file=$PROM_DIR/prometheus.yml \\
    --storage.tsdb.path=$PROM_DATA_DIR \\
    --web.listen-address=0.0.0.0:9090 \\
    --storage.tsdb.retention.time=15d

[Install]
WantedBy=multi-user.target
EOF
    
    echo "Starting Prometheus service..."
    systemctl daemon-reload
    systemctl enable --now prometheus.service
    echo "Prometheus installation complete! Running on port 9090"
    echo "Directory of prometheus: $PROM_DIR"
}

install_node_exporter() {


set -e  # Stop script on error

# Update the system
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y wget tar curl

# Get the latest Node Exporter version dynamically
NODE_EXPORTER_VERSION=$(curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest | grep -oP '"tag_name": "v\K[0-9.]+')

# Check if Node Exporter is already installed
if command -v node_exporter &> /dev/null; then
    echo "Node Exporter is already installed. Skipping installation."
    exit 0
fi

# Download Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v$NODE_EXPORTER_VERSION/node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz

# Extract the downloaded file
tar -xvzf node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz

# Move the binary to /usr/local/bin
sudo mv node_exporter-$NODE_EXPORTER_VERSION.linux-amd64/node_exporter /usr/local/bin/

# Remove downloaded files to save space
rm -rf node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz node_exporter-$NODE_EXPORTER_VERSION.linux-amd64

# Ensure the user exists
if ! id "node_exporter" &>/dev/null; then
    sudo useradd -rs /bin/false node_exporter
fi

# Create a systemd service for Node Exporter
cat << EOF | sudo tee /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=default.target
EOF

# Reload systemd daemon and enable the service
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter

# Check if Node Exporter is running
sudo systemctl status node_exporter --no-pager

echo "-----------------------------------"
echo " ✅ Node Exporter installed and running on port 9100"
echo "-----------------------------------"

}

add_node_exporter_to_prometheus() {
    read -p "Enter the IP address of the Node Exporter: " NODE_EXPORTER_IP
    read -p "Enter the job name for Node Exporter: " JOB_NAME
    echo "Adding Node Exporter job to prometheus.yml..."
    cat <<EOF >> $PROM_DIR/prometheus.yml

  - job_name: '$JOB_NAME'
    static_configs:
      - targets: ['$NODE_EXPORTER_IP:9100']
EOF
    echo "Node Exporter job '$JOB_NAME' added to Prometheus configuration. Restarting Prometheus..."
    systemctl restart prometheus.service
}

# Menu for installation
echo "--------------------------------------------------"
echo "Choose an option:"
echo "1) Install Prometheus"
echo "2) Install Node Exporter"
echo "3) Add Node Exporter to Prometheus"
echo "4) Exit"
echo "--------------------------------------------------"
read -p "Enter your choice: " CHOICE

case $CHOICE in
    1)
        install_prometheus
        ;;
    2)
        install_node_exporter
        ;;
    3)
        add_node_exporter_to_prometheus
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac


# Final message
echo "--------------------------------------------------"
echo "Installation process complete!"
echo "--------------------------------------------------"

}
configure_graphana () {

# Starting message
echo "Starting Grafana installation."

# Update system repositories
echo "Updating system repositories..."
apt update && apt upgrade -y

# Install necessary dependencies
echo "Installing necessary dependencies..."
apt install -y software-properties-common wget

# Add the official Grafana repository
echo "Adding the official Grafana repository..."
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | tee -a /etc/apt/sources.list.d/grafana.list

# Update repositories after adding Grafana
echo "Updating repositories after adding Grafana..."
apt update

# Install Grafana
echo "Installing Grafana..."
apt install -y grafana

# Verify installation
if [ $? -eq 0 ]; then
    echo "Grafana installed successfully."
else
    echo "There was a problem installing Grafana. Please check the errors."
    exit 1
fi

# Start and enable the Grafana service
echo "Starting the Grafana service..."
systemctl start grafana-server
systemctl enable grafana-server

# Verify the status of Grafana
echo "Checking the Grafana service status..."
systemctl status grafana-server --no-pager | grep -i 'active'

# Final message
echo "----------------------------------------------------------------------------------"
echo "Grafana has been successfully installed on the server!"
echo "You can access the Grafana web interface at http://<YOUR-SERVER-IP>:3000."
echo "Default username: admin"
echo "Default password: admin"

# Warning message for first login
echo "Remember to change the password on the first login."
echo "-----------------------------------------------------------------------------------"

}

setup_virtualhost () {


# Ask user for domain name
read -p "Enter your domain name: " DOMAIN

# Ask user for document root
read -p "Enter your document root (default: /var/www/html/$DOMAIN): " DOC_ROOT
DOC_ROOT=${DOC_ROOT:-/var/www/html/$DOMAIN}

# Ask user if they want SSL
read -p "Do you want to enable SSL? (y/n): " ENABLE_SSL
CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN.conf
SSL_CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN-ssl.conf

sudo chown -R $USER:$USER $DOC_ROOT
sudo chmod -R 755 /var/www/html

# Create virtual host configuration
sudo tee $CONFIG_FILE > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@$DOMAIN
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot $DOC_ROOT
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
</VirtualHost>
EOF

# Enable SSL if chosen
if [ "$ENABLE_SSL" == "y" ]; then
    sudo tee $SSL_CONFIG_FILE > /dev/null <<EOF
<VirtualHost *:443>
    ServerAdmin webmaster@$DOMAIN
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot $DOC_ROOT
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/$DOMAIN.crt
    SSLCertificateKeyFile /etc/ssl/private/$DOMAIN.key
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-ssl-access.log combined
</VirtualHost>
EOF
    sudo a2enmod ssl
    sudo a2ensite $DOMAIN-ssl.conf
fi

# Enable the site and reload Apache
sudo a2ensite $DOMAIN.conf
sudo systemctl reload apache2

# Output success message
echo "Virtual host for $DOMAIN has been created successfully!"
if [ "$ENABLE_SSL" == "y" ]; then
    echo "SSL has been enabled for $DOMAIN. Make sure to place your certificate files in /etc/ssl/certs/ and /etc/ssl/private/."
fi
}

network_scan() {

# Function to scan the local network and display connected devices
scan_network() {

      #show interfaces
            echo ""
            echo "++++++++++++++++++++++++++++++++"
            echo "Available interfaces"
            echo "++++++++++++++++++++++++++++++++"
            INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
            echo "$INTERFACES"
            echo "++++++++++++++++++++++++++++++++"
            echo ""
            read -p "What interface wwould use to scan: " interface

    echo "Scanning devices on the local network using interface $interface..."
    echo ""

    # Use arp-scan to get connected devices
    if command -v arp-scan > /dev/null 2>&1; then
        sudo arp-scan --interface="$interface" --localnet
    else
        echo "arp-scan is not installed. Installing it..."
        sudo apt update && sudo apt install -y arp-scan
        sudo arp-scan --interface="$interface" --localnet
    fi
}

# Interactive menu
while true; do
    echo ""
    echo "--- Connected Devices Scan ---"
    echo "1. Scan the local network"
    echo "2. Exit"
    read -p "Select an option: " option

    case $option in
        1) scan_network ;;
        2) echo "Exiting..."; exit 1 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done
}

show_system_info () {
# Show a welcome message
echo "*******************************************************************"
echo "****** MONITORING CPU, MEMORY, DISK AND NETWORK INFORMATION *******"
echo "*******************************************************************"

echo "To run this script successfully, please ensure 'curl' is installed. You can install it using: 'snap install curl' or 'apt install curl'"
echo

# Function to get the hostname
get_HOSTNAME() {
    HOSTNAME=$(cat /etc/hostname)
}

# Function to get CPU usage
get_cpu_usage() {
    echo "CPU USAGE:"
    top -bn1 | grep "Cpu(s)" | awk '{printf "CPU in use: %.2f%%\n", $2 + $4}'
}

# Function to get memory usage in GB
get_memory_usage() {
    echo "MEMORY USAGE:"
    free -m | grep Mem | awk '{printf "Memory used: %.2fGB of %.2fGB\n", $3/1024, $2/1024}'
}

# Function to get disk usage
get_disk_usage() {
    echo "DISK USAGE:"
    df -h / | grep / | awk '{print "Disk usage: " $5 " (" $3 " used of " $2 ")"}'
}

# Function to get swap memory usage
get_swap_usage() {
    echo "SWAP USAGE:"
    free -m | grep Swap | awk '{printf "Swap used: %.2fGB of %.2fGB\n", $3/1024, $2/1024}'
}

# Function to get the network interface in use
get_network_interface() {
    interfaz=$(ip route | grep '^default' | awk '{print $5}')
    if [[ -z "$interfaz" ]]; then
        echo "A network interface could not be detected."
        return 1
    fi
    echo "Your network interface is: $interfaz"
}

# Function to get local IP
get_local_ip() {
    echo "LOCAL IP:"
    hostname -I
}

# Function to get MAC address
get_DIR_MAC() {
    echo "MAC ADDRESS:"
    interfaz=$(ip route | grep '^default' | awk '{print $5}')
    cat /sys/class/net/$interfaz/address
}

# Function to get the default gateway
get_DEFAULT_GATEWAY() {
    echo "DEFAULT GATEWAY:"
    ip route show default
}

# Function to get the public IP
get_public_ip() {
    echo "PUBLIC IP:"
    PUBLIC_IP=$(curl -s ifconfig.me)
    if [[ -n "$PUBLIC_IP" ]]; then
        echo "Public IP: $PUBLIC_IP"
    else
        echo "Could not obtain your Public IP Address. Check your Internet connection."
    fi
}

# Function to check internet connection
get_INTERNET_CONNECTION() {
    echo "INTERNET CONNECTION:"
    var=$(curl -s --head http://www.google.com | head -n 1)
    if [[ $var == *"200 OK"* ]]; then
        echo "Internet Connection: Active"
    else
        echo "No internet connection detected. Please check your network adapter and rerun the script."
    fi
}

# Get system information
echo "-----------------------------------"
echo "The Hostname of the system is: $HOSTNAME"
echo "-----------------------------------"
get_cpu_usage
echo "-----------------------------------"
get_memory_usage
echo "-----------------------------------"
get_disk_usage
echo "-----------------------------------"
get_swap_usage
echo "-----------------------------------"
get_network_interface
echo "-----------------------------------"
get_local_ip
echo "-----------------------------------"
get_DIR_MAC
echo "-----------------------------------"
get_DEFAULT_GATEWAY
echo "-----------------------------------"
get_public_ip
echo "-----------------------------------"
get_INTERNET_CONNECTION
echo "-----------------------------------"


} 

# Función para gestionar Certbot (instalar, ver, eliminar)
manage_certbot() {
  while true; do
    clear
    echo "=== Certbot SSL Certificate Manager ==="
    echo "1) Install SSL certificate"
    echo "2) Show existing certificates"
    echo "3) Delete SSL certificate"
    echo "4) Back to main menu"
    echo "======================================="
    read -p "Select an option [1-4]: " choice

    case $choice in
      1)
        read -p "Enter the domain for the SSL certificate: " domain
        read -p "Enter your email address: " email

        echo "Updating repositories and upgrading system..."
        apt update && apt upgrade -y || { echo "Failed to update system"; return; }

        echo "Installing Certbot..."
        apt install -y certbot || { echo "Failed to install Certbot"; return; }

        echo "Select your web server:"
        echo "1) Apache"
        echo "2) Nginx"
        read -p "Choice [1-2]: " web_server

        case $web_server in
          1)
            apt install -y python3-certbot-apache || { echo "Failed to install Apache plugin"; return; }
            certbot --apache -d "$domain" --email "$email" --agree-tos --no-eff-email
            ;;
          2)
            apt install -y python3-certbot-nginx || { echo "Failed to install Nginx plugin"; return; }
            certbot --nginx -d "$domain" --email "$email" --agree-tos --no-eff-email
            ;;
          *)
            echo "Invalid web server option. Returning..."
            return
            ;;
        esac

        echo "✅ SSL certificate installed successfully for $domain."
        read -p "Press enter to continue..." ;;
      
      2)
        echo "📋 Listing installed SSL certificates..."
        certbot certificates || echo "⚠️ No certificates found or Certbot is not installed."
        read -p "Press enter to continue..." ;;
      
      3)
        read -p "Enter the domain name of the certificate to delete: " domain
        certbot delete --cert-name "$domain"
        read -p "Press enter to continue..." ;;
      
      4)
        break ;;
      
      *)
        echo "Invalid option. Please try again."
        sleep 2 ;;
    esac
  done
}

setup_wireguard_vpn(){

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		echo "OpenVZ is not supported"
		exit 1
	}
	function lxcErr() {
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			apk update && apk add virt-what
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		apk add wireguard-tools iptables libqrencode-tools
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall WireGuard"
	echo "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi

}
reboot_system() {

	reboot now
	echo "The system will reboot"
	
}

shutdown_system() {

		shutdown now
		echo "The system will shutdown"

}
PXE_Setup () {

echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo -e "${CYAN}${BOLD}                            iVentoy PXE Setup${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo
# Colors for messages
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m" # No color

# Variables
IVENTOY_VERSION="1.0.19"
INSTALL_DIR="/opt/iventoy"
JSON_FILE="$INSTALL_DIR/iventoy.json"
SERVICE_FILE="/etc/systemd/system/iventoy.service"
DOWNLOAD_URL="https://github.com/ventoy/PXE/releases/download/v$IVENTOY_VERSION/iventoy-$IVENTOY_VERSION-linux-free.tar.gz"

echo -e "${BLUE}🚀 Starting iVentoy PXE installation...${NC}"

# ------------------------------
# 1️⃣ Stop and clean previous installation and configuration files
# ------------------------------
echo -e "${YELLOW}🔄 Stopping and removing previous configurations...${NC}"

if systemctl is-active --quiet iventoy.service; then
    echo -e "${YELLOW}Stopping existing service...${NC}"
    sudo systemctl stop iventoy.service
fi

if systemctl list-unit-files | grep -q iventoy.service; then
    echo -e "${YELLOW}Disabling existing service...${NC}"
    sudo systemctl disable iventoy.service
fi

if [ -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Removing old service file...${NC}"
    sudo rm -f "$SERVICE_FILE"
fi

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Removing previous installation and configuration files...${NC}"
    sudo rm -rf "$INSTALL_DIR"
fi

# ------------------------------
# 2️⃣ Create installation directory
# ------------------------------
echo -e "${BLUE}📂 Creating installation directory: $INSTALL_DIR${NC}"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

# ------------------------------
# 3️⃣ Download and extract iVentoy
# ------------------------------
echo -e "${BLUE}⬇️  Downloading iVentoy version $IVENTOY_VERSION...${NC}"
wget $DOWNLOAD_URL -O /tmp/iventoy.tar.gz

echo -e "${BLUE}📦 Extracting files into $INSTALL_DIR...${NC}"
tar -xzf /tmp/iventoy.tar.gz -C $INSTALL_DIR

# ------------------------------
# 4️⃣ Detect iventoy.sh
# ------------------------------
SCRIPT_PATH=$(find $INSTALL_DIR -name iventoy.sh | head -n1)
if [ -z "$SCRIPT_PATH" ]; then
    echo -e "${RED}❌ Error: iventoy.sh was not found after extracting the tar.${NC}"
    exit 1
fi
chmod +x "$SCRIPT_PATH"
echo -e "${GREEN}✔ Found iventoy.sh at: $SCRIPT_PATH${NC}"

# ------------------------------
# 5️⃣ Create JSON file
# ------------------------------
echo -e "${BLUE}📝 Creating JSON file with executable path...${NC}"
cat <<EOF > $JSON_FILE
{
  "path": "$SCRIPT_PATH"
}
EOF
echo -e "${GREEN}✔ JSON created at $JSON_FILE${NC}"

# ------------------------------
# 6️⃣ Create systemd service
# ------------------------------
echo -e "${BLUE}⚙️  Configuring systemd service...${NC}"
sudo bash -c "cat <<EOF > $SERVICE_FILE
[Unit]
Description=iVentoy PXE Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash $SCRIPT_PATH start
ExecStop=/bin/bash $SCRIPT_PATH stop
Restart=on-failure
WorkingDirectory=$(dirname $SCRIPT_PATH)
User=root

[Install]
WantedBy=multi-user.target
EOF"

# ------------------------------
# 7️⃣ Enable and start service
# ------------------------------
echo -e "${BLUE}🚀 Enabling and starting the service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable iventoy.service
sudo systemctl restart iventoy.service

# ------------------------------
# 8️⃣ Quick verification
# ------------------------------
echo -e "${GREEN}🎉 iVentoy successfully installed in $INSTALL_DIR${NC}"
echo -e "${GREEN}📄 JSON created at $JSON_FILE${NC}"
echo -e "${GREEN}🔹 Systemd service active: systemctl status iventoy.service${NC}"
echo -e "${GREEN}🔹 iVentoy will start automatically at boot${NC}"
echo -e "${GREEN}🔹 To access the PXE Web UI, go to http://x.x.x.x:26000 or localhost:26000${NC}"

}


# Main Menu
while true; do

# Nuevo bloque de bienvenida con colores
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo -e "${CYAN}${BOLD}============= Linux Server Configuration Toolkit v3.3 =============${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo -e "${CYAN}${BOLD}==================== by: Jaime Galvez Martinez ====================${NC}"
echo -e "${CYAN}${BOLD}=================== GitHub: JaimeGalvezMartinez ===================${NC}"
echo -e "${BLUE}${BOLD}===================================================================${NC}"
echo ""    

echo "1) Configure network interfaces"
    echo "2) Configure gateway server"
    echo "3) Configure DHCP server"
    echo "4) Install forwarder + cache DNS "
    echo "5) Configur Local DNS Server"
    echo "6) Configure SAMBA server"
    echo "7) Configure FTP server over SSH"
    echo "8) Configure Firewall"
    echo "9) Install Nextcloud latest version"
    echo "10) Install Moodle Latest Version"
    echo "11) Install Wordpress"
    echo "12) VirtualHost Setup"
    echo "13) Network Scan"
    echo "14) Install & Configure Prometheus "
    echo "15) Install Graphana "
    echo "16) Show system Informaton "
    echo "17) Configure ACL "
    echo "18) Cerbot Management "
    echo "19) Make Backup or restore backup from ssh server "
    echo "20) Setup OpenVPN (integration with Alpine Linux)"
    echo "21) Setup Wireguard VPN (integration with Alpine Linux)"
    echo "22) Install Preboot eXecution Environment (PXE) "
	echo "23) Install Zentyal on Ubuntu 22.04 or lastest"
	echo "24) Self-Signed TLS/SSL Setup"
	echo "25) Install Vaultwarden with Docker + Reverse Nginx HTTPS with self-signed certificates"
	echo "26) Reboot System "
	echo "27) Shutdown System "
	echo -e "${RED}${BOLD}0) Exit${NC}"
read -rp "Choose an option: " opcion


    # case for execute the fuctions
    case $opcion in
    1) configure_network ;;
    2) configure_gateway_server ;;
    3) configure_dhcp_server ;;
	4) install_forwarder_dns ;;
    5) configure_local_dns_server ;;
    6) install_samba_server ;;
    7) install_ftp_server_over_ssh ;;
    8) configure_firewall ;;
    9) nextcloud_install ;;
    10) moodle_install ;;
	11) wp_install ;;
 	12) setup_virtualhost ;;
    13) network_scan ;;
	14) configure_prometheus ;;
 	15) configure_graphana ;;
  	16) show_system_info ;;
   	17) configure_acl ;;
    18) manage_certbot ;;
	19) backup_or_restore_backup_from_ssh_server ;;
 	20) setup_open_vpn;;
  	21) setup_wireguard_vpn;;
	22) PXE_Setup;;
	23) zentyal_80_setup;;
	24) setup_autofirmed_https;;
	25) setup_vaultwarden_in_docker;;
	26) reboot_system ;;
	27) shutdown_system ;;
    0) echo "Exiting. Goodbye!"; break ;;
        *) echo "Invalid option." ;;
    esac
done
