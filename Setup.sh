#!/usr/bin/env bash

# Halt on errors and undeclared variables and print out each command.
set -uex

# Generate a random string of 64 bytes.
random() {
    openssl rand -hex 32
}

# Make a backup copy of a file.
backup() {
    if test -f "$1"; then
        cp "$1" "$1.backup-$(date +"%Y%m%d%H%M%S")"
    fi
}

# Complain and quit.
bail() {
    echo "$0: $1" >&2
    exit 1
}

manual() {
    cat <<- EOF >&2
    SYNOPSIS
        Initial server configuration for hosting web applications.
        See more on https://github.com/corenzan/provision.

    OPTIONS
        -h --help                       Print out this manual.
EOF
}

# Parse options manually since getopt is not installed.
parse_options() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h|--help)
        manual
        exit 0
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Unknown option: $1" >&2
        exit 1
        ;;
    esac
  done
}

# Call the function to parse options.
parse_options "$@"

# Set defaults.
log="${log:-provision-$(date +"%Y%m%d%H%M%S").log}"

# Log everything if a file was set.
if test "$log" != "-"; then
    exec &> >(tee "$log")
fi

# Let debconf know we won't interact.
export DEBIAN_FRONTEND="noninteractive"

# Require privilege, i.e., sudo, after administrative tools block.
test "$(id -u)" -eq 0 || bail "This script must be run as root."

# Install essential packages.
apt-get update
apt-get install -y apt-utils openssh-server iptables rsyslog logrotate curl wget nano vim sudo net-tools lsb-release less ufw software-properties-common \
                   gnupg2 dirmngr apt-transport-https ca-certificates debsums htop lsof man-db unzip gzip bzip2 tar rsync cron build-essential libssl-dev libffi-dev \
                   python3 python3-pip python3-venv python3-dev util-linux linux-headers-$(uname -r) cloud-init cloud-guest-utils locales mc

# Auto-determine hostname
hostname="$(cat /etc/hostname)"

# Auto-detect the current admin username
username=$(logname)

# Validate username and public-key
required() {
    if [ -z "$1" ]; then
        bail "Required value for $1 not provided"
    fi
}
required username

# Assume public key is in the default location
public_key_file="/var/lib/.sheppy/.ssh/id_rsa.pub"
if ! test -f "$public_key_file"; then
    bail "Public key could not be found in '$public_key_file'."
fi

public_key="$(cat "$public_key_file")"

# Update hostname.
echo "$hostname" > /etc/hostname
hostname "$hostname"

# Clear rules for IPv4.
iptables -F
iptables -t nat -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Clear rules for IPv6.
ip6tables -F
ip6tables -t nat -F
ip6tables -P INPUT ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD ACCEPT

# Accept anything from/to loopback interface in IPv4.
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Accept anything from/to loopback interface in IPv6.
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# Keep established or related connections in IPv4.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Keep established or related connections in IPv6.
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow DNS communication in IPv4.
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow DNS communication in IPv6.
ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT
ip6tables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow regular pings in IPv4.
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT

# Allow regular pings in IPv6.
ip6tables -A INPUT -p icmpv6 -j ACCEPT

# Allow dockerd communication in IPv4.
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

# Allow dockerd communication in IPv6.
ip6tables -A INPUT -s ::1 -p tcp --dport 2375 -j ACCEPT

# Allow incoming traffic for HTTP, HTTPS, and SSH in IPv4.
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 822 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 5900 -j ACCEPT
iptables -A INPUT -p tcp --dport 5901 -j ACCEPT
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p tcp --dport 7860 -j ACCEPT
iptables -A INPUT -p tcp --dport 7861 -j ACCEPT
iptables -A INPUT -p tcp --dport 7862 -j ACCEPT

# Allow incoming traffic for HTTP, HTTPS, and SSH in IPv6.
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 822 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 7860 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 7861 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 3389 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 5900 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 5901 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 5000 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 7862 -j ACCEPT

# Block any other incoming connections in IPv4.
iptables -A INPUT -j DROP

# Block any other incoming connections in IPv6.
ip6tables -A INPUT -j DROP

# Log all the traffic in IPv4.
iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[iptables] "
iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[iptables] "

# Log all the traffic in IPv6.
ip6tables -A INPUT -j LOG --log-tcp-options --log-prefix "[ip6tables] "
ip6tables -A FORWARD -j LOG --log-tcp-options --log-prefix "[ip6tables] "

# Pipe iptables log to its own file.
cat > /etc/rsyslog.d/10-iptables.conf << EOF
:msg, contains, "[iptables] " -/var/log/iptables.log
& stop
EOF

# Pipe ip6tables log to its own file.
cat > /etc/rsyslog.d/10-ip6tables.conf << EOF
:msg, contains, "[ip6tables] " -/var/log/ip6tables.log
& stop
EOF

# Apply rsyslog configuration.
service rsyslog restart

# Rotate iptables logs.
cat > /etc/logrotate.d/iptables << EOF
/var/log/iptables.log
{
    rotate 30
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}
EOF

# Rotate ip6tables logs.
cat > /etc/logrotate.d/ip6tables << EOF
/var/log/ip6tables.log
{
    rotate 30
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}
EOF

# Save iptables configuration, but only after installing new packages, since they might have modified the rules.
iptables-save > /etc/iptables.conf

# Save ip6tables configuration, but only after installing new packages, since they might have modified the rules.
ip6tables-save > /etc/ip6tables.conf

# Load iptables config when network device is up.
cat > /etc/network/if-up.d/iptables << EOF
#!/usr/bin/env bash
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables

# Load ip6tables config when network device is up.
cat > /etc/network/if-up.d/ip6tables << EOF
#!/usr/bin/env bash
ip6tables-restore < /etc/ip6tables.conf
EOF
chmod +x /etc/network/if-up.d/ip6tables

# Save a copy.
backup /etc/ssh/sshd_config

# Configure the SSH server.
cat > /etc/ssh/sshd_config << EOF
    # We omit ListenAddress so SSHD listens on all interfaces, both IPv4 and IPv6.

    # Supported HostKey algorithms by order of preference.
    HostKey /etc/ssh/ssh_host_rsa_key
    HostKey /etc/ssh/ssh_host_ed25519_key

    # Select the host key algorithms that the server is willing to use for authentication.
    HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

    # Select the signature algorithms that the server is willing to use for certificate authority (CA) signatures.
    CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

    # Select the key exchange algorithms that the server is willing to use for GSSAPI (Generic Security Services Application Program Interface) authentication.
    GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

    # Select the public key algorithms that the server is willing to accept for authentication.
    PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh.ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

    # Choose stronger Key Exchange algorithms.
    KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

    # Use modern ciphers for encryption.
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    # Use MACs with larger tag sizes.
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

    # LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
    LogLevel VERBOSE

    # Let users set environment variables.
    PermitUserEnvironment yes

    # Support older less secure protocols.
    Protocol 2,1

    # Forwarding to X11 is considered insecure.
    X11Forwarding yes

    # Allow port forwarding and tunneling.
    AllowTcpForwarding yes
    AllowStreamLocalForwarding yes
    GatewayPorts yes
    PermitTunnel yes

    # Don't allow login if the account has an empty password.
    PermitEmptyPasswords no

    # Ignore .rhosts and .shosts.
    IgnoreRhosts yes

    # Verify hostname matches IP.
    UseDNS yes

    # TCPKeepAlive is not encrypted.
    TCPKeepAlive no

    AllowAgentForwarding yes
    Compression yes

    # Allow root sessions.
    PermitRootLogin yes

    # Don't allow .rhosts or /etc/hosts.equiv.
    HostbasedAuthentication no

    # Passwords are insecure. Who cares
    PasswordAuthentication yes

    # Allow users in 'remote' group to connect.
    # To add and remove users from the group, respectively:
    # - usermod -aG remote <username>
    # - gpasswd -d <username> remote
    AllowGroups remote

    # Drop clients that idle longer than 10 minutes.
    #ClientAliveInterval 60
    #ClientAliveCountMax 10

    # Drop if a client takes too long to authenticate.
    #LoginGraceTime 10

    # Log additional failures.
    MaxAuthTries 2

    # Limit connections from the same network.
    #MaxSessions 2

    # Allow only one authentication at a time.
    #MaxStartups 2

    # Silence is golden.
    DebianBanner no
    PrintMotd no

    # Change default port.
    Port 822
    Port 22
EOF

# The Diffie-Hellman algorithm is used by SSH to establish a secure connection.
# The larger the moduli (key size) the stronger the encryption.
# Remove all moduli smaller than 3072 bits.
cp --preserve /etc/ssh/moduli /etc/ssh/moduli.insecure
awk '$5 >= 3071' /etc/ssh/moduli.insecure > /etc/ssh/moduli

# Delete existing host keys.
rm /etc/ssh/ssh_host_*

# Create new host keys.
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Restart SSH server.
service ssh restart
