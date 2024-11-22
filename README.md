# OpenVPN
Auto Install OpenVPN Script

### Step-by-Step Guide to Installing OpenVPN 🚀

Here's a step-by-step guide to installing OpenVPN using the provided script:

#### Step 1: Prepare Your System 🖥️

1. **Ensure your system is updated**:
   ```sh
   sudo apt-get update && sudo apt-get upgrade -y
   ```

2. **Ensure you have bash installed** (it is usually installed by default on most systems).

#### Step 2: Download the Installation Script 📥

Download the OpenVPN installation script from the provided repository:

```sh
wget https://raw.githubusercontent.com/Cybersecsolution/OpenVPN/main/openvpn-ubuntu-install.sh -O openvpn-ubuntu-install.sh
```

#### Step 3: Run the Script ▶️

Make the script executable and run it:

```sh
chmod +x openvpn-ubuntu-install.sh
```

#### Step 4: Follow the Script Prompts 🔍

1. **Protocol Selection**:
   - Choose between UDP (recommended) or TCP for OpenVPN.
   - Enter the protocol number (1 for UDP or 2 for TCP).

2. **Port Selection**:
   - Enter the port number for OpenVPN to listen on (default is 1194).

3. **DNS Server Selection**:
   - Choose a DNS server for the clients:
     - 1) Current system resolvers
     - 2) Google
     - 3) 1.1.1.1 Failover
     - 4) OpenDNS
     - 5) Quad9
     - 6) AdGuard

4. **Number of Clients**:
   - Enter the number of client configurations to generate (1-50).

5. **Certificate Expiration Duration**:
    - Choose the expiration duration for the certificates:
      - 1) 1 month
      - 2) 3 months
      - 3) 1 year
      - 4) 6 years

#### Step 5: Installation and Configuration ⚙️

The script will proceed with the installation and configuration of OpenVPN, setting up necessary components, and generating configuration files.

#### Step 6: Post-Installation Menu 📋

If OpenVPN is already installed, the script presents a menu with options to:
- Add a new client
- Revoke an existing client
- Remove OpenVPN
- Exit the script

### Notes 📝

- **Public IP Detection with 1.1.1.1 Failover**: The script includes multiple failover sources to determine the public IP address, ensuring higher accuracy and reliability even if some services are unavailable.

By following these steps, you can successfully install and configure OpenVPN on your server using the provided script.

### 5. Test/Verify Connection 🛠️

1. **Ping the OpenVPN server gateway**:
   ```sh
   ping 10.8.0.1
   ```

2. **Ensure the routing setup is working**:
   ```sh
   ip route
   ```

3. **Verify the public IP address of the OpenVPN server**:
   ```sh
   dig TXT +short o-o.myaddr.l.google.com @ns1.google.com
   ```

### 6. Add or Remove a New VPN User with a Certificate 🔑

To add or remove a new VPN user with a TLS certificate, run the same script again:
```sh
sudo ./openvpn-ubuntu-install.sh
```

### Script Information ℹ️

#### Script Execution Check:
- The script checks if it is being run with bash and if it has superuser privileges.

#### OS Detection:
- The script detects the operating system and version to apply OS-specific configurations.
- Supported OSes include Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, and Fedora.

#### Prerequisites Check:
- The script ensures that the TUN device is available.

#### IP Address Detection:
- If the system has a single IPv4 address, it is selected automatically.
- If there are multiple IPv4 addresses, the script will ask you to select one.
- If the server is behind NAT, you will be prompted to enter the public IPv4 address or hostname.

#### IPv6 Address Detection (if applicable):
- The script will automatically detect the IPv6 address or ask you to select one if multiple are detected.

#### Firewall Installation:
- The script installs `firewalld` or `iptables` if they are not already available and configures them appropriately.

#### Easy-RSA Installation:
- The script downloads and sets up Easy-RSA for generating certificates.

#### PKI and Certificate Setup:
- Initializes the PKI, sets up the CA, server, and client certificates, and generates the necessary keys.

#### OpenVPN Configuration:
- Generates the OpenVPN server configuration file (`server.conf`), including IP forwarding settings, DNS settings, and more.

#### Firewall Rules:
- Configures firewall rules for OpenVPN, including port and source settings and NAT rules.

#### System Service Configuration:
- Sets up a systemd service for persistent iptables rules and ensures the OpenVPN service starts automatically.

#### Client Configuration Generation 📄
- Creates a template for client configurations (`client-common.txt`).
- For each specified client, generates a unique client certificate and configuration file (.ovpn), including the CA, certificate, key, and TLS crypt key.

#### Additional Client Management 👥
- **Adding New Clients**:
  - Enter the base name for the clients.
  - Specify the number of clients to generate.
  - Select the certificate expiration duration.
  - The script generates certificates and configurations for each client.

- **Revoking Clients**:
  - Lists existing clients and allows you to select a client to revoke.
  - Updates the certificate revocation list (CRL).

- **Removing OpenVPN**:
  - Prompts for confirmation and removes OpenVPN, associated configurations, and firewall rules if confirmed.

### End-to-End Encryption Details 🔒

**TLS Authentication and Encryption**: The script uses a static TLS key for additional authentication, enhancing the security of the VPN connection.

**DNS Failover**: The script sets up multiple DNS servers for redundancy.

**Disabled Compression**: The script avoids enabling any form of compression, thus maintaining security.
