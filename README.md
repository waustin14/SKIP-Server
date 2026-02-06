# SKIP Server

A Python implementation of the **Secure Key Integration Protocol (SKIP)** based on [draft-cisco-skip-02](https://datatracker.ietf.org/doc/draft-cisco-skip/02/). This server enables quantum-safe key distribution between Cisco IOS XE routers and Key Providers using ML-KEM-1024 for key encapsulation and TLS-PSK for secure client communication.

## Overview

SKIP Server acts as a Key Provider (KP) that supplies cryptographic keys to network encryptors (such as Cisco routers). It supports:

- **TLS-PSK (Pre-Shared Key)** authentication for router-to-server communication on port 443
- **mTLS (Mutual TLS)** for secure server-to-server key exchange on port 8443
- **ML-KEM-1024** (formerly Kyber1024) post-quantum key encapsulation for forward-secure key distribution
- **RESTful API** endpoints compliant with the SKIP draft specification

### Architecture

```
┌─────────────────┐    TLS-PSK (443)     ┌─────────────────┐
│   Cisco Router  │◄──────────────────►  │   SKIP Server   │
│   (Encryptor)   │                      │  (Key Provider) │
└─────────────────┘                      └────────┬────────┘
                                                  │
                                         mTLS (8443) + ML-KEM
                                                  │
                                         ┌────────▼────────┐
                                         │  Remote SKIP    │
                                         │    Server(s)    │
                                         └─────────────────┘
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/capabilities` | GET | Returns Key Provider capabilities and configuration |
| `/entropy` | GET | Generates cryptographically secure random bytes |
| `/key` | GET | Generates a new symmetric key and exchanges it with peer KP |
| `/key/{key_id}` | GET | Retrieves an existing key by ID (one-time retrieval) |
| `/key-exchange` | POST | Receives KEM payload from peer Key Provider (server-to-server) |

---

## Preparation

### Prerequisites

- Python 3.10+ (or Docker)
- OpenSSL 3.x with OQS provider (for ML-KEM key generation) **OR** OpenSSL 3.5+
- Cisco IOS XE 17.12+ router (for SKIP client support)

### Directory Structure

Create the following directory structure for your deployment:

```
skip-server/
├── config/
│   └── skip.yaml           # Server configuration
├── certs/
│   └── ca/
│       └── ca.pem          # Certificate Authority certificate
│   ├── skip1.pem.crt       # Server TLS certificate
│   └── skip1_key.pem       # Server TLS private key
└── secrets/
    ├── psk.txt             # Pre-shared keys for router clients
    ├── kem_pub.pem         # This server's ML-KEM public key
    ├── kem_priv.pem        # This server's ML-KEM private key
    └── skip2_kem_pub.pem   # Remote server's ML-KEM public key (for each peer)
```

### Step 1: Create Certificate Authority

Generate a CA that will sign all server certificates:

```bash
./scripts/create_ca.sh ./certs/ca

# Output files:
#   ./certs/ca/ca.pem     - CA certificate
#   ./certs/ca/ca.key     - CA private key (keep secure!)
```

**Environment variables:**
- `CA_CN` - Common Name for CA (default: "My Lab CA")
- `CA_KEY_SIZE` - RSA key size in bits (default: 4096)
- `CA_VALIDITY_DAYS` - Certificate validity period (default: 3650)

### Step 2: Generate Server Certificates

Create and sign a certificate for each SKIP server:

```bash
./scripts/sign_server_cert.sh \
    -c ./certs/ca/ca.pem \
    -k ./certs/ca/ca.key \
    -o ./certs \
    skip1.cml.lab \
    "skip1.cml.lab,localhost" \
    "10.89.0.2,127.0.0.1"

# Arguments:
#   1. Common Name (hostname)
#   2. DNS Subject Alternative Names (comma-separated)
#   3. IP Subject Alternative Names (comma-separated)

# Output files:
#   ./certs/skip1.pem.crt  - Server certificate
#   ./certs/skip1_key.pem  - Server private key
```

### Step 3: Generate ML-KEM Key Pairs

Generate a post-quantum key pair for each SKIP server:

```bash
./scripts/generate_mlkem_kp.sh \
    -p ./secrets/kem_pub.pem \
    -s ./secrets/kem_priv.pem

# Output files:
#   ./secrets/kem_pub.pem   - ML-KEM-1024 public key
#   ./secrets/kem_priv.pem  - ML-KEM-1024 private key
```

> **Note:** Requires OpenSSL 3.5+ **OR** OpenSSL with OQS provider. The public key must be shared with peer SKIP servers.

### Step 4: Create Pre-Shared Keys

Generate PSK credentials for each router client:

```bash
./scripts/create_psk.sh -i router1 -f ./secrets/psk.txt
./scripts/create_psk.sh -i router2 -f ./secrets/psk.txt

# File format (identity:hex_key):
#   router1:aa07eb6271b089a1b2c3d4e5f6...
#   router2:bb18fc7382c19ab2c3d4e5f6a7...
```

**Options:**
- `-i <identity>` - Client identity string (required)
- `-l <length>` - Key length in bytes (default: 48)
- `-f <file>` - Output file path (default: psk.txt)

### Step 5: Configure SKIP Server

Copy and customize the configuration file:

```bash
cp config/skip.yaml.example config/skip.yaml
```

Edit `config/skip.yaml`:

```yaml
---
localSystemID: "skip1.cml.lab"

# Remote SKIP servers for key exchange
remoteSystems:
  - id: "skip2.cml.lab"
    ip: "172.31.255.2"
    pubkey_path: "/data/appdata/secrets/skip2_kem_pub.pem"

algorithm: "PRF"
default_key_size_bits: 256
default_entropy_bits: 256
keystore_path: "/data/appdata/secrets/keystore.db"
kem_pub_key_path: "/data/appdata/secrets/kem_pub.pem"
kem_priv_key_path: "/data/appdata/secrets/kem_priv.pem"

# TLS-PSK for router clients
use_psk: true
psk_file: "/data/appdata/secrets/psk.txt"
psk_identity: "skip1.cml.lab"

# mTLS for server-to-server
use_ssl: true
certfile: "/data/appdata/certs/skip1.pem.crt"
keyfile: "/data/appdata/certs/skip1_key.pem"
cafile: "/data/appdata/certs/ca/ca.pem"
```

### Step 6: Exchange Public Keys

For each pair of SKIP servers that will exchange keys:

1. Copy the local server's `kem_pub.pem` to the `secrets` folder of remote servers
2. Update each server's config with the path to peer public keys

```bash
# On skip1: copy skip2's public key
scp user@skip2:/path/to/kem_pub.pem ./secrets/skip2_kem_pub.pem

# Update remoteSystems in skip.yaml with pubkey_path
```

---

## Deployment on Cisco IOx

This section covers deploying the SKIP Server as an IOx application on a Cisco router.

### Prerequisites

- Download the latest IOx package from the `releases` section of this repo
- If you'd like to build the IOx package yourself, follow the instructions in the `Build the IOx Package` section
- Otherwise, proceed to `Deploy to Router`

### Build the IOx Package
- Install `ioxclient` from the [Cisco DevNet Portal](https://developer.cisco.com/docs/iox/iox-resource-downloads/#downloads)
- Clone this repository and enter project directory
```bash
git clone https://github.com/waustin14/SKIP-Server.git && cd SKIP-Server
```
- Build the Docker container
```bash
docker build -t skip-server .
```
- Create the IOx package
```bash
ioxclient docker package skip-server ./iox
```

### Prepare the Router for IOx Package Installation
- Enable IOx
```
Router(config)# iox
```
- Configure VirtualPortGroup interface to enable app-hosting
```
Router(config)# interface VirtualPortGroup0
Router(config-if)# ip address 169.254.0.1 255.255.255.252
```
- Configure app-hosting parameters for SKIP Server
```
Router(config)# app-hosting appid SKIP_Server
Router(config-app-hosting)# app-vnic gateway0 virtualportgroup 0 guest-interface 0
Router(config-app-hosting-gateway0)# guest-ipaddress 169.254.0.2 netmask 255.255.255.252
Router(config-app-hosting)# app-default-gateway 169.254.0.1 guest-interface 0
Router(config-app-hosting)# app-resource docker
Router(config-app-hosting-docker)# prepend-pkg-opts
Router(config-app-hosting-docker)# run-opts 1 "--env KEYSTORE_MASTER_KEY=<generated key>"
Router(config-app-hosting-docker)# run-opts 2 "--hostname skip1.cml.lab"
Router(config-app-hosting)# name-server0 <DNS server> ! if FQDNs are used in skip.yaml
```
- Disable IOx signature validation (signing IOx packages is outside the scope of this project)
```
Router# app-hosting verification disable
```

### Deploy to Router

- Copy the downloaded IOx package to the router
```bash
scp package.tar admin@router:bootflash:package.tar
```
- Install the SKIP Server IOx package
```
Router# app-hosting install appid SKIP_Server package bootflash:package.tar
```

### Copy Necessary Files into the Deployed Container
- Copy the SKIP Server's configuration, certificates, and keys to the router's bootflash
- Copy the necessary files into the deployed container (**NOTE:** Destination paths are relative to `/data/appdata/` in the container)
```
Router# app-hosting data appid SKIP_Server copy bootflash:certs/ca/ca.pem certs/ca/ca.pem
Router# app-hosting data appid SKIP_Server copy bootflash:certs/skip1.pem.crt certs/skip1.pem.crt
Router# app-hosting data appid SKIP_Server copy bootflash:certs/skip1_key.pem certs/skip1_key.pem
Router# app-hosting data appid SKIP_Server copy bootflash:config/skip.yaml config/skip.yaml
Router# app-hosting data appid SKIP_Server copy bootflash:secrets/keystore.db secrets/keystore.db
Router# app-hosting data appid SKIP_Server copy bootflash:secrets/kem_pub.pem secrets/kem_pub.pem
Router# app-hosting data appid SKIP_Server copy bootflash:secrets/kem_priv.pem secrets/kem_priv.pem
Router# app-hosting data appid SKIP_Server copy bootflash:secrets/psk.txt secrets/psk.txt
Router# app-hosting data appid SKIP_Server copy bootflash:secrets/skip2_kem_pub.pem secrets/skip2_kem_pub.pem
! Copy ML-KEM public keys for all peer SKIP Servers
```

### Start the SKIP Server and Verify Deployment
- Start the SKIP Server container
```
Router# app-hosting start appid SKIP_Server
```
- Confirm IOx container is running
```
Router# show app-hosting list
```
- Connect to IOx container's console to view live logs
```
Router# app-hosting connect appid SKIP_Server console
```

---

## Router Configuration for Quantum-Secure IPsec Using SKIP

This section covers the router configurations necessary for leveraging the local SKIP Server

### Step 1: IKEv2 Configuration
- Configure SKIP client (Use the PSK generated earlier)
```
Router(config)# crypto skip-client SKIP-CLIENT
Router(config-crypto-skip-client)# server fqdn skip1.cml.lab port 443
Router(config-crypto-skip-client)# psk id skip1.cml.lab key hex 0123456789abcdef...
```
- Configure an IKEv2 keyring
```
Router(config)# crypto ikev2 keyring SKIP-KR
Router(config-ikev2-keyring)# peer skip2
Router(config-ikev2-keyring-peer)# address 10.0.12.2 255.255.255.0
Router(config-ikev2-keyring-peer)# identity fqdn skip2.cml.lab
Router(config-ikev2-keyring-peer)# ppk dynamic SKIP-CLIENT required
```
- Configure an IKEv2 proposal
```
Router(config)# crypto ikev2 proposal IKE-PROPOSAL
Router(config-ikev2-proposal)# encryption aes-gcm-256
Router(config-ikev2-proposal)# prf sha512
Router(config-ikev2-proposal)# group 21 20 19
```
- Configure an IKEv2 profile leveraging the keyring
```
Router(config)# crypto ikev2 profile IKE-PROFILE
Router(config-ikev2-profile)# proposal IKE-PROPOSAL
Router(config-ikev2-profile)# match identity remote domain cml.lab
Router(config-ikev2-profile)# identity local fqdn skip1.cml.lab
Router(config-ikev2-profile)# authentication local pre-share key cisco
Router(config-ikev2-profile)# authentication remote pre-share key cisco
Router(config-ikev2-profile)# keyring ppk SKIP-KR
```

### Step 2: IPsec Configuration
- Configure an IPsec transform-set
```
Router(config)# crypto ipsec transform-set esp-aes 256 esp-sha512-hmac
Router(cfg-crypto-trans)# mode tunnel
```
- Configure an IPsec profile
```
Router(config)# crypto ipsec profile IPSEC-PROFILE
Router(ipsec-profile)# set transform-set IPSEC-TS
Router(ipsec-profile)# set ikev2-profile IKE-PROFILE
```

### Step 3: Create Trustpoint for CA
- Retrieve the SHA1 fingerprint for your CA certificate (on a separate machine)
```bash
openssl x509 -noout -fingerprint -sha1 -in certs/ca/ca.pem | cut -d '=' -f 2 | tr -d ':'
```
- Create a new PKI truspoint
```
Router(config)# crypto pki trustpoint MyLabCA
Router(ca-trustpoint)# enrollment terminal
Router(ca-trustpoint)# revocation-check none
Router(ca-trustpoint)# hash sha256
Router(ca-trustpoint)# fingerprint <CA fingerprint>
```
- Authenticate the CA certificate to establish trust
```
Router# crypto pki authenticate MyLabCA
Router# <paste CA certificate in PEM format>
```

### Step 4: Tunnel Configuration
- Configure the secure tunnel interface
```
Router(config)# interface Tunnel10
Router(config-if)# ip address 172.16.10.1 255.255.255.0
Router(config-if)# tunnel source GigabitEthernet1
Router(config-if)# tunnel destination 10.0.12.2
Router(config-if)# tunnel mode ipsec ipv4
Router(config-if)# tunnel protection ipsec profile IPSEC-PROFILE
```
- Dynamic PPKs using SKIP can also be used for more complex tunnels like DMVPN
- Sample configurations for other tunnel types will be added to this repo later

---

## Development

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python src/skip_server.py --host 0.0.0.0 --config config/skip.yaml
```

### Docker

```bash
# Build the image
docker build -t skip-server .

# Run with mounted config and secrets
docker run -d \
    -p 443:443 \
    -p 8443:8443 \
    -v $(pwd)/config:/data/appdata/config \
    -v $(pwd)/certs:/data/appdata/certs \
    -v $(pwd)/secrets:/data/appdata/secrets \
    -e "KEYSTORE_MASTER_KEY=<generated key> \
    --hostname skip1.cml.lab \
    skip-server
```

---

## References

- [IETF Draft: Secure Key Integration Protocol (SKIP)](https://datatracker.ietf.org/doc/draft-cisco-skip/02/)
- [Cisco IOS XE SKIP Configuration Guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-quantum-resistance.html)
- [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)

---

## License

<!-- TODO: Add license information -->
