import argparse
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import uuid
from typing import Dict, List, Literal, Optional, Tuple

import httpx
import sslpsk3
import uvicorn
import yaml
from fastapi import FastAPI, HTTPException, Query
from pqcrypto.kem.ml_kem_1024 import decrypt, encrypt
from pydantic import BaseModel, Field

from secure_keyloader import SecureKeyLoader
from secure_keystore import SecureKeyStore

# TLS-PSK Cipher Suites supported by this server (AES-256 only, matching Cisco IOS XE)
# 0x00a9 = TLS_PSK_WITH_AES_256_GCM_SHA384
# 0x00ab = TLS_PSK_WITH_AES_256_CBC_SHA384
# 0x00af = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
# 0x00b3 = TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
PSK_CIPHER_SUITES = "PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:DHE-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-CBC-SHA384"

# Sample configuration for the Key Provider (KP)
KP_CONFIG = {
    "localSystemID": "KP_Alice_LOC1",
    "remoteSystemIDs": [
        {"id": "KP_Bob_LOC1", "ip": "192.0.2.1", "pubkey": "abc123"},
        {"id": "KP_*_LOC2", "ip": "192.0.2.2", "pubkey": "def456"},
    ],
    "algorithm": "OS-based CSRNG, ML-KEM-1024",
    "default_key_size_bits": 256,
    "default_entropy_bits": 256,
}

class CapabilitiesResponse(BaseModel):
    entropy: bool = Field(..., description="True if the KP supports the GET /entropy method.")
    key: bool = Field(..., description="True if the KP supports the GET /key method.")
    algorithm: str = Field(..., description="Identifier for the key generation/synchronization algorithm.")
    localSystemID: str = Field(..., description="Identifier for this Key Provider.")
    remoteSystemID: List[str] = Field(..., description="List of identifiers for remote KPs this KP can peer with.")

class KeyResponse(BaseModel):
    keyId: str = Field(..., description="Hexadecimal-encoded identifier for the key.")
    key: str = Field(..., description="Hexadecimal-encoded key.")

class EntropyResponse(BaseModel):
    randomStr: str = Field(..., description="Hexadecimal-encoded random bytes string.")
    minentropy: int = Field(..., description="Length of the random string in bits.")

class KEMPayload(BaseModel):
    system_id: str = Field(..., description="Identifier for the sending Key Provider.")
    key_id: str = Field(..., description="Hexadecimal-encoded identifier for the key.")
    length: Literal[128, 192, 256] = Field(256, description="Length of the encapsulated key in bits. Default is 256 bits.")
    ciphertext: str = Field(..., description="Ciphertext containing the encapsulated shared secret.")

class SkipServer:
    """
    A FastAPI application that implements a lightweight version of the Secure Key Integration Protocol (SKIP)
    based on draft-cisco-skip-01.
    """

    # Default ports
    DEFAULT_CLIENT_PORT = 443      # TLS-PSK port for router clients
    DEFAULT_MTLS_PORT = 8443       # mTLS port for server-to-server

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_CLIENT_PORT,
        config_path: str = "skip.yaml",
    ):
        """Initialize the SkipServer with the given parameters."""
        self.app = FastAPI(
            title="Cisco SKIP Server",
            description="A lightweight implementation of the Secure Key Integration Protocol (SKIP) based on draft-cisco-skip-01.",
            version="0.1.0",
        )
        self.host = host
        self.port = port
        self.config_path = config_path
        self.config = {}

        # Load configuration from YAML file
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
                self.config.update(config)
        except FileNotFoundError:
            self.config = KP_CONFIG

        self.use_ssl = self.config.get("use_ssl", False)
        self.local_system_id = self.config.get("localSystemID", "skip_server")
        self.certfile = self.config.get("certfile")
        self.keyfile = self.config.get("keyfile")
        self.cafile = self.config.get("cafile")

        # PSK (Pre-Shared Key) configuration for TLS-PSK cipher suites
        self.use_psk = self.config.get("use_psk", False)
        self.psk_file = self.config.get("psk_file")
        self.psk_identity = self.config.get("psk_identity", self.local_system_id)
        self.psk_keys: Dict[str, bytes] = {}

        # Port configuration with defaults
        self.port = self.config.get("port", port)  # Override with config if present
        self.mtls_port = self.config.get("mtls_port", self.DEFAULT_MTLS_PORT)
        if self.use_psk and self.psk_file:
            self._load_psk_file(self.psk_file)

        kem_pub_key_path = self.config.get("kem_pub_key_path", "certs/skip1.pem.crt")
        with open(kem_pub_key_path, "r") as f:
            self.kem_pub_key = bytes.fromhex(f.read().strip())
        self.kem_priv_key_path = self.config.get("kem_priv_key_path", "certs/skip1.pem.key")
        keystore_path = self.config.get("keystore_path", "keystore.db")
        self.keystore = SecureKeyStore(filepath=keystore_path)
        self.key_records: Dict[str, str] = {}

        self._register_routes()
        self.run()

    def _load_psk_file(self, psk_file_path: str) -> None:
        """
        Load PSK identities and keys from a file.
        File format: identity:hex_encoded_key (one per line)
        Example: spoke1:aa07eb6271b089a1
        """
        try:
            with open(psk_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        identity, key_hex = line.split(":", 1)
                        self.psk_keys[identity.strip()] = bytes.fromhex(key_hex.strip())
        except FileNotFoundError:
            pass

    def _get_psk_for_identity(self, identity: bytes) -> bytes:
        """PSK callback for server: returns the PSK for a given client identity."""
        identity_str = identity.decode("utf-8") if isinstance(identity, bytes) else str(identity)
        print(f"PSK lookup for identity: '{identity_str}'")
        psk = self.psk_keys.get(identity_str)
        if psk:
            print(f"PSK found for identity: '{identity_str}'")
            return psk
        else:
            print(f"PSK NOT found for identity: '{identity_str}' (available: {list(self.psk_keys.keys())})")
            return b""

    def _get_psk_for_hint(self, hint: bytes) -> Tuple[bytes, bytes]:
        """PSK callback for client: returns (psk, identity) for a given server hint."""
        identity_bytes = self.psk_identity.encode("utf-8") if isinstance(self.psk_identity, str) else self.psk_identity
        psk = self.psk_keys.get(self.psk_identity, b"")
        return (psk, identity_bytes)

    def _register_routes(self):

        #############################################################
        ### SKIP Server Required Endpoints (Encryptor <-> Server) ###
        #############################################################
        @self.app.get("/capabilities", response_model=CapabilitiesResponse, tags=["SKIP"])
        async def get_capabilities():
            """
            Returns the capabilities of the Key Provider, as defined in Section 4.1.
            """
            remote_system_ids = [r["id"] for r in self.config.get("remoteSystems", [])]
            return {
                "entropy": True,
                "key": True,
                "algorithm": self.config.get("algorithm"),
                "localSystemID": self.config.get("localSystemID"),
                "remoteSystemID": remote_system_ids,
            }
        
        @self.app.get("/entropy", response_model=EntropyResponse, tags=["SKIP"])
        async def get_entropy(minentropy: Optional[int] = Query(None, description="The desired length of entropy in bits (128, 192, or 256).")):
            """
            Returns a randomly generated entropy string, as defined in Section 4.3.
            """
            bits_to_generate = minentropy if minentropy is not None else self.config.get("default_entropy_bits", 256)
            
            # Add validation for allowed values
            if minentropy is not None and minentropy not in [128, 192, 256]:
                raise HTTPException(status_code=400, detail="minentropy must be 128, 192, or 256 bits.")
            
            if bits_to_generate <= 0 or bits_to_generate % 8 != 0:
                raise HTTPException(status_code=400, detail="minentropy must be a positive integer divisible by 8.")
            
            num_bytes = bits_to_generate // 8
            random_string = secrets.token_hex(num_bytes)
            
            return {"randomStr": random_string, "minentropy": bits_to_generate}

        @self.app.get("/key", response_model=KeyResponse, tags=["SKIP"])
        async def generate_new_key(
            remoteSystemID: str = Query(..., description="The system ID of the remote/peer KP."),
            size: Optional[int] = Query(None, description="The desired key size in bits (128, 192, or 256).")
        ):
            """
            Generates a new key and keyId for an initiating encryptor.
            This corresponds to methods 2 and 3 in Table 2 of the RFC.
            The key is stored to be retrieved by the peer.
            """
            remoteIds = [r["id"] for r in self.config.get("remoteSystems", [])]
            if remoteSystemID not in remoteIds:
                raise HTTPException(status_code=400, detail=f"Unknown remoteSystemID '{remoteSystemID}'.")
            
            if size not in (128, 192, 256, None):
                raise HTTPException(status_code=400, detail="Key size must be one of 128, 192, or 256 bits.")

            key_size_bits = size if size is not None else self.config["default_key_size_bits"]
            if key_size_bits <= 0 or key_size_bits % 8 != 0:
                raise HTTPException(status_code=400, detail="Key size must be a positive integer divisible by 8.")

            # Generate a new key and a unique keyId (128-bit default)
            key_id = uuid.uuid4().hex  # A 128-bit hex string
            remote_system = next((r for r in self.config.get("remoteSystems", []) if r["id"] == remoteSystemID), None)
            if not remote_system:
                raise ValueError(f"Remote system with ID '{remoteSystemID}' not found in configuration.")
            remote_pub_key = bytes.fromhex(remote_system.get("pubkey"))
            ciphertext, shared_secret = encrypt(remote_pub_key)
            kem_payload = KEMPayload(
                system_id=self.local_system_id,
                key_id=key_id,
                length=key_size_bits,
                ciphertext=ciphertext.hex(),
            )

            self.key_records[key_id] = remoteSystemID

            resp = await self.send_key_to_remote(remoteSystemID, kem_payload)
            if resp is not True:
                raise HTTPException(status_code=500, detail="Failed to send key to remote system.")
            
            # Truncate the share secret to the requested key size
            if key_size_bits != 256:
                # Convert the shared secret to bytes and truncate it
                shared_secret = shared_secret[:key_size_bits // 8]

            # Per RFC, the initiator receives the key and keyId.
            return {"keyId": key_id, "key": shared_secret.hex()}
        
        @self.app.get("/key/{key_id}", response_model=KeyResponse, tags=["SKIP"])
        async def get_key_by_id(
            key_id: str,
            remoteSystemID: str = Query(..., description="The system ID of the remote/peer KP.")
        ):
            """
            Retrieves an existing key for a responding encryptor using a keyId.
            This corresponds to method 4 in Table 2 of the RFC.
            Crucially, this action "zeroizes" the key after retrieval.
            """
            if key_id in self.keystore.list_keys():
                key = self.keystore.get(key_id)
                self.keystore.delete(key_id)  # Zeroize the key after providing it
                return {"keyId": key_id, "key": key}
            raise HTTPException(
                    status_code=400,
                    detail=f"Key for keyId '{key_id}' not found. It may have already been retrieved or never existed."
                )
        
        ##############################################################
        ### SKIP Server Key Exchange Endpoints (Server <-> Server) ###
        ##############################################################
        @self.app.post("/key-exchange", tags=["SKIP"])
        async def key_exchange(body: KEMPayload):
            """Receives a KEM payload for key exchange from another Key Provider."""
            if not self.kem_priv_key_path:
                raise HTTPException(status_code=500, detail="KEM private key is not configured.")
            
            try:
                # Decapsulate the symmetric key from the KEM payload
                remote_system_id = body.system_id
                key_id = body.key_id
                length = body.length
                ciphertext = body.ciphertext
                with SecureKeyLoader(self.kem_priv_key_path) as priv_key:
                    shared_secret = decrypt(priv_key, bytes.fromhex(ciphertext))
                    if length != 256:
                        # Truncate the shared secret to the requested key size
                        shared_secret = shared_secret[:length // 8]
                    self.keystore.set(key_id, shared_secret.hex())
            except Exception:
                raise HTTPException(status_code=400, detail="Failed to decapsulate key from KEM payload.")

            self.key_records[key_id] = remote_system_id  

            return {
                "status": "success",
                "message": f"Key with keyId {key_id} successfully received and stored for remote system {remote_system_id}."
            }

        # Add catch-all route for unsupported HTTP methods
        @self.app.api_route("/{path:path}", methods=["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], tags=["Error Handling"])
        async def method_not_allowed(path: str):
            """
            Returns 405 Method Not Allowed for any non-GET request to any endpoint.
            """
            raise HTTPException(
                status_code=405, 
                detail="Method not allowed. This server only supports GET requests.",
                headers={"Allow": "GET"}
            )

    async def send_key_to_remote(self, remote_system_id: str, kem_payload: KEMPayload) -> bool:
        """
        Sends the symmetric key to a remote system using KEM encapsulation.
        Uses mTLS (certificate-based mutual TLS) for server-to-server communication.
        When connecting to a SKIP server running in PSK mode, uses port+1 for mTLS.
        """
        remote = next((r for r in self.config.get("remoteSystems", []) if r["id"] == remote_system_id), None)
        if not remote:
            raise ValueError(f"Remote system ID '{remote_system_id}' not found in configuration.")

        if not self.certfile or not self.keyfile or not self.cafile:
            raise ValueError("mTLS certificate, key, and CA files must be provided for server-to-server communication.")

        # Create mTLS context with client certificate
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        # Determine the remote port - use mtls_port from config, or default to 8443
        remote_ip = remote['ip']
        remote_port = remote.get('mtls_port', self.DEFAULT_MTLS_PORT)
        
        # Build the URL with explicit port if specified
        if ':' in remote_ip:
            # IP already includes port
            url = f"https://{remote_ip}/key-exchange"
        else:
            url = f"https://{remote_ip}:{remote_port}/key-exchange"

        print(f"Sending key {kem_payload.key_id} to remote SKIP server at {url}")
        async with httpx.AsyncClient(verify=ctx) as client:
            response = await client.post(url, json=kem_payload.model_dump())
            if response.status_code != 200:
                print(f"Remote server returned {response.status_code}: {response.text}", file=sys.stderr)
                raise HTTPException(status_code=response.status_code, detail=response.text)
        print(f"Key {kem_payload.key_id} successfully sent to {remote_system_id}")
        return True

    def _create_psk_ssl_socket(self, sock, server_side: bool = True):
        """Wrap a socket with TLS-PSK using sslpsk3."""
        hint = self.psk_identity.encode() if isinstance(self.psk_identity, str) else self.psk_identity
        if server_side:
            return sslpsk3.wrap_socket(
                sock,
                server_side=True,
                ssl_version=ssl.PROTOCOL_TLS,
                ciphers=PSK_CIPHER_SUITES,
                psk=self._get_psk_for_identity,
                hint=hint,
            )
        else:
            return sslpsk3.wrap_socket(
                sock,
                server_side=False,
                ssl_version=ssl.PROTOCOL_TLS,
                ciphers=PSK_CIPHER_SUITES,
                psk=self._get_psk_for_hint,
            )

    def _handle_psk_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Handle a single TLS-PSK client connection."""
        ssl_sock = None
        try:
            # Wrap the socket with TLS-PSK
            ssl_sock = self._create_psk_ssl_socket(client_sock, server_side=True)
            print(f"TLS-PSK handshake successful from {client_addr[0]}:{client_addr[1]}")
            
            # Read HTTP request
            request_data = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                # Check if we have a complete HTTP request (headers end with \r\n\r\n)
                if b"\r\n\r\n" in request_data:
                    break
            
            if not request_data:
                return
            
            # Parse HTTP request
            request_text = request_data.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")
            if not lines:
                self._send_http_response(ssl_sock, 400, {"error": "Bad Request"})
                return
            
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                self._send_http_response(ssl_sock, 400, {"error": "Bad Request"})
                return
            
            method = parts[0]
            path = parts[1]
            
            # Parse query parameters
            query_params = {}
            if "?" in path:
                path, query_string = path.split("?", 1)
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        query_params[key] = value
            
            # Route the request
            response = self._route_request(method, path, query_params)
            self._send_http_response(ssl_sock, response["status"], response["body"])
            
            # Log the request
            print(f"{client_addr[0]} - \"{method} {parts[1]}\" {response['status']}")
            
        except ssl.SSLError as e:
            print(f"TLS-PSK handshake failed for {client_addr}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error handling client {client_addr}: {e}", file=sys.stderr)
        finally:
            try:
                if ssl_sock:
                    ssl_sock.shutdown(socket.SHUT_RDWR)
                    ssl_sock.close()
                else:
                    client_sock.close()
            except Exception:
                pass

    def _send_http_response(self, sock, status_code: int, body: dict) -> None:
        """Send an HTTP response over the socket."""
        status_messages = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }
        status_message = status_messages.get(status_code, "Unknown")
        body_json = json.dumps(body)
        response = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_json)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body_json}"
        )
        sock.sendall(response.encode("utf-8"))

    def _route_request(self, method: str, path: str, query_params: dict) -> dict:
        """Route HTTP request to appropriate handler."""
        if method != "GET":
            return {"status": 405, "body": {"detail": "Method not allowed. This server only supports GET requests."}}
        
        if path == "/capabilities":
            remote_system_ids = [r["id"] for r in self.config.get("remoteSystems", [])]
            return {
                "status": 200,
                "body": {
                    "entropy": True,
                    "key": True,
                    "algorithm": self.config.get("algorithm"),
                    "localSystemID": self.config.get("localSystemID"),
                    "remoteSystemID": remote_system_ids,
                },
            }
        
        elif path == "/entropy":
            minentropy_str = query_params.get("minentropy")
            bits_to_generate = self.config.get("default_entropy_bits", 256)
            if minentropy_str:
                try:
                    minentropy = int(minentropy_str)
                    if minentropy not in [128, 192, 256]:
                        return {"status": 400, "body": {"detail": "minentropy must be 128, 192, or 256 bits."}}
                    bits_to_generate = minentropy
                except ValueError:
                    return {"status": 400, "body": {"detail": "Invalid minentropy value."}}
            
            num_bytes = bits_to_generate // 8
            random_string = secrets.token_hex(num_bytes)
            return {"status": 200, "body": {"randomStr": random_string, "minentropy": bits_to_generate}}
        
        elif path == "/key":
            remote_system_id = query_params.get("remoteSystemID")
            if not remote_system_id:
                return {"status": 400, "body": {"detail": "remoteSystemID query parameter is required."}}
            
            remote_ids = [r["id"] for r in self.config.get("remoteSystems", [])]
            if remote_system_id not in remote_ids:
                return {"status": 400, "body": {"detail": f"Unknown remoteSystemID '{remote_system_id}'."}}
            
            size_str = query_params.get("size")
            key_size_bits = self.config.get("default_key_size_bits", 256)
            if size_str:
                try:
                    size = int(size_str)
                    if size not in [128, 192, 256]:
                        return {"status": 400, "body": {"detail": "Key size must be one of 128, 192, or 256 bits."}}
                    key_size_bits = size
                except ValueError:
                    return {"status": 400, "body": {"detail": "Invalid size value."}}
            
            # Generate key using KEM encapsulation
            key_id = uuid.uuid4().hex
            remote_system = next((r for r in self.config.get("remoteSystems", []) if r["id"] == remote_system_id), None)
            if not remote_system:
                return {"status": 500, "body": {"detail": f"Remote system '{remote_system_id}' not found."}}
            
            try:
                remote_pub_key = bytes.fromhex(remote_system.get("pubkey", ""))
                ciphertext, shared_secret = encrypt(remote_pub_key)
            except Exception as e:
                print(f"KEM encryption error: {e}", file=sys.stderr)
                return {"status": 500, "body": {"detail": "Failed to encrypt key with remote public key."}}
            
            kem_payload = KEMPayload(
                system_id=self.local_system_id,
                key_id=key_id,
                length=key_size_bits,  # type: ignore[arg-type]
                ciphertext=ciphertext.hex(),
            )
            
            self.key_records[key_id] = remote_system_id
            
            # Send key to remote SKIP server via mTLS
            try:
                import asyncio
                # Run the async send in a new event loop (we're in a sync context)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(self.send_key_to_remote(remote_system_id, kem_payload))
                finally:
                    loop.close()
            except Exception as e:
                print(f"Failed to send key to remote system: {e}", file=sys.stderr)
                return {"status": 500, "body": {"detail": f"Failed to send key to remote system: {e}"}}
            
            # Truncate the shared secret to the requested key size
            if key_size_bits != 256:
                shared_secret = shared_secret[:key_size_bits // 8]
            
            return {"status": 200, "body": {"keyId": key_id, "key": shared_secret.hex()}}
        
        elif path.startswith("/key/"):
            key_id = path[5:]  # Extract key_id from /key/{key_id}
            if key_id in self.keystore.list_keys():
                key = self.keystore.get(key_id)
                self.keystore.delete(key_id)
                return {"status": 200, "body": {"keyId": key_id, "key": key}}
            return {"status": 400, "body": {"detail": f"Key for keyId '{key_id}' not found."}}
        
        else:
            return {"status": 404, "body": {"detail": "Not found."}}

    def run(self):
        if self.use_psk and self.psk_keys:
            # Run custom TLS-PSK server using sslpsk3 for router clients
            # Also start a secondary mTLS server for server-to-server communication
            print(f"Starting TLS-PSK server on {self.host}:{self.port}")
            print(f"PSK identity hint: {self.psk_identity}")
            print(f"Loaded {len(self.psk_keys)} PSK identities")
            
            # Start mTLS server for server-to-server on mtls_port (default 8443) if certs are configured
            if self.certfile and self.keyfile and self.cafile:
                print(f"Starting mTLS server for server-to-server on {self.host}:{self.mtls_port}")
                mtls_thread = threading.Thread(
                    target=self._run_mtls_server,
                    args=(self.host, self.mtls_port),
                    daemon=True,
                )
                mtls_thread.start()
            else:
                print("Warning: mTLS not configured - server-to-server communication will fail")
            
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(128)
            
            print(f"TLS-PSK server listening on {self.host}:{self.port}")
            
            try:
                while True:
                    client_sock, client_addr = server_sock.accept()
                    thread = threading.Thread(
                        target=self._handle_psk_client,
                        args=(client_sock, client_addr),
                        daemon=True,
                    )
                    thread.start()
            except KeyboardInterrupt:
                print("\nShutting down TLS-PSK server...")
            finally:
                server_sock.close()

        elif self.use_ssl:
            if not self.certfile or not self.keyfile or not self.cafile:
                raise ValueError("SSL is enabled but certfile, keyfile, and cafile must be provided.")
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            ssl_context.load_verify_locations(cafile=self.cafile)
            config = uvicorn.Config(self.app, host=self.host, port=self.port)
            config.load()
            config.ssl = ssl_context
            server = uvicorn.Server(config)
            server.run()

        else:
            uvicorn.run(self.app, host=self.host, port=self.port)

    def _run_mtls_server(self, host: str, port: int) -> None:
        """Run a secondary mTLS server for server-to-server communication."""
        if not self.certfile or not self.keyfile or not self.cafile:
            raise ValueError("mTLS server requires certfile, keyfile, and cafile to be configured.")
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        ssl_context.load_verify_locations(cafile=self.cafile)
        ssl_context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate for mTLS
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(128)
        
        print(f"mTLS server listening on {host}:{port}")
        
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                thread = threading.Thread(
                    target=self._handle_mtls_client,
                    args=(client_sock, client_addr, ssl_context),
                    daemon=True,
                )
                thread.start()
            except Exception as e:
                print(f"mTLS server error: {e}", file=sys.stderr)

    def _handle_mtls_client(self, client_sock: socket.socket, client_addr: Tuple[str, int], ssl_context: ssl.SSLContext) -> None:
        """Handle a single mTLS client connection (server-to-server)."""
        ssl_sock = None
        try:
            ssl_sock = ssl_context.wrap_socket(client_sock, server_side=True)
            print(f"mTLS handshake successful from {client_addr[0]}:{client_addr[1]}")
            
            # Read HTTP request (including body for POST)
            request_data = b""
            content_length = 0
            headers_complete = False
            
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                
                if not headers_complete and b"\r\n\r\n" in request_data:
                    headers_complete = True
                    # Parse Content-Length header
                    header_part = request_data.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
                    for line in header_part.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":", 1)[1].strip())
                            break
                
                if headers_complete:
                    # Check if we have the complete body
                    header_end = request_data.find(b"\r\n\r\n") + 4
                    body_received = len(request_data) - header_end
                    if body_received >= content_length:
                        break
            
            if not request_data:
                return
            
            # Parse HTTP request
            request_text = request_data.decode("utf-8", errors="replace")
            header_part, body_part = request_text.split("\r\n\r\n", 1) if "\r\n\r\n" in request_text else (request_text, "")
            lines = header_part.split("\r\n")
            
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                self._send_http_response(ssl_sock, 400, {"error": "Bad Request"})
                return
            
            method = parts[0]
            path = parts[1]
            
            # Route the request (handle POST for /key-exchange)
            if method == "POST" and path == "/key-exchange":
                response = self._handle_key_exchange_post(body_part)
            else:
                # Parse query parameters for GET requests
                query_params = {}
                if "?" in path:
                    path, query_string = path.split("?", 1)
                    for param in query_string.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            query_params[key] = value
                response = self._route_request(method, path, query_params)
            
            self._send_http_response(ssl_sock, response["status"], response["body"])
            print(f"mTLS {client_addr[0]} - \"{method} {parts[1]}\" {response['status']}")
            
        except ssl.SSLError as e:
            print(f"mTLS handshake failed for {client_addr}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error handling mTLS client {client_addr}: {e}", file=sys.stderr)
        finally:
            try:
                if ssl_sock:
                    ssl_sock.shutdown(socket.SHUT_RDWR)
                    ssl_sock.close()
                else:
                    client_sock.close()
            except Exception:
                pass

    def _handle_key_exchange_post(self, body: str) -> dict:
        """Handle POST /key-exchange for server-to-server key exchange."""
        try:
            payload = json.loads(body)
            remote_system_id = payload.get("system_id")
            key_id = payload.get("key_id")
            length = payload.get("length", 256)
            ciphertext = payload.get("ciphertext")
            
            if not all([remote_system_id, key_id, ciphertext]):
                return {"status": 400, "body": {"detail": "Missing required fields."}}
            
            with SecureKeyLoader(self.kem_priv_key_path) as priv_key:
                shared_secret = decrypt(priv_key, bytes.fromhex(ciphertext))
                if length != 256:
                    shared_secret = shared_secret[:length // 8]
                self.keystore.set(key_id, shared_secret.hex())
            
            self.key_records[key_id] = remote_system_id
            
            return {
                "status": 200,
                "body": {
                    "status": "success",
                    "message": f"Key with keyId {key_id} successfully received.",
                },
            }
        except json.JSONDecodeError:
            return {"status": 400, "body": {"detail": "Invalid JSON body."}}
        except Exception as e:
            print(f"Key exchange error: {e}", file=sys.stderr)
            return {"status": 400, "body": {"detail": "Failed to decapsulate key."}}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the SkipServer.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server.")
    parser.add_argument("--port", type=int, default=443, help="Port to bind the server.")
    parser.add_argument("--config", default="/data/appdata/config/skip.yaml", help="Path to the configuration file.")
    args = parser.parse_args()

    server = SkipServer(
        host=args.host,
        port=args.port,
        config_path=args.config
    )