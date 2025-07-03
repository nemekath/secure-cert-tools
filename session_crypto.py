#!/usr/bin/env python3
"""
Session-Based Cryptography Manager

Provides server-side session-specific encryption for private keys using ECDH key exchange
and AES-GCM encryption to protect against malicious root access.

Security Features:
- Worker-specific entropy generation
- ECDH key exchange with browser clients
- AES-GCM encryption for private keys
- Automatic session cleanup and expiration
- Memory protection and secure key handling
"""

import os
import secrets
import time
import threading
import json
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Set up logging
logger = logging.getLogger(__name__)

@dataclass
class SessionData:
    """Session data container with expiration tracking"""
    session_key: bytes
    worker_private_key: ec.EllipticCurvePrivateKey
    worker_public_key: ec.EllipticCurvePublicKey
    created_at: float
    expires_at: float
    client_ip: str

class SessionCryptoManager:
    """
    Manages session-based encryption for private key protection against root access
    """
    
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize session crypto manager
        
        Args:
            session_timeout: Session timeout in seconds (default: 1 hour)
        """
        # Worker-specific entropy (regenerated per worker restart)
        self.worker_entropy = secrets.token_bytes(32)
        self.worker_id = secrets.token_hex(16)
        self.session_timeout = session_timeout
        
        # Thread-safe session storage
        self.active_sessions: Dict[str, SessionData] = {}
        self.session_lock = threading.RLock()
        
        # Session cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_sessions_loop, 
            daemon=True,
            name=f"SessionCleanup-{self.worker_id[:8]}"
        )
        self.cleanup_running = True
        self.cleanup_thread.start()
        
        # Statistics
        self.stats = {
            'sessions_created': 0,
            'sessions_expired': 0,
            'encryption_operations': 0,
            'cleanup_runs': 0,
            'start_time': time.time()
        }
        
        logger.info(f"SessionCryptoManager initialized for worker {self.worker_id[:8]}...")
        logger.info(f"Session timeout: {session_timeout}s, Worker entropy: {len(self.worker_entropy)} bytes")
    
    def create_session_encryption(self, session_id: str, client_public_key_data: bytes, 
                                client_entropy: bytes, client_ip: str = "unknown") -> Dict[str, Any]:
        """
        Create session-specific encryption for private key protection
        
        Args:
            session_id: Unique session identifier from client
            client_public_key_data: Client's ECDH public key (raw format)
            client_entropy: Client-generated entropy bytes
            client_ip: Client IP address for logging
            
        Returns:
            Dict containing session encryption data
        """
        try:
            logger.debug(f"Creating session encryption for {session_id[:8]}... from {client_ip}")
            
            # Validate inputs
            if len(client_public_key_data) != 64:  # 32 bytes x + 32 bytes y for P-256
                raise ValueError(f"Invalid client public key length: {len(client_public_key_data)}")
            
            if len(client_entropy) != 32:
                raise ValueError(f"Invalid client entropy length: {len(client_entropy)}")
            
            # Generate worker ECDH key pair
            worker_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            worker_public_key = worker_private_key.public_key()
            
            # Import client's public key from raw coordinates
            client_public_key = self._import_client_public_key(client_public_key_data)
            
            # Perform ECDH key exchange
            shared_secret = worker_private_key.exchange(ec.ECDH(), client_public_key)
            
            # Derive session encryption key using HKDF
            session_key = self._derive_session_key(shared_secret, client_entropy)
            
            # Export worker public key for client
            worker_public_key_data = self._export_worker_public_key(worker_public_key)
            
            # Store session data with expiration
            session_data = SessionData(
                session_key=session_key,
                worker_private_key=worker_private_key,
                worker_public_key=worker_public_key,
                created_at=time.time(),
                expires_at=time.time() + self.session_timeout,
                client_ip=client_ip
            )
            
            with self.session_lock:
                self.active_sessions[session_id] = session_data
                self.stats['sessions_created'] += 1
            
            logger.info(f"Session encryption created for {session_id[:8]}... from {client_ip}")
            
            return {
                'session_key': session_key,
                'worker_public_key_data': list(worker_public_key_data)
            }
            
        except Exception as e:
            logger.error(f"Failed to create session encryption for {session_id[:8]}...: {str(e)}")
            raise ValueError(f"Session encryption failed: {str(e)}")
    
    def encrypt_private_key(self, session_id: str, private_key_pem: str) -> Dict[str, Any]:
        """
        Encrypt private key using session-specific encryption
        
        Args:
            session_id: Session identifier
            private_key_pem: Private key in PEM format
            
        Returns:
            Dict containing encrypted data and metadata
        """
        # Validate session and get session data
        session_data = self._get_valid_session(session_id)
        
        try:
            logger.debug(f"Encrypting private key for session {session_id[:8]}...")
            
            # Encrypt private key using AES-GCM
            aesgcm = AESGCM(session_data.session_key)
            iv = secrets.token_bytes(12)  # 96-bit IV for GCM
            
            # Additional authenticated data (AAD) for integrity
            aad = f"session:{session_id}:worker:{self.worker_id}".encode('utf-8')
            
            encrypted_data = aesgcm.encrypt(
                iv, 
                private_key_pem.encode('utf-8'), 
                aad
            )
            
            # Update statistics
            with self.session_lock:
                self.stats['encryption_operations'] += 1
            
            # Export worker public key for client decryption
            worker_public_key_data = self._export_worker_public_key(session_data.worker_public_key)
            
            logger.info(f"Private key encrypted for session {session_id[:8]}... ({len(encrypted_data)} bytes)")
            
            return {
                'encrypted_data': list(encrypted_data),
                'iv': list(iv),
                'worker_public_key_data': list(worker_public_key_data),
                'session_id': session_id,
                'encryption_algorithm': 'AES-GCM-256'
            }
            
        except Exception as e:
            logger.error(f"Private key encryption failed for {session_id[:8]}...: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")
    
    def _get_valid_session(self, session_id: str) -> SessionData:
        """Get and validate session data"""
        with self.session_lock:
            if session_id not in self.active_sessions:
                raise ValueError("Invalid or expired session")
            
            session_data = self.active_sessions[session_id]
            
            # Check session expiration
            current_time = time.time()
            if current_time > session_data.expires_at:
                del self.active_sessions[session_id]
                self.stats['sessions_expired'] += 1
                raise ValueError("Session has expired")
            
            return session_data
    
    def _import_client_public_key(self, client_public_key_data: bytes) -> ec.EllipticCurvePublicKey:
        """Import client's public key from raw format"""
        try:
            # P-256 public key: 0x04 + 32 bytes x + 32 bytes y (uncompressed format)
            uncompressed_key = bytes([0x04]) + client_public_key_data
            
            client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), 
                uncompressed_key
            )
            
            return client_public_key
            
        except Exception as e:
            logger.error(f"Failed to import client public key: {str(e)}")
            raise ValueError(f"Invalid client public key: {str(e)}")
    
    def _derive_session_key(self, shared_secret: bytes, client_entropy: bytes) -> bytes:
        """Derive session encryption key using HKDF"""
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES-GCM
                salt=client_entropy + self.worker_entropy,
                info=b"PrivateKeyEncryption",
                backend=default_backend()
            )
            
            session_key = hkdf.derive(shared_secret)
            return session_key
            
        except Exception as e:
            logger.error(f"Failed to derive session key: {str(e)}")
            raise ValueError(f"Key derivation failed: {str(e)}")
    
    def _export_worker_public_key(self, worker_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Export worker public key in raw format for client"""
        try:
            # Get public key coordinates
            public_numbers = worker_public_key.public_numbers()
            
            # Convert to 32-byte big-endian format (P-256)
            x_bytes = public_numbers.x.to_bytes(32, 'big')
            y_bytes = public_numbers.y.to_bytes(32, 'big')
            
            # Return raw coordinates (64 bytes total)
            return x_bytes + y_bytes
            
        except Exception as e:
            logger.error(f"Failed to export worker public key: {str(e)}")
            raise ValueError(f"Public key export failed: {str(e)}")
    
    def _cleanup_sessions_loop(self):
        """Background thread loop for cleaning up expired sessions"""
        logger.info(f"Session cleanup thread started for worker {self.worker_id[:8]}...")
        
        while self.cleanup_running:
            try:
                self._cleanup_expired_sessions()
                
                # Sleep for 5 minutes between cleanup runs
                for _ in range(300):  # 5 minutes = 300 seconds
                    if not self.cleanup_running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Session cleanup error: {str(e)}")
                time.sleep(60)  # Retry in 1 minute on error
        
        logger.info(f"Session cleanup thread stopped for worker {self.worker_id[:8]}...")
    
    def _cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        with self.session_lock:
            for session_id, session_data in list(self.active_sessions.items()):
                if current_time > session_data.expires_at:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.active_sessions[session_id]
                self.stats['sessions_expired'] += 1
            
            self.stats['cleanup_runs'] += 1
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            for session_id in expired_sessions[:5]:  # Log first 5 for debugging
                logger.debug(f"Expired session: {session_id[:8]}...")
    
    def get_session_count(self) -> int:
        """Get current number of active sessions"""
        with self.session_lock:
            return len(self.active_sessions)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get session manager statistics"""
        with self.session_lock:
            current_time = time.time()
            active_sessions = len(self.active_sessions)
            
            return {
                'worker_id': self.worker_id[:8] + '...',
                'active_sessions': active_sessions,
                'session_timeout': self.session_timeout,
                'uptime_seconds': current_time - self.stats.get('start_time', current_time),
                **self.stats
            }
    
    def cleanup_all_sessions(self):
        """Clean up all sessions (called on shutdown)"""
        logger.info(f"Cleaning up all sessions for worker {self.worker_id[:8]}...")
        
        with self.session_lock:
            session_count = len(self.active_sessions)
            self.active_sessions.clear()
        
        # Stop cleanup thread
        self.cleanup_running = False
        
        logger.info(f"Cleaned up {session_count} sessions")
    
    def __del__(self):
        """Cleanup on object destruction"""
        try:
            self.cleanup_all_sessions()
        except:
            pass  # Ignore errors during cleanup


# Global session manager instance (one per worker process)
_session_crypto_manager: Optional[SessionCryptoManager] = None

def get_session_crypto_manager() -> SessionCryptoManager:
    """Get or create the global session crypto manager"""
    global _session_crypto_manager
    
    if _session_crypto_manager is None:
        _session_crypto_manager = SessionCryptoManager()
        logger.info("Global session crypto manager created")
    
    return _session_crypto_manager

def cleanup_session_crypto_manager():
    """Cleanup the global session crypto manager"""
    global _session_crypto_manager
    
    if _session_crypto_manager is not None:
        _session_crypto_manager.cleanup_all_sessions()
        _session_crypto_manager = None
        logger.info("Global session crypto manager cleaned up")

# Module cleanup on exit
import atexit
atexit.register(cleanup_session_crypto_manager)
