import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import padding
from typing import Optional, List, Union
import logging

class GameSession:
    def __init__(self, session_id: str, cipher_type: str, 
                 rotation_interval: int = 15,
                 max_backup_keys: int = 3):
        self.session_id = session_id
        self.cipher_type = cipher_type
        self.key = os.urandom(32)
        self.created_at = datetime.now()
        self.last_rotation = self.created_at
        self.rotation_interval = timedelta(minutes=rotation_interval)
        self.backup_keys: List[bytes] = []
        self.max_backup_keys = max_backup_keys
        self.is_valid = True
        self.logger = logging.getLogger(f'session_{session_id}')
        
        self.logger.info(f"Session created: {session_id}")

    def should_rotate_key(self) -> bool:
        if not self.is_valid:
            return False
        return datetime.now() - self.last_rotation >= self.rotation_interval

    def rotate_key(self) -> bytes:
        try:
            # Store current key as backup
            self._add_backup_key(self.key)
            
            # Generate new key
            self.key = os.urandom(32)
            self.last_rotation = datetime.now()
            
            self.logger.info(f"Key rotated for session {self.session_id}")
            return self.key
        except Exception as e:
            self.logger.error(f"Key rotation failed: {str(e)}")
            raise

    def _add_backup_key(self, key: bytes) -> None:
        self.backup_keys.append(key)
        if len(self.backup_keys) > self.max_backup_keys:
            self.backup_keys.pop(0)

    def invalidate(self) -> None:
        self.is_valid = False
        self.logger.info(f"Session invalidated: {self.session_id}")

    @staticmethod
    def pad_data(data: Union[str, bytes]) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        padder = padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()

    @staticmethod
    def unpad_data(padded_data: bytes) -> bytes:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def __str__(self) -> str:
        return f"GameSession(id={self.session_id}, created={self.created_at}, valid={self.is_valid})"