import os
import json
import uuid
import base64
from datetime import datetime

from .crypto_utils import pbkdf2_hmac_sha256, generate_salt, generate_key, generate_nonce, secure_delete_file
from .sm4_cipher import encrypt_file, decrypt_file


class VaultManager:
    def __init__(self, vault_path: str):
        """初始化文件库管理器"""
        self.vault_path = vault_path
        self.index_path = os.path.join(vault_path, "vault_index.json")
        self.master_key = None
        self.index = None
    
    def initialize(self, password: str):
        """初始化新文件库"""
        # 创建目录
        os.makedirs(self.vault_path, exist_ok=True)
        
        # 生成salt
        salt = generate_salt()
        
        # 派生主密钥
        self.master_key = pbkdf2_hmac_sha256(password, salt)
        
        # 创建验证哈希
        verification_hash = pbkdf2_hmac_sha256(password, salt, iterations=1)
        
        # 创建初始索引
        self.index = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "master_salt": base64.b64encode(salt).decode('utf-8'),
            "pbkdf2_iterations": 100000,
            "verification_hash": base64.b64encode(verification_hash).decode('utf-8'),
            "files": []
        }
        
        # 保存索引
        self._save_index()
    
    def unlock(self, password: str) -> bool:
        """解锁文件库（验证密码）"""
        # 读取索引
        self._load_index()
        
        # 获取salt
        salt = base64.b64decode(self.index["master_salt"])
        
        # 派生主密钥
        self.master_key = pbkdf2_hmac_sha256(password, salt)
        
        # 验证密码
        verification_hash = pbkdf2_hmac_sha256(password, salt, iterations=1)
        stored_hash = base64.b64decode(self.index["verification_hash"])
        
        if verification_hash != stored_hash:
            return False
        
        return True
    
    def _load_index(self):
        """加载索引文件"""
        if not os.path.exists(self.index_path):
            raise FileNotFoundError("文件库索引不存在")
        
        with open(self.index_path, 'r', encoding='utf-8') as f:
            self.index = json.load(f)
    
    def _save_index(self):
        """保存索引文件"""
        with open(self.index_path, 'w', encoding='utf-8') as f:
            json.dump(self.index, f, indent=2, ensure_ascii=False)
