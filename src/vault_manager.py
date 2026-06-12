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
    
    def _encrypt_fek(self, fek: bytes) -> bytes:
        """使用MK加密FEK"""
        from .sm4_cipher import ctr_encrypt
        nonce = generate_nonce()
        encrypted_fek = ctr_encrypt(self.master_key[:16], nonce, fek)
        return nonce + encrypted_fek
    
    def _decrypt_fek(self, encrypted_fek_with_nonce: bytes) -> bytes:
        """使用MK解密FEK"""
        from .sm4_cipher import ctr_decrypt
        nonce = encrypted_fek_with_nonce[:8]
        encrypted_fek = encrypted_fek_with_nonce[8:]
        return ctr_decrypt(self.master_key[:16], nonce, encrypted_fek)
    
    def import_file(self, file_path: str, secure_delete: bool = False):
        """导入文件到文件库"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if self.master_key is None:
            raise ValueError("文件库未解锁")
        
        fek = generate_key()
        nonce = generate_nonce()
        
        file_id = str(uuid.uuid4())
        encrypted_name = f"{file_id}.enc"
        encrypted_path = os.path.join(self.vault_path, encrypted_name)
        
        encrypt_file(file_path, encrypted_path, fek, nonce)
        
        encrypted_fek = self._encrypt_fek(fek)
        
        import hashlib
        with open(file_path, 'rb') as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        
        file_entry = {
            "id": file_id,
            "original_name": os.path.basename(file_path),
            "encrypted_name": encrypted_name,
            "file_size": os.path.getsize(file_path),
            "encrypted_fek": base64.b64encode(encrypted_fek).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "checksum": checksum
        }
        
        self.index["files"].append(file_entry)
        self._save_index()
        
        if secure_delete:
            secure_delete_file(file_path)
    
    def export_file(self, file_id: str, output_path: str):
        """从文件库导出文件"""
        if self.master_key is None:
            raise ValueError("文件库未解锁")
        
        file_entry = None
        for entry in self.index["files"]:
            if entry["id"] == file_id:
                file_entry = entry
                break
        
        if file_entry is None:
            raise FileNotFoundError(f"文件不存在: {file_id}")
        
        encrypted_fek_with_nonce = base64.b64decode(file_entry["encrypted_fek"])
        fek = self._decrypt_fek(encrypted_fek_with_nonce)
        
        nonce = base64.b64decode(file_entry["nonce"])
        
        encrypted_path = os.path.join(self.vault_path, file_entry["encrypted_name"])
        decrypt_file(encrypted_path, output_path, fek, nonce)
    
    def list_files(self) -> list:
        """列出文件库中的文件"""
        if self.index is None:
            raise ValueError("文件库未解锁")
        
        files = []
        for entry in self.index["files"]:
            files.append({
                "id": entry["id"],
                "original_name": entry["original_name"],
                "file_size": entry["file_size"],
                "created_at": entry["created_at"]
            })
        
        return files
    
    def delete_file(self, file_id: str, secure_delete: bool = False):
        """从文件库删除文件"""
        if self.master_key is None:
            raise ValueError("文件库未解锁")
        
        file_entry = None
        file_index = None
        for i, entry in enumerate(self.index["files"]):
            if entry["id"] == file_id:
                file_entry = entry
                file_index = i
                break
        
        if file_entry is None:
            raise FileNotFoundError(f"文件不存在: {file_id}")
        
        encrypted_path = os.path.join(self.vault_path, file_entry["encrypted_name"])
        if os.path.exists(encrypted_path):
            if secure_delete:
                secure_delete_file(encrypted_path)
            else:
                os.remove(encrypted_path)
        
        self.index["files"].pop(file_index)
        self._save_index()
