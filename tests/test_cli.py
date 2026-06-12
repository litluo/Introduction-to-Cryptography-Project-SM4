# tests/test_cli.py

import pytest
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from io import StringIO

from src.cli import SM4VaultCLI


class TestSM4VaultCLI:
    """CLI测试类"""
    
    def setup_method(self):
        """测试前准备"""
        self.test_dir = tempfile.mkdtemp()
        self.cli = SM4VaultCLI()
    
    def teardown_method(self):
        """测试后清理"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_format_size(self):
        """测试文件大小格式化"""
        assert self.cli.format_size(0) == "0.00 B"
        assert self.cli.format_size(1023) == "1023.00 B"
        assert self.cli.format_size(1024) == "1.00 KB"
        assert self.cli.format_size(1024*1024) == "1.00 MB"
        assert self.cli.format_size(1024*1024*1024) == "1.00 GB"
    
    @patch('src.cli.Prompt.ask')
    @patch('src.cli.Confirm.ask')
    def test_initialize_vault(self, mock_confirm, mock_prompt):
        """测试初始化文件库"""
        vault_path = os.path.join(self.test_dir, "test_vault")
        
        # 模拟用户输入
        mock_prompt.side_effect = [vault_path, "test_password", "test_password"]
        mock_confirm.return_value = True
        
        # 模拟VaultManager
        with patch('src.cli.VaultManager') as MockVaultManager:
            mock_vault = MagicMock()
            MockVaultManager.return_value = mock_vault
            
            self.cli.initialize_vault()
            
            # 验证调用
            MockVaultManager.assert_called_once_with(vault_path)
            mock_vault.initialize.assert_called_once_with("test_password")
    
    @patch('src.cli.Prompt.ask')
    def test_open_vault(self, mock_prompt):
        """测试打开文件库"""
        vault_path = os.path.join(self.test_dir, "test_vault")
        
        # 模拟用户输入
        mock_prompt.side_effect = [vault_path, "test_password"]
        
        # 模拟VaultManager
        with patch('src.cli.VaultManager') as MockVaultManager:
            mock_vault = MagicMock()
            mock_vault.unlock.return_value = True
            MockVaultManager.return_value = mock_vault
            
            self.cli.open_vault()
            
            # 验证调用
            MockVaultManager.assert_called_once_with(vault_path)
            mock_vault.unlock.assert_called_once_with("test_password")
    
    @patch('src.cli.Prompt.ask')
    def test_open_vault_wrong_password(self, mock_prompt):
        """测试打开文件库密码错误"""
        vault_path = os.path.join(self.test_dir, "test_vault")
        
        # 模拟用户输入
        mock_prompt.side_effect = [vault_path, "wrong_password"]
        
        # 模拟VaultManager
        with patch('src.cli.VaultManager') as MockVaultManager:
            mock_vault = MagicMock()
            mock_vault.unlock.return_value = False
            MockVaultManager.return_value = mock_vault
            
            self.cli.open_vault()
            
            # 验证调用
            MockVaultManager.assert_called_once_with(vault_path)
            mock_vault.unlock.assert_called_once_with("wrong_password")
    
    def test_display_files(self):
        """测试显示文件列表"""
        files = [
            {
                "id": "test-id-1",
                "original_name": "test1.txt",
                "file_size": 1024,
                "created_at": "2026-01-01T00:00:00Z"
            },
            {
                "id": "test-id-2",
                "original_name": "test2.txt",
                "file_size": 2048,
                "created_at": "2026-01-02T00:00:00Z"
            }
        ]
        
        # 捕获输出
        import io
        from rich.console import Console
        
        console = Console(file=io.StringIO())
        self.cli.console = console
        
        self.cli.display_files(files)
        
        output = console.file.getvalue()
        assert "test1.txt" in output
        assert "test2.txt" in output
        assert "1.00 KB" in output
        assert "2.00 KB" in output
