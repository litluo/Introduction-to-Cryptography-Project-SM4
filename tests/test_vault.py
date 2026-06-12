import pytest
import os
import tempfile
import shutil
from src.vault_manager import VaultManager


class TestVaultManager:
    """文件库管理测试"""

    def setup_method(self):
        """测试前准备"""
        self.test_dir = tempfile.mkdtemp()
        self.vault_path = os.path.join(self.test_dir, "vault")

    def teardown_method(self):
        """测试后清理"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_initialize(self):
        """测试文件库初始化"""
        vault = VaultManager(self.vault_path)
        vault.initialize("test_password")

        assert os.path.exists(self.vault_path)
        assert os.path.exists(os.path.join(self.vault_path, "vault_index.json"))

    def test_unlock(self):
        """测试文件库解锁"""
        vault = VaultManager(self.vault_path)
        vault.initialize("test_password")

        vault2 = VaultManager(self.vault_path)
        result = vault2.unlock("test_password")
        assert result is True

    def test_unlock_wrong_password(self):
        """测试错误密码"""
        vault = VaultManager(self.vault_path)
        vault.initialize("test_password")

        vault2 = VaultManager(self.vault_path)
        result = vault2.unlock("wrong_password")
        assert result is False

    def test_import_export_file(self):
        """测试文件导入导出"""
        vault = VaultManager(self.vault_path)
        vault.initialize("test_password")

        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Hello, World!")

        vault.import_file(test_file)

        files = vault.list_files()
        assert len(files) == 1
        assert files[0]["original_name"] == "test.txt"

        export_path = os.path.join(self.test_dir, "exported.txt")
        vault.export_file(files[0]["id"], export_path)

        with open(export_path, 'r') as f:
            content = f.read()
        assert content == "Hello, World!"

    def test_delete_file(self):
        """测试文件删除"""
        vault = VaultManager(self.vault_path)
        vault.initialize("test_password")

        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Hello, World!")

        vault.import_file(test_file)

        files = vault.list_files()
        assert len(files) == 1

        vault.delete_file(files[0]["id"])

        files = vault.list_files()
        assert len(files) == 0

    def test_change_password(self):
        """测试密码修改"""
        vault = VaultManager(self.vault_path)
        vault.initialize("old_password")

        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Hello, World!")

        vault.import_file(test_file)

        vault.change_password("old_password", "new_password")

        vault2 = VaultManager(self.vault_path)
        result = vault2.unlock("new_password")
        assert result is True

        files = vault2.list_files()
        assert len(files) == 1

        export_path = os.path.join(self.test_dir, "exported.txt")
        vault2.export_file(files[0]["id"], export_path)

        with open(export_path, 'r') as f:
            content = f.read()
        assert content == "Hello, World!"

    def test_change_password_multiple_files(self):
        """测试密码修改（多个文件）"""
        vault = VaultManager(self.vault_path)
        vault.initialize("old_password")

        # 创建多个测试文件
        test_file1 = os.path.join(self.test_dir, "test1.txt")
        with open(test_file1, 'w') as f:
            f.write("File 1 content")

        test_file2 = os.path.join(self.test_dir, "test2.txt")
        with open(test_file2, 'w') as f:
            f.write("File 2 content")

        test_file3 = os.path.join(self.test_dir, "test3.txt")
        with open(test_file3, 'w') as f:
            f.write("File 3 content")

        # 导入所有文件
        vault.import_file(test_file1)
        vault.import_file(test_file2)
        vault.import_file(test_file3)

        # 修改密码
        vault.change_password("old_password", "new_password")

        # 使用新密码解锁
        vault2 = VaultManager(self.vault_path)
        result = vault2.unlock("new_password")
        assert result is True

        # 验证所有文件仍然可访问
        files = vault2.list_files()
        assert len(files) == 3

        # 导出并验证每个文件的内容
        for file_entry in files:
            export_path = os.path.join(self.test_dir, f"exported_{file_entry['original_name']}")
            vault2.export_file(file_entry["id"], export_path)

            with open(export_path, 'r') as f:
                content = f.read()

            if file_entry["original_name"] == "test1.txt":
                assert content == "File 1 content"
            elif file_entry["original_name"] == "test2.txt":
                assert content == "File 2 content"
            elif file_entry["original_name"] == "test3.txt":
                assert content == "File 3 content"
