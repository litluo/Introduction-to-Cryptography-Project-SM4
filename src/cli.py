import os
import time
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

from .vault_manager import VaultManager
from .sm4_core import encrypt_block, decrypt_block


class SM4VaultCLI:
    def __init__(self):
        self.console = Console()
        self.vault = None

    def run(self):
        """运行CLI主循环"""
        while True:
            self.console.print("\n[bold blue]SM4保密文件库[/bold blue]")
            self.console.print("1. 初始化新文件库")
            self.console.print("2. 打开现有文件库")
            self.console.print("3. 退出")

            choice = Prompt.ask("请选择", choices=["1", "2", "3"])

            if choice == "1":
                self.initialize_vault()
            elif choice == "2":
                self.open_vault()
            elif choice == "3":
                self.console.print("[green]再见！[/green]")
                break

    def initialize_vault(self):
        """初始化新文件库"""
        vault_path = Prompt.ask("请输入文件库路径")
        password = Prompt.ask("请输入主密码", password=True)
        confirm_password = Prompt.ask("请确认主密码", password=True)

        if password != confirm_password:
            self.console.print("[red]密码不匹配[/red]")
            return

        try:
            self.vault = VaultManager(vault_path)
            self.vault.initialize(password)
            self.console.print("[green]文件库初始化成功[/green]")
            self.vault_menu()
        except Exception as e:
            self.console.print(f"[red]初始化失败: {e}[/red]")

    def open_vault(self):
        """打开现有文件库"""
        vault_path = Prompt.ask("请输入文件库路径")
        password = Prompt.ask("请输入主密码", password=True)

        try:
            self.vault = VaultManager(vault_path)
            if self.vault.unlock(password):
                self.console.print("[green]文件库解锁成功[/green]")
                self.vault_menu()
            else:
                self.console.print("[red]密码错误[/red]")
        except Exception as e:
            self.console.print(f"[red]打开失败: {e}[/red]")

    def vault_menu(self):
        """文件库操作菜单"""
        while True:
            self.console.print("\n[bold blue]文件库操作[/bold blue]")
            self.console.print("1. 导入文件")
            self.console.print("2. 导出文件")
            self.console.print("3. 查看文件列表")
            self.console.print("4. 删除文件")
            self.console.print("5. 修改密码")
            self.console.print("6. 性能测试")
            self.console.print("7. 返回主菜单")

            choice = Prompt.ask("请选择", choices=["1", "2", "3", "4", "5", "6", "7"])

            if choice == "1":
                self.import_file()
            elif choice == "2":
                self.export_file()
            elif choice == "3":
                self.list_files()
            elif choice == "4":
                self.delete_file()
            elif choice == "5":
                self.change_password()
            elif choice == "6":
                self.performance_test()
            elif choice == "7":
                self.vault = None
                break

    def display_files(self, files: list):
        """显示文件列表"""
        table = Table(title="文件库内容")

        table.add_column("ID", style="cyan")
        table.add_column("文件名", style="green")
        table.add_column("大小", style="magenta")
        table.add_column("导入时间", style="yellow")

        for file in files:
            table.add_row(
                file["id"],
                file["original_name"],
                self.format_size(file["file_size"]),
                file["created_at"]
            )

        self.console.print(table)

    def format_size(self, size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def import_file(self):
        """导入文件"""
        file_path = Prompt.ask("请输入要导入的文件路径")

        if not os.path.exists(file_path):
            self.console.print("[red]文件不存在[/red]")
            return

        secure_delete = Confirm.ask("是否安全删除原文件？", default=False)

        try:
            self.vault.import_file(file_path, secure_delete)
            self.console.print("[green]文件导入成功[/green]")
        except Exception as e:
            self.console.print(f"[red]导入失败: {e}[/red]")

    def export_file(self):
        """导出文件"""
        files = self.vault.list_files()

        if not files:
            self.console.print("[yellow]文件库为空[/yellow]")
            return

        self.display_files(files)

        file_id = Prompt.ask("请输入要导出的文件ID")
        output_path = Prompt.ask("请输入导出路径")

        try:
            self.vault.export_file(file_id, output_path)
            self.console.print("[green]文件导出成功[/green]")
        except Exception as e:
            self.console.print(f"[red]导出失败: {e}[/red]")

    def list_files(self):
        """查看文件列表"""
        files = self.vault.list_files()

        if not files:
            self.console.print("[yellow]文件库为空[/yellow]")
            return

        self.display_files(files)

    def delete_file(self):
        """删除文件"""
        files = self.vault.list_files()

        if not files:
            self.console.print("[yellow]文件库为空[/yellow]")
            return

        self.display_files(files)

        file_id = Prompt.ask("请输入要删除的文件ID")
        secure_delete = Confirm.ask("是否安全删除？", default=False)

        try:
            self.vault.delete_file(file_id, secure_delete)
            self.console.print("[green]文件删除成功[/green]")
        except Exception as e:
            self.console.print(f"[red]删除失败: {e}[/red]")

    def change_password(self):
        """修改密码"""
        old_password = Prompt.ask("请输入旧密码", password=True)
        new_password = Prompt.ask("请输入新密码", password=True)
        confirm_password = Prompt.ask("请确认新密码", password=True)

        if new_password != confirm_password:
            self.console.print("[red]新密码不匹配[/red]")
            return

        try:
            self.vault.change_password(old_password, new_password)
            self.console.print("[green]密码修改成功[/green]")
        except Exception as e:
            self.console.print(f"[red]密码修改失败: {e}[/red]")
