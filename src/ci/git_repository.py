import os
import subprocess
from typing import Dict, List


class GitRepository:
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._validate_repo()
        
    def _validate_repo(self) -> None:
        try:
            result = subprocess.run(
                ["git", "-C", self.repo_path, "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                check=True
            )
            if "true" not in result.stdout.lower():
                raise ValueError(f"Path is not a git repository: {self.repo_path}")
        except subprocess.SubprocessError:
            raise ValueError(f"Path is not a git repository: {self.repo_path}")

    def get_total_commits(self) -> int:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "rev-list", "--count", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        return int(result.stdout.strip())
         
    def get_latest_commit(self) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    
    def get_commit_by_number(self, n: int) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "rev-list", "--reverse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        commits = result.stdout.strip().split('\n')
        if 1 <= n <= len(commits):
            return commits[n - 1]
        else:
            raise ValueError(f"Commit number {n} is out of range. Total commits: {len(commits)}")
    def get_changed_files(self, commit_hash: str) -> list:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().split('\n')

    def get_diff_by_commit(self, commit_hash: str) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "show", commit_hash],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    
    def get_commit_files(self, commit_hash: str) -> List[Dict[str, str]]:
        result = subprocess.run(
            ["git", "-C", self.repo_path, "show", "--name-only", "--format=", commit_hash],
            capture_output=True,
            text=True,
            check=True
        )
        
        changed_files = [f for f in result.stdout.strip().split('\n') if f]
        code_changes = []
        
        for file_path in changed_files:
            full_path = os.path.join(self.repo_path, file_path)
            
            is_binary = self._is_git_binary_file(file_path, commit_hash)
            if is_binary or (os.path.isfile(full_path) and self._is_binary_file(full_path)):
                print(f"Skipping binary file: {file_path}")
                continue
                
            # Get the content of the file in the latest commit
            try:
                # Use text=False to get bytes and handle encoding safely
                result = subprocess.run(
                    ["git", "-C", self.repo_path, "show", f"{commit_hash}:{file_path}"],
                    capture_output=True,
                    text=False,  # Get bytes instead of assuming UTF-8
                    check=True
                )
                
                try:
                    content = result.stdout.decode('utf-8', errors='replace')
                except UnicodeError:
                    print(f"Warning: Could not decode {file_path} as UTF-8, skipping")
                    continue
                
                code_changes.append({
                    "filename": file_path,
                    "content": content,
                    "patch": self._get_file_patch(file_path, commit_hash)
                })
            except subprocess.SubprocessError as e:
                print(f"Error processing file {file_path}: {str(e)}")
                continue
                
        return code_changes
    
    def get_latest_commit_files(self) -> List[Dict[str, str]]:
        commit_hash = self.get_latest_commit()
        
        result = subprocess.run(
            ["git", "-C", self.repo_path, "show", "--name-only", "--format=", commit_hash],
            capture_output=True,
            text=True,
            check=True
        )
        
        changed_files = [f for f in result.stdout.strip().split('\n') if f]
        code_changes = []
        
        for file_path in changed_files:
            full_path = os.path.join(self.repo_path, file_path)
            
            is_binary = self._is_git_binary_file(file_path, commit_hash)
            if is_binary or (os.path.isfile(full_path) and self._is_binary_file(full_path)):
                print(f"Skipping binary file: {file_path}")
                continue
                
            # Get the content of the file in the latest commit
            try:
                # Use text=False to get bytes and handle encoding safely
                result = subprocess.run(
                    ["git", "-C", self.repo_path, "show", f"{commit_hash}:{file_path}"],
                    capture_output=True,
                    text=False,  # Get bytes instead of assuming UTF-8
                    check=True
                )
                
                # Try to decode as UTF-8 with error handling
                try:
                    content = result.stdout.decode('utf-8', errors='replace')
                except UnicodeError:
                    print(f"Warning: Could not decode {file_path} as UTF-8, skipping")
                    continue
                
                code_changes.append({
                    "filename": file_path,
                    "content": content,
                    "patch": self._get_file_patch(file_path, commit_hash)
                })
            except subprocess.SubprocessError as e:
                print(f"Error processing file {file_path}: {str(e)}")
                continue
                
        return code_changes
        
    def _is_git_binary_file(self, file_path: str, commit_hash: str) -> bool:
        try:
            result = subprocess.run(
                ["git", "-C", self.repo_path, "grep", "-I", "--quiet", ".", f"{commit_hash}:{file_path}"],
                capture_output=True,
                check=False
            )
            return result.returncode == 2
        except subprocess.SubprocessError:
            return True
            
    def _get_file_patch(self, file_path: str, commit_hash: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", self.repo_path, "show", "--format=", "--patch", f"{commit_hash}", "--", file_path],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.SubprocessError:
            return ""
            
    def _is_binary_file(self, file_path: str) -> bool:
        try:
            # Read a small chunk to check for binary content
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)  # Read first 8KB
                
            # Check for null bytes - common indicator of binary files
            if b'\x00' in chunk:
                return True
                
            if len(chunk) > 0:
                printable_count = sum(1 for byte in chunk if 32 <= byte <= 126 or byte in [9, 10, 13])
                printable_ratio = printable_count / len(chunk)
                
                if printable_ratio < 0.7:
                    return True
                
            try:
                chunk.decode('utf-8')
                return False
            except UnicodeDecodeError:
                return True
                
        except Exception:
            return True