import pytest
import os
import sys
import tempfile
import subprocess
from unittest.mock import patch, MagicMock
import argparse

# Add the project root to sys.path to make imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import main


@pytest.fixture
def temp_git_repo():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize git repo
        subprocess.run(["git", "init", temp_dir], check=True, capture_output=True)
        
        # Configure git user for the test repo
        subprocess.run(["git", "-C", temp_dir, "config", "user.name", "Test User"], check=True, capture_output=True)
        subprocess.run(["git", "-C", temp_dir, "config", "user.email", "test@example.com"], check=True, capture_output=True)
        
        # Create a sample file and commit it
        sample_file = os.path.join(temp_dir, "sample.py")
        with open(sample_file, "w") as f:
            f.write("print('Hello, world!')")
        
        subprocess.run(["git", "-C", temp_dir, "add", "sample.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", temp_dir, "commit", "-m", "Initial commit"], check=True, capture_output=True)
        
        yield temp_dir


class TestMain:
    
    @patch('argparse.ArgumentParser.parse_args')
    @patch('src.main.run_pipeline')
    def test_main_analyze_only(self, mock_run_pipeline, mock_parse_args, temp_git_repo):
        # Set up mock args
        mock_args = argparse.Namespace()
        mock_args.repo_path = temp_git_repo
        mock_args.patch = False
        mock_args.commit_all = False
        mock_parse_args.return_value = mock_args
        
        # Set up mock pipeline return value
        mock_run_pipeline.return_value = {
            "status": "completed",
            "bugs": [{"description": "Test bug", "vulnerability_type": "test"}],
            "summary": "Found 1 vulnerability"
        }
        
        # Call the main function
        with patch.dict('os.environ', {"OPENAI_API_KEY": "test_api_key"}):
            with patch('sys.exit') as mock_exit:
                main()
                mock_exit.assert_not_called()
        
        # Verify the pipeline was called with the correct path
        mock_run_pipeline.assert_called_once_with(temp_git_repo)
    
    @patch('argparse.ArgumentParser.parse_args')
    @patch('src.main.run_pipeline')
    @patch('src.main.VulnPatcher')
    def test_main_with_patching(self, mock_patcher_class, mock_run_pipeline, mock_parse_args, temp_git_repo):
        # Set up mock args
        mock_args = argparse.Namespace()
        mock_args.repo_path = temp_git_repo
        mock_args.patch = True
        mock_args.commit_all = False
        mock_parse_args.return_value = mock_args
        
        # Set up mock pipeline return value with vulnerabilities
        mock_run_pipeline.return_value = {
            "status": "completed",
            "bugs": [{"description": "Test bug", "vulnerability_type": "test"}],
            "summary": "Found 1 vulnerability"
        }
        
        # Set up mock patcher instance
        mock_patcher = MagicMock()
        mock_patcher.process_vulnerabilities.return_value = [
            {"applied_to_repo": True, "original_file": "sample.py"}
        ]
        mock_patcher_class.return_value = mock_patcher
        
        # Call the main function
        with patch.dict('os.environ', {"OPENAI_API_KEY": "test_api_key"}):
            main()
        
        # Verify that the patcher was initialized and patches were created
        mock_patcher_class.assert_called_once_with(temp_git_repo)
        mock_patcher.process_vulnerabilities.assert_called_once()
    
    @patch('argparse.ArgumentParser.parse_args')
    @patch('src.main.run_pipeline')
    @patch('src.main.VulnPatcher')
    def test_main_with_patching_no_vulnerabilities(self, mock_patcher_class, mock_run_pipeline, mock_parse_args, temp_git_repo):
        # Set up mock args
        mock_args = argparse.Namespace()
        mock_args.repo_path = temp_git_repo
        mock_args.patch = True
        mock_args.commit_all = False
        mock_parse_args.return_value = mock_args
        
        # Set up mock pipeline return value with no vulnerabilities
        mock_run_pipeline.return_value = {
            "status": "completed",
            "bugs": [],
            "summary": "No vulnerabilities found"
        }
        
        # Call the main function
        with patch.dict('os.environ', {"OPENAI_API_KEY": "test_api_key"}):
            main()
        
        # Verify that the patcher was not initialized since no bugs found
        mock_patcher_class.assert_not_called()
    
    @patch('os.path.isdir')
    @patch('src.main.GitRepository')
    @patch('src.main.run_pipeline')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_invalid_path(self, mock_parse_args, mock_run_pipeline, mock_git_repo, mock_isdir):
        """Test main function with an invalid repository path."""
        # Set up mock args with nonexistent path
        mock_args = argparse.Namespace()
        mock_args.repo_path = "/path/does/not/exist"
        mock_args.commit_all = False
        mock_args.patch = False
        mock_parse_args.return_value = mock_args
        
        # Mock path validation to fail
        mock_isdir.return_value = False
        
        # Call the main function and expect sys.exit
        with patch('sys.exit') as mock_exit:
            main()
            # Should exit with code 1 (can be called multiple times due to mocking)
            mock_exit.assert_called_with(1)
    
    @patch('src.main.GitRepository')
    @patch('src.main.run_pipeline')  
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_invalid_git_repo(self, mock_parse_args, mock_run_pipeline, mock_git_repo):
        """Test main function with a path that is not a git repository."""
        # Create a temporary directory that is not a git repo
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up mock args
            mock_args = argparse.Namespace()
            mock_args.repo_path = temp_dir
            mock_args.commit_all = False
            mock_args.patch = False
            mock_parse_args.return_value = mock_args
            
            # Mock GitRepository to raise an exception (simulating git repository error)
            mock_git_repo.side_effect = ValueError(f"Path is not a git repository: {temp_dir}")
            
            # Call the main function and expect sys.exit
            with patch('sys.exit') as mock_exit:
                main()
                # Should exit with code 1 (can be called multiple times due to mocking)
                mock_exit.assert_called_with(1)


class TestMainIntegration:
    
    @patch('src.main.run_pipeline')
    @patch('src.main.VulnPatcher')
    def test_end_to_end_with_patching(self, mock_patcher_class, mock_run_pipeline, temp_git_repo):
        """Test end-to-end flow with patching."""
        # Create a vulnerable file
        vulnerable_file = os.path.join(temp_git_repo, "vulnerable.py")
        with open(vulnerable_file, "w") as f:
            f.write('user_input = input("Enter something: ")\n')
            f.write('eval(user_input)  # Vulnerable to code execution')
        
        # Commit the vulnerable file
        subprocess.run(["git", "-C", temp_git_repo, "add", "vulnerable.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", temp_git_repo, "commit", "-m", "Add vulnerable code"], check=True, capture_output=True)
        
        # Mock the pipeline result
        mock_run_pipeline.return_value = {
            "status": "completed",
            "bugs": [{"description": "Unsafe eval()", "vulnerability_type": "code injection"}],
            "summary": "Found potential code injection vulnerability"
        }
        
        # Mock the patcher
        mock_patcher = MagicMock()
        mock_patcher.process_vulnerabilities.return_value = [
            {"applied_to_repo": True, "original_file": "vulnerable.py"}
        ]
        mock_patcher_class.return_value = mock_patcher
        
        # Call the CLI with arguments
        test_args = ['src/main.py', temp_git_repo, '--patch']
        with patch('sys.argv', test_args):
            with patch.dict('os.environ', {"OPENAI_API_KEY": "test_api_key"}):
                main()
        
        # Verify interactions
        mock_run_pipeline.assert_called_once_with(temp_git_repo)
        mock_patcher_class.assert_called_once_with(temp_git_repo)
        mock_patcher.process_vulnerabilities.assert_called_once()