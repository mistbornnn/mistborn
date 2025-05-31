import pytest
import os
import sys
import tempfile
import subprocess
from unittest.mock import patch, MagicMock

# Add the src directory to sys.path to make imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))


@pytest.fixture
def mock_openai_key():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        yield


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


@pytest.fixture
def vulnerable_git_repo(temp_git_repo):
    vulnerable_file = os.path.join(temp_git_repo, "vulnerable.py")
    with open(vulnerable_file, "w") as f:
        f.write('user_input = input("Enter something: ")\n')
        f.write('eval(user_input)  # Vulnerable to code execution')
    
    subprocess.run(["git", "-C", temp_git_repo, "add", "vulnerable.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", temp_git_repo, "commit", "-m", "Add vulnerable code"], check=True, capture_output=True)
    
    yield temp_git_repo


@pytest.fixture
def mock_vuln_detector():
    with patch("src.analyzer.vuln_detector.VulnDetector") as mock_detector:
        mock_instance = MagicMock()
        mock_instance.detect_bugs.return_value = {
            "status": "completed",
            "bugs": [{"description": "Test vulnerability", "vulnerability_type": "test"}],
            "summary": "Test summary"
        }
        mock_detector.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_vuln_patcher():
    with patch("src.analyzer.vuln_patcher.VulnPatcher") as mock_patcher:
        mock_instance = MagicMock()
        mock_instance.process_vulnerabilities.return_value = [
            {"original_file": "test.py", "applied_to_repo": True}
        ]
        mock_patcher.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_gpt_client():
    with patch("src.analyzer.gpt_client.GPTClient") as mock_client:
        mock_instance = MagicMock()
        mock_instance.send_prompt.return_value = {"choices": [{"message": {"content": "Test response"}}]}
        mock_instance.receive_response.return_value = "Mock API response"
        mock_client.return_value = mock_instance
        yield mock_instance