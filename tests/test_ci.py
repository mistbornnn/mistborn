import pytest
import os
import tempfile
import subprocess
from unittest.mock import patch, MagicMock
from src.ci.git_repository import GitRepository
from src.ci.pipeline import run_pipeline


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


def test_run_pipeline(temp_git_repo):
    # Test with the local repository path directly
    with patch("src.analyzer.vuln_detector.VulnDetector") as mock_detector:
        mock_instance = MagicMock()
        mock_instance.detect_bugs.return_value = {
            "status": "completed",
            "bugs": [],
            "summary": "No bugs detected"
        }
        mock_detector.return_value = mock_instance
        
        result = run_pipeline(temp_git_repo)
        assert result is not None
        assert 'status' in result
        assert result['status'] == "completed"


class TestGitRepository:
    
    def test_init_valid_repo(self, temp_git_repo):
        """Test initializing with a valid git repository."""
        repo = GitRepository(temp_git_repo)
        assert repo.repo_path == temp_git_repo
    
    def test_init_invalid_repo(self):
        """Test initializing with an invalid git repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError) as excinfo:
                GitRepository(temp_dir)
            assert "Path is not a git repository" in str(excinfo.value)
    
    def test_get_latest_commit(self, temp_git_repo):
        """Test getting the latest commit hash."""
        repo = GitRepository(temp_git_repo)
        commit_hash = repo.get_latest_commit()
        assert commit_hash is not None
        assert len(commit_hash) == 40  # SHA-1 hash length
    
    def test_get_latest_commit_files(self, temp_git_repo):
        """Test getting files from the latest commit."""
        repo = GitRepository(temp_git_repo)
        files = repo.get_latest_commit_files()
        
        assert len(files) == 1
        assert files[0]["filename"] == "sample.py"
        assert "print('Hello, world!')" in files[0]["content"]
        assert "patch" in files[0]
    
    def test_get_latest_commit_with_binary_file(self, temp_git_repo):
        """Test handling of binary files in latest commit."""
        # Create a binary file
        binary_file = os.path.join(temp_git_repo, "binary.bin")
        with open(binary_file, "wb") as f:
            f.write(bytes([0x13, 0x37] * 50))
        
        # Commit the binary file
        subprocess.run(["git", "-C", temp_git_repo, "add", "binary.bin"], check=True, capture_output=True)
        subprocess.run(["git", "-C", temp_git_repo, "commit", "-m", "Add binary file"], check=True, capture_output=True)
        
        # Test that binary files are properly handled
        repo = GitRepository(temp_git_repo)
        files = repo.get_latest_commit_files()
        
        # Should only contain text files (i.e., sample.py but not binary.bin)
        binary_files = [f for f in files if f["filename"] == "binary.bin"]
        assert len(binary_files) == 0
    
    def test_is_binary_file(self, temp_git_repo):
        """Test binary file detection."""
        repo = GitRepository(temp_git_repo)
        
        # Test with text file
        text_file = os.path.join(temp_git_repo, "text.txt")
        with open(text_file, "w") as f:
            f.write("This is a text file")
        
        assert repo._is_binary_file(text_file) is False
        
        # Test with binary file
        binary_file = os.path.join(temp_git_repo, "binary.bin")
        with open(binary_file, "wb") as f:
            f.write(bytes([0x13, 0x37] * 50))
        
        assert repo._is_binary_file(binary_file) is True


class TestPipeline:
    
    @patch("src.analyzer.vuln_detector.VulnDetector")
    def test_run_pipeline(self, mock_vuln_detector, temp_git_repo):
        """Test running the analysis pipeline with a mock detector."""
        # Configure the mock detector
        mock_instance = MagicMock()
        mock_instance.detect_bugs.return_value = {
            "status": "completed",
            "bugs": [{"description": "Test bug", "vulnerability_type": "test"}],
            "summary": "Test summary"
        }
        mock_vuln_detector.return_value = mock_instance
        
        # Run the pipeline with our test repository
        result = run_pipeline(temp_git_repo)
        
        # Verify the detector was called with the latest commit files
        mock_instance.detect_bugs.assert_called_once()
        
        # Check the result structure
        assert result["status"] == "completed"
        assert len(result["bugs"]) == 1
        assert result["summary"] == "Test summary"
    
    @patch.dict("os.environ", {}, clear=True)
    def test_run_pipeline_missing_api_key(self, temp_git_repo):
        """Test pipeline handling of missing API key."""
        # Without mocking VulnDetector, it will try to initialize with real env vars
        with pytest.raises(ValueError) as excinfo:
            run_pipeline(temp_git_repo)
        assert "OpenAI API key not found" in str(excinfo.value)
    
    @patch.dict("os.environ", {"OPENAI_API_KEY": "test_api_key"})
    @patch("src.analyzer.vuln_detector.VulnDetector")
    def test_run_pipeline_with_env_var(self, mock_vuln_detector, temp_git_repo):
        """Test pipeline with environment variable set."""
        # Configure the mock detector
        mock_instance = MagicMock()
        mock_instance.detect_bugs.return_value = {
            "status": "completed",
            "bugs": [],
            "summary": "No bugs detected"
        }
        mock_vuln_detector.return_value = mock_instance
        
        # Run the pipeline
        result = run_pipeline(temp_git_repo)
        
        # Verify the result
        assert result["status"] == "completed"
        assert result["bugs"] == []
        assert result["summary"] == "No bugs detected"
    
    def test_run_pipeline_integration(self, temp_git_repo):
        """Integration test for the pipeline with a vulnerable file."""
        # Create a file with a potential vulnerability
        vulnerable_file = os.path.join(temp_git_repo, "vulnerable.py")
        with open(vulnerable_file, "w") as f:
            f.write('user_input = input("Enter something: ")\n')
            f.write('eval(user_input)  # Vulnerable to code execution')
        
        # Commit the vulnerable file
        subprocess.run(["git", "-C", temp_git_repo, "add", "vulnerable.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", temp_git_repo, "commit", "-m", "Add vulnerable code"], check=True, capture_output=True)
        
        # Mock the VulnDetector to avoid actual API calls
        with patch("src.analyzer.vuln_detector.VulnDetector") as mock_detector:
            mock_instance = MagicMock()
            mock_instance.detect_bugs.return_value = {
                "status": "completed",
                "bugs": [{"description": "Unsafe eval()", "vulnerability_type": "code injection"}],
                "summary": "Found potential code injection vulnerability"
            }
            mock_detector.return_value = mock_instance
            
            # Run the pipeline
            result = run_pipeline(temp_git_repo)
            
            # Verify results
            assert result["status"] == "completed"
            assert len(result["bugs"]) == 1
            assert result["bugs"][0]["vulnerability_type"] == "code injection"