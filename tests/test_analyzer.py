import pytest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from src.analyzer.vuln_detector import VulnDetector
from src.analyzer.gpt_client import GPTClient
from src.analyzer.vuln_patcher import VulnPatcher

# Test VulnDetector class
def test_vuln_detector_initialization():
    # Mock environment variable
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        detector = VulnDetector()
        assert detector.gpt_client is not None
        assert detector.gpt_client.api_key == "test_api_key"

def test_vuln_detector_init_missing_api_key():
    # Test initialization with missing API key
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError) as excinfo:
            VulnDetector()
        assert "OpenAI API key not found" in str(excinfo.value)

def test_analyze_code():
    # Test analyze_code method which formats code for analysis
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        detector = VulnDetector()

        code_data = [
            {"filename": "test.py", "content": "def test(): pass", "patch": ""}
        ]

        formatted_code = detector.analyze_code(code_data)
        assert "File0:" in formatted_code
        assert "test.py" in formatted_code
        assert "def test(): pass" in formatted_code

def test_detect_bugs_empty_input():
    # Test detect_bugs with empty code data
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        detector = VulnDetector()
        result = detector.detect_bugs([])
        assert result["status"] == "no_code"
        assert result["bugs"] == []

def test_detect_bugs():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        detector = VulnDetector()

        # Mock GPT client methods
        detector.gpt_client.send_prompt = MagicMock(return_value={"mock": "response"})
        detector.gpt_client.receive_response = MagicMock(return_value="Bug: Division by zero\nVulnerability: buffer overflow\nLocation: Line 2")

        code_data = [
            {"filename": "buggy.py", "content": "def faulty_function():\n    return 1 / 0", "patch": ""}
        ]

        result = detector.detect_bugs(code_data)

        # Check if GPT client was called correctly
        detector.gpt_client.send_prompt.assert_called()
        detector.gpt_client.receive_response.assert_called()

        # Check result structure
        assert result["status"] == "completed"
        assert "vulnerability_analysis" in result

def test_extract_bugs_from_analysis():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        detector = VulnDetector()
        
        # Mock the GPT client methods to avoid API calls
        detector.gpt_client.send_prompt = MagicMock(return_value={"mock": "response"})
        detector.gpt_client.receive_response = MagicMock(return_value="yes")

        # Test with a single bug
        analysis = "Bug: SQL Injection vulnerability\nLocation: File: user.py, Line 15"
        bugs = detector._extract_bugs_from_analysis(analysis)
        
        # Should return a list with one bug
        assert len(bugs) == 1
        assert bugs[0]["description"] == "Bug: SQL Injection vulnerability"
        assert bugs[0]["vulnerability_type"] == "sql injection"
        assert bugs[0]["location"] == "Unknown location"

# Remove the test_generate_summary function since VulnDetector doesn't have _generate_summary method

# Test GPTClient class
def test_gpt_client_initialization():
    client = GPTClient("test_api_key")
    assert client.api_key == "test_api_key"

def test_send_prompt():
    with patch("openai.resources.chat.Completions.create") as mock_create:
        mock_create.return_value = {"id": "test", "choices": [{"message": {"content": "Test response"}}]}

        client = GPTClient("test_api_key")
        response = client.send_prompt("Test prompt")

        mock_create.assert_called_once()
        assert response["id"] == "test"
        assert "choices" in response

def test_receive_response():
    client = GPTClient("test_api_key")

    # Test valid response format
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "No bugs found."
    result = client.receive_response(mock_response)
    assert result == "No bugs found."

    # Test invalid response format
    result = client.receive_response({})
    assert result is None

# Test VulnPatcher class
def test_vuln_patcher_initialization():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()
        assert patcher.gpt_client is not None
        assert os.path.exists(patcher.patches_dir)

def test_vuln_patcher_generate():
    from unittest.mock import patch as mock_patch
    with mock_patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()
        
        # Mock all GPT client methods to avoid API calls
        patcher.gpt_client.send_prompt = MagicMock(return_value={"mock": "response"})
        patcher.gpt_client.receive_response = MagicMock(return_value="```python\ndef faulty_function():\n    if 0 != 0:  # This will never be true\n        return 1 / 0\n    return 1  # Safe return value\n```")
        patcher.gpt_client.embed_text = MagicMock(return_value=[0.1] * 1536)  # Mock embedding
        
        # Mock the retrieve_context method to avoid vector search
        patcher.retrieve_context = MagicMock(return_value=["Mock CVE example"])

        code_data = [
            {
                "filename": "example.py",
                "content": "def faulty_function():\n    return 1 / 0",
                "patch": ""
            }
        ]

        vulnerability_report = "Division by zero error in function"

        # Test generating a patch
        patches = patcher.generate_patch(code_data, vulnerability_report)

        # Verify patch contents
        assert "basic" in patches
        assert "reward" in patches
        assert "punish" in patches
        assert "chain_of_thought" in patches
        assert "rag" in patches
        assert "best" in patches

def test_extract_code_from_response():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()

        # Test with code blocks
        response = "Here's the fixed code:\n```python\ndef fixed():\n    return 42\n```\nThe fix is complete."
        extracted = patcher._extract_code_from_response(response)
        assert extracted == "def fixed():\n    return 42"

        # Test without code blocks
        response = "def fixed():\n    return 42"
        extracted = patcher._extract_code_from_response(response)
        assert extracted == response

def test_test_patch():
    from unittest.mock import patch as mock_patch
    with mock_patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()

        # Create a mock patch
        patch = {
            "original_file": "test_file.py",
            "original_code": "def bug(): return 1/0",
            "patched_code": "def bug(): return 1"
        }

        # Mock subprocess.run to simulate successful test
        with mock_patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Tests passed", stderr="")

            success, output = patcher.test_patch(patch, "echo 'test'")
            assert success is True
            assert output == "Tests passed"

        # Mock subprocess.run to simulate failed test
        with mock_patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Tests failed")

            success, output = patcher.test_patch(patch, "echo 'test'")
            assert success is False
            assert output == "Tests failed"

        # Test exception handling
        with mock_patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Error running tests")

            success, output = patcher.test_patch(patch, "echo 'test'")
            assert success is False
            assert "Error running tests" in output

def test_save_patch():
    from unittest.mock import patch as mock_patch
    with mock_patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()

        # Create a sample patch
        patch = {
            "original_file": "test_file.py",
            "original_code": "def buggy():\n    return 1/0",
            "patched_code": "def buggy():\n    if 0:\n        return 1/0\n    return 1",
            "bug_info": {"severity": "high", "description": "Division by zero"},
            "created_at": "2025-01-01T12:00:00"
        }

        # Use a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Override the patches directory
            original_patches_dir = patcher.patches_dir
            patcher.patches_dir = temp_dir

            # Save the patch
            saved_path = patcher.save_patch(patch)

            # Verify the patch was saved
            assert os.path.exists(saved_path)

            # Read back the saved patch
            with open(saved_path, 'r') as f:
                saved_data = json.load(f)

            assert saved_data["original_file"] == "test_file.py"
            assert saved_data["patched_code"] == "def buggy():\n    if 0:\n        return 1/0\n    return 1"

            # Test with custom output path
            custom_path = os.path.join(temp_dir, "custom_patch.json")
            saved_custom_path = patcher.save_patch(patch, output_path=custom_path)
            assert saved_custom_path == custom_path
            assert os.path.exists(custom_path)

            # Restore the original patches directory
            patcher.patches_dir = original_patches_dir

def test_generate_and_test_patch():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test_api_key"}):
        patcher = VulnPatcher()

        # Mock the generate_patch and test_patch methods
        patcher.generate_patch = MagicMock(return_value={
            "original_file": "secure_code.py",
            "original_code": "def format_string(user_input):\n    return 'Result: %s' % user_input",
            "patched_code": "def format_string(user_input):\n    return f'Result: {user_input}'",
            "bug_info": {"description": "String formatting vulnerability"},
            "created_at": "2025-01-01T12:00:00"
        })

        patcher.test_patch = MagicMock(return_value=(True, "All tests passed"))
        patcher.save_patch = MagicMock(return_value="/path/to/saved/patch.json")

        bug_info = {
            "description": "String formatting vulnerability",
            "severity": "medium",
            "location": "Line 3"
        }

        affected_code = {
            "filename": "secure_code.py",
            "content": "def format_string(user_input):\n    return 'Result: %s' % user_input"
        }

        # Test with auto_save=True
        patch_result = patcher.generate_and_test_patch(
            bug_info, 
            affected_code,
            test_command="echo 'test'",
            auto_save=True
        )

        # Verify methods were called correctly
        patcher.generate_patch.assert_called_once()
        patcher.test_patch.assert_called_once()
        patcher.save_patch.assert_called_once()

        # Verify result structure
        assert patch_result["test_success"] is True
        assert patch_result["test_output"] == "All tests passed"
        assert patch_result["saved_path"] == "/path/to/saved/patch.json"

        # Test with auto_save=False
        patcher.generate_patch.reset_mock()
        patcher.test_patch.reset_mock()
        patcher.save_patch.reset_mock()

        patcher.generate_and_test_patch(
            bug_info, 
            affected_code,
            test_command="echo 'test'",
            auto_save=False
        )

        # Verify save_patch was not called
        patcher.generate_patch.assert_called_once()
        patcher.test_patch.assert_called_once()
        patcher.save_patch.assert_not_called()