# mistborn - Code Vulnerability Analyzer

This project analyzes local git repositories for potential security vulnerabilities using OpenAI's GPT models through prompt engineering. It inspects commits in a repository, analyzes the code, and provides feedback about potential vulnerabilities with optional automated patching capabilities.

## Project Structure

```
mistborn
├── src
│   ├── analyzer
│   │   ├── __init__.py
│   │   ├── vuln_detector.py
│   │   ├── vuln_patcher.py
│   │   ├── gpt_client.py
│   │   └── prompt_templates.py
│   ├── ci
│   │   ├── __init__.py
│   │   ├── git_repository.py
│   │   └── pipeline.py
│   ├── config
│   │   ├── __init__.py
│   │   └── settings.py
│   └── main.py
├── tests
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_analyzer.py
│   ├── test_ci.py
│   └── test_main.py
├── patches      # Directory where generated vulnerability patches are stored
├── example      # Example repositories for testing vulnerability detection
├── requirements.txt
├── setup.py
└── README.md
```

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd mistborn
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   Create a `.env` file in the project root with the following:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```
   Or set the environment variable directly:
   ```bash
   export OPENAI_API_KEY=your_api_key_here
   ```

5. **Run the application:**
   Execute the main script to analyze a local git repository:
   ```bash
   python src/main.py /path/to/your/repository
   ```

## Usage

### Basic Analysis
Analyze the latest commit in a git repository for security vulnerabilities:

```bash
python src/main.py /path/to/your/repository
```

### Advanced Options

**Analyze all commits in the repository:**
```bash
python src/main.py /path/to/your/repository --commit-all
```

**Generate and apply patches for detected vulnerabilities:**
```bash
python src/main.py /path/to/your/repository --patch
```

**Combine options to analyze all commits and apply patches:**
```bash
python src/main.py /path/to/your/repository --commit-all --patch
```

### Output Features
When vulnerabilities are detected:
- Detailed vulnerability analysis is displayed
- Vulnerability types and locations are identified
- Risk assessments are provided

When patches are generated (with `--patch` flag):
- Patches are saved to the `patches` directory
- Original files are backed up with `.bak` extension
- Patches are automatically applied to repository files
- Summary of applied patches is displayed

## Dependencies

The project relies on the following major dependencies:
- **faiss-cpu** - Vector similarity search for embedding-based analysis
- **Flask** - Web framework for API endpoints
- **OpenAI** - GPT model integration for vulnerability detection
- **Requests** - HTTP client for API communications
- **Langchain-community** - LLM framework components
- **NumPy** - Numerical computing support
- **Tiktoken** - Token counting for GPT models
- **Python-dotenv** - Environment variable management
- **Pytest** - Testing framework

## Testing

To run the tests, use the following command:
```bash
pytest tests/
```

## Example Repositories

The project includes example repositories in the `example` directory that can be used for testing the vulnerability detection functionality.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.