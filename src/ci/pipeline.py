#!/usr/bin/env python3

def run_pipeline(repo_path):
    from ..analyzer.vuln_detector import VulnDetector
    from .git_repository import GitRepository
    
    if not repo_path:
        raise ValueError("Repository path is required for analysis")
    
    repo = GitRepository(repo_path)
    vuln_detector = VulnDetector()
    
    print(f"Analyzing latest commit in repository: {repo_path}")
    code_changes = repo.get_latest_commit_files()
    
    if not code_changes:
        print("No code changes found in the latest commit.")
        return {"status": "no_code", "bugs": [], "summary": "No code to analyze"}
    
    commit_hash = repo.get_latest_commit()
    print(f"Analyzing commit: {commit_hash}")
    print(f"Found {len(code_changes)} changed files in this commit")
    
    vulnerabilities = vuln_detector.detect_bugs(code_changes)
    
    return vulnerabilities