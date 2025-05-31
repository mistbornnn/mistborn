#!/usr/bin/env python3

import argparse
import os
import sys

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from src.ci.pipeline import run_pipeline
from src.analyzer.vuln_patcher import VulnPatcher
from src.ci.git_repository import GitRepository
from src.analyzer.vuln_detector import VulnDetector
from analyzer.patch_organizer import PatchOrganizer

def main():
    parser = argparse.ArgumentParser(
        description='Analyze a git repository for security vulnerabilities in the latest commit and optionally patch them.'
    )
    parser.add_argument(
        'repo_path', 
        help='Path to the git repository to analyze.'
    )
    parser.add_argument(
        '--commit-all',
        action='store_true',
        help='Analyze all commits in the repository.'        
    )
    parser.add_argument(
        '--patch', 
        action='store_true',
        help='Generate and apply patches for detected vulnerabilities'
    )
    args = parser.parse_args()
    
    if not os.path.isdir(args.repo_path):
        print(f"Error: The specified path does not exist or is not a directory: {args.repo_path}")
        sys.exit(1)
    
    try:
        repo = GitRepository(args.repo_path)
    except ValueError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    
    
    vulnerabilities = None
    
    if args.commit_all:
        total_commits = repo.get_total_commits()
        print(f"Total commits in the repository: {total_commits}")
        
        for i in range(1, total_commits + 1):
            print(f"\nAnalyzing commit {i}/{total_commits}...")
            commit_hash = repo.get_commit_by_number(i)
            print(f"Analyzing commit: {commit_hash}")
            
            code_changes = repo.get_commit_files(commit_hash)

            if not code_changes:
                print("No code changes found in the latest commit.")
            else:
                print(f"Found {len(code_changes)} changed files in this commit")

                vuln_detector = VulnDetector()
                vuln_patcher = VulnPatcher(args.repo_path)
                patch_organizer = PatchOrganizer()

                detect_result = vuln_detector.detect_bugs(code_changes)

                if 'Vulnerable: yes' in detect_result['vulnerability_analysis'] or 'yes' in detect_result['bugs']:
                    print("yn_reply: yes")
                    generate_result = vuln_patcher.generate_patch(code_changes, detect_result['vulnerability_analysis'])
                    patch_organizer.organize_patches(code_changes, generate_result, generate_result['best'])
                else:
                    print("yn_reply: no")

    else:
        print(f"Analyzing the latest commit in repository: {args.repo_path}")
        
        try:
            vulnerabilities = run_pipeline(args.repo_path)
        except ValueError as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
        if vulnerabilities.get('status') == 'no_code':
            print("No code changes found in the latest commit.")
            sys.exit(0)
        elif vulnerabilities.get('status') != 'completed':
            print("Error during vulnerability analysis. Please check the logs.")
            sys.exit(1)        
        print(f"Analysis completed. Found {len(vulnerabilities.get('bugs', []))} vulnerabilities in the latest commit.")
        print("Vulnerabilities found:")        
        print(vulnerabilities.get('vulnerability_analysis', 'No vulnerabilities found.'))
    
    if args.patch and vulnerabilities.get('bugs'):
        print("\n" + "=" * 50)
        print("Starting vulnerability patching process...")
        
        patcher = VulnPatcher(args.repo_path)
        
        repo = GitRepository(args.repo_path)

        code_files = repo.get_latest_commit_files()
        
        patches = patcher.process_vulnerabilities(vulnerabilities, code_files)
        
        if patches:
            print("\n" + "=" * 50)
            print(f"Summary: Generated {len(patches)} patches for detected vulnerabilities")
            print("Patches have been saved to the 'patches' directory.")
            
            applied_count = sum(1 for p in patches if p.get("applied_to_repo", False))
            if applied_count > 0:
                print(f"{applied_count} patches have been applied directly to the repository files.")
                print("Original files have been backed up with '.bak' extension.")
        else:
            print("\nNo patches were generated.")

if __name__ == "__main__":
    main()