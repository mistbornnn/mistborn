import os
from typing import List, Dict, Any
from .gpt_client import GPTClient
from .prompt_templates import VULN_DETECTION_PROMPT, VULN_YES_NO_PROMPT

class VulnDetector:
    def __init__(self):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        self.gpt_client = GPTClient(api_key)
        self.default_patterns = [
            "Buffer overflow due to unchecked strcpy or memcpy",
            "Format string vulnerability using printf without format specifier",
            "Use of gets which allows buffer overflow",
            "Integer overflow in memory allocation calculations",
            "Use after free from accessing freed memory",
            "Double free by calling free twice on same pointer",
            "Uninitialized memory read",
            "Null pointer dereference",
            "Integer signedness error leading to logic flaw"
        ]
        
    def analyze_code(self, code_data: List[Dict[str, str]]) -> str:
        formatted_code = ""
        for i, file in enumerate(code_data):
            formatted_code += f"File{str(i)}: \nfile name:{file['filename']}\n file content:\n```\n{file['content']}\n```\nfile changes:\n```\n{file['patch']}\n```\n"
        return formatted_code
        
    def detect_bugs(self, code_data: List[Dict[str, str]], 
                   repo_name: str = "unknown", 
                   vulnerability_patterns: List[str] = None) -> Dict[str, Any]:
        if not code_data:
            return {"status": "no_code", "bugs": [], "summary": "No code to analyze"}

        patterns = vulnerability_patterns or self.default_patterns

        commit_change = self.analyze_code(code_data)
        files_changed = len(code_data)
        
        vuln_prompt = VULN_DETECTION_PROMPT.format(
            repo_name=repo_name,
            files_changed=files_changed,
            code_and_diff=commit_change,
            vulnerability_patterns="\n- " + "\n- ".join(patterns),
        )
        
        vuln_response = self.gpt_client.send_prompt(vuln_prompt)
        vuln_analysis = self.gpt_client.receive_response(vuln_response)

        bugs = self._extract_bugs_from_analysis(vuln_analysis)
        
        return {
            "status": "completed",
            "bugs": bugs if isinstance(bugs, list) else [],
            "vulnerability_analysis": vuln_analysis,
            "summary": self._generate_summary(bugs if isinstance(bugs, list) else [])
        }
    
    def _extract_bugs_from_analysis(self, analysis: str) -> List[Dict[str, Any]]:
        if not analysis:
            return []
        
        yn_prompt = VULN_YES_NO_PROMPT.format(
            vuln_report=analysis.strip(),
        )
        
        yn_raw = self.gpt_client.send_prompt(yn_prompt)
        yn_reply = self.gpt_client.receive_response(yn_raw).strip().lower()
        
        bugs = []
        if "yes" in yn_reply:
            lines = analysis.split('\n')
            for line in lines:
                line = line.strip()
                if line.lower().startswith('bug:') or 'vulnerability' in line.lower():
                    bug = {
                        "description": line,
                        "vulnerability_type": self._extract_vuln_type(line),
                        "location": "Unknown location"
                    }
                    bugs.append(bug)
        
        return bugs
    
    def _extract_vuln_type(self, description: str) -> str:
        desc_lower = description.lower()
        if 'sql injection' in desc_lower:
            return 'sql injection'
        elif 'xss' in desc_lower:
            return 'xss'
        elif 'buffer overflow' in desc_lower:
            return 'buffer overflow'
        elif 'deserialization' in desc_lower:
            return 'insecure deserialization'
        else:
            return 'general'
    
    def _generate_summary(self, bugs: List[Dict[str, Any]]) -> str:
        if not bugs:
            return "No Issues Found - 0 vulnerabilities detected"
        
        vuln_counts = {}
        for bug in bugs:
            vuln_type = bug.get('vulnerability_type', 'unknown')
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        summary = f"Vulnerabilities Found: {len(bugs)}\n"
        summary += "Action Required\n"
        for vuln_type, count in vuln_counts.items():
            summary += f"{vuln_type.title()}: {count}\n"
        
        return summary.strip()