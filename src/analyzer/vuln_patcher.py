import os
import json
import tempfile
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from .gpt_client import GPTClient
from .prompt_templates import BASIC_AGENT_PROMPT, REWARD_AGENT_PROMPT, PUNISH_AGENT_PROMPT, RAG_AGENT_PROMPT, CHAIN_OF_THOUGHT_PROMPT, PATCH_SELECTION_PROMPT
import tiktoken
import numpy as np
import faiss
import pickle
import logging
from ..config.settings import DEBUG_MODE

class VulnPatcher:
    
    def __init__(self, repo_path: Optional[str] = None):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        self.gpt_client = GPTClient(api_key)
        self.repo_path = repo_path
        self.patches_dir = os.path.join(os.getcwd(), "patches")
        
        if not os.path.exists(self.patches_dir):
            os.makedirs(self.patches_dir)
        self.embedding_model = "text-embedding-3-large"
        self.vector_index_path = "src/utils/openai_faiss_index.bin"
        self.vector_meta_path = "src/utils/openai_index_metadata.pkl"
        self.tokenizer = tiktoken.encoding_for_model(self.embedding_model)
        self.load_vector_index()

        if DEBUG_MODE:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("VulnPatcher")
    
    def analyze_code(self, code_data: List[Dict[str, str]]) -> str:
        formatted_code = ""
        for i, file in enumerate(code_data):
            formatted_code += f"File{str(i)}: \nfile name:{file['filename']}\n file content:\n```\n{file['content']}\n```\nfile changes:\n```\n{file['patch']}\n```\n"
        return formatted_code
    
    def load_vector_index(self):
        self.vector_index = faiss.read_index(self.vector_index_path)
        with open(self.vector_meta_path, "rb") as f:
            self.vector_metadata = pickle.load(f)

    def embed_text(self, text: str) -> List[float]:
        response = self.gpt_client.embed_text(text, self.embedding_model)
        return response
    
    def retrieve_context(self, query: str, top_k: int = 5) -> List[str]:
        embedding = np.array(self.embed_text(query)).astype("float32").reshape(1, -1)
        distances, indices = self.vector_index.search(embedding, top_k)
        return [self.vector_metadata[i]["text"] for i in indices[0] if i < len(self.vector_metadata)]

    def generate_patch(self, code_data: List[Dict[str, str]], vulnerability_report: str) -> Dict[str, str]:
        commit_change = self.analyze_code(code_data)
        patch_1 = self.gpt_client.send_prompt(
            BASIC_AGENT_PROMPT.format(
            code_and_diff=commit_change,
            bug_report=vulnerability_report,
            )
        )
        
        patch_basic = self.gpt_client.receive_response(patch_1)

        if DEBUG_MODE:
            self.logger.info(f"Agent 1: Simple prompt: {patch_basic}")        

        # Agent 2: Reward-focused prompt
        patch_2 = self.gpt_client.send_prompt(
            REWARD_AGENT_PROMPT.format(
            code_and_diff=commit_change,
            bug_report=vulnerability_report,
            )
        )
        patch_reward = self.gpt_client.receive_response(patch_2)
        if DEBUG_MODE:
            self.logger.info(f"Agent 2: Reward-focused prompt: {patch_basic}")

        # Agent 3: Punishment-avoidance prompt
        patch_3 = self.gpt_client.send_prompt(
            PUNISH_AGENT_PROMPT.format(
            code_and_diff=commit_change,
            bug_report=vulnerability_report,
            )
        )
        patch_punish = self.gpt_client.receive_response(patch_3)
        if DEBUG_MODE:
            self.logger.info(f"Agent 3: Punishment-avoidance prompt: {patch_basic}")

        # Agent 4: Chain-of-thought reasoning
        patch_4 = self.gpt_client.send_prompt(
            CHAIN_OF_THOUGHT_PROMPT.format(
            code_and_diff=commit_change,
            bug_report=vulnerability_report,
            )
        )
        patch_cot = self.gpt_client.receive_response(patch_4)
        if DEBUG_MODE:
            self.logger.info(f"Agent 4: Chain-of-thought reasoning: {patch_basic}")

        # Agent 5: RAG (Retrieval-Augmented Generation)
        rag_context = []
        need_more_info = True
        query = vulnerability_report

        # Keep retrieving more context until LLM says it's enough
        while need_more_info:
            context = self.retrieve_context(query+'\n'.join(rag_context))
            rag_request = self.gpt_client.send_prompt(
                RAG_AGENT_PROMPT.format(
                code_and_diff=commit_change,
                bug_report=vulnerability_report,
                prior_knowledge="\n".join(context),
                )
            )
            rag_response = self.gpt_client.receive_response(rag_request)
            rag_context.append(rag_response)

            # Stop if LLM says no more retrieval is needed
            if "need to retrieve more context" in rag_response.lower():
                need_more_info = True
            else:
                need_more_info = False
        
        patch_rag = self.gpt_client.receive_response(rag_response)
        if DEBUG_MODE:
            self.logger.info(f"Agent 5: RAG (Retrieval-Augmented Generation): {patch_basic}")

        # Agent 6: Patch selector (choose the best)
        patch_6 = self.select_best_patch([patch_basic, patch_reward, patch_punish, patch_cot, patch_rag])
        best_patch = self.gpt_client.receive_response(patch_6)
        print(best_patch)
        if DEBUG_MODE:
            self.logger.info(f"Agent 6: Patch selector (choose the best): {patch_basic}")

        return {
            "basic": patch_basic,
            "reward": patch_reward,
            "punish": patch_punish,
            "chain_of_thought": patch_cot,
            "rag": patch_rag,
            "best": best_patch
        }

    def select_best_patch(self, patches: List[str]) -> str:
        selection_prompt = PATCH_SELECTION_PROMPT.format(
                patch_list="\n".join(f"Patch {i+1}:\n{patch}\n\n" for i, patch in enumerate(patches))
                )
        
        return self.gpt_client.send_prompt(selection_prompt)
    
    def _extract_code_from_response(self, response: str) -> str:
        # Basic extraction - finds code between triple backticks
        code_blocks = []
        in_code_block = False
        current_block = []
        
        for line in response.split('\n'):
            if line.strip().startswith('```'):
                if in_code_block:
                    # End of code block
                    in_code_block = False
                    code_blocks.append('\n'.join(current_block))
                    current_block = []
                else:
                    # Start of code block
                    in_code_block = True
                    # Skip the language identifier if present
                    if len(line.strip()) > 3 and not line.strip().endswith('```'):
                        continue
            elif in_code_block:
                current_block.append(line)
        
        # If we have code blocks, return the first one
        if code_blocks:
            return code_blocks[0]
        
        # If no code blocks found, return the complete response
        # (GPT might not have wrapped the code in backticks)
        return response
    
    def test_patch(self, patch: Dict[str, Any], test_command: str = "pytest") -> Tuple[bool, str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy the original file to the temp directory
            original_file_path = patch["original_file"]
            temp_file_path = os.path.join(temp_dir, os.path.basename(original_file_path))
            
            # Create any necessary directories in the temp path
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
            
            # Write the patched code to the temp file
            with open(temp_file_path, 'w') as f:
                f.write(patch["patched_code"])
            
            # Run the tests
            try:
                result = subprocess.run(
                    test_command,
                    shell=True,
                    cwd=temp_dir,
                    capture_output=True,
                    text=True
                )
                success = result.returncode == 0
                return success, result.stdout + result.stderr
            except Exception as e:
                return False, str(e)
    
    def save_patch(self, patch: Dict[str, Any], output_path: Optional[str] = None) -> str:
        if output_path is None:
            # Generate a filename based on the original file and current timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = os.path.basename(patch["original_file"])
            filename = f"{base_filename.rsplit('.', 1)[0]}_{timestamp}.patch"
            output_path = os.path.join(self.patches_dir, filename)
        
        # Save the patch data as JSON
        with open(output_path, 'w') as f:
            json.dump(patch, f, indent=2)
        
        return output_path
    
    def generate_and_test_patch(self, bug_info: Dict[str, Any], affected_code: Dict[str, str], 
                               test_command: str = "pytest", auto_save: bool = True) -> Dict[str, Any]:
        patch = self.generate_patch(bug_info, affected_code)
        
        # Test the patch
        success, test_output = self.test_patch(patch, test_command)
        patch["test_success"] = success
        patch["test_output"] = test_output
        
        # Save the patch if tests passed and auto_save is enabled
        if success and auto_save:
            saved_path = self.save_patch(patch)
            patch["saved_path"] = saved_path
        
        return patch
    
    def apply_patch_to_repo(self, patch: Dict[str, Any]) -> bool:
        if not self.repo_path:
            raise ValueError("No repository path provided to apply the patch")
            
        # Get the full path to the file in the repository
        file_path = os.path.join(self.repo_path, patch["original_file"])
        
        if not os.path.isfile(file_path):
            print(f"Error: File not found in repository: {file_path}")
            return False
            
        try:
            # Backup the original file
            backup_path = f"{file_path}.bak"
            shutil.copy2(file_path, backup_path)
            
            # Write the patched code to the file
            with open(file_path, 'w') as f:
                f.write(patch["patched_code"])
                
            print(f"Successfully applied patch to {file_path}")
            print(f"Original file backed up to {backup_path}")
            return True
        except Exception as e:
            print(f"Error applying patch: {str(e)}")
            # Restore from backup if it exists
            if os.path.isfile(backup_path):
                shutil.copy2(backup_path, file_path)
                print("Restored original file from backup")
            return False
            
    def process_vulnerabilities(self, vulnerabilities: Dict[str, Any], code_files: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        if not vulnerabilities.get('bugs', []):
            print("No vulnerabilities to patch.")
            return []
            
        patches = []
        bugs = vulnerabilities.get('bugs', [])
        
        print(f"\nGenerating patches for {len(bugs)} vulnerabilities...")
        
        for i, bug in enumerate(bugs, 1):
            # Try to determine which file is affected by this bug
            affected_file = None
            # Look for filename in the bug location
            if 'location' in bug:
                for file_data in code_files:
                    if file_data['filename'] in bug['location']:
                        affected_file = file_data
                        break
            
            # If still not found, use heuristics or prompt user
            if affected_file is None:
                # For simplicity, we'll just use the first code file
                # In a real implementation, we'd want to prompt the user or use more advanced heuristics
                if code_files:
                    affected_file = code_files[0]
                    print(f"Warning: Couldn't determine affected file for bug {i}. Using {affected_file['filename']}.")
                else:
                    print(f"Error: No affected file found for bug {i}.")
                    continue

            if hasattr(bug, 'get'):        
                print(f"\nGenerating patch for vulnerability {i}/{len(bugs)}:")
                print(f"  Type: {bug.get('vulnerability_type', 'Unknown')}")
                print(f"  Description: {bug.get('description', 'No description')}")
                print(f"  File: {affected_file['filename']}")
            
            # Generate patch
            patch = self.generate_patch(bug, affected_file)
            
            # Apply the patch if we have a repository path
            if self.repo_path:
                success = self.apply_patch_to_repo(patch)
                patch["applied_to_repo"] = success
                
            # Save the patch
            saved_path = self.save_patch(patch)
            patch["saved_path"] = saved_path
            
            patches.append(patch)
            
            print(f"  ✓ Patch created and saved to {saved_path}")
            if self.repo_path and patch.get("applied_to_repo", False):
                print("  ✓ Patch applied to repository file")
                
        return patches