import os
import re
from typing import Dict, List, Optional
import logging
from config.settings import DEBUG_MODE

class PatchOrganizer:
    
    def __init__(self, repo_path: Optional[str] = None):
        self.patches_dir = os.path.join(os.getcwd(), "patches")

        if not os.path.exists(self.patches_dir):
            os.makedirs(self.patches_dir)

        if DEBUG_MODE:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("PatchOrganizer")

    def organize_patches(self, code_data: List[Dict[str, str]], generated_patch: List[Dict[str, str]], generation_report: str) -> Dict[str, str]:
        selected_patch = self._extract_selected_patch_key(generation_report)

        patch_code = generated_patch.get(selected_patch)
        if not patch_code:
            raise ValueError(f"No patch found for selected key: {selected_patch}")

        stripped_code = self._extract_code_block(patch_code)

        # Step 4: Find target file to replace
        target_file = self._guess_target_filename(stripped_code, code_data)

        # Step 5: Replace content in that file
        patched_files = []
        for file in code_data:
            if file["filename"] in target_file:
                patched_files.append({
                    "filename": file["filename"],
                    "content": stripped_code
                })
            else:
                patched_files.append(file)
        for file in patched_files:
            print(file['filename'], file['content'])
        return patched_files

    def _extract_selected_patch_key(self, report: str) -> str:
        match = re.search(r"Patch (\d+)", report)
        key_map = {
            "1": "basic",
            "2": "reward",
            "3": "punish",
            "4": "chain_of_thought",
            "5": "rag"
        }
        patch_number = match.group(1) if match else "1"
        return key_map.get(patch_number, "basic")

    def _extract_code_block(self, text: str) -> str:
        match = re.search(r"```[a-zA-Z]*\n(.*?)\n```", text, re.DOTALL)
        return match.group(1).strip() if match else text.strip()

    def _guess_target_filename(self, patch_code: str, code_data: List[Dict[str, str]]) -> str:
        target_functions = []
        for file in code_data:
            if file["filename"] in patch_code:
                target_functions.append(file["filename"])

        if len(target_functions) < 1:
            print("No matching file found for patch code.")

        return target_functions