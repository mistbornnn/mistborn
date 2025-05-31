import os
import sys
import json
import openai
import faiss
import pickle
from typing import List, Dict
import numpy as np
import tiktoken

# Make sure your API key is in the environment
openai.api_key = os.getenv("OPENAI_API_KEY")

# Set working directory to script's parent directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ""))  # or further up if needed
sys.path.insert(0, ROOT_DIR)

CWE_PATH = os.path.join(ROOT_DIR, "cwe_top25.json")
CVE_PATH = os.path.join(ROOT_DIR, "patch_db_cwe_names.json")
INDEX_PATH = os.path.join(ROOT_DIR, "openai_faiss_index.bin")
META_PATH = os.path.join(ROOT_DIR, "openai_index_metadata.pkl")
EMBED_MODEL = "text-embedding-3-large"

MAX_TOKENS = 8000
tokenizer = tiktoken.encoding_for_model(EMBED_MODEL)

def load_json(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def format_cve(entry: Dict) -> Dict:
    return {
        "type": "cve",
        "cwe": entry.get("CWE_ID"),
        "text": f"""[CVE Example]
CWE: {entry.get('CWE_ID')} - {entry.get('CWE_Name')}
Commit Message: {entry.get('commit_message', '').strip()}
Patch Diff:
{entry.get('diff_code', '').strip()}
""",
        "source": entry
    }


def format_cwe(entry: Dict) -> Dict:
    return {
        "type": "cwe",
        "cwe": entry.get("cwe_id"),
        "text": f"""[CWE Top 25]
{entry.get('CWE-ID')} - {entry.get('Name')}
Description: {entry.get('Description')}
Mitigation: {entry.get('Potential Mitigations')}
""",
        "source": entry
    }


def is_within_token_limit(text: str, limit=MAX_TOKENS) -> bool:
    return len(tokenizer.encode(text)) <= limit

def embed_texts(texts: List[str]) -> List[List[float]]:
    print(f"🔍 Embedding {len(texts)} items...")
    valid_texts = [t for t in texts if is_within_token_limit(t)]
    print(f"🔍 Valid texts: {len(valid_texts)}")
    embeddings = []
    for i in range(0, len(valid_texts), 20):  # batch up to 20 at a time
        batch = valid_texts[i:i+20]
        response = openai.embeddings.create(
            model=EMBED_MODEL,
            input=batch
        )
        batch_embeddings = [d.embedding for d in response.data]
        embeddings.extend(batch_embeddings)
    return embeddings

def build_faiss_index(vectors: List[List[float]]):
    dim = len(vectors[0])
    index = faiss.IndexFlatL2(dim)
    index.add(np.array(vectors).astype("float32"))
    return index

if __name__ == "__main__":
    # Load data
    cve_entries = load_json(CVE_PATH)
    cwe_entries = load_json(CWE_PATH)
    print(f"🔍 Loaded {len(cve_entries)} CVE entries and {len(cwe_entries)} CWE entries.")

    # Format documents
    documents = [format_cve(c) for c in cve_entries] + [format_cwe(c) for c in cwe_entries]
    texts = [doc["text"] for doc in documents]
    print(f"🔍 Formatted {len(texts)} documents for embedding.")

    # Embed
    embeddings = embed_texts(texts)
    print(f"🔍 Embedded {len(embeddings)} documents.")

    # Build and save index
    index = build_faiss_index(embeddings)
    faiss.write_index(index, INDEX_PATH)

    # Save metadata
    with open(META_PATH, "wb") as f:
        pickle.dump(documents, f)

    print(f"✅ FAISS index saved to {INDEX_PATH}")
    print(f"✅ Metadata saved to {META_PATH}")