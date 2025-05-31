import os
import sys
import openai
import faiss
import pickle
import numpy as np
import tiktoken

# Load environment key
openai.api_key = os.getenv("OPENAI_API_KEY")

# Set working directory to script's parent directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ""))  # or further up if needed
sys.path.insert(0, ROOT_DIR)

INDEX_PATH = os.path.join(ROOT_DIR, "openai_faiss_index.bin")
META_PATH = os.path.join(ROOT_DIR, "openai_index_metadata.pkl")
EMBED_MODEL = "text-embedding-3-large"

# Load FAISS index and metadata
index = faiss.read_index(INDEX_PATH)
with open(META_PATH, "rb") as f:
    metadata = pickle.load(f)

# Token limit checker (optional)
tokenizer = tiktoken.encoding_for_model(EMBED_MODEL)
def is_within_token_limit(text: str, limit: int = 8000) -> bool:
    return len(tokenizer.encode(text)) <= limit

def query_faiss(text: str, k: int = 5):
    if not is_within_token_limit(text):
        print("❌ Query too long, exceeds token limit.")
        return []

    # Get embedding for query text
    response = openai.embeddings.create(
        model=EMBED_MODEL,
        input=text
    )
    embedding = np.array(response.data[0].embedding).astype("float32").reshape(1, -1)

    # Search FAISS index
    distances, indices = index.search(embedding, k)

    # Collect and return results
    results = []
    for idx, dist in zip(indices[0], distances[0]):
        if idx >= 0 and idx < len(metadata):
            entry = metadata[idx]
            results.append({
                "score": float(dist),
                "type": entry.get("type"),
                "cwe": entry.get("cwe"),
                "text": entry.get("text")[:800] + "..." if len(entry.get("text", "")) > 800 else entry.get("text"),
                "source": entry.get("source")
            })
    return results

# Example usage
if __name__ == "__main__":
    query = "Use of strcpy without bounds checking may lead to buffer overflow."
    results = query_faiss(query, k=5)

    for i, res in enumerate(results):
        print(f"\n--- Result {i+1} ---")
        print(f"Type: {res['type']} | CWE: {res['cwe']} | Score: {res['score']:.2f}")
        print(f"Text:\n{res['text']}\n")
