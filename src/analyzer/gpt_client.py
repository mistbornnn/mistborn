import logging
from ..config.settings import DEBUG_MODE, GPT_MODEL
from typing import List
import openai

class GPTClient:
    def __init__(self, api_key):
        self.api_key = api_key
        if DEBUG_MODE:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("GPTClient")

    def send_prompt(self, prompt):
        from openai import OpenAI
        
        client = OpenAI(api_key=self.api_key)
        
        if DEBUG_MODE:
            self.logger.info(f"Sending prompt to GPT: {prompt}")
        
        response = client.chat.completions.create(model=GPT_MODEL,
        messages=[{"role": "user", "content": prompt}])
        
        if DEBUG_MODE:
            self.logger.info(f"Received raw response from GPT: {response}")
        
        return response

    def receive_response(self, response):
        content = response.choices[0].message.content if response and hasattr(response, 'choices') else None
        
        if DEBUG_MODE:
            self.logger.info(f"Processed GPT response: {content}")
            
        return content

    def embed_text(self, text: str, embedding_model) -> List[float]:
        response = openai.embeddings.create(
            model=embedding_model,
            input=text
        )
        return response.data[0].embedding