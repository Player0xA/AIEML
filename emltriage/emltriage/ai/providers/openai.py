"""OpenAI provider for GPT models."""

import os
from typing import Optional

import requests

from emltriage.ai.models import AIProviderType
from emltriage.ai.providers.base import AIProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class OpenAIProvider(AIProvider):
    """OpenAI provider for GPT-4, GPT-3.5, etc."""
    
    DEFAULT_MODEL = "gpt-4"
    BASE_URL = "https://api.openai.com/v1"
    
    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        api_key: Optional[str] = None,
    ):
        """Initialize OpenAI provider.
        
        Args:
            model: Model name (e.g., 'gpt-4', 'gpt-3.5-turbo')
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            api_key: OpenAI API key (from env if not provided)
        """
        super().__init__(model or self.DEFAULT_MODEL, temperature, max_tokens)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    
    @property
    def provider_type(self) -> AIProviderType:
        """Return provider type."""
        return AIProviderType.OPENAI
    
    def is_available(self) -> bool:
        """Check if OpenAI is configured.
        
        Returns:
            True if API key is set
        """
        return bool(self.api_key)
    
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response using OpenAI API.
        
        Args:
            system_prompt: System instructions
            user_prompt: User query
            
        Returns:
            Generated text
        """
        if not self.api_key:
            raise RuntimeError("OpenAI API key not configured")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
        
        except requests.RequestException as e:
            logger.error(f"OpenAI request failed: {e}")
            if response.status_code == 429:
                raise RuntimeError("OpenAI rate limit exceeded")
            elif response.status_code == 401:
                raise RuntimeError("OpenAI authentication failed")
            raise RuntimeError(f"OpenAI generation failed: {e}")
        
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected OpenAI response format: {e}")
            raise RuntimeError(f"Invalid OpenAI response: {e}")
