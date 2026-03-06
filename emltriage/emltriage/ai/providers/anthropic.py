"""Anthropic provider for Claude models."""

import os
from typing import Optional

import requests

from emltriage.ai.models import AIProviderType
from emltriage.ai.providers.base import AIProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class AnthropicProvider(AIProvider):
    """Anthropic provider for Claude models."""
    
    DEFAULT_MODEL = "claude-3-opus-20240229"
    BASE_URL = "https://api.anthropic.com/v1"
    
    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        api_key: Optional[str] = None,
    ):
        """Initialize Anthropic provider.
        
        Args:
            model: Model name (e.g., 'claude-3-opus', 'claude-3-sonnet')
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            api_key: Anthropic API key (from env if not provided)
        """
        super().__init__(model or self.DEFAULT_MODEL, temperature, max_tokens)
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    
    @property
    def provider_type(self) -> AIProviderType:
        """Return provider type."""
        return AIProviderType.ANTHROPIC
    
    def is_available(self) -> bool:
        """Check if Anthropic is configured.
        
        Returns:
            True if API key is set
        """
        return bool(self.api_key)
    
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response using Anthropic API.
        
        Args:
            system_prompt: System instructions
            user_prompt: User query
            
        Returns:
            Generated text
        """
        if not self.api_key:
            raise RuntimeError("Anthropic API key not configured")
        
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        
        # Combine prompts for Claude
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {"role": "user", "content": full_prompt},
            ],
        }
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/messages",
                headers=headers,
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            
            data = response.json()
            return data["content"][0]["text"]
        
        except requests.RequestException as e:
            logger.error(f"Anthropic request failed: {e}")
            if response.status_code == 429:
                raise RuntimeError("Anthropic rate limit exceeded")
            elif response.status_code == 401:
                raise RuntimeError("Anthropic authentication failed")
            raise RuntimeError(f"Anthropic generation failed: {e}")
        
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected Anthropic response format: {e}")
            raise RuntimeError(f"Invalid Anthropic response: {e}")
