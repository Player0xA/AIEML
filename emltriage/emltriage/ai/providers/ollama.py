"""Ollama provider for local AI models."""

import json
import os
from typing import Optional

import requests

from emltriage.ai.models import AIProviderType
from emltriage.ai.providers.base import AIProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class OllamaProvider(AIProvider):
    """Ollama provider for running local models."""
    
    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "llama3.1"
    
    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        base_url: Optional[str] = None,
    ):
        """Initialize Ollama provider.
        
        Args:
            model: Model name (e.g., 'llama3.1', 'mistral', 'codellama')
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            base_url: Ollama API base URL
        """
        super().__init__(model or self.DEFAULT_MODEL, temperature, max_tokens)
        self.base_url = base_url or os.environ.get("OLLAMA_BASE_URL", self.DEFAULT_BASE_URL)
        self._available = None  # Cache availability check
    
    @property
    def provider_type(self) -> AIProviderType:
        """Return provider type."""
        return AIProviderType.OLLAMA
    
    def is_available(self) -> bool:
        """Check if Ollama is available.
        
        Returns:
            True if Ollama server is running
        """
        if self._available is None:
            try:
                response = requests.get(f"{self.base_url}/api/tags", timeout=5)
                self._available = response.status_code == 200
            except requests.RequestException:
                self._available = False
                logger.warning(f"Ollama not available at {self.base_url}")
        return self._available
    
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response using Ollama.
        
        Args:
            system_prompt: System instructions
            user_prompt: User query
            
        Returns:
            Generated text
        """
        if not self.is_available():
            raise RuntimeError(f"Ollama not available at {self.base_url}")
        
        # Combine system and user prompts
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300,  # Long timeout for local generation
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get("response", "")
        
        except requests.RequestException as e:
            logger.error(f"Ollama request failed: {e}")
            raise RuntimeError(f"Ollama generation failed: {e}")
    
    def list_models(self) -> list[str]:
        """List available models.
        
        Returns:
            List of model names
        """
        if not self.is_available():
            return []
        
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            data = response.json()
            return [m["name"] for m in data.get("models", [])]
        
        except requests.RequestException as e:
            logger.error(f"Failed to list Ollama models: {e}")
            return []
