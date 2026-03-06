"""AI provider base class and interface."""

from abc import ABC, abstractmethod
from typing import Optional

from emltriage.ai.models import AIProviderType


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    def __init__(self, model: Optional[str] = None, temperature: float = 0.1, max_tokens: int = 4096):
        """Initialize AI provider.
        
        Args:
            model: Model identifier (provider-specific)
            temperature: Sampling temperature (0.0-1.0, lower = more deterministic)
            max_tokens: Maximum tokens in response
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    @property
    @abstractmethod
    def provider_type(self) -> AIProviderType:
        """Return the provider type identifier."""
        pass
    
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response from AI.
        
        Args:
            system_prompt: System instructions
            user_prompt: User query/input
            
        Returns:
            Generated text response
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available/configured.
        
        Returns:
            True if provider can be used
        """
        pass
    
    @property
    def provider_string(self) -> str:
        """Get provider:model string identifier.
        
        Returns:
            Provider string (e.g., 'ollama:llama3.1')
        """
        return f"{self.provider_type.value}:{self.model or 'default'}"
