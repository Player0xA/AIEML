"""AI provider base class and interface."""

from abc import ABC, abstractmethod
from typing import Optional

from emltriage.ai.models import AIProviderType, AIReport


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    def __init__(self, model: Optional[str] = None, temperature: float = 0.1):
        """Initialize AI provider.
        
        Args:
            model: Model identifier (provider-specific)
            temperature: Sampling temperature (0.0-1.0)
        """
        self.model = model
        self.temperature = temperature
    
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
