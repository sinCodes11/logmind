"""Base LLM provider interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    """Response from LLM provider."""

    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    metadata: dict = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        """Get total token count."""
        return self.input_tokens + self.output_tokens


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model name being used."""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            LLMResponse with generated content
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        pass
