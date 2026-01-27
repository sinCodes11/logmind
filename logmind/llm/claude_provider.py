"""Anthropic Claude LLM provider."""

from logmind.config.settings import get_settings
from logmind.llm.base import BaseLLMProvider, LLMResponse
from logmind.llm.rate_limiter import RateLimiter


class ClaudeProvider(BaseLLMProvider):
    """
    Anthropic Claude API provider.

    Supports Claude 3 models for security log analysis.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """
        Initialize Claude provider.

        Args:
            api_key: Anthropic API key (defaults to env var)
            model: Model name (defaults to config)
            rate_limiter: Optional rate limiter (creates default if None)
        """
        settings = get_settings()

        self._api_key = api_key
        if not self._api_key and settings.anthropic_api_key:
            self._api_key = settings.anthropic_api_key.get_secret_value()

        self._model = model or settings.llm_model
        self._client = None

        # Rate limiting: 50 calls/min, 100K tokens/min by default
        self._rate_limiter = rate_limiter or RateLimiter(
            max_calls=50,
            time_window=60.0,
            max_tokens_per_minute=100000,
        )

    def _get_client(self):
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise ImportError("anthropic package required: pip install anthropic")
        return self._client

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return self._model

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """Generate response using Claude API with rate limiting."""
        # Rate limiting check
        can_proceed, reason = self._rate_limiter.can_proceed()
        if not can_proceed:
            raise RuntimeError(f"Rate limit exceeded: {reason}")

        # Input validation
        if len(prompt) > 100000:  # ~25K tokens max
            raise ValueError("Prompt too long (max 100K characters)")
        if system_prompt and len(system_prompt) > 10000:
            raise ValueError("System prompt too long (max 10K characters)")

        client = self._get_client()

        messages = [{"role": "user", "content": prompt}]

        kwargs = {
            "model": self._model,
            "max_tokens": min(max_tokens, 4096),  # Cap at 4096
            "temperature": max(0.0, min(1.0, temperature)),  # Clamp 0-1
            "messages": messages,
            "timeout": 60.0,  # 60 second timeout
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = client.messages.create(**kwargs)

        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        llm_response = LLMResponse(
            content=content,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            metadata={
                "stop_reason": response.stop_reason,
                "id": response.id,
            },
        )

        # Record the call for rate limiting
        self._rate_limiter.record_call(
            llm_response.input_tokens + llm_response.output_tokens
        )

        return llm_response

    def is_available(self) -> bool:
        """Check if Claude API is configured."""
        if not self._api_key:
            return False

        try:
            self._get_client()
            return True
        except Exception:
            return False
