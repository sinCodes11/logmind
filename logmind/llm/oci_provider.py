"""Oracle Cloud Infrastructure Generative AI provider."""

from logmind.config.settings import get_settings
from logmind.llm.base import BaseLLMProvider, LLMResponse


class OCIGenAIProvider(BaseLLMProvider):
    """
    OCI Generative AI provider.

    Supports Cohere and other models available on OCI.
    """

    def __init__(
        self,
        compartment_id: str | None = None,
        endpoint: str | None = None,
        model: str | None = None,
        config_file: str | None = None,
        config_profile: str | None = None,
    ) -> None:
        """
        Initialize OCI GenAI provider.

        Args:
            compartment_id: OCI compartment OCID
            endpoint: OCI GenAI endpoint URL
            model: Model ID to use
            config_file: OCI config file path
            config_profile: OCI config profile name
        """
        settings = get_settings()

        self._compartment_id = compartment_id or settings.oci_compartment_id
        self._endpoint = endpoint or settings.oci_genai_endpoint
        self._model = model or settings.oci_genai_model
        self._config_file = config_file or settings.oci_config_file
        self._config_profile = config_profile or settings.oci_config_profile
        self._client = None

    def _get_client(self):
        """Get or create OCI GenAI client."""
        if self._client is None:
            try:
                import oci
                from oci.generative_ai_inference import GenerativeAiInferenceClient

                config = oci.config.from_file(
                    file_location=self._config_file,
                    profile_name=self._config_profile,
                )

                self._client = GenerativeAiInferenceClient(
                    config=config,
                    service_endpoint=self._endpoint,
                )
            except ImportError:
                raise ImportError("oci package required: pip install oci")
        return self._client

    @property
    def provider_name(self) -> str:
        return "oci"

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
        """Generate response using OCI GenAI API."""
        try:
            from oci.generative_ai_inference.models import (
                ChatDetails,
                CohereChatRequest,
                OnDemandServingMode,
            )
        except ImportError:
            raise ImportError("oci package required: pip install oci")

        client = self._get_client()

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        chat_request = CohereChatRequest(
            message=full_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            is_stream=False,
        )

        chat_details = ChatDetails(
            compartment_id=self._compartment_id,
            serving_mode=OnDemandServingMode(model_id=self._model),
            chat_request=chat_request,
        )

        response = client.chat(chat_details)
        chat_response = response.data.chat_response

        content = chat_response.text if hasattr(chat_response, "text") else str(chat_response)

        input_tokens = 0
        output_tokens = 0
        if hasattr(chat_response, "meta") and chat_response.meta:
            if hasattr(chat_response.meta, "billed_units"):
                billed = chat_response.meta.billed_units
                input_tokens = getattr(billed, "input_tokens", 0) or 0
                output_tokens = getattr(billed, "output_tokens", 0) or 0

        return LLMResponse(
            content=content,
            model=self._model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            metadata={
                "compartment_id": self._compartment_id,
                "endpoint": self._endpoint,
            },
        )

    def is_available(self) -> bool:
        """Check if OCI GenAI is configured."""
        if not self._compartment_id:
            return False

        try:
            self._get_client()
            return True
        except Exception:
            return False
