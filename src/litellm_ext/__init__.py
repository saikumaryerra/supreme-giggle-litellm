"""litellm-ext: self-built enterprise layer for the LiteLLM proxy.

All features attach through LiteLLM's documented OSS extension points
(custom_auth, CustomLogger, CustomGuardrail, router model_list). Nothing in
this package imports from litellm's enterprise/ directory or the
litellm_enterprise package.
"""

__version__ = "0.1.0"
