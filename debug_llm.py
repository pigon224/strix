import os

import litellm


litellm._turn_on_debug()

response = litellm.completion(
    model=os.getenv("STRIX_LLM"),
    messages=[{"role": "user", "content": "hi"}],
    api_key=os.getenv("LLM_API_KEY"),
    api_base=os.getenv("LLM_API_BASE"),
    api_version=os.getenv("AZURE_API_VERSION"),
)
print(response)
