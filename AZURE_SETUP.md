# Azure AI Foundry Setup

Quick reference for running Strix with Azure OpenAI (Azure AI Foundry).

## Required Environment Variables

| Variable | What it is | Where to find it |
| --- | --- | --- |
| `STRIX_LLM` | Model identifier with `azure/` prefix | Your deployment name in Azure AI Foundry |
| `LLM_API_KEY` | Azure API key | Azure AI Foundry → Project → Settings → Keys and Endpoint |
| `LLM_API_BASE` | Azure endpoint URL | Azure AI Foundry → Project → Settings → Keys and Endpoint |
| `AZURE_API_VERSION` | API version string | Use `2024-08-01-preview` unless you have a specific requirement |

## PowerShell

```powershell
$env:STRIX_LLM        = "azure/your-deployment-name"
$env:LLM_API_KEY      = "your-azure-api-key"
$env:LLM_API_BASE     = "https://your-resource.openai.azure.com/"
$env:AZURE_API_VERSION = "2024-08-01-preview"
```

## Run

```powershell
poetry run strix --target https://your-target.com
```

## Common Mistakes

**Missing `azure/` prefix** — `STRIX_LLM` must be `azure/<deployment-name>`, not just the deployment name alone. Without the prefix, LiteLLM routes to OpenAI and fails with an auth error.

**Missing `AZURE_API_VERSION`** — Azure OpenAI requires an API version. Without it you get a `404 Resource not found` error.

**Wrong deployment name** — The value after `azure/` must match the **deployment name** in Azure AI Foundry exactly (case-sensitive), not the model name. Check under **Deployments** in your project.

**Variables lost on new terminal** — PowerShell `$env:` variables are session-scoped. Set all four variables again if you open a new terminal. Strix saves the config to `~/.strix/cli-config.json` after the first successful run.
