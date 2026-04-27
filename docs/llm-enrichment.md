# LLM Enrichment (Experimental, Opt-in)

> **Status:** Experimental — interfaces and behaviour may change without notice.

## Overview

Syftient includes an opt-in, **local-first** LLM enrichment layer that improves SBOM quality for fields that deterministic catalogers cannot resolve confidently (e.g. packages with `NOASSERTION` or missing SPDX license identifiers).

The enrichment pipeline is:

1. **Disabled by default** — existing Syft behaviour is completely unchanged unless you explicitly pass `--llm-enabled`.
2. **Local-first** — powered by [Ollama](https://ollama.com), running entirely on your machine. No data ever leaves your network.
3. **Graceful** — if Ollama is unreachable, a warning is logged and the scan continues with the standard SBOM output.
4. **Auditable** — every LLM-derived field carries structured evidence metadata (`source`, `model`, `confidence`, `prompt_hash`).

## Why local-first?

- **Privacy**: package names, versions, and file paths may contain sensitive information. Running inference locally ensures data never reaches a cloud API.
- **Zero telemetry**: Ollama has no call-home functionality; neither does Syftient.
- **Reproducibility**: with `temperature=0` and a fixed seed, results are deterministic across runs on the same model version.
- **No API keys or billing**: no accounts required; Ollama is free and open-source.

## Quickstart with Ollama

### 1. Start Ollama

```bash
# Using Docker:
docker run -d --rm -p 11434:11434 ollama/ollama

# Or install natively: https://ollama.com/download
```

### 2. Pull the default model

```bash
docker exec <container> ollama pull llama3.2:3b
# or, natively:
ollama pull llama3.2:3b
```

### 3. Run Syftient with LLM enrichment

```bash
syft alpine:latest --llm-enabled
```

### docker-compose snippet

```yaml
services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama

  syftient:
    image: syftient:latest
    depends_on:
      - ollama
    command: >
      scan alpine:latest
      --llm-enabled
      --llm-endpoint http://ollama:11434
      --llm-model llama3.2:3b
      -o spdx-json

volumes:
  ollama_data:
```

## Configuration reference

All options can be set via CLI flags, environment variables (`SYFT_LLM_*`), or the Syft config file (`.syft.yaml`).

| Field | CLI flag | Default | Description |
|-------|----------|---------|-------------|
| `enabled` | `--llm-enabled` | `false` | Enable the LLM enrichment layer |
| `provider` | `--llm-provider` | `"ollama"` | Backend provider (only `"ollama"` supported in this release) |
| `endpoint` | `--llm-endpoint` | `http://localhost:11434` | Base URL of the LLM provider |
| `model` | `--llm-model` | `llama3.2:3b` | Model name/tag to use |
| `timeout` | — | `30s` | Per-request timeout |
| `temperature` | — | `0.0` | Sampling temperature; `0.0` = fully deterministic |
| `min-confidence` | — | `0.75` | Minimum confidence score `[0,1]` to accept an LLM-derived field |
| `tasks` | — | _(all)_ | Enrichment tasks to run; empty = all registered tasks |
| `max-tokens` | — | `100000` | Soft per-scan token budget; enrichment stops when exhausted |

### Example `.syft.yaml`

```yaml
llm:
  enabled: true
  provider: ollama
  endpoint: http://localhost:11434
  model: llama3.2:3b
  timeout: 45s
  temperature: 0.0
  min-confidence: 0.8
  tasks:
    - licenses
  max-tokens: 50000
```

## How to add a new EnrichmentTask

1. Create a new file in `syft/pkg/cataloger/llmenrich/`.
2. Implement the `EnrichmentTask` interface:

```go
type EnrichmentTask interface {
    Name() string
    Applies(pkg.Package) bool
    Enrich(ctx context.Context, p pkg.Package, client llm.Client) (*pkg.Package, error)
}
```

3. Register your task in `DefaultTasks()` inside `enricher.go`.
4. Add unit tests using `llm.MockClient` (no real Ollama needed).

### Guidelines

- Keep tasks focused on a single SBOM field or concern.
- Use `llm.Request{Temperature: 0.0}` for determinism.
- Always call `AttachEvidence(&enriched, ev)` on the returned package so consumers know the field is LLM-derived.
- Return `nil, nil` (not an error) when the model output does not meet quality requirements — this silently skips the package rather than failing the scan.

## Privacy & data handling

- **No data leaves your machine** when using the default Ollama backend.
- Package names, versions, and types are sent to the local model as part of the prompt. File paths and other sensitive data are **not** included in the default prompts.
- A `// TODO` comment in `license_classifier.go` marks the location where `internal/redact` integration should be added once prompt engineering is finalised.
- The LLM response cache is stored in the same directory as Syft's other caches (configurable via `--cache-dir`). Cache keys are `sha256(prompt + systemPrompt + model + modelVersion)` — no raw package data is stored in the key.

## Limitations & known issues

- Only the `"licenses"` task is implemented in this release. The task targets packages with `NOASSERTION` or empty SPDX license identifiers.
- The SPDX license enum used to bound model output is a small placeholder list. The full SPDX list integration is planned for a follow-up PR.
- Only `"ollama"` is supported as a provider. Cloud providers (OpenAI, Anthropic, etc.) are planned for future releases.
- The per-scan token budget (`max-tokens`) is approximate — it is based on the `eval_count` field in Ollama responses.
- Enrichment runs sequentially (one package at a time). Parallelism is planned for a future release.
- This feature is **Experimental** and may change or be removed without prior deprecation notice.

## Roadmap

Follow-up PRs planned after this scaffolding:

1. **License Classifier prompt tuning** — few-shot examples, improved accuracy
2. **Full SPDX list integration** — load from `internal/spdxlicense` to validate model output
3. **Benchmark dataset** — golden-file tests for license classification accuracy
4. **Additional tasks** — Unknown Binary Identifier, CPE normalisation
5. **Embedding pre-filter** — skip packages that are unlikely to benefit from LLM enrichment
6. **Optional cloud providers** — OpenAI, Anthropic (all opt-in, API key required)
