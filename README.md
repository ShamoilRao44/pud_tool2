# PUD Pipeline

This project builds a deterministic Stage 1 inventory and classification pipeline for IBM mainframe sources.

## Setup

1. Open a terminal in the project root.
2. Create a virtual environment:
   - Windows PowerShell: `python -m venv .venv`
   - then: `.\.venv\Scripts\Activate.ps1`
3. Install dependencies:
   - `python -m pip install -r requirements.txt`
4. Copy the environment template:
   - `Copy-Item .env.example .env`
   - or `cp .env.example .env`
5. Set `SOURCE_DIR` in `.env` to the legacy source tree root you want to analyze.

## Run the app

```bash
python run.py
```

The server listens on the configured `FLASK_HOST` and `FLASK_PORT` values.

## Run tests

```bash
pytest -q
```

## Example HTTP calls

### PowerShell

```powershell
$env:SOURCE_DIR = "C:\\path\\to\\customer_search_isolated"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api/v1/runs" -ContentType "application/json" -Body '{"stages":[1]}'
```

### curl

```bash
curl -X POST http://127.0.0.1:5000/api/v1/runs \
  -H "Content-Type: application/json" \
  -d '{"stages":[1]}'
```

## How to add Stage N

1. Create a new package under `app/stages/stageN_name/`.
2. Define a subclass of `Stage`.
3. Register it with `@register_stage(N)`.
4. Implement the `run()` and `verify()` methods.
5. Add JSON schema files under `app/schemas/stageN/`.
6. Add tests under `tests/`.
7. No API route changes are required; the registry and runner discover the new stage automatically.
