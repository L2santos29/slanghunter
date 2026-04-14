# SlangHunter Knowledge Base Data Files

The files in this directory externalize the category knowledge base used by
[`SlangHunter.from_data_dir()`](../src/slanghunter.py) and
[`SlangHunter.reload_from_data_dir()`](../src/slanghunter.py).

Each `*.json` file defines one category. The filename stem becomes the category
name exposed by the engine and the REST API.

## Current Files

- [`drugs.json`](drugs.json)
- [`money_laundering.json`](money_laundering.json)
- [`surikae.json`](surikae.json)

## JSON Schema

Every file must follow this structure:

```json
{
  "keywords": ["keyword one", "keyword two"],
  "slang_patterns": ["p[3e]rc[s0]?", "m[\\s._]*[o0][\\s._]*l[\\s._]*l[\\s._]*y"],
  "risk_threshold": {
    "min": 0.0,
    "max": 80.0,
    "description": "Why this price band is suspicious"
  },
  "legal_reference": {
    "statute": "21 U.S.C. § 841",
    "name": "Statute title",
    "summary": "U.S. legal basis"
  },
  "jp_legal_reference": {
    "statute": "薬機法 Art. 84",
    "name": "Japanese statute title",
    "summary": "Japanese legal basis"
  }
}
```

## How to Add New Keywords or Patterns

1. Open the category file you want to extend.
2. Add the new plain-language term to `keywords`.
3. Add the raw regex string to `slang_patterns` if evasion detection is needed.
4. Keep the file valid JSON with double quotes and no trailing commas.
5. Reload the running API with `POST /reload`.

### Worked Example

If operators want to catch a new drug term such as `ketamine` and a simple
evasion pattern `k[e3]t[a@]m[i1]n[e3]?`, update [`drugs.json`](drugs.json):

```json
{
  "keywords": [
    "fentanyl",
    "ketamine"
  ],
  "slang_patterns": [
    "p[3e]rc[s0]?",
    "k[e3]t[a@]m[i1]n[e3]?"
  ]
}
```

The loader compiles regex strings at runtime, so store pattern text only.
Do not attempt to serialize Python `re.Pattern` objects into JSON.

## ReDoS Warning for New Regex Patterns

Externalized patterns increase operational flexibility, but they also create a
security review obligation. Follow this repository policy for every new regex:

- Avoid nested quantifiers such as `(a+)+`.
- Prefer explicit character classes and bounded repetition.
- Keep patterns linear in the length of the input.
- Treat every new regex as security-sensitive review material.

Unsafe regex can turn the API into a denial-of-service target.

## Hot Reload via the REST API

When the API is running, reload the in-memory knowledge base without restarting
the server:

```bash
curl -X POST http://127.0.0.1:8000/reload
```

The endpoint responds with the reload status and the currently loaded category
list.
