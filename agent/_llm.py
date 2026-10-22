"""Central LLM call with provider switching (ollama | gemini) and optional tracing.

Every LLM call in loop.py and ai_target.py goes through chat(). The tracer wraps
this function, not the callers.
"""
import json
import os
import time
import urllib.request

try:  # load GEMINI_API_KEY (and friends) from a .env file if present
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def chat(messages, model, agent_name="main", config=None, tracer=None) -> str:
    t0 = time.time()
    llm = (config or {}).get("llm") or {}
    provider = llm.get("provider", "ollama")
    key = llm.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")

    if provider == "gemini" and key:
        try:
            resp = _gemini(messages, model, key)
        except Exception as ge:
            # Fall back to ollama; if that is also unavailable, surface the real
            # Gemini error rather than a misleading "start ollama" message.
            try:
                resp = _ollama(messages, llm.get("ollama_model", "llama3.1"))
            except RuntimeError:
                raise RuntimeError(f"Gemini call failed and ollama is unavailable: {ge}")
    else:
        resp = _ollama(messages, model)

    if tracer is not None:
        tracer.record(agent_name, model, messages, resp, (time.time() - t0) * 1000)
    return resp


def _ollama(messages, model):
    try:
        import ollama  # lazy: dry runs work without the SDK installed
        r = ollama.chat(model=model, messages=messages)
    except ImportError:
        raise RuntimeError("ollama SDK not installed. Install it with:  pip install ollama")
    except Exception as e:  # ollama down, model missing, etc.
        raise RuntimeError(
            f"ollama call failed: {e}\n"
            "Is ollama running? Start it with:  ollama serve\n"
            f"Is the model pulled?  ollama pull {model}")
    return r["message"]["content"]


def _gemini(messages, model, key):
    # Gemini REST is stateless HTTP, safe to call from multiple threads at once.
    text = "\n\n".join(f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages)
    # Use a concrete Gemini model id as-is; map anything non-Gemini to a current flash.
    mdl = model if model.startswith("gemini") else "gemini-flash-lite-latest"
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{mdl}:generateContent?key={key}")
    body = json.dumps({"contents": [{"parts": [{"text": text}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    return data["candidates"][0]["content"]["parts"][0]["text"]
