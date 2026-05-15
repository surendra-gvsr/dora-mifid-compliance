import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

from openai import OpenAI

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    _env = Path(__file__).resolve().parent / ".env"
    if _env.exists():
        load_dotenv(_env, override=False)
except ImportError:
    pass


def _provider() -> str:
    return os.getenv("LLM_PROVIDER", "GEMINI").upper()


def _xai_client() -> OpenAI:
    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        raise RuntimeError("XAI_API_KEY not set.")
    return OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")


def _openai_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set.")
    return OpenAI(api_key=api_key)


def _call_grok(prompt: str) -> str:
    client = _xai_client()
    model = os.getenv("XAI_MODEL", "grok-3-mini")
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return resp.choices[0].message.content.strip()


async def chat_completion_async(
    prompt: str,
    model: Optional[str] = None,
    timeout: int = 120,
    max_retries: int = 3,
    **_kwargs,          # absorb extra kwargs (response_schema etc.) gracefully
) -> str:
    """Provider-agnostic async LLM call with retry + exponential backoff."""
    provider = _provider()
    loop = asyncio.get_event_loop()

    # ---- xAI Grok ----
    if provider == "XAI":
        last_err = None
        for attempt in range(max_retries):
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(None, _call_grok, prompt),
                    timeout=timeout,
                )
            except Exception as exc:
                last_err = exc
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError(f"xAI call failed after {max_retries} attempts: {last_err}")

    # ---- Google Gemini ----
    if provider == "GEMINI":
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not set.")
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ImportError("Run: pip install google-generativeai") from exc

        genai.configure(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        gmodel = genai.GenerativeModel(
            model_name,
            generation_config={"temperature": 0.2, "max_output_tokens": 8192},
        )
        last_err = None
        for attempt in range(max_retries):
            try:
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, gmodel.generate_content, prompt),
                    timeout=timeout,
                )
                text = getattr(response, "text", None)
                if text:
                    return text.strip()
                # fallback extraction
                candidates = getattr(response, "candidates", None) or []
                parts = []
                for c in candidates:
                    content = getattr(c, "content", None)
                    if content and hasattr(content, "parts"):
                        parts.extend(str(p) for p in content.parts)
                if parts:
                    return "\n".join(parts).strip()
            except Exception as exc:
                last_err = exc
                if attempt < max_retries - 1:
                    logger.warning("Gemini attempt %d failed: %s", attempt + 1, exc)
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError(f"Gemini call failed after {max_retries} attempts: {last_err}")

    # ---- OpenAI ----
    def _sync_openai() -> str:
        client = _openai_client()
        model_name = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        resp = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_openai),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"OpenAI call timed out after {timeout}s")
