"""
Cycle 11 – Ollama Multi-Agent Swarm
=====================================
Core module: OllamaClient wraps the local Ollama REST API.
All agents use this to call the local LLM.
"""
import json
import urllib.request
import urllib.error
from typing import Optional

OLLAMA_BASE = "http://127.0.0.1:11434"


class OllamaClient:
    def __init__(self, model: str = "llama3.2", base_url: str = OLLAMA_BASE):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def list_models(self) -> list:
        """Return list of locally available model names."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            return []

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        """
        Send a generate request to Ollama and return the full response text.
        Uses /api/generate with stream=False for simplicity.
        """
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": 2048},
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1200) as resp:
                data = json.loads(resp.read())
                return data.get("response", "").strip()
        except TimeoutError as e:
            raise ConnectionError(
                f"Ollama generate timed out after 1200s for model {self.model}."
            ) from e
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot reach Ollama at {self.base_url}. "
                f"Is 'ollama serve' running? Error: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Ollama call failed: {e}") from e

    def chat(self, messages: list, temperature: float = 0.3, num_predict: int = 1024) -> Optional[str]:
        """
        Chat-style call using /api/chat.
        messages: list of {"role": "user"|"assistant"|"system", "content": "..."}
        """
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": num_predict},
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1200) as resp:
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "").strip()
        except TimeoutError as e:
            raise ConnectionError(
                f"Ollama chat timed out after 1200s for model {self.model}."
            ) from e
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot reach Ollama at {self.base_url}. "
                f"Is 'ollama serve' running? Error: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Ollama chat call failed: {e}") from e
