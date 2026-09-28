"""
Cycle 11 – Ollama Multi-Agent Swarm
=====================================
Core module: LLMClient acts as a router for local Ollama and Groq API.
"""
import json
import os
import urllib.request
import urllib.error
from typing import Optional

OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class LLMClient:
    def __init__(self, model: str = "llama3.2", base_url: str = OLLAMA_BASE):
        self.model = model
        self.base_url = base_url.rstrip("/")
        
        # Check if routing to Groq
        self.is_groq = self.model.startswith("groq/")
        if self.is_groq:
            self.groq_model = self.model[len("groq/"):]
            self.groq_api_key = os.environ.get("GROQ_API_KEY", "")
            if not self.groq_api_key:
                raise ValueError("GROQ_API_KEY environment variable is required when using groq/ models.")

    def list_models(self) -> list:
        """Return list of locally available model names. Groq models are dynamic."""
        if self.is_groq:
            return [self.model] # Groq models aren't queried here
            
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            return []

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        """
        Send a generate request and return the full response text.
        """
        if self.is_groq:
            return self._generate_groq(prompt, system, temperature)
        else:
            return self._generate_ollama(prompt, system, temperature)

    def _generate_groq(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        payload = json.dumps({
            "model": self.groq_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 2048,
        }).encode("utf-8")
        
        req = urllib.request.Request(
            GROQ_API_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.groq_api_key}"
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            raise RuntimeError(f"Groq API call failed: {e}") from e

    def _generate_ollama(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
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
        Chat-style call.
        messages: list of {"role": "user"|"assistant"|"system", "content": "..."}
        """
        if self.is_groq:
            return self._chat_groq(messages, temperature, num_predict)
        else:
            return self._chat_ollama(messages, temperature, num_predict)
            
    def _chat_groq(self, messages: list, temperature: float = 0.3, num_predict: int = 1024) -> Optional[str]:
        payload = json.dumps({
            "model": self.groq_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": num_predict,
        }).encode("utf-8")
        
        req = urllib.request.Request(
            GROQ_API_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.groq_api_key}",
                "User-Agent": "Swarm-Security-Scanner/1.0"
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(f"Groq API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            raise RuntimeError(f"Groq API chat call failed: {e}") from e

    def _chat_ollama(self, messages: list, temperature: float = 0.3, num_predict: int = 1024) -> Optional[str]:
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

# Alias for backwards compatibility if anyone directly imports OllamaClient
OllamaClient = LLMClient
