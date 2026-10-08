"""
Cycle 11 – Multi-Agent Swarm LLM Client
=========================================
Core module: LLMClient acts as a router for local Ollama, Groq API, and NVIDIA NIM.
"""
import json
import os
import urllib.request
import urllib.error
from typing import Optional
from dotenv import load_dotenv
load_dotenv(override=True)

OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
NVIDIA_BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")


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

        # Check if routing to NVIDIA NIM
        self.is_nim = (
            self.model.startswith("nvidia/")
            or self.model.startswith("nim/")
            or (bool(os.environ.get("NVIDIA_API_KEY")) and self.model.startswith(("meta/", "ibm/", "microsoft/")))
        )
        if self.is_nim:
            if self.model.startswith("nim/"):
                self.nim_model = self.model[len("nim/"):]
            else:
                self.nim_model = self.model
            self.nim_api_key = os.environ.get("NVIDIA_API_KEY", "") or os.environ.get("NIM_API_KEY", "")
            self.nim_api_url = f"{NVIDIA_BASE_URL}/chat/completions"
            if not self.nim_api_key:
                raise ValueError("NVIDIA_API_KEY environment variable is required when using NVIDIA NIM models.")

    def list_models(self) -> list:
        """Return list of locally available model names. Cloud models are dynamic."""
        if self.is_groq or self.is_nim:
            return [self.model]
            
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        """
        Send a generate request and return the full response text.
        """
        if self.is_nim:
            return self._generate_nim(prompt, system, temperature)
        elif self.is_groq:
            return self._generate_groq(prompt, system, temperature)
        else:
            return self._generate_ollama(prompt, system, temperature)

    def _generate_nim(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._call_openai_compatible(
            url=self.nim_api_url,
            api_key=self.nim_api_key,
            model_name=self.nim_model,
            messages=messages,
            temperature=temperature,
            max_tokens=2048,
            provider_name="NVIDIA NIM",
        )

    def _generate_groq(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[str]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._call_openai_compatible(
            url=GROQ_API_URL,
            api_key=self.groq_api_key,
            model_name=self.groq_model,
            messages=messages,
            temperature=temperature,
            max_tokens=2048,
            provider_name="Groq",
        )

    def _call_openai_compatible(
        self,
        url: str,
        api_key: str,
        model_name: str,
        messages: list,
        temperature: float,
        max_tokens: int,
        provider_name: str,
    ) -> Optional[str]:
        payload = json.dumps({
            "model": model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "SwarmSecurityScanner/1.0",
            },
            method="POST",
        )

        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = json.loads(resp.read())
                    return data["choices"][0]["message"]["content"].strip()
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    raise RuntimeError(
                        f"Invalid {provider_name} API Key (HTTP {e.code}). Please verify your API key in .env file or choose local Ollama models."
                    ) from e
                if e.code == 429 and attempt < 4:
                    import time
                    time.sleep(2 ** attempt + 3)
                    continue
                err_body = e.read().decode('utf-8', errors='replace')
                raise RuntimeError(f"{provider_name} API HTTP {e.code}: {err_body}") from e
            except Exception as e:
                if attempt < 4:
                    import time
                    time.sleep(2 ** attempt + 3)
                    continue
                raise RuntimeError(f"{provider_name} API call failed: {e}") from e

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
        if self.is_nim:
            return self._call_openai_compatible(
                url=self.nim_api_url,
                api_key=self.nim_api_key,
                model_name=self.nim_model,
                messages=messages,
                temperature=temperature,
                max_tokens=num_predict,
                provider_name="NVIDIA NIM",
            )
        elif self.is_groq:
            return self._call_openai_compatible(
                url=GROQ_API_URL,
                api_key=self.groq_api_key,
                model_name=self.groq_model,
                messages=messages,
                temperature=temperature,
                max_tokens=num_predict,
                provider_name="Groq",
            )
        else:
            return self._chat_ollama(messages, temperature, num_predict)

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
