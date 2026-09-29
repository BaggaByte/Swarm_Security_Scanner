"""
Real-World Repository Ingester
================================
Handles cloning a Git repository or walking a local path, discovering
source files, building a structural map (file list + function-level chunks),
and preparing context bundles for LLM agents.

Key design principles:
  - Language-aware file filtering (Python, JS, TS, Go, Java, Ruby, etc.)
  - Chunk by function/class boundary rather than raw line count
  - Produce a lightweight RepoMap so agents can navigate without loading
    every file into a single context window
  - Works offline — only uses stdlib + optional GitPython
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from .redaction import redact_sensitive_content

try:
    from backend.git_url_policy import validate_git_url
    from backend.security import validate_local_scan_path
except ImportError:  # Direct script execution from cycle11_ollama_swarm
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from backend.git_url_policy import validate_git_url
    from backend.security import validate_local_scan_path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# File extensions to include in the security scan
SECURITY_RELEVANT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".hpp",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".cfg",
    ".sh", ".bash", ".ps1", ".dockerfile",
}

# Directories to always skip
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", "dist", "build", ".pytest_cache", ".mypy_cache",
    "*.egg-info", "vendor", "third_party", ".idea", ".vscode",
    "coverage", "htmlcov", ".tox",
}

# Maximum file size to include (bytes) — avoid binary blobs
MAX_FILE_BYTES = 200_000  # 200 KB

# Maximum chunk size (characters) for LLM context windows
MAX_CHUNK_CHARS = 6_000

# Minimum meaningful file size (bytes)
MIN_FILE_BYTES = 50


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    """Represents a single source file in the repository."""
    rel_path: str           # Relative to repo root
    abs_path: str           # Absolute path on disk
    language: str           # Detected language
    size_bytes: int
    content: str            # Full file content (loaded lazily if large)
    line_count: int


@dataclass
class CodeChunk:
    """A semantically meaningful chunk of code for LLM analysis."""
    file_path: str          # Relative path
    language: str
    chunk_type: str         # "module" | "class" | "function" | "config" | "raw"
    name: str               # Qualified name (e.g., "UserService.authenticate")
    start_line: int
    end_line: int
    content: str            # The actual code text
    imports: list[str] = field(default_factory=list)   # Imports detected in this chunk


@dataclass
class RepoMap:
    """Lightweight structural summary of a repository."""
    root: str               # Absolute path to repo root
    repo_name: str
    language_distribution: dict[str, int]  # ext -> file count
    total_files: int
    total_lines: int
    entry_points: list[str]                # Detected main/entry files
    config_files: list[str]                # Config files (requirements.txt, etc.)
    framework_signals: list[str]           # Detected frameworks (flask, django, express…)
    technology_inventory: list[str]        # Tech stack detected (sql, redis, jwt, etc.)
    cross_references: dict[str, str] = field(default_factory=dict) # function/class name -> "file_path:start_line"
    files: list[FileEntry] = field(default_factory=list)

    def find_definition(self, name: str) -> Optional[str]:
        """Look up the location of a function/class definition by name."""
        return self.cross_references.get(name)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".h": "c_header", ".hpp": "cpp_header",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".toml": "toml", ".ini": "ini", ".env": "env", ".cfg": "ini",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".dockerfile": "docker",
}

FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "flask":       ["from flask", "import flask", "Flask(__name__)"],
    "django":      ["from django", "import django", "django.urls"],
    "fastapi":     ["from fastapi", "import fastapi", "FastAPI()"],
    "express":     ["require('express')", "import express", "express()"],
    "spring":      ["@SpringBootApplication", "import org.springframework"],
    "rails":       ["Rails.application", "ActiveRecord::Base"],
    "laravel":     ["use Illuminate\\", "namespace App\\"],
    "nextjs":      ["next/router", "getServerSideProps", "getStaticProps"],
}

TECH_PATTERNS: dict[str, list[str]] = {
    "sql":         ["sqlite3", "sqlalchemy", "psycopg2", "mysql", "postgresql",
                    "SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM"],
    "jwt":         ["jwt", "jsonwebtoken", "PyJWT", "decode_token"],
    "redis":       ["redis", "aioredis", "redis-py"],
    "aws":         ["boto3", "aws-sdk", "AWS_ACCESS_KEY"],
    "docker":      ["docker", "Dockerfile", "docker-compose"],
    "crypto":      ["hashlib", "hmac", "cryptography", "bcrypt", "argon2"],
    "subprocess":  ["subprocess", "os.system", "os.popen", "exec(", "eval("],
    "file_io":     ["open(", "pathlib", "os.path", "shutil"],
    "env_vars":    ["os.environ", "os.getenv", "dotenv", "process.env"],
    "network":     ["requests", "httpx", "aiohttp", "urllib", "fetch(", "axios"],
    "deserialization": ["pickle", "yaml.load(", "marshal", "shelve"],
    "template":    ["jinja2", "render_template", "Template(", "Markup("],
}


def detect_language(path: Path) -> str:
    return EXT_TO_LANG.get(path.suffix.lower(), "unknown")


def detect_framework(content: str, all_content: str = "") -> list[str]:
    combined = content + all_content
    detected = []
    for fw, patterns in FRAMEWORK_PATTERNS.items():
        if any(p in combined for p in patterns):
            detected.append(fw)
    return detected


def detect_technologies(content: str) -> list[str]:
    detected = []
    for tech, patterns in TECH_PATTERNS.items():
        if any(p in content for p in patterns):
            detected.append(tech)
    return detected


# ---------------------------------------------------------------------------
# Repository cloner
# ---------------------------------------------------------------------------

def _validate_repo_url(url: str):
    return validate_git_url(url)

def _validate_local_path(path_str: str):
    return validate_local_scan_path(path_str)

def clone_repo(url: str, target_dir: Optional[str] = None, branch: Optional[str] = None) -> str:
    """
    Clone a Git repository. Returns the absolute path to the cloned directory.
    Falls back to shallow clone (--depth 1) for speed.
    """
    _validate_repo_url(url)
    if not shutil.which("git"):
        raise RuntimeError(
            "git is not installed or not on PATH. "
            "Install git or provide a local repository path instead."
        )
    owns_target_dir = target_dir is None
    if owns_target_dir:
        target_dir = tempfile.mkdtemp(prefix="swarm_repo_")
    else:
        os.makedirs(target_dir, exist_ok=True)

    print(f"  [INGEST] Cloning {url} → {target_dir}", flush=True)
    t0 = time.time()

    cmd = ["git", "-c", "http.followRedirects=false", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, target_dir])

    git_env = os.environ.copy()
    git_env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    for key in ("GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_EXEC_PATH", "GIT_SSH_COMMAND", "GIT_ASKPASS"):
        git_env.pop(key, None)
    for key in list(git_env):
        if key.startswith(("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            git_env.pop(key, None)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=git_env)
    except Exception:
        if owns_target_dir:
            shutil.rmtree(target_dir, ignore_errors=True)
        raise

    if result.returncode != 0:
        if owns_target_dir:
            shutil.rmtree(target_dir, ignore_errors=True)
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}):\n{result.stderr}"
        )

    elapsed = time.time() - t0
    print(f"  [INGEST] Clone complete in {elapsed:.1f}s", flush=True)
    return target_dir


# ---------------------------------------------------------------------------
# File walker
# ---------------------------------------------------------------------------

def _should_skip_dir(dir_name: str) -> bool:
    if dir_name == ".github":
        return False
    return dir_name in SKIP_DIRS or dir_name.startswith(".")


def walk_repo_files(root: str) -> Iterator[Path]:
    """Yield all security-relevant files in a repository, skipping noise."""
    root_path = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(root_path):
        current = Path(dirpath)
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d) and not (current / d).is_symlink()]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            low_name = fpath.name.lower()
            if low_name in {".env", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials", "credentials.json"}:
                continue
            if low_name.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")):
                continue
            if fpath.suffix.lower() in SECURITY_RELEVANT_EXTENSIONS or fpath.name.lower() in {"makefile", "dockerfile", "caddyfile", "nginx.conf", ".dockerignore", ".gitignore", ".env"}:
                try:
                    resolved = fpath.resolve(strict=True)
                    if os.path.commonpath((str(root_path), str(resolved))) != str(root_path):
                        continue
                    if MIN_FILE_BYTES <= resolved.stat().st_size <= MAX_FILE_BYTES:
                        yield resolved
                except (OSError, ValueError):
                    continue


# ---------------------------------------------------------------------------
# Python-specific chunker (AST-based)
# ---------------------------------------------------------------------------

def _chunk_python(file_entry: FileEntry) -> list[CodeChunk]:
    """Chunk a Python file by top-level classes and functions using the AST."""
    chunks: list[CodeChunk] = []
    lines = file_entry.content.splitlines()

    try:
        tree = ast.parse(file_entry.content)
    except SyntaxError:
        # Fall back to raw chunking
        return _chunk_raw(file_entry)

    # Collect top-level imports once
    top_imports = [
        ast.get_source_segment(file_entry.content, node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and hasattr(node, "lineno") and node.lineno <= 30
    ]
    top_imports = [i for i in top_imports if i]

    # Get all top-level nodes with line numbers
    top_nodes = [
        node for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and hasattr(node, "lineno")
    ]

    def append_bounded(name: str, chunk_type: str, start_line: int, end_line: int, snippet: str) -> None:
        if len(snippet) <= MAX_CHUNK_CHARS:
            chunks.append(CodeChunk(
                file_path=file_entry.rel_path,
                language="python",
                chunk_type=chunk_type,
                name=name,
                start_line=start_line,
                end_line=end_line,
                content=snippet,
                imports=top_imports,
            ))
            return
        fragment = FileEntry(
            rel_path=file_entry.rel_path,
            abs_path=file_entry.abs_path,
            language="python",
            size_bytes=len(snippet.encode("utf-8")),
            content=snippet,
            line_count=snippet.count("\n") + 1,
        )
        for part_index, raw_chunk in enumerate(_chunk_raw(fragment)):
            chunks.append(CodeChunk(
                file_path=file_entry.rel_path,
                language="python",
                chunk_type=chunk_type,
                name=f"{name}[part{part_index}]",
                start_line=start_line + raw_chunk.start_line - 1,
                end_line=start_line + raw_chunk.end_line - 1,
                content=raw_chunk.content,
                imports=top_imports,
            ))

    # Keep module-level executable statements and constants as source chunks;
    # previously only files with no functions received any module context.
    definition_lines: set[int] = set()
    for node in top_nodes:
        decorator_lines = [decorator.lineno for decorator in getattr(node, "decorator_list", [])]
        start_line = min([node.lineno, *decorator_lines])
        end_line = getattr(node, "end_lineno", node.lineno)
        definition_lines.update(range(start_line, end_line + 1))
    module_segment: list[str] = []
    module_start = 1

    def flush_module_segment(end_line: int) -> None:
        nonlocal module_segment, module_start
        source = "".join(module_segment)
        if source.strip():
            fragment = FileEntry(
                rel_path=file_entry.rel_path,
                abs_path=file_entry.abs_path,
                language="python",
                size_bytes=len(source.encode("utf-8")),
                content=source,
                line_count=source.count("\n") + 1,
            )
            for part_index, raw_chunk in enumerate(_chunk_raw(fragment)):
                chunks.append(CodeChunk(
                    file_path=file_entry.rel_path,
                    language="python",
                    chunk_type="module",
                    name=f"{Path(file_entry.rel_path).stem}[module{part_index}]",
                    start_line=module_start + raw_chunk.start_line - 1,
                    end_line=module_start + raw_chunk.end_line - 1,
                    content=raw_chunk.content,
                    imports=top_imports,
                ))
        module_segment = []

    for line_number, source_line in enumerate(lines, start=1):
        if line_number in definition_lines:
            flush_module_segment(line_number - 1)
            module_start = line_number + 1
        else:
            if not module_segment:
                module_start = line_number
            module_segment.append(source_line + "\n")
    flush_module_segment(len(lines))

    for node in top_nodes:
        decorator_lines = [decorator.lineno for decorator in getattr(node, "decorator_list", [])]
        start = min([node.lineno, *decorator_lines]) - 1
        end = getattr(node, "end_lineno", start + 30)
        snippet = "\n".join(lines[start:end])

        chunk_type = "class" if isinstance(node, ast.ClassDef) else "function"
        append_bounded(node.name, chunk_type, start + 1, end, snippet)

    return chunks


def _chunk_raw(file_entry: FileEntry) -> list[CodeChunk]:
    """Chunk at line boundaries and keep every prompt below the size ceiling."""
    chunks: list[CodeChunk] = []
    part = 0
    current: list[str] = []
    current_chars = 0
    current_start = 1
    current_line = 1

    for line in file_entry.content.splitlines(keepends=True):
        pieces = [line[i:i + MAX_CHUNK_CHARS] for i in range(0, len(line), MAX_CHUNK_CHARS)] or [line]
        for piece in pieces:
            if current and current_chars + len(piece) > MAX_CHUNK_CHARS:
                current_content = "".join(current)
                chunks.append(CodeChunk(
                    file_path=file_entry.rel_path,
                    language=file_entry.language,
                    chunk_type="raw",
                    name=f"{Path(file_entry.rel_path).name}[part{part}]",
                    start_line=current_start,
                    end_line=max(current_start, current_start + current_content.count("\n") - int(current_content.endswith("\n"))),
                    content=current_content,
                ))
                part += 1
                current = []
                current_chars = 0
                current_start = current_line
            current.append(piece)
            current_chars += len(piece)
            current_line += piece.count("\n")

    if current:
        content = "".join(current)
        chunks.append(CodeChunk(
            file_path=file_entry.rel_path,
            language=file_entry.language,
            chunk_type="raw",
            name=f"{Path(file_entry.rel_path).name}[part{part}]",
            start_line=current_start,
            end_line=max(current_start, current_start + content.count("\n") - int(content.endswith("\n"))),
            content=content,
        ))

    return chunks


def chunk_file(file_entry: FileEntry) -> list[CodeChunk]:
    """Dispatch to the right chunker by language."""
    if file_entry.language == "python":
        return _chunk_python(file_entry)
    return _chunk_raw(file_entry)


# ---------------------------------------------------------------------------
# Main ingest function
# ---------------------------------------------------------------------------

def ingest_repository(source: str, clone_to: Optional[str] = None, diff_filter: Optional[dict[str, list[int]]] = None, branch: Optional[str] = None) -> tuple[RepoMap, list[CodeChunk]]:
    """
    Ingest a repository from a URL or local path.

    Args:
        source:   Git URL (https://github.com/...) or local directory path.
        clone_to: Optional target directory for cloning. A temp dir is used if None.

    Returns:
        (RepoMap, list[CodeChunk])  — The structural map and all code chunks.
    """
    # Step 1: Resolve to a local path
    is_remote = source.startswith(("http://", "https://", "git@"))
    if is_remote:
        repo_root = clone_repo(source, clone_to, branch)
        repo_name = source.rstrip("/").split("/")[-1].removesuffix(".git")
    else:
        repo_root = os.path.abspath(source)
        _validate_local_path(repo_root)
        if not os.path.isdir(repo_root):
            raise FileNotFoundError(f"Repository path not found: {repo_root}")
        repo_name = os.path.basename(repo_root)

    print(f"  [INGEST] Walking {repo_root} …", flush=True)

    # Step 2: Walk and load files
    files: list[FileEntry] = []
    lang_distribution: dict[str, int] = {}
    frameworks_seen: set[str] = set()
    technologies_seen: set[str] = set()

    for fpath in walk_repo_files(repo_root):
        try:
            content = redact_sensitive_content(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue

        rel_path = str(fpath.relative_to(repo_root)).replace("\\", "/")
        if diff_filter is not None and rel_path not in diff_filter:
            continue
            
        lang = detect_language(fpath)
        lang_distribution[lang] = lang_distribution.get(lang, 0) + 1

        entry = FileEntry(
            rel_path=rel_path,
            abs_path=str(fpath),
            language=lang,
            size_bytes=fpath.stat().st_size,
            content=content,
            line_count=content.count("\n") + 1,
        )
        files.append(entry)

        # Inventory all loaded files instead of sampling only a repository prefix.
        frameworks_seen.update(detect_framework(content))
        technologies_seen.update(detect_technologies(content))

    # Step 3: Detect frameworks and technologies
    frameworks = sorted(frameworks_seen)
    technologies = sorted(technologies_seen)

    # Step 4: Identify entry points and config files
    entry_point_names = {"main.py", "app.py", "server.py", "api.py", "wsgi.py",
                         "index.js", "index.ts", "server.js", "main.go", "app.rb"}
    config_file_names = {"requirements.txt", "package.json", "go.mod", "pom.xml",
                         "Gemfile", "composer.json", "pyproject.toml", ".env.example",
                         "docker-compose.yml", "Dockerfile"}

    entry_points = [f.rel_path for f in files if Path(f.rel_path).name in entry_point_names]
    config_files = [f.rel_path for f in files if Path(f.rel_path).name in config_file_names]
    total_lines = sum(f.line_count for f in files)

    repo_map = RepoMap(
        root=repo_root,
        repo_name=repo_name,
        language_distribution=lang_distribution,
        total_files=len(files),
        total_lines=total_lines,
        entry_points=entry_points,
        config_files=config_files,
        framework_signals=frameworks,
        technology_inventory=technologies,
        files=files,
    )

    print(
        f"  [INGEST] {len(files)} files | {total_lines:,} lines | "
        f"langs: {dict(sorted(lang_distribution.items(), key=lambda x: -x[1]))} | "
        f"frameworks: {frameworks} | tech: {technologies}",
        flush=True,
    )

    # Step 5: Chunk all files and build cross-references
    all_chunks: list[CodeChunk] = []
    for file_entry in files:
        try:
            chunks = chunk_file(file_entry)
            
            # Filter chunks if diff_filter is provided
            if diff_filter is not None:
                changed_lines = diff_filter.get(file_entry.rel_path, [])
                filtered_chunks = []
                for c in chunks:
                    if any(c.start_line <= line <= c.end_line for line in changed_lines):
                        filtered_chunks.append(c)
                chunks = filtered_chunks

            all_chunks.extend(chunks)
            # Add to cross-references
            for c in chunks:
                if c.name and c.name != "module":
                    # Store as "rel_path:start_line"
                    repo_map.cross_references[c.name] = f"{c.file_path}:{c.start_line}"
        except Exception as exc:
            print(f"  [INGEST] WARNING: could not chunk {file_entry.rel_path}: {exc}", flush=True)

    print(f"  [INGEST] Generated {len(all_chunks)} code chunks for LLM analysis.", flush=True)
    return repo_map, all_chunks


def repo_map_to_summary(repo_map: RepoMap) -> str:
    """
    Generate a compact text summary of the RepoMap to inject into agent prompts.
    Provides a heuristic inventory and asks agents to verify source evidence.
    """
    lines = [
        f"REPOSITORY: {repo_map.repo_name}",
        f"Files: {repo_map.total_files} | Lines: {repo_map.total_lines:,}",
        f"Languages: {json.dumps(repo_map.language_distribution)}",
        f"Frameworks detected: {', '.join(repo_map.framework_signals) or 'none'}",
        f"Technologies detected: {', '.join(repo_map.technology_inventory) or 'none'}",
        f"Entry points: {', '.join(repo_map.entry_points) or 'none identified'}",
        f"Config files: {', '.join(repo_map.config_files) or 'none identified'}",
        "",
        "Technology inventory is heuristic and may be incomplete. Absence from this list is not proof",
        "that a technology or vulnerability is absent. Verify claims against the supplied code.",
    ]
    return "\n".join(lines)
