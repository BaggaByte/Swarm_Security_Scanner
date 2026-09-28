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
    ".git", ".github", "__pycache__", "node_modules", ".venv", "venv",
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
    import urllib.parse
    import socket
    import ipaddress
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Security error: only 'https://' Git repositories are permitted (got {parsed.scheme})")
    if parsed.username or parsed.password:
        raise ValueError("Security error: credentials in Git URLs are forbidden")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Security error: missing hostname in Git URL")
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip = ipaddress.ip_address(entry[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ValueError(f"Security error: Git URL resolves to blocked/internal IP {ip}")
    except socket.gaierror:
        raise ValueError(f"Security error: unable to resolve hostname '{hostname}'")

def _validate_local_path(path_str: str):
    real = os.path.realpath(path_str)
    real_lower = real.lower()
    forbidden = ["/etc", "/var", "/proc", "/sys", "/dev", "/root", "c:\\windows", "c:\\program files"]
    for fb in forbidden:
        if real_lower == fb or real_lower.startswith(fb + os.sep) or real_lower.startswith(fb + "/"):
            raise PermissionError(f"Security error: scanning system directory '{path_str}' is forbidden")
    allowed_root = os.getenv("SWARM_ALLOWED_SCAN_ROOT")
    if allowed_root:
        real_root = os.path.realpath(allowed_root)
        if not (real == real_root or real.startswith(real_root + os.sep)):
            raise PermissionError(f"Security error: path must be inside SWARM_ALLOWED_SCAN_ROOT: {real_root}")

def clone_repo(url: str, target_dir: Optional[str] = None) -> str:
    """
    Clone a Git repository. Returns the absolute path to the cloned directory.
    Falls back to shallow clone (--depth 1) for speed.
    """
    _validate_repo_url(url)
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="swarm_repo_")
    else:
        os.makedirs(target_dir, exist_ok=True)

    # Check git availability
    if not shutil.which("git"):
        raise RuntimeError(
            "git is not installed or not on PATH. "
            "Install git or provide a local repository path instead."
        )

    print(f"  [INGEST] Cloning {url} → {target_dir}", flush=True)
    t0 = time.time()

    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", url, target_dir],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
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
    return dir_name in SKIP_DIRS or dir_name.startswith(".")


def walk_repo_files(root: str) -> Iterator[Path]:
    """Yield all security-relevant files in a repository, skipping noise."""
    root_path = Path(root)
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in SECURITY_RELEVANT_EXTENSIONS:
                if MIN_FILE_BYTES <= fpath.stat().st_size <= MAX_FILE_BYTES:
                    yield fpath


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

    for node in top_nodes:
        start = node.lineno - 1
        end = getattr(node, "end_lineno", start + 30)
        snippet = "\n".join(lines[start:end])

        # For classes, also extract methods as sub-chunks
        if isinstance(node, ast.ClassDef):
            # Class-level chunk (include class body up to MAX_CHUNK_CHARS)
            if len(snippet) <= MAX_CHUNK_CHARS:
                chunks.append(CodeChunk(
                    file_path=file_entry.rel_path,
                    language="python",
                    chunk_type="class",
                    name=node.name,
                    start_line=start + 1,
                    end_line=end,
                    content=snippet,
                    imports=top_imports,
                ))
            else:
                # Class too large — emit each method separately
                for method in ast.iter_child_nodes(node):
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_start = method.lineno - 1
                        m_end = getattr(method, "end_lineno", m_start + 30)
                        m_snippet = "\n".join(lines[m_start:m_end])
                        chunks.append(CodeChunk(
                            file_path=file_entry.rel_path,
                            language="python",
                            chunk_type="function",
                            name=f"{node.name}.{method.name}",
                            start_line=m_start + 1,
                            end_line=m_end,
                            content=m_snippet,
                            imports=top_imports,
                        ))
        else:
            chunks.append(CodeChunk(
                file_path=file_entry.rel_path,
                language="python",
                chunk_type="function",
                name=node.name,
                start_line=start + 1,
                end_line=end,
                content=snippet,
                imports=top_imports,
            ))

    # If nothing was extracted (e.g., module-level script), add whole file as module chunk
    if not chunks:
        chunks.append(CodeChunk(
            file_path=file_entry.rel_path,
            language="python",
            chunk_type="module",
            name=Path(file_entry.rel_path).stem,
            start_line=1,
            end_line=len(lines),
            content=file_entry.content[:MAX_CHUNK_CHARS],
            imports=top_imports,
        ))

    return chunks


def _chunk_raw(file_entry: FileEntry) -> list[CodeChunk]:
    """Fallback: chunk by raw character count for non-Python files."""
    chunks: list[CodeChunk] = []
    content = file_entry.content
    part = 0

    for offset in range(0, len(content), MAX_CHUNK_CHARS):
        snippet = content[offset:offset + MAX_CHUNK_CHARS]
        start_line = content[:offset].count("\n") + 1
        end_line = start_line + snippet.count("\n")
        chunks.append(CodeChunk(
            file_path=file_entry.rel_path,
            language=file_entry.language,
            chunk_type="raw",
            name=f"{Path(file_entry.rel_path).name}[part{part}]",
            start_line=start_line,
            end_line=end_line,
            content=snippet,
        ))
        part += 1

    return chunks


def chunk_file(file_entry: FileEntry) -> list[CodeChunk]:
    """Dispatch to the right chunker by language."""
    if file_entry.language == "python":
        return _chunk_python(file_entry)
    return _chunk_raw(file_entry)


# ---------------------------------------------------------------------------
# Main ingest function
# ---------------------------------------------------------------------------

def ingest_repository(source: str, clone_to: Optional[str] = None, diff_filter: Optional[dict[str, list[int]]] = None) -> tuple[RepoMap, list[CodeChunk]]:
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
        repo_root = clone_repo(source, clone_to)
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
    all_content_sample = ""   # Sample for framework detection (first 50KB)

    for fpath in walk_repo_files(repo_root):
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
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

        # Accumulate sample for framework/tech detection
        if len(all_content_sample) < 50_000:
            all_content_sample += content[:1_000]

    # Step 3: Detect frameworks and technologies
    frameworks = detect_framework(all_content_sample)
    technologies = detect_technologies(all_content_sample)

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
    Tells agents what technologies exist so they don't hallucinate absent ones.
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
        "IMPORTANT CONSTRAINT FOR AGENTS:",
        "Only report vulnerabilities that involve technologies ACTUALLY PRESENT in the list above.",
        f"If 'sql' is NOT in the technology list, do NOT claim SQL injection.",
        f"If 'deserialization' is NOT in the technology list, do NOT claim deserialization attacks.",
    ]
    return "\n".join(lines)
