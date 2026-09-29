"""
Swarm Security Scanner — Hardened Exploit Validation Sandbox
============================================================
Runs untrusted LLM-generated exploit code inside a locked-down container:
  - Network egress disabled by default (network_mode="none")
  - Read-only root filesystem (read_only=True)
  - Dropped Linux capabilities (cap_drop=["ALL"])
  - Privilege escalation disabled (no-new-privileges:true)
  - Strict resource limits (PIDs, memory, CPU)
  - Execution as non-root user
"""

import os
import time
from typing import Tuple

try:
    import docker
except ImportError:
    docker = None


def run_exploit_in_sandbox(
    exploit_code: str,
    finding_id: str,
    target_url: str = "http://localhost:5000",
    timeout_seconds: int = 10,
    allow_network: bool = False,
) -> Tuple[bool, str]:
    """
    Runs the provided exploit code inside a secure, hardened Docker sandbox.
    Returns (success_bool, output_str)
    """
    if docker is None:
        return False, "Docker SDK is not installed in the Python environment."

    if os.getenv("SWARM_ENABLE_EXPLOIT_VERIFICATION", "false").lower() not in ("true", "1", "yes"):
        return False, "Exploit verification is disabled; enable it only with a dedicated isolated Docker daemon."

    try:
        client = docker.from_env()
    except Exception as e:
        return False, f"Docker daemon unavailable: {str(e)}"

    container = None
    try:
        # Determine network mode:
        # Default to completely isolated 'none' (zero network stack)
        # If network access to target container is required, use isolated internal bridge
        net_mode = "none"
        if allow_network:
            # Internal network with no external internet gateway
            net_mode = os.getenv("SWARM_SANDBOX_NETWORK", "none")

        container = client.containers.run(
            image=os.getenv("SWARM_SANDBOX_IMAGE", "antigravity-sandbox:latest"),
            command=["python3", "-c", exploit_code],
            detach=True,
            mem_limit="128m",
            nano_cpus=1_000_000_000,               # 1.0 CPU max
            pids_limit=50,                         # Fork-bomb protection
            read_only=True,                        # Immutable root filesystem
            tmpfs={"/tmp": "size=16m,mode=1777"},  # Ephemeral writable scratch space only
            cap_drop=["ALL"],                      # Strip all Linux root capabilities
            security_opt=["no-new-privileges:true"],# Disallow setuid privilege escalation
            network_mode=net_mode,                 # Isolated network
            user="1000:1000",                      # Non-root unprivileged execution
            environment={
                "TARGET_URL": target_url,
                "PYTHONUNBUFFERED": "1",
            },
        )

        try:
            result = container.wait(timeout=timeout_seconds)
            exit_code = result.get("StatusCode", -1)
        except Exception:
            container.kill()
            exit_code = -1

        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        success = (exit_code == 0) and (f"EXPLOIT_SUCCESS:{finding_id}" in logs)
        return success, logs

    except Exception as e:
        return False, f"Sandbox security execution error: {str(e)}"
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
