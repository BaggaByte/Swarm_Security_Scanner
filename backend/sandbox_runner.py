import os
import time

try:
    import docker
except ImportError:
    docker = None

def run_exploit_in_sandbox(exploit_code: str, target_url: str, timeout_seconds: int = 10):
    """
    Runs the provided exploit code inside a secure Docker sandbox.
    Returns (success_bool, output_str)
    """
    if docker is None:
        return False, "Docker library is not installed. Run `pip install docker`."
        
    try:
        client = docker.from_env()
    except Exception as e:
        return False, f"Error connecting to Docker daemon: {str(e)}"
    
    container = None
    try:
        # We assume the image 'antigravity-sandbox:latest' is already built
        container = client.containers.run(
            image="antigravity-sandbox:latest",
            command=["python3", "-c", exploit_code],
            detach=True,
            mem_limit="128m",
            cap_drop=["ALL"],
            network_mode="bridge",
            environment={"TARGET_URL": target_url}
        )
        
        # Wait for the container to finish or timeout
        try:
            result = container.wait(timeout=timeout_seconds)
            exit_code = result.get("StatusCode", -1)
        except Exception: 
            # Timeout or other error during wait
            container.kill()
            exit_code = -1
            
        # Get logs
        logs = container.logs(stdout=True, stderr=True).decode("utf-8")
        
        success = (exit_code == 0) and ("error" not in logs.lower() and "exception" not in logs.lower())
        return success, logs

    except Exception as e:
        return False, f"Sandbox execution error: {str(e)}"
    finally:
        if container:
            try:
                container.remove(force=True)
            except:
                pass
