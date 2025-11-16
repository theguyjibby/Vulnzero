import subprocess
import shutil
import os
import json
import uuid
import time
import sys

def wait_for_docker(docker_exe, total_timeout=30, interval=1):
    """
    Wait for docker daemon to respond to `docker info`.
    Returns (True, output) on success, (False, last_exception_message) on failure.
    """
    deadline = time.time() + total_timeout
    last_err = None
    while time.time() < deadline:
        try:
            info = subprocess.run([docker_exe, "info"], capture_output=True, text=True, timeout=5)
            if info.returncode == 0:
                return True, info.stdout
            last_err = info.stderr.strip() or info.stdout.strip() or f"exit {info.returncode}"
        except subprocess.TimeoutExpired:
            last_err = "docker info timed out"
        except FileNotFoundError:
            return False, "docker executable not found"
        except Exception as e:
            last_err = str(e)
        time.sleep(interval)
    return False, last_err or "docker daemon not reachable"

def run_nikto_scan(target_url, timeout=60, output_filename="scan-results.json"):
    """
    Run nikto inside 'nikto-scanner' docker image with a timeout (seconds).
    Streams combined stdout/stderr while waiting; if timeout is reached the container
    is stopped and any partial JSON output is returned (or raw preview).
    """
    if not isinstance(target_url, str) or not target_url:
        return []

    docker = shutil.which("docker")
    print(f"DEBUG: docker executable = {docker}", flush=True)
    if not docker:
        return []

    ok, info_msg = wait_for_docker(docker, total_timeout=30, interval=1)
    print("DEBUG: docker info check ok:", ok, flush=True)
    if not ok:
        return []

    host_dir = os.path.abspath(os.getcwd()).replace("\\", "/")
    mount = f"{host_dir}:/tmp"
    output_in_container = f"/tmp/{output_filename}"
    container_name = f"nikto_scan_{uuid.uuid4().hex[:8]}"

    cmd = [
        docker,
        "run",
        "--rm",
        "--name", container_name,
        "-v", mount,
        "nikto-scanner",
        "-h", target_url,
        "-o", output_in_container,
        "-Format", "json"
    ]

    print("DEBUG: running command:", " ".join(cmd), flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except:
        return []

    stdout_buf = []
    start = time.time()
    timed_out = False

    try:
        while proc.poll() is None and (time.time() - start) < timeout:
            line = proc.stdout.readline()
            if line:
                stdout_buf.append(line)
                print(line, end="", flush=True)
            else:
                time.sleep(0.05)

        if proc.poll() is None:
            timed_out = True
            print(f"\nDEBUG: timeout reached ({timeout}s), attempting to stop container {container_name}", flush=True)
            try:
                subprocess.run([docker, "stop", container_name], capture_output=True, text=True, timeout=10)
            except:
                pass
            try:
                out, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            if out:
                stdout_buf.append(out)
                print(out, end="", flush=True)
        else:
            out, _ = proc.communicate(timeout=5)
            if out:
                stdout_buf.append(out)
                print(out, end="", flush=True)

    except:
        try:
            proc.kill()
        except:
            pass
        return []

    stdout_text = "".join(stdout_buf).strip()

    # try to read JSON result written to host
    host_path = os.path.join(os.getcwd(), output_filename)
    parsed = None
    raw = None
    if os.path.exists(host_path):
        try:
            with open(host_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
        except:
            parsed = None

    # ALWAYS RETURN A LIST FROM HERE ↓↓↓↓↓↓↓
    alerts = []
    if isinstance(parsed, dict):
        alerts = parsed.get("findings") or parsed.get("vulnerabilities") or []

    return alerts


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.206.129"
    result = run_nikto_scan(target, timeout=60)
    try:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception:
        print(result)
