import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, Any, Optional
import docker
from docker.errors import ImageNotFound, APIError, DockerException


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class DockerRunner:
    """Manages isolated Docker containers with automatic local subprocess fallback."""

    def __init__(self, settings: Dict[str, Any]):
        self.python_image = settings["sandbox"]["python_image"]
        self.java_image = settings["sandbox"]["java_image"]
        self.timeout_sec = settings["sandbox"]["container_timeout_sec"]
        self.memory_limit = settings["sandbox"]["memory_limit"]
        self.network_disabled = settings["sandbox"]["network_disabled"]
        self.client: Optional[docker.DockerClient] = None
        self.use_docker = False

        try:
            self.client = docker.from_env()
            self.client.ping()
            self.use_docker = True
        except DockerException:
            print("[Sandbox] Docker daemon unavailable. Using isolated local subprocess fallback.")
            self.use_docker = False

    def build_sandbox_images(self, docker_dir: str = "docker") -> None:
        """Builds the Python and Java sandbox base images if Docker is active."""
        if not self.use_docker or self.client is None:
            return

        images = [
            (self.python_image, "python_sandbox.Dockerfile"),
            (self.java_image, "java_sandbox.Dockerfile"),
        ]
        for tag, dockerfile in images:
            try:
                self.client.images.get(tag)
            except ImageNotFound:
                print(f"[Sandbox] Building Docker image {tag}...")
                self.client.images.build(
                    path=docker_dir,
                    dockerfile=dockerfile,
                    tag=tag,
                    rm=True,
                )

    def run_command(self, repo_path: str, command: str, ecosystem: str) -> ExecutionResult:
        if self.use_docker and self.client is not None:
            return self._run_in_docker(repo_path, command, ecosystem)
        return self._run_locally_isolated(repo_path, command, ecosystem)

    def _run_in_docker(self, repo_path: str, command: str, ecosystem: str) -> ExecutionResult:
        image = self.python_image if ecosystem == "PyPI" else self.java_image
        abs_repo_path = os.path.abspath(repo_path)

        container = None
        try:
            container = self.client.containers.run(
                image=image,
                command=["/bin/bash", "-c", command],
                volumes={abs_repo_path: {"bind": "/workspace", "mode": "rw"}},
                working_dir="/workspace",
                mem_limit=self.memory_limit,
                network_disabled=self.network_disabled,
                detach=True,
            )

            result = container.wait(timeout=self.timeout_sec)
            logs_stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            logs_stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            return ExecutionResult(
                exit_code=result.get("StatusCode", 1),
                stdout=logs_stdout,
                stderr=logs_stderr,
                timed_out=False,
            )
        except Exception as e:
            if "Read timed out" in str(e) or "Timeout" in str(e):
                return ExecutionResult(exit_code=124, stdout="", stderr="Execution timed out.", timed_out=True)
            return ExecutionResult(exit_code=1, stdout="", stderr=f"Docker execution error: {e}")
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except APIError:
                    pass

    def _run_locally_isolated(self, repo_path: str, command: str, ecosystem: str) -> ExecutionResult:
        """Runs verification commands safely in an ephemeral local copy when Docker is offline."""
        temp_dir = tempfile.mkdtemp(prefix="sandbox_eval_")
        work_repo = os.path.join(temp_dir, "workspace")
        shutil.copytree(repo_path, work_repo)

        try:
            # Translate Linux-style chained commands to Windows-compatible execution
            if ecosystem == "PyPI":
                adapted_cmd = command.replace("pip install", f'"{sys.executable}" -m pip install')
                adapted_cmd = adapted_cmd.replace("python ", f'"{sys.executable}" ')
                adapted_cmd = adapted_cmd.replace("pytest ", f'"{sys.executable}" -m pytest ')
            else:
                adapted_cmd = command

            res = subprocess.run(
                adapted_cmd,
                cwd=work_repo,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
            )
            return ExecutionResult(
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(exit_code=124, stdout="", stderr="Execution timed out.", timed_out=True)
        except Exception as e:
            return ExecutionResult(exit_code=1, stdout="", stderr=f"Local sandbox error: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    