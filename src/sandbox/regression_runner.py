from typing import Tuple
from .docker_runner import DockerRunner


class RegressionRunner:
    """Executes existing repository unit tests to ensure zero breaking changes."""

    def __init__(self, runner: DockerRunner):
        self.runner = runner

    def run_tests(self, repo_path: str, ecosystem: str) -> Tuple[bool, str]:
        if ecosystem == "PyPI":
            cmd = "pip install -q -r requirements.txt && pytest -q"
            res = self.runner.run_command(repo_path, cmd, ecosystem)

            if res.exit_code == 0:
                return True, "All Python regression tests passed."
            return False, f"Regression failure: {res.stdout[-300:]}\n{res.stderr[-300:]}"

        elif ecosystem == "Maven":
            cmd = "mvn test"
            res = self.runner.run_command(repo_path, cmd, ecosystem)

            if res.exit_code == 0:
                return True, "All Java Maven regression tests passed."
            return False, f"Maven regression failure: {res.stdout[-300:]}"

        return False, f"Unsupported ecosystem: {ecosystem}"
