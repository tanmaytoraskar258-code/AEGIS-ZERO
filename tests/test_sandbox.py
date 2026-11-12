import os
import tempfile
import yaml
import pytest
from src.sandbox import DockerRunner, ExploitVerifier, RegressionRunner


@pytest.fixture(scope="module")
def docker_runner():
    with open("config/settings.yaml", "r", encoding="utf-8") as f:
        settings = yaml.safe_load(f)
    runner = DockerRunner(settings)
    runner.build_sandbox_images()
    return runner


def test_sandbox_exploit_and_regression_verification(docker_runner):
    """Tests that the sandbox accurately detects patched vs vulnerable code."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Create a patched safe module (using PyYAML>=6.0.2 compatible with Python 3.14)
        with open(os.path.join(tmp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("PyYAML>=6.0.2\n")

        with open(os.path.join(tmp_dir, "config_loader.py"), "w", encoding="utf-8") as f:
            f.write("import yaml\n\ndef load_cfg(text):\n    return yaml.safe_load(text)\n")

        # 2. Create a PoC exploit script (exits 0 if exploit is blocked)
        poc_code = (
            "import yaml\n"
            "from config_loader import load_cfg\n\n"
            "payload = '!!python/object/apply:os.system [\"echo PWNED\"]'\n"
            "try:\n"
            "    load_cfg(payload)\n"
            "    exit(1)  # Exploit succeeded -> patch failed\n"
            "except yaml.YAMLError:\n"
            "    exit(0)  # Exploit blocked -> patch succeeded\n"
        )
        with open(os.path.join(tmp_dir, "poc_exploit.py"), "w", encoding="utf-8") as f:
            f.write(poc_code)

        # 3. Create a standard functional unit test
        test_code = (
            "from config_loader import load_cfg\n\n"
            "def test_valid_yaml():\n"
            "    assert load_cfg('service: auth\\nport: 8080') == {'service': 'auth', 'port': 8080}\n"
        )
        with open(os.path.join(tmp_dir, "test_config.py"), "w", encoding="utf-8") as f:
            f.write(test_code)

        exploit_ok, exploit_msg = ExploitVerifier(docker_runner).verify_fix(tmp_dir, "PyPI")
        tests_ok, tests_msg = RegressionRunner(docker_runner).run_tests(tmp_dir, "PyPI")

        assert exploit_ok is True, f"Exploit check failed: {exploit_msg}"
        assert tests_ok is True, f"Regression check failed: {tests_msg}"
