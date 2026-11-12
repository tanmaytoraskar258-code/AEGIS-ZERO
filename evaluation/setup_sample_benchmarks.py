import json
import os
import subprocess


BENCHMARKS = {
    "repo_01_yaml_deserialization": {
        "requirements.txt": "PyYAML>=6.0.2\nrequests>=2.31.0\nurllib3>=2.0.0\n",
        "advisories.json": json.dumps([
            {
                "cve_id": "CVE-2020-14343",
                "cwe_ids": ["CWE-502"],
                "package_name": "PyYAML",
                "package_version": "5.3.1",
                "ecosystem": "PyPI",
                "summary": "Arbitrary code execution via unsafe yaml.load() with full Loader",
                "affected_functions": ["yaml.load"]
            },
            {
                "cve_id": "CVE-2023-32681",
                "cwe_ids": ["CWE-200"],
                "package_name": "requests",
                "package_version": "2.28.0",
                "ecosystem": "PyPI",
                "summary": "Unintended leak of Proxy-Authorization header (Unreachable dead dependency)",
                "affected_functions": ["requests.Session.send"]
            },
            {
                "cve_id": "CVE-2023-43804",
                "cwe_ids": ["CWE-200"],
                "package_name": "urllib3",
                "package_version": "1.26.14",
                "ecosystem": "PyPI",
                "summary": "Cookie request header leak on cross-origin redirect (Unreachable dead dependency)",
                "affected_functions": ["urllib3.PoolManager.urlopen"]
            }
        ], indent=2),
        "app.py": (
            "import yaml\n\n"
            "def parse_user_profile(raw_yaml: str) -> dict:\n"
            "    # Vulnerable sink: CWE-502 arbitrary object deserialization\n"
            "    return yaml.load(raw_yaml, Loader=yaml.Loader)\n\n"
            "def main():\n"
            "    sample = 'role: analyst\\nactive: true'\n"
            "    return parse_user_profile(sample)\n"
        ),
        "poc_exploit.py": (
            "import yaml\n"
            "from app import parse_user_profile\n\n"
            "malicious_payload = '!!python/object/apply:os.system [\"echo EXPLOITED\"]'\n"
            "try:\n"
            "    parse_user_profile(malicious_payload)\n"
            "    exit(1)  # Exploit succeeded -> vulnerable\n"
            "except yaml.YAMLError:\n"
            "    exit(0)  # Exploit blocked -> patched\n"
        ),
        "test_app.py": (
            "from app import parse_user_profile\n\n"
            "def test_valid_profile():\n"
            "    res = parse_user_profile('role: engineer\\nlevel: 3')\n"
            "    assert res == {'role': 'engineer', 'level': 3}\n"
        ),
    },
    "repo_02_jinja2_ssti": {
        "requirements.txt": "Jinja2>=3.1.2\nFlask>=3.0.0\n",
        "advisories.json": json.dumps([
            {
                "cve_id": "CVE-2020-28493",
                "cwe_ids": ["CWE-79"],
                "package_name": "Jinja2",
                "package_version": "2.11.2",
                "ecosystem": "PyPI",
                "summary": "Cross-site scripting (XSS) via unescaped Environment(autoescape=False)",
                "affected_functions": ["Environment"]
            },
            {
                "cve_id": "CVE-2023-30861",
                "cwe_ids": ["CWE-539"],
                "package_name": "Flask",
                "package_version": "2.0.1",
                "ecosystem": "PyPI",
                "summary": "Session cookie disclosure on permanent session (Unreachable dead dependency)",
                "affected_functions": ["Flask.open_session"]
            }
        ], indent=2),
        "app.py": (
            "from jinja2 import Environment\n\n"
            "def render_greeting(user_template: str, username: str) -> str:\n"
            "    # Vulnerable sink: CWE-79 unescaped Jinja2 Environment\n"
            "    env = Environment(autoescape=False)\n"
            "    tmpl = env.from_string(user_template)\n"
            "    return tmpl.render(name=username)\n\n"
            "def main():\n"
            "    return render_greeting('Hello {{ name }}', 'Alice')\n"
        ),
        "poc_exploit.py": (
            "from app import render_greeting\n\n"
            "xss_input = '<script>alert(1)</script>'\n"
            "output = render_greeting('Welcome {{ name }}', xss_input)\n"
            "if '<script>' in output:\n"
            "    exit(1)  # Unescaped XSS succeeded -> vulnerable\n"
            "exit(0)      # Escaped safely -> patched\n"
        ),
        "test_app.py": (
            "from app import render_greeting\n\n"
            "def test_normal_greeting():\n"
            "    assert render_greeting('Hi {{ name }}!', 'Bob') == 'Hi Bob!'\n"
        ),
    },
    "repo_03_eval_injection": {
        "requirements.txt": "PyYAML>=6.0.2\nnumpy>=2.0.0\n",
        "advisories.json": json.dumps([
            {
                "cve_id": "CVE-2024-99901",
                "cwe_ids": ["CWE-94"],
                "package_name": "builtins",
                "package_version": "3.14",
                "ecosystem": "PyPI",
                "summary": "Arbitrary code injection via unsafe eval() on untrusted arithmetic expression",
                "affected_functions": ["eval"]
            },
            {
                "cve_id": "CVE-2021-41496",
                "cwe_ids": ["CWE-120"],
                "package_name": "numpy",
                "package_version": "1.24.0",
                "ecosystem": "PyPI",
                "summary": "Buffer overflow in array_from_pyobj (Unreachable dead dependency)",
                "affected_functions": ["numpy.array"]
            }
        ], indent=2),
        "app.py": (
            "import ast\n\n"
            "def evaluate_formula(expr: str) -> float:\n"
            "    # Vulnerable sink: CWE-94 unsafe eval() on user input\n"
            "    return float(eval(expr))\n\n"
            "def main():\n"
            "    return evaluate_formula('2 + 3 * 4')\n"
        ),
        "poc_exploit.py": (
            "from app import evaluate_formula\n\n"
            "payload = \"__import__('os').system('echo PWNED') or 1\"\n"
            "try:\n"
            "    evaluate_formula(payload)\n"
            "    exit(1)  # Arbitrary code executed -> vulnerable\n"
            "except Exception:\n"
            "    exit(0)  # Malicious expression rejected -> patched\n"
        ),
        "test_app.py": (
            "from app import evaluate_formula\n\n"
            "def test_safe_literal():\n"
            "    assert evaluate_formula('42') == 42.0\n"
        ),
    },
}


def setup_benchmarks(base_dir: str = "benchmarks/vul4j_subset") -> None:
    os.makedirs(base_dir, exist_ok=True)

    for repo_name, files in BENCHMARKS.items():
        repo_path = os.path.join(base_dir, repo_name)
        os.makedirs(repo_path, exist_ok=True)

        for filename, content in files.items():
            with open(os.path.join(repo_path, filename), "w", encoding="utf-8") as f:
                f.write(content)

        subprocess.run(["git", "init"], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "research@bench.local"], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Benchmark Runner"], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial vulnerable baseline"], cwd=repo_path, capture_output=True)
        print(f"[Setup] Created benchmark repository: {repo_path}")


if __name__ == "__main__":
    setup_benchmarks()
