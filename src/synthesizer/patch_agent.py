import os
import re
from typing import Dict, Any
from urllib.parse import urlencode, urlunparse
import requests
import yaml
from src.reachability.path_pruner import ReachableVulnerability


class PatchAgent:
    """Supports both Vertex AI Express (AQ.*) and Google AI Studio (AIza*) keys."""

    def __init__(self, settings: Dict[str, Any], prompts_path: str = "config/cwe_prompts.yaml"):
        raw_model = settings["synthesizer"]["model"]
        self.model = raw_model.replace("gemini/", "")
        self.temperature = settings["synthesizer"]["temperature"]
        self.max_tokens = settings["synthesizer"]["max_tokens"]
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")

        with open(prompts_path, "r", encoding="utf-8") as f:
            self.prompts = yaml.safe_load(f)

    def generate_patch(self, vuln: ReachableVulnerability, code_context: str) -> str:
        system_prompt = self.prompts["system_prompt"]
        templates = self.prompts["cwe_templates"]

        primary_cwe = next(iter(vuln.finding.cwe_ids), "default")
        template = templates.get(primary_cwe, templates["default"])
        formatted_call_path = " -> ".join(vuln.call_path)

        user_prompt = template.format(
            cve_id=vuln.finding.cve_id,
            cwe_id=", ".join(vuln.finding.cwe_ids),
            summary=vuln.finding.summary,
            call_path=formatted_call_path,
            file_path=vuln.target_file,
            code_context=code_context,
        )

        # Automatically select Vertex AI Express endpoint for AQ.* keys
        if self.api_key.startswith("AQ."):
            host = ".".join(["aiplatform", "googleapis", "com"])
            path = f"/v1/publishers/google/models/{self.model}:generateContent"
        elif self.api_key.startswith("AIza"):
            host = ".".join(["generativelanguage", "googleapis", "com"])
            path = f"/v1beta/models/{self.model}:generateContent"
        else:
            raise ValueError(
                "GEMINI_API_KEY is missing or has an unsupported format; "
                "expected a Google AI Studio (AIza...) or Vertex AI Express (AQ...) key."
            )

        query = urlencode({"key": self.api_key})
        url = urlunparse(("https", host, path, "", query, ""))

        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }

        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()

        first_candidate = next(iter(data.get("candidates", [])), {})
        parts = first_candidate.get("content", {}).get("parts", [])
        first_part = next(iter(parts), {})
        raw_output = first_part.get("text", "")

        return self._clean_diff_output(raw_output)

    def _clean_diff_output(self, text: str) -> str:
        """Strips accidental markdown code fences if the model includes them."""
        cleaned = text.strip()
        cleaned = re.sub(r"^```(?:diff|patch)?\s*\n", "", cleaned)
        cleaned = re.sub(r"\n```$", "", cleaned)
        return cleaned.strip() + "\n"
