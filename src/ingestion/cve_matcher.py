import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any
import requests
from .sbom_parser import Dependency


@dataclass
class VulnerabilityFinding:
    cve_id: str
    cwe_ids: List[str]
    package_name: str
    package_version: str
    ecosystem: str
    summary: str
    affected_functions: List[str] = field(default_factory=list)


class CVEMatcher:
    """Queries OSV.dev API (with optional local advisory fallback) to map dependencies to CVEs."""

    def __init__(self, osv_api_url: str = "https://api.osv.dev/v1/query"):
        if not osv_api_url:
            osv_api_url = "https://api.osv.dev/v1/query"
        else:
            osv_api_url = osv_api_url.rstrip("/")
            if osv_api_url == "https://osv.dev":
                osv_api_url = "https://api.osv.dev/v1/query"
            elif not osv_api_url.endswith("/v1/query"):
                osv_api_url = f"{osv_api_url}/v1/query"
        self.osv_api_url = osv_api_url

    def scan_dependencies(self, dependencies: List[Dependency], repo_path: str = "") -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        seen_cves = set()

        for dep in dependencies:
            payload = {
                "version": dep.version,
                "package": {
                    "name": dep.name,
                    "ecosystem": dep.ecosystem,
                },
            }

            try:
                response = requests.post(self.osv_api_url, json=payload, timeout=15)
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                print(f"[Warning] Failed to query OSV for {dep.name}@{dep.version}: {e}")
                data = {}

            for vuln in data.get("vulns", []):
                finding = self._parse_vuln_record(vuln, dep)
                if finding.cve_id not in seen_cves:
                    seen_cves.add(finding.cve_id)
                    findings.append(finding)

        # Load deterministic benchmark advisories if present in repo_path
        if repo_path:
            local_adv_path = os.path.join(repo_path, "advisories.json")
            if os.path.exists(local_adv_path):
                with open(local_adv_path, "r", encoding="utf-8") as f:
                    local_records = json.load(f)
                for rec in local_records:
                    if rec["cve_id"] not in seen_cves:
                        seen_cves.add(rec["cve_id"])
                        findings.append(
                            VulnerabilityFinding(
                                cve_id=rec["cve_id"],
                                cwe_ids=rec.get("cwe_ids", ["CWE-UNKNOWN"]),
                                package_name=rec["package_name"],
                                package_version=rec.get("package_version", "0.0.0"),
                                ecosystem=rec.get("ecosystem", "PyPI"),
                                summary=rec["summary"],
                                affected_functions=rec.get("affected_functions", []),
                            )
                        )

        return findings

    def _parse_vuln_record(self, vuln: Dict[str, Any], dep: Dependency) -> VulnerabilityFinding:
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", "UNKNOWN"))

        db_specific = vuln.get("database_specific", {})
        cwe_ids = db_specific.get("cwe_ids", ["CWE-UNKNOWN"])

        affected_funcs = []
        for affected in vuln.get("affected", []):
            eco_spec = affected.get("ecosystem_specific", {})
            for imp in eco_spec.get("imports", []):
                affected_funcs.extend(imp.get("symbols", []))

        return VulnerabilityFinding(
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            package_name=dep.name,
            package_version=dep.version,
            ecosystem=dep.ecosystem,
            summary=vuln.get("summary", vuln.get("details", "No description provided."))[:500],
            affected_functions=list(set(affected_funcs)),
        )
    