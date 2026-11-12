import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # "PyPI" or "Maven"


class SBOMParser:
    """Extracts third-party dependencies from Python and Java project manifests."""

    def parse_repository(self, repo_path: str) -> List[Dependency]:
        dependencies: List[Dependency] = []

        req_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_path):
            dependencies.extend(self._parse_requirements_txt(req_path))

        pom_path = os.path.join(repo_path, "pom.xml")
        if os.path.exists(pom_path):
            dependencies.extend(self._parse_pom_xml(pom_path))

        return dependencies

    def _parse_requirements_txt(self, file_path: str) -> List[Dependency]:
        deps = []
        pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*[=<>~!]+\s*([a-zA-Z0-9\.\-\+]+)")

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = pattern.match(line)
                if match:
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="PyPI",
                        )
                    )
        return deps

    def _parse_pom_xml(self, file_path: str) -> List[Dependency]:
        deps = []
        tree = ET.parse(file_path)
        root = tree.getroot()

        ns = {"mvn": root.tag.split("}").strip("{")} if "}" in root.tag else {}
        dep_elements = root.findall(".//mvn:dependency", ns) if ns else root.findall(".//dependency")

        for dep in dep_elements:
            group_el = dep.find("mvn:groupId", ns) if ns else dep.find("groupId")
            artifact_el = dep.find("mvn:artifactId", ns) if ns else dep.find("artifactId")
            version_el = dep.find("mvn:version", ns) if ns else dep.find("version")

            if group_el is not None and artifact_el is not None and version_el is not None:
                version_text = version_el.text.strip()
                if not version_text.startswith("${"):
                    deps.append(
                        Dependency(
                            name=f"{group_el.text.strip()}:{artifact_el.text.strip()}",
                            version=version_text,
                            ecosystem="Maven",
                        )
                    )
        return deps
