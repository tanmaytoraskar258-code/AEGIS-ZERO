from dataclasses import dataclass
from typing import List, Optional
import networkx as nx
from src.ingestion.cve_matcher import VulnerabilityFinding


@dataclass
class ReachableVulnerability:
    finding: VulnerabilityFinding
    call_path: List[str]        # e.g., ["app.py::upload", "parser.py::parse_yaml", "EXTERNAL::yaml.load"]
    target_file: str            # The internal file invoking the vulnerable sink
    sink_function: str


class PathPruner:
    """Filters out unreachable CVEs by verifying paths in the directed call graph."""

    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth

    def prune_unreachable(
        self, graph: nx.DiGraph, findings: List[VulnerabilityFinding]
    ) -> List[ReachableVulnerability]:
        reachable_vulns: List[ReachableVulnerability] = []

        entrypoints = [
            node_id for node_id, data in graph.nodes(data=True)
            if data.get("type") == "internal" and data.get("is_entrypoint", False)
        ]

        external_sinks = [
            node_id for node_id, data in graph.nodes(data=True)
            if data.get("type") == "external"
        ]

        for finding in findings:
            matching_sinks = self._match_finding_to_sinks(finding, external_sinks, graph)

            for sink_id in matching_sinks:
                path = self._find_shortest_entrypoint_path(graph, entrypoints, sink_id)
                if path and len(path) >= 2:
                    # The internal caller right before the external sink is the patch target
                    caller_node_id = path[-2]
                    target_file = graph.nodes[caller_node_id].get("file_path", "")

                    reachable_vulns.append(
                        ReachableVulnerability(
                            finding=finding,
                            call_path=path,
                            target_file=target_file,
                            sink_function=sink_id.replace("EXTERNAL::", ""),
                        )
                    )
                    break  # Move to next CVE once at least one reachable path is proven

        return reachable_vulns

    def _match_finding_to_sinks(
        self, finding: VulnerabilityFinding, external_sinks: List[str], graph: nx.DiGraph
    ) -> List[str]:
        matched = []
        # Normalize package name (e.g., "PyYAML" -> "yaml", "org.apache.logging.log4j:log4j-core" -> "log4j")
        pkg_token = finding.package_name.lower().split(":")[-1].replace("py", "")

        for sink_id in external_sinks:
            sink_name = sink_id.replace("EXTERNAL::", "").lower()

            # 1. Check if OSV reported an exact vulnerable symbol name
            if any(func.lower() in sink_name for func in finding.affected_functions):
                matched.append(sink_id)
                continue

            # 2. Check if the sink call references the package name or if caller imports the package
            if pkg_token and pkg_token in sink_name:
                matched.append(sink_id)
                continue

            for predecessor in graph.predecessors(sink_id):
                imports_str = " ".join(graph.nodes[predecessor].get("imports", [])).lower()
                if pkg_token and pkg_token in imports_str:
                    matched.append(sink_id)
                    break

        return matched

    def _find_shortest_entrypoint_path(
        self, graph: nx.DiGraph, entrypoints: List[str], target_sink: str
    ) -> Optional[List[str]]:
        shortest_path = None
        for entry in entrypoints:
            if nx.has_path(graph, entry, target_sink):
                path = nx.shortest_path(graph, source=entry, target=target_sink)
                if len(path) <= self.max_depth:
                    if shortest_path is None or len(path) < len(shortest_path):
                        shortest_path = path
        return shortest_path
