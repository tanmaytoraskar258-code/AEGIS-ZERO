import os
import networkx as nx
from src.reachability.path_pruner import ReachableVulnerability


class ContextSlicer:
    """Extracts minimal, high-signal source code context around a reachable vulnerability."""

    def __init__(self, padding_lines: int = 15):
        self.padding_lines = padding_lines

    def extract_context(
        self, repo_path: str, vuln: ReachableVulnerability, graph: nx.DiGraph
    ) -> str:
        full_file_path = os.path.join(repo_path, vuln.target_file)
        if not os.path.exists(full_file_path):
            return ""

        with open(full_file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Identify the internal caller node immediately preceding the external sink
        caller_node_id = vuln.call_path[-2]
        node_data = graph.nodes.get(caller_node_id, {})

        start_line = max(1, node_data.get("start_line", 1) - self.padding_lines)
        end_line = min(len(lines), node_data.get("end_line", len(lines)) + self.padding_lines)

        sliced_lines = []
        # Always include top-of-file imports (first 25 lines) for full type/import awareness
        header_limit = min(25, start_line - 1)
        for idx in range(header_limit):
            sliced_lines.append(f"{idx + 1:4d} | {lines[idx].rstrip()}")

        if header_limit > 0 and start_line > header_limit + 1:
            sliced_lines.append("     | ... [snip] ...")

        for idx in range(start_line - 1, end_line):
            sliced_lines.append(f"{idx + 1:4d} | {lines[idx].rstrip()}")

        return "\n".join(sliced_lines)
