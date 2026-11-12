from typing import List, Dict
import networkx as nx
from .ast_extractor import FunctionNode


class CallGraphBuilder:
    """Builds a directed call graph linking application entrypoints to third-party library sinks."""

    def build_graph(self, nodes: List[FunctionNode]) -> nx.DiGraph:
        graph = nx.DiGraph()

        # Index internal functions by their short name for resolution
        name_to_ids: Dict[str, List[str]] = {}
        for fn in nodes:
            graph.add_node(
                fn.id,
                type="internal",
                name=fn.name,
                file_path=fn.file_path,
                start_line=fn.start_line,
                end_line=fn.end_line,
                imports=fn.imports,
                is_entrypoint=fn.is_entrypoint,
            )
            name_to_ids.setdefault(fn.name, []).append(fn.id)

        # Create directed edges for internal calls and external library sinks
        for fn in nodes:
            for raw_call in fn.calls:
                short_call_name = raw_call.split(".")[-1]

                if short_call_name in name_to_ids:
                    for target_id in name_to_ids[short_call_name]:
                        if target_id != fn.id:
                            graph.add_edge(fn.id, target_id, call_site=raw_call)
                else:
                    # External third-party sink node
                    sink_id = f"EXTERNAL::{raw_call}"
                    if not graph.has_node(sink_id):
                        graph.add_node(sink_id, type="external", name=raw_call)
                    graph.add_edge(fn.id, sink_id, call_site=raw_call)

        return graph
