import ast
import os
from dataclasses import dataclass, field
from typing import List
import javalang


@dataclass
class FunctionNode:
    id: str                     # e.g., "app.py::process_upload"
    name: str                   # e.g., "process_upload"
    file_path: str
    start_line: int
    end_line: int
    language: str
    imports: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    is_entrypoint: bool = False


class ASTExtractor:
    """Uses pure-Python AST parsers to extract functions, imports, and call sites."""

    def extract_from_repo(self, repo_path: str) -> List[FunctionNode]:
        extracted_nodes: List[FunctionNode] = []

        for root, _, files in os.walk(repo_path):
            if any(part.startswith(".") or part in ("venv", "node_modules", "target") for part in root.split(os.sep)):
                continue

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo_path)

                if file.endswith(".py"):
                    extracted_nodes.extend(self._parse_python_file(full_path, rel_path))
                elif file.endswith(".java"):
                    extracted_nodes.extend(self._parse_java_file(full_path, rel_path))

        return extracted_nodes

    def _parse_python_file(self, full_path: str, rel_path: str) -> List[FunctionNode]:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            return []

        file_imports: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                file_imports.append(f"from {node.module} import ...")

        functions: List[FunctionNode] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = self._extract_py_calls(node)
                is_entry = node.name in ("main", "handler", "index") or not node.name.startswith("_")

                functions.append(
                    FunctionNode(
                        id=f"{rel_path}::{node.name}",
                        name=node.name,
                        file_path=rel_path,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno),
                        language="python",
                        imports=file_imports,
                        calls=calls,
                        is_entrypoint=is_entry,
                    )
                )

        return functions

    def _extract_py_calls(self, func_node: ast.AST) -> List[str]:
        calls = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = self._resolve_attr_name(node.func)
                if call_name:
                    calls.append(call_name)
        return list(set(calls))

    def _resolve_attr_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._resolve_attr_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _parse_java_file(self, full_path: str, rel_path: str) -> List[FunctionNode]:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        try:
            tree = javalang.parse.parse(source)
        except Exception:
            return []

        file_imports = [f"import {imp.path};" for imp in tree.imports]
        functions: List[FunctionNode] = []

        for _, node in tree.filter(javalang.tree.MethodDeclaration):
            calls = []
            for _, inv in node.filter(javalang.tree.MethodInvocation):
                if inv.qualifier:
                    calls.append(f"{inv.qualifier}.{inv.member}")
                else:
                    calls.append(inv.member)

            start_line = node.position.line if node.position else 1
            is_entry = "public" in (node.modifiers or set())

            functions.append(
                FunctionNode(
                    id=f"{rel_path}::{node.name}",
                    name=node.name,
                    file_path=rel_path,
                    start_line=start_line,
                    end_line=start_line + 30,
                    language="java",
                    imports=file_imports,
                    calls=list(set(calls)),
                    is_entrypoint=is_entry,
                )
            )

        return functions
