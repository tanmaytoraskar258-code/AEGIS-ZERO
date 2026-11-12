import time
from dataclasses import dataclass, field
from typing import List, Dict, Any
import yaml
from dotenv import load_dotenv

from src.ingestion import SBOMParser, CVEMatcher
from src.reachability import ASTExtractor, CallGraphBuilder, PathPruner
from src.synthesizer import ContextSlicer, PatchAgent, PatchApplier
from src.sandbox import DockerRunner, ExploitVerifier, RegressionRunner


@dataclass
class VulnerabilityOutcome:
    cve_id: str
    package_name: str
    call_path: List[str]
    patched_successfully: bool
    attempts_used: int
    final_patch_diff: str = ""
    status_message: str = ""


@dataclass
class PipelineResult:
    repo_path: str
    total_cves_detected: int
    reachable_cves_count: int
    false_positives_eliminated: int
    execution_time_sec: float
    outcomes: List[VulnerabilityOutcome] = field(default_factory=list)


class RemediationPipeline:
    """End-to-end orchestrator connecting Ingestion, Reachability, Synthesis, and Sandbox."""

    def __init__(self, settings_path: str = "config/settings.yaml"):
        load_dotenv(override=True)
        with open(settings_path, "r", encoding="utf-8") as f:
            self.settings: Dict[str, Any] = yaml.safe_load(f)

        # Stage 0
        self.sbom_parser = SBOMParser()
        self.cve_matcher = CVEMatcher(self.settings["ingestion"]["osv_api_url"])

        # Stage 1
        self.ast_extractor = ASTExtractor()
        self.cg_builder = CallGraphBuilder()
        self.path_pruner = PathPruner(self.settings["reachability"]["max_call_depth"])

        # Stage 2
        self.context_slicer = ContextSlicer()
        self.patch_agent = PatchAgent(self.settings)
        self.patch_applier = PatchApplier()

        # Stage 3
        self.docker_runner = DockerRunner(self.settings)
        self.exploit_verifier = ExploitVerifier(self.docker_runner)
        self.regression_runner = RegressionRunner(self.docker_runner)

        self.max_retries = self.settings["synthesizer"]["max_retries"]

    def run(self, repo_path: str, build_images: bool = True) -> PipelineResult:
        start_time = time.time()

        if build_images:
            self.docker_runner.build_sandbox_images()

        # --- STAGE 0: Ingestion & Baseline CVE Scan ---
        print(f"\n[Stage 0] Scanning dependencies in {repo_path}...")
        deps = self.sbom_parser.parse_repository(repo_path)
        raw_findings = self.cve_matcher.scan_dependencies(deps, repo_path=repo_path)
        print(f" -> Found {len(raw_findings)} total CVEs across {len(deps)} dependencies.")

        # --- STAGE 1: Static Reachability Analysis ---
        print("[Stage 1] Building AST & Directed Call Graph...")
        func_nodes = self.ast_extractor.extract_from_repo(repo_path)
        call_graph = self.cg_builder.build_graph(func_nodes)
        reachable_vulns = self.path_pruner.prune_unreachable(call_graph, raw_findings)

        pruned_count = len(raw_findings) - len(reachable_vulns)
        print(f" -> Reachable CVEs: {len(reachable_vulns)} | False Positives Pruned: {pruned_count}")

        outcomes: List[VulnerabilityOutcome] = []

        # --- STAGES 2 & 3: Closed-Loop Synthesis & Verification ---
        for vuln in reachable_vulns:
            print(f"\n[Stage 2 & 3] Remediating {vuln.finding.cve_id} in {vuln.target_file}...")
            code_context = self.context_slicer.extract_context(repo_path, vuln, call_graph)
            feedback_history = ""
            success = False
            final_diff = ""
            status_msg = ""

            for attempt in range(1, self.max_retries + 1):
                print(f" -> Attempt {attempt}/{self.max_retries}: Synthesizing patch via Gemini...")
                enriched_context = code_context
                if feedback_history:
                    enriched_context += f"\n\n[PREVIOUS ATTEMPT FAILED]\n{feedback_history}\nFix the issue above in your new diff."

                try:
                    diff = self.patch_agent.generate_patch(vuln, enriched_context)
                except Exception as e:
                    status_msg = f"Patch generation failed: {e}"
                    feedback_history = status_msg
                    print(f" -> [ERROR] {status_msg}")
                    continue

                # Apply diff
                applied, apply_msg = self.patch_applier.apply_patch(repo_path, diff)
                if not applied:
                    feedback_history = f"Git Apply Error: {apply_msg}"
                    status_msg = feedback_history
                    continue

                # Verify exploit is blocked
                exploit_ok, exploit_msg = self.exploit_verifier.verify_fix(
                    repo_path, vuln.finding.ecosystem
                )
                if not exploit_ok:
                    self.patch_applier.revert_changes(repo_path)
                    feedback_history = f"Security Verification Failed: {exploit_msg}"
                    status_msg = feedback_history
                    continue

                # Verify existing tests still pass
                tests_ok, tests_msg = self.regression_runner.run_tests(
                    repo_path, vuln.finding.ecosystem
                )
                if not tests_ok:
                    self.patch_applier.revert_changes(repo_path)
                    feedback_history = f"Regression Test Failed: {tests_msg}"
                    status_msg = feedback_history
                    continue

                # Both security and regression checks passed!
                success = True
                final_diff = diff
                status_msg = "Verified: Exploit blocked & all regression tests passed."
                print(f" -> [SUCCESS] {status_msg}")
                break

            outcomes.append(
                VulnerabilityOutcome(
                    cve_id=vuln.finding.cve_id,
                    package_name=vuln.finding.package_name,
                    call_path=vuln.call_path,
                    patched_successfully=success,
                    attempts_used=attempt if success else self.max_retries,
                    final_patch_diff=final_diff,
                    status_message=status_msg,
                )
            )

        elapsed = round(time.time() - start_time, 2)
        return PipelineResult(
            repo_path=repo_path,
            total_cves_detected=len(raw_findings),
            reachable_cves_count=len(reachable_vulns),
            false_positives_eliminated=pruned_count,
            execution_time_sec=elapsed,
            outcomes=outcomes,
        )
