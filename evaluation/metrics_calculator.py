import csv
import json
import os
from typing import List
from src.pipeline import PipelineResult


class MetricsCalculator:
    """Computes publication-ready metrics and exports CSV/JSON tables for research papers."""

    def compute_and_export(self, results: List[PipelineResult], output_dir: str = "evaluation/results") -> dict:
        os.makedirs(output_dir, exist_ok=True)

        total_baseline_cves = sum(r.total_cves_detected for r in results)
        total_reachable_cves = sum(r.reachable_cves_count for r in results)
        total_pruned = sum(r.false_positives_eliminated for r in results)

        fp_reduction_pct = (
            round((total_pruned / total_baseline_cves) * 100, 2)
            if total_baseline_cves > 0
            else 0.0
        )

        all_outcomes = [o for r in results for o in r.outcomes]
        total_targeted = len(all_outcomes)
        pass_at_1 = sum(1 for o in all_outcomes if o.patched_successfully and o.attempts_used == 1)
        pass_at_k = sum(1 for o in all_outcomes if o.patched_successfully)

        pass_1_rate = round((pass_at_1 / total_targeted) * 100, 2) if total_targeted > 0 else 0.0
        pass_k_rate = round((pass_at_k / total_targeted) * 100, 2) if total_targeted > 0 else 0.0
        avg_latency = round(sum(r.execution_time_sec for r in results) / len(results), 2) if results else 0.0

        summary = {
            "repositories_evaluated": len(results),
            "baseline_cves_flagged": total_baseline_cves,
            "reachable_cves_confirmed": total_reachable_cves,
            "false_positives_eliminated": total_pruned,
            "false_positive_reduction_percent": fp_reduction_pct,
            "pass_at_1_percent": pass_1_rate,
            "pass_at_k_percent": pass_k_rate,
            "average_pipeline_latency_sec": avg_latency,
        }

        # Export JSON summary
        json_path = os.path.join(output_dir, "benchmark_summary.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)

        # Export detailed per-CVE CSV table for paper figures/tables
        csv_path = os.path.join(output_dir, "detailed_outcomes.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Repository", "CVE_ID", "Package", "Call_Depth", "Patched", "Attempts", "Status"])
            for r in results:
                repo_name = os.path.basename(r.repo_path)
                for o in r.outcomes:
                    writer.writerow([
                        repo_name,
                        o.cve_id,
                        o.package_name,
                        len(o.call_path),
                        o.patched_successfully,
                        o.attempts_used,
                        o.status_message,
                    ])

        return summary
