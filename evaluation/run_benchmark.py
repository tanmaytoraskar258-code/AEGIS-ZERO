import os
from src.pipeline import RemediationPipeline
from evaluation.metrics_calculator import MetricsCalculator


def main():
    benchmark_dir = "benchmarks/vul4j_subset"
    repos = [
        os.path.join(benchmark_dir, d)
        for d in os.listdir(benchmark_dir)
        if os.path.isdir(os.path.join(benchmark_dir, d))
    ]

    if not repos:
        print(f"No benchmark repositories found in {benchmark_dir}.")
        print("Add target repositories or run unit tests first.")
        return

    pipeline = RemediationPipeline()
    pipeline.docker_runner.build_sandbox_images()

    all_results = []
    for repo in sorted(repos):
        result = pipeline.run(repo, build_images=False)
        all_results.append(result)

    calculator = MetricsCalculator()
    summary = calculator.compute_and_export(all_results)

    print("\n==========================================")
    print("       RESEARCH BENCHMARK SUMMARY         ")
    print("==========================================")
    for key, value in summary.items():
        print(f"{key:35s}: {value}")


if __name__ == "__main__":
    main()
