"""
Run experiments for all scenarios with proper attack plan.
"""

import httpx
import time
import json
from pathlib import Path
from typing import Dict, List, Optional
from rsa_toolkit.client.attacker import AttackerClient

SERVER_URL = "http://127.0.0.1:8001"

class ExperimentRunner:
    def __init__(self, server_url: str = SERVER_URL):
        self.server_url = server_url
        self.results_dir = Path("experiment_results")
        self.results_dir.mkdir(exist_ok=True)

    def create_scenario(self, scenario_type: str, seed: int = None) -> Dict:
        """Create a new scenario."""
        client = httpx.Client(timeout=120.0)
        try:
            response = client.post(
                f"{self.server_url}/scenarios/create",
                json={"scenario_type": scenario_type, "seed": seed}
            )
            response.raise_for_status()
            return response.json()
        finally:
            client.close()

    def run_attack(self, scenario_id: str, scenario_code: str) -> Dict:
        """Run attacker client against a scenario (with server verification)."""
        attacker = AttackerClient(server_url=self.server_url)

        try:
            report = attacker.run_full_attack(scenario_id)
            recon = report.reconnaissance

            attacks = [
                {
                    "attack_name": a.attack_name,
                    "success": a.success,
                    "time_elapsed": a.time_elapsed,
                    "iterations": a.iterations,
                    "error_message": a.error_message
                }
                for a in report.attacks
            ]

            successful_attack = None
            if report.successful_attack is not None:
                a = report.successful_attack
                successful_attack = {
                    "attack_name": a.attack_name,
                    "time_elapsed": a.time_elapsed,
                    "iterations": a.iterations
                }

            return {
                "scenario_id": scenario_id,
                "scenario_code": scenario_code,
                "scenario_type": report.scenario_type,
                "success": successful_attack is not None,
                "successful_attack": successful_attack,
                "all_attacks": attacks,
                "users": recon.users,
                "analysis": recon.analysis,
                "total_attack_time": report.total_time
            }
        finally:
            attacker.close()

    def run_scenario_experiment(self, scenario_code: str, scenario_type: str, num_runs: int = 5):
        """Run a scenario multiple times and record results."""
        print(f"\n{'='*60}")
        print(f"Running scenario {scenario_code} ({scenario_type})")
        print(f"{'='*60}")

        all_runs = []

        for run_num in range(1, num_runs + 1):
            print(f"\n--- Run {run_num}/{num_runs} ---")
            seed = run_num * 1000

            try:
                # Create scenario
                print(f"Creating scenario with seed {seed}...")
                scenario = self.create_scenario(scenario_type, seed)
                scenario_id = scenario["scenario_id"]
                print(f"Created scenario: {scenario_id}")

                # Run attack
                print("Running attack...")
                start_time = time.perf_counter()
                result = self.run_attack(scenario_id, scenario_code)
                total_time = time.perf_counter() - start_time

                result["run_number"] = run_num
                result["seed"] = seed
                result["total_time"] = total_time

                print(f"Success: {result['success']}")
                if result['success']:
                    attack = result['successful_attack']
                    print(f"Attack: {attack['attack_name']}")
                    print(f"Time: {attack['time_elapsed']:.6f}s")
                    print(f"Iterations: {attack['iterations']}")
                else:
                    print("All attacks failed")

                all_runs.append(result)

                # Save individual run result
                run_file = self.results_dir / f"{scenario_code}_run_{run_num}.json"
                with open(run_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Saved to {run_file}")

            except Exception as e:
                print(f"ERROR in run {run_num}: {e}")
                import traceback
                traceback.print_exc()
                all_runs.append({
                    "run_number": run_num,
                    "seed": seed,
                    "success": False,
                    "error": str(e)
                })

        # Save summary for this scenario
        summary_file = self.results_dir / f"{scenario_code}_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(all_runs, f, indent=2)
        print(f"\nSummary saved to {summary_file}")

        return all_runs

if __name__ == "__main__":
    import sys

    runner = ExperimentRunner()

    # All scenarios S0-S10
    scenarios = [
        ("S0", "S0"),
        ("S1", "S1"),
        ("S2", "S2"),
        ("S3", "S3"),
        ("S4", "S4"),
        ("S5", "S5"),
        ("S6", "S6"),
        ("S7", "S7"),
        ("S8", "S8"),
        ("S9", "S9"),
        ("S10", "S10"),
    ]

    # Check if a specific scenario was requested
    if len(sys.argv) > 1:
        target_scenario = sys.argv[1]
        scenarios = [(s, t) for s, t in scenarios if s == target_scenario]
        if not scenarios:
            print(f"Scenario {target_scenario} not found")
            sys.exit(1)

    for scenario_code, scenario_type in scenarios:
        try:
            runner.run_scenario_experiment(scenario_code, scenario_type, num_runs=5)
        except Exception as e:
            print(f"ERROR running scenario {scenario_code}: {e}")
            import traceback
            traceback.print_exc()
