"""
CLI interface for RSA Attack Toolkit.

This module provides a command-line interface using Typer and Rich
for interacting with the attacker client.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from typing import Optional

from rsa_toolkit.client.attacker import AttackerClient, AttackReport

app = typer.Typer(
    name="rsa-attack-toolkit",
    help="RSA Attack Toolkit - Security testing tool for RSA vulnerabilities",
    add_completion=False
)

console = Console()


@app.command()
def attack(
    scenario_id: str = typer.Argument(..., help="Scenario ID to attack"),
    server_url: str = typer.Option("http://127.0.0.1:8000", "--server", "-s", help="Server URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """
    Run full attack against a scenario.

    Args:
        scenario_id: Scenario identifier
        server_url: URL of the vulnerable server
        verbose: Enable verbose output
    """
    rprint(Panel.fit(f"[bold blue]RSA Attack Toolkit[/bold blue]\nAttacking scenario: {scenario_id}"))

    client = AttackerClient(server_url=server_url)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Reconnaissance
            task = progress.add_task("Reconnaissance...", total=None)
            recon = client.reconnaissance(scenario_id)
            progress.update(task, description="Reconnaissance complete")

            # Feature extraction
            task = progress.add_task("Analyzing features...", total=None)
            recon.analysis = client.analyze_features(recon)
            progress.update(task, description="Feature analysis complete")

            # Attack planning
            task = progress.add_task("Planning attacks...", total=None)
            attack_plan = client.plan_attacks(recon)
            progress.update(task, description=f"Attack plan: {', '.join(attack_plan)}")

            # Execute attacks
            attacks = []
            successful_attack = None

            for attack_name in attack_plan:
                task = progress.add_task(f"Executing {attack_name}...", total=None)
                attack_result = client.execute_attack(attack_name, recon)
                attacks.append(attack_result)

                if attack_result.success:
                    progress.update(task, description=f"[green]{attack_name} succeeded![/green]")
                    # Verify
                    if client.verify_result(scenario_id, attack_result):
                        successful_attack = attack_result
                        progress.update(task, description=f"[green]{attack_name} verified![/green]")
                        break
                else:
                    progress.update(task, description=f"[red]{attack_name} failed[/red]")

        # Display results
        _display_attack_report(scenario_id, recon, attacks, successful_attack, verbose)

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@app.command()
def list_scenarios(
    server_url: str = typer.Option("http://127.0.0.1:8000", "--server", "-s", help="Server URL")
):
    """
    List all available scenarios on the server.

    Args:
        server_url: URL of the vulnerable server
    """
    import httpx

    rprint(Panel.fit("[bold blue]RSA Attack Toolkit[/bold blue]\nListing scenarios"))

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{server_url}/scenarios")
            response.raise_for_status()
            data = response.json()

            if not data["scenarios"]:
                console.print("[yellow]No scenarios available[/yellow]")
                return

            table = Table(title="Available Scenarios")
            table.add_column("Scenario ID", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Description", style="green")

            for scenario_id in data["scenarios"]:
                # Get scenario details
                response = client.get(f"{server_url}/scenarios/{scenario_id}")
                response.raise_for_status()
                scenario_data = response.json()

                table.add_row(
                    scenario_id,
                    scenario_data["scenario_type"],
                    scenario_data["description"]
                )

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)


@app.command()
def create_scenario(
    scenario_type: str = typer.Argument(..., help="Scenario type (S0-S9)"),
    server_url: str = typer.Option("http://127.0.0.1:8000", "--server", "-s", help="Server URL"),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed for reproducibility")
):
    """
    Create a new scenario on the server.

    Args:
        scenario_type: Type of scenario (S0-S9)
        server_url: URL of the vulnerable server
        seed: Optional random seed
    """
    import httpx

    rprint(Panel.fit(f"[bold blue]RSA Attack Toolkit[/bold blue]\nCreating scenario: {scenario_type}"))

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{server_url}/scenarios/create",
                json={"scenario_type": scenario_type, "seed": seed}
            )
            response.raise_for_status()
            data = response.json()

            console.print(f"[green]Scenario created successfully![/green]")
            console.print(f"Scenario ID: [cyan]{data['scenario_id']}[/cyan]")
            console.print(f"Type: [magenta]{data['scenario_type']}[/magenta]")
            console.print(f"Description: [green]{data['description']}[/green]")
            console.print(f"Users: {', '.join(data['users'])}")

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)


@app.command()
def scenario_info(
    scenario_id: str = typer.Argument(..., help="Scenario ID"),
    server_url: str = typer.Option("http://127.0.0.1:8000", "--server", "-s", help="Server URL")
):
    """
    Get detailed information about a scenario.

    Args:
        scenario_id: Scenario identifier
        server_url: URL of the vulnerable server
    """
    import httpx

    rprint(Panel.fit(f"[bold blue]RSA Attack Toolkit[/bold blue]\nScenario Info: {scenario_id}"))

    try:
        with httpx.Client(timeout=10.0) as client:
            # Get scenario details
            response = client.get(f"{server_url}/scenarios/{scenario_id}")
            response.raise_for_status()
            scenario_data = response.json()

            # Get users
            response = client.get(f"{server_url}/scenarios/{scenario_id}/users")
            response.raise_for_status()
            users_data = response.json()

            # Display info
            table = Table(title=f"Scenario: {scenario_id}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Scenario ID", scenario_data["scenario_id"])
            table.add_row("Type", scenario_data["scenario_type"])
            table.add_row("Description", scenario_data["description"])
            table.add_row("Users", ", ".join(users_data["users"]))

            console.print(table)

            # Display public keys
            console.print("\n[bold]Public Keys:[/bold]")
            key_table = Table()
            key_table.add_column("User", style="cyan")
            key_table.add_column("n (bits)", style="magenta")
            key_table.add_column("e", style="green")

            for user_id in users_data["users"]:
                response = client.get(
                    f"{server_url}/scenarios/{scenario_id}/users/{user_id}/public_key"
                )
                response.raise_for_status()
                key_data = response.json()

                n = key_data["n"]
                e = key_data["e"]

                key_table.add_row(user_id, str(n.bit_length()), str(e))

            console.print(key_table)

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)


def _display_attack_report(
    scenario_id: str,
    recon,
    attacks,
    successful_attack,
    verbose: bool
):
    """Display attack report using Rich formatting."""
    # Summary
    if successful_attack:
        rprint(Panel.fit(
            f"[bold green]Attack Successful![/bold green]\n"
            f"Method: {successful_attack.attack_name}\n"
            f"Time: {successful_attack.time_elapsed:.4f}s\n"
            f"Iterations: {successful_attack.iterations}",
            title="Success"
        ))
    else:
        rprint(Panel.fit(
            "[bold red]Attack Failed[/bold red]\n"
            "All attack methods were unsuccessful.",
            title="Failure"
        ))

    # Reconnaissance summary
    console.print("\n[bold]Reconnaissance:[/bold]")
    recon_table = Table()
    recon_table.add_column("User", style="cyan")
    recon_table.add_column("N (bits)", style="magenta")
    recon_table.add_column("e", style="green")
    recon_table.add_column("Analysis", style="yellow")

    for user_id in recon.users:
        n, e = recon.public_keys[user_id]
        recon_table.add_row(
            user_id,
            str(recon.bit_lengths[user_id]),
            str(e),
            recon.analysis.get(user_id, "N/A")
        )

    console.print(recon_table)

    # Attack results
    console.print("\n[bold]Attack Results:[/bold]")
    attack_table = Table()
    attack_table.add_column("Attack", style="cyan")
    attack_table.add_column("Status", style="magenta")
    attack_table.add_column("Time (s)", style="green")
    attack_table.add_column("Iterations", style="yellow")

    for attack in attacks:
        status = "[green]Success[/green]" if attack.success else "[red]Failed[/red]"
        attack_table.add_row(
            attack.attack_name,
            status,
            f"{attack.time_elapsed:.4f}",
            str(attack.iterations)
        )

    console.print(attack_table)

    # Verbose details
    if verbose and successful_attack:
        console.print("\n[bold]Successful Attack Details:[/bold]")
        console.print(f"Result: {successful_attack.result}")


if __name__ == "__main__":
    app()
