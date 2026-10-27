"""
Main entry point for RSA Attack Toolkit.

This module provides entry points for running the server and client.
"""

import typer
from rich.console import Console

from rsa_toolkit.server.app import run_server
from rsa_toolkit.client.cli import app as client_app

console = Console()


main_app = typer.Typer(
    name="rsa-toolkit",
    help="RSA Attack Toolkit - Security testing tool for RSA vulnerabilities",
    add_completion=False
)


@main_app.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to")
):
    """
    Start the vulnerable RSA server.

    Args:
        host: Host to bind to
        port: Port to bind to
    """
    console.print(f"[bold blue]Starting RSA Attack Toolkit Server[/bold blue]")
    console.print(f"Host: {host}")
    console.print(f"Port: {port}")
    console.print("")

    run_server(host=host, port=port)


main_app.add_typer(client_app, name="client", help="Client commands for attacking scenarios")


if __name__ == "__main__":
    main_app()
