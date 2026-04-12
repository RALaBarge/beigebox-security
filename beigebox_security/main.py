"""CLI entry point for BeigeBox Security."""

import uvicorn
import click

from beigebox_security.config import get_config
from beigebox_security.api import create_app


@click.group()
def cli():
    """BeigeBox Security — LLM/RAG security orchestration."""
    pass


@cli.command()
@click.option("--host", default=None, help="Host to bind to")
@click.option("--port", default=None, type=int, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def server(host: str, port: int, reload: bool):
    """Start the security microservice server."""
    config = get_config()

    uvicorn.run(
        "beigebox_security.api:app",
        host=host or config.host,
        port=port or config.port,
        reload=reload or config.reload,
        log_level="info",
    )


@cli.command()
def health():
    """Check health of running security service."""
    import httpx

    config = get_config()
    url = f"http://{config.host}:{config.port}/health"

    try:
        response = httpx.get(url, timeout=5)
        if response.status_code == 200:
            click.echo("✓ Security service is healthy")
            click.echo(f"  Response: {response.json()}")
        else:
            click.echo(f"✗ Service returned {response.status_code}")
    except Exception as e:
        click.echo(f"✗ Cannot reach service: {e}")


@cli.command()
def docs():
    """Show documentation."""
    click.echo("API Documentation: http://localhost:8001/docs")
    click.echo("OpenAPI Schema: http://localhost:8001/openapi.json")


def main():
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
