import click
from secrets_manager.cli.keyring import keyring
from secrets_manager.cli.secrets import secrets


@click.group(help="Keyring application to store secrets")
@click.version_option()
def cli() -> None:
    pass


cli.add_command(keyring)
cli.add_command(secrets)
