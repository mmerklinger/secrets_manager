import click
from secrets_manager_tpm.cli.keyring import keyring
from secrets_manager_tpm.cli.secrets import secrets


@click.group(help="Keyring application to store secrets")
@click.version_option()
def cli() -> None:
    pass


cli.add_command(keyring)
cli.add_command(secrets)
