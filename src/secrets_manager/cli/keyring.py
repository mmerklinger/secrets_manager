import click
from click.core import Context
from secrets_manager.keyring import (
    Keyring,
    KeyringAlreadyExistsError,
    KeyringNotFoundError,
)


@click.group("keyring", help="Keyring management")
def keyring() -> None:
    pass


@keyring.command("create", help="Create a keyring")
@click.argument("name", required=True, type=str)
@click.option(
    "-p",
    "--password",
    required=True,
    prompt=True,
    hide_input=True,
    type=str,
    help="Password for the keyring",
)
@click.pass_context
def keyring_create(ctx: Context, name: str, password: str) -> None:
    try:
        Keyring.create_keyring(name, password.encode())
    except KeyringAlreadyExistsError:
        click.echo("Error: Keyring already exists.", err=True)
        ctx.exit(1)


@keyring.command("list", help="List keyrings")
def keyring_list() -> None:
    keyrings = Keyring.list_keyrings()

    for keyring in keyrings:
        print(keyring)


@keyring.command("remove", help="Remove a keyring")
@click.argument("name", required=True, type=str)
@click.pass_context
def keyring_remove(ctx: Context, name: str) -> None:
    try:
        Keyring.remove_keyring(name)
    except KeyringNotFoundError:
        click.echo("Error: Keyring not found.", err=True)
        ctx.exit(1)
