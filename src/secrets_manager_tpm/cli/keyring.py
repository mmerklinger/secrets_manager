import click
from click.core import Context
from secrets_manager_tpm.keyring import (
    Keyring,
    KeyringNotFoundError,
    KeyringAlreadyExistsError,
)
from secrets_manager_tpm.tpm import (
    KeyNotFoundError,
    KeyAlreadyExistsError,
    PolicyNotFoundError,
    PolicyValueError,
    TpmNotFoundError,
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
@click.option(
    "--bind-platform",
    type=bool,
    default=False,
    help="Bind key usage to trusted platform configuration",
)
@click.pass_context
def keyring_create(ctx: Context, name: str, password: str, bind_platform: bool) -> None:
    try:
        Keyring.create_keyring(name, password.encode(), bind_platform)
    except KeyringAlreadyExistsError:
        click.echo("Error: Keyring already exists.", err=True)
        ctx.exit(1)
    except KeyNotFoundError:
        click.echo("Error: Key not found in keystore.", err=True)
        ctx.exit(1)
    except KeyAlreadyExistsError:
        click.echo("Error: Key already exists in keystore.", err=True)
        ctx.exit(1)
    except PolicyNotFoundError:
        click.echo("Error: Policy not found in keystore.", err=True)
        ctx.exit(1)
    except PolicyValueError:
        click.echo("Error: Policy has wrong format.", err=True)
        ctx.exit(1)
    except TpmNotFoundError:
        click.echo("Error: TPM not found.", err=True)
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
    except KeyNotFoundError:
        click.echo("Error: Key not found on TPM.", err=True)
        ctx.exit(1)
    except TpmNotFoundError:
        click.echo("Error: TPM not found.", err=True)
        ctx.exit(1)
