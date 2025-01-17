import click
from click.core import Context
from secrets_manager.keyring import (
    Keyring,
    KeyringFileInvalidError,
    KeyringNotFoundError,
    SecretAlreadyExistsError,
    SecretNotFoundError,
)


@click.group("secrets", help="Secrets management")
@click.option("-k", "--keyring", required=True, type=str, help="Name of the keyring")
@click.option(
    "-p",
    "--password",
    required=True,
    hide_input=True,
    prompt=True,
    type=str,
    help="Password of the keyring",
)
@click.pass_context
def secrets(ctx: Context, keyring: str, password: str) -> None:
    try:
        ctx.obj = ctx.with_resource(Keyring(keyring, password))
    except KeyringNotFoundError:
        click.echo("Error: Keyring not found.", err=True)
        ctx.exit(1)
    except KeyringFileInvalidError:
        click.echo("Error: Keyring file invalid", err=True)
        ctx.exit(1)


@secrets.command("add", help="Add a secret")
@click.option("-n", "--name", required=True, type=str, help="Name of the secret")
@click.option(
    "-s",
    "--secret",
    required=True,
    prompt=True,
    hide_input=True,
    type=str,
    help="The value of the secret",
)
@click.pass_context
def secrets_add(ctx: Context, name: str, secret: str) -> None:
    try:
        ctx.obj.add_secret(name, secret)
    except SecretAlreadyExistsError:
        click.echo("Error: Secret already exists.", err=True)
        ctx.exit(1)


@secrets.command("update", help="Update a secret")
@click.option("-n", "--name", required=True, type=str, help="Name of the secret")
@click.option(
    "-s",
    "--secret",
    required=True,
    prompt=True,
    hide_input=True,
    type=str,
    help="The value of the secret",
)
@click.pass_context
def secrets_update(ctx: Context, name: str, secret: str) -> None:
    try:
        ctx.obj.update_secret(name, secret)
    except SecretNotFoundError:
        click.echo("Error: Secret not found.", err=True)
        ctx.exit(1)


@secrets.command("list", help="List secrets")
@click.pass_context
def secrets_list(ctx: Context) -> None:
    secrets = ctx.obj.list_secrets()

    for secret in secrets:
        print(secret)


@secrets.command("get", help="Get a secret")
@click.argument("name", required=True, type=str)
@click.pass_context
def secrets_get(ctx: Context, name: str) -> None:
    try:
        secret = ctx.obj.get_secret(name)
    except SecretNotFoundError:
        click.echo("Error: Secret not found.", err=True)
        ctx.exit(1)

    print(f"Secret: {secret}")


@secrets.command("remove", help="Remove a secret")
@click.argument("name", required=True, type=str)
@click.pass_context
def secrets_remove(ctx: Context, name: str) -> None:
    try:
        ctx.obj.remove_secret(name)
    except SecretNotFoundError:
        click.echo("Error: Secret not found.", err=True)
        ctx.exit(1)
