# Secrets Manager

This repository contains two simple implementations of a secret manager.
The storage of the secrets is key value based (secret name and secret password).
Stored secrets are encrypted before being written out to disk.
The first implementation uses a common crypthographic library for encryption and the second implementation uses a Trusted Platform Module 2.0 (TPM).

## Repository structure

The source code of both applications are stored under in the `src/` subdirectory.

- The *secrets-manager* source is stored in `src/secrets_manager`.
- The *secrets-manager-tpm* source is stored in`src/secrets_manager_tpm`.

## Development

This project uses the *uv* package and project manager tool. The used build system is setup tools.
The tool can be obtained from the [project website](https://docs.astral.sh/uv/), from [PyPI](https://pypi.org/project/uv/), or your distribution repository.

The applications can be run with `uv run secrets-manager` and `uv run secrets-manager-tpm`.
An update of the environment can be started with `uv sync`.
