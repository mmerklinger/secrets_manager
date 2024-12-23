# Secrets Manager

This repository contains two simple implementations of a secret manager.
The storage of the secrets is key value based (secret name and secret password).
Stored secrets are encrypted before being written out to disk.
The first implementation uses a common crypthographic library for encryption and the second implementation uses a Trusted Platform Module 2.0 (TPM).
