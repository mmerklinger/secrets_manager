import pickle
from pickle import UnpicklingError
from pathlib import Path
from typing import Self, Final, Optional, Literal, Type, List, Dict
from types import TracebackType
from secrets_manager_tpm.tpm import Key, PolicyCurrentPcr, POLICY_PLATFORM_PCR

BASE_PATH: Final[Path] = Path.cwd()
FILE_EXTENSION: Final[str] = ".db"


class KeyringFileInvalidError(Exception):
    def __init__(self) -> None:
        pass


class KeyringNotFoundError(Exception):
    def __init__(self) -> None:
        pass


class KeyringAlreadyExistsError(Exception):
    def __init__(self) -> None:
        pass


class SecretNotFoundError(Exception):
    def __init__(self) -> None:
        pass


class SecretAlreadyExistsError(Exception):
    def __init__(self) -> None:
        pass


class Keyring:
    def __init__(self, name: str, password: bytes) -> None:
        self._name = name
        self._password = password
        self._load()

    def _load(self) -> None:
        path = BASE_PATH / Path(f"{self._name}{FILE_EXTENSION}")
        try:
            self._file = open(path, "rb+")
        except FileNotFoundError:
            raise KeyringNotFoundError

        try:
            keyring_db = pickle.load(self._file)
            secrets_encrypted = keyring_db["secrets"]
        except UnpicklingError:
            raise KeyringFileInvalidError

        with Key(self._name, self._password) as key:
            secrets_decrypted = key.decrypt(secrets_encrypted)
        self._secrets: Dict[str, str] = pickle.loads(secrets_decrypted)

    def _save(self) -> None:
        with Key(self._name, self._password) as key:
            secrets = key.encrypt(pickle.dumps(self._secrets))

        db = {
            "secrets": secrets,
        }

        self._file.seek(0)
        pickle.dump(db, self._file)
        self._file.truncate()
        self._file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        self._save()
        return False

    @classmethod
    def create_keyring(cls, name: str, password: bytes, bind_platform: bool) -> None:
        path = BASE_PATH / Path(f"{name}{FILE_EXTENSION}")
        if Path.exists(path):
            raise KeyringAlreadyExistsError

        if bind_platform:
            PolicyCurrentPcr.create(PolicyCurrentPcr(POLICY_PLATFORM_PCR))
        Key.create(name, password, bind_platform)

        with Key(name, password) as key:
            secrets = key.encrypt(pickle.dumps({}))

        db = {
            "secrets": secrets,
        }

        with open(path, "wb") as f:
            pickle.dump(db, f)

    @classmethod
    def list_keyrings(cls) -> List[str]:
        paths = BASE_PATH.glob("*" + FILE_EXTENSION)
        files = [path for path in paths if path.is_file()]
        return [file.name.rstrip(FILE_EXTENSION) for file in files]

    @classmethod
    def remove_keyring(cls, name: str) -> None:
        path = BASE_PATH / Path(f"{name}{FILE_EXTENSION}")
        if Path.exists(path):
            path.unlink()
        else:
            raise KeyringNotFoundError
        Key.delete(name)

    def _secret_exists(self, name: str) -> bool:
        return True if name in self._secrets.keys() else False

    def add_secret(self, name: str, value: str) -> None:
        if self._secret_exists(name):
            raise SecretAlreadyExistsError
        self._secrets[name] = value

    def update_secret(self, name: str, value: str) -> None:
        if not self._secret_exists(name):
            raise SecretNotFoundError
        self._secrets[name] = value

    def get_secret(self, name: str) -> str:
        if not self._secret_exists(name):
            raise SecretNotFoundError
        return self._secrets[name]

    def list_secrets(self) -> List[str]:
        return list(self._secrets.keys())

    def remove_secret(self, name: str) -> None:
        if not self._secret_exists(name):
            raise SecretNotFoundError
        del self._secrets[name]
