from tpm2_pytss import FAPI, TSS2_Exception
from tpm2_pytss.constants import TSS2_RC
from types import TracebackType
from typing import Final, List, Literal, Self, Optional, Type, Union, Any, Mapping


POLICY_BASE_PATH: Final[str] = "/policy/secret-manager-tpm"
POLICY_NAME: Final[str] = "secret-manager-tpm-platform"
POLICY_DESCRIPTION: Final[str] = "Bind secret manager to platform"
POLICY_PLATFORM_PCR: Final[List[int]] = [
    0,  # UEFI boot and runtime services
    1,  # other interfaces
    2,  # other loaded drivers
]
KEY_BASE_PATH: Final[str] = "HS/SRK/secret-manager-tpm"
KEY_TYPE: Final[str] = "decrypt"


class KeyNotFoundError(Exception):
    def __init__(self) -> None:
        pass


class KeyAlreadyExistsError(Exception):
    def __init__(self) -> None:
        pass


class PolicyNotFoundError(Exception):
    def __init__(self) -> None:
        pass


class InvalidEncryptedDataError(Exception):
    def __init__(self) -> None:
        pass


class PolicyValueError(Exception):
    def __init__(self) -> None:
        pass


class TpmNotFoundError(Exception):
    def __init__(self) -> None:
        pass


class WrongPasswordError(Exception):
    def __init__(self) -> None:
        pass


class PolicyCurrentPcr(dict[str, Union[str, list[int]]]):
    def __init__(self, pcrs: list[int]) -> None:
        self._pcrs = pcrs
        dict.__init__(self, type="pcr", currentpcrs=self._pcrs)

    @classmethod
    def create(cls, pcr_policy: Self) -> None:
        Policy.create("platform", Policy(POLICY_NAME, POLICY_DESCRIPTION, [pcr_policy]))


class Policy(dict[str, Union[str, list[Mapping[Any, Any]]]]):
    def __init__(
        self, name: str, description: str, policies: list[Mapping[Any, Any]]
    ) -> None:
        self._name = name
        self._description = description
        self._policies = policies
        dict.__init__(
            self, name=self._name, description=self._description, policy=self._policies
        )

    @classmethod
    def create(cls, name: str, policy: Self) -> None:
        path = POLICY_BASE_PATH + "_" + name
        try:
            with FAPI() as fapi:
                fapi.import_object(path, str(policy), True)
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.FAPI_RC_BAD_VALUE:
                raise PolicyValueError
            elif e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError


class Key:
    def __init__(self, name: str, password: bytes) -> None:
        self._name = name
        self._key_path = KEY_BASE_PATH + "_" + self._name
        try:
            self._fapi = FAPI()
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError
        self._fapi.set_auth_callback(callback=self._callback_auth, user_data=password)
        if not self._exists():
            raise KeyNotFoundError

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        self._fapi.close()
        return False

    def _exists(self) -> bool:
        for path in self._fapi.list():
            if path.endswith(self._key_path):
                return True
        return False

    def encrypt(self, data: bytes) -> bytes:
        try:
            data_encrypted = bytes(self._fapi.encrypt(self._key_path, data))
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError
        return data_encrypted

    def decrypt(self, data: bytes) -> bytes:
        try:
            data_decrypted = bytes(self._fapi.decrypt(self._key_path, data))
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.TPM_RC_LAYER:
                raise InvalidEncryptedDataError
            elif e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError
            elif e.rc == 2446:
                raise WrongPasswordError
        return data_decrypted

    @staticmethod
    def _callback_auth(path: str, description: str, user_data: bytes) -> bytes:
        return user_data

    @classmethod
    def create(cls, name: str, password: bytes, bind_platform: bool) -> None:
        key_path = KEY_BASE_PATH + "_" + name
        try:
            with FAPI() as fapi:
                if bind_platform:
                    policy_path = POLICY_BASE_PATH + "_" + "platform"
                    fapi.create_key(key_path, KEY_TYPE, policy_path, password)
                else:
                    fapi.create_key(key_path, KEY_TYPE, auth_value=password)
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.FAPI_RC_PATH_ALREADY_EXISTS:
                raise KeyAlreadyExistsError
            elif e.rc == TSS2_RC.FAPI_RC_POLICY_UNKNOWN:
                raise PolicyNotFoundError
            elif e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError

    @classmethod
    def delete(cls, name: str) -> None:
        key_path = KEY_BASE_PATH + "_" + name
        try:
            with FAPI() as fapi:
                fapi.delete(key_path)
        except TSS2_Exception as e:
            if e.rc == TSS2_RC.FAPI_RC_BAD_PATH:
                raise KeyNotFoundError
            elif e.rc == TSS2_RC.FAPI_RC_NO_TPM:
                raise TpmNotFoundError
