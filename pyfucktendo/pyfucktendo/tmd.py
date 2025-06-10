from enum import Enum
from dataclasses import dataclass
from typing import List, Optional
from io import BytesIO

import binascii, struct

class SignatureType(Enum):
    RSA_4096_SHA_1   = 0x10000
    RSA_2048_SHA_1   = 0x10001
    ECDSA_SHA_1      = 0x10002
    RSA_4096_SHA_256 = 0x10003
    RSA_2048_SHA_256 = 0x10004
    ECDSA_SHA_256    = 0x10005

@dataclass
class ContentRecord:
    content_id: str
    index: int
    content_type: int
    content_size: int
    content_hash: bytes

class KeyType(Enum):
    RSA_4096 = 0x00
    RSA_2048 = 0x01
    ECC_B233 = 0x02

@dataclass
class CertificateRecord:
    signature_type: SignatureType
    signature: bytes
    signature_issuer: str
    key_type: KeyType
    subject: str
    key_id: int
    public_key: bytes
    public_exponent: Optional[int]

class Platform(Enum):
    WII      = 0x01
    DSI      = 0x03
    THREE_DS = 0x04
    WII_U    = 0x05

class TitleMetadata:
    def __init__(self):
        self.__signature_type: SignatureType = SignatureType.RSA_4096_SHA_1
        self.__signature: bytes = b""
        self.__signature_issuer: str = ""
        self.__tmd_version: int = 0
        self.__ca_crl_version: int = 0
        self.__signer_crl_version: int = 0
        self.__reserved: bytes = b""
        self.__system_version: bytes = b"" # help
        self.__title_id: str = ""
        self.__title_type: bytes = b""
        self.__group_id: int = 0
        self.__unknown_2: bytes = b"" # not 100% sure
        self.__access_rights: bytes = b""
        self.__title_version: int = 0
        self.__boot_index: int = 0
        self.__unknown_3: bytes = b"" # not 100% sure

        if self.__tmd_version == 1: # i don't care at the moment
            self.__irrelevant: bytes = b""

        self.__contents: List[ContentRecord] = []
        self.__certificates: List[CertificateRecord] = []

    def __i_need_a_function_name(self, signature_type: SignatureType) -> tuple[int, int]:
        match signature_type:
            case SignatureType.RSA_4096_SHA_1 | SignatureType.RSA_4096_SHA_256:
                return 512, 60
            case SignatureType.RSA_2048_SHA_1 | SignatureType.RSA_2048_SHA_256:
                return 256, 60
            case SignatureType.ECDSA_SHA_1 | SignatureType.ECDSA_SHA_256:
                return 60, 64

    def __i_need_a_function_name_2(self, key_type: KeyType) -> tuple[int, bool, int]:
        match key_type:
            case KeyType.RSA_4096:
                return 512, True, 52
            case KeyType.RSA_2048:
                return 256, True, 52
            case KeyType.ECC_B233:
                return 60, False, 60

    def load(self, tmd: bytes):
        data = BytesIO(tmd)
        self.__signature_type = SignatureType(int.from_bytes(data.read(4), "big"))
        signature_size, padding = self.__i_need_a_function_name(self.__signature_type)
        self.__signature = data.read(signature_size)
        data.read(padding)
        self.__signature_issuer = data.read(64).replace(b"\x00", b"").decode("utf-8")
        self.__tmd_version = int.from_bytes(data.read(1), "big")
        self.__ca_crl_version = int.from_bytes(data.read(1), "big")
        self.__signer_crl_version = int.from_bytes(data.read(1), "big")
        self.__reserved = data.read(1)
        self.__system_version = data.read(8) # help
        self.__title_id = binascii.hexlify(data.read(8)).decode("utf-8")
        self.__title_type = data.read(4)
        self.__group_id = int.from_bytes(data.read(2), "big")
        self.__unknown_2 = data.read(44) # not 100% sure
        data.read(18)
        self.__access_rights = data.read(4)
        self.__title_version = int.from_bytes(data.read(2), "big")
        content_count = int.from_bytes(data.read(2), "big")
        self.__boot_index = int.from_bytes(data.read(2), "big")
        self.__unknown_3 = data.read(2) # not 100% sure

        if self.__tmd_version == 1: # i don't care at the moment
            self.__irrelevant = data.read(2336)

        for i in range(0, content_count):
            content_id = binascii.hexlify(data.read(4)).decode("utf-8")
            index, content_type, content_size = struct.unpack(">HHQ", data.read(12))
            content_hash = b""
            if self.__tmd_version == 1:
                content_hash = data.read(32)
                if self.get_platform() == Platform.WII_U:
                    content_hash = content_hash[:20]
            elif self.__tmd_version == 0:
                content_hash = data.read(20)
            self.__contents.append(ContentRecord(content_id, index, content_type, content_size, content_hash))

        while data.tell() < len(data.getvalue()):
            signature_type: SignatureType = SignatureType(int.from_bytes(data.read(4), "big"))
            signature_size, padding = self.__i_need_a_function_name(signature_type)
            signature: bytes = data.read(signature_size)
            data.read(padding)
            signature_issuer: str = data.read(64).replace(b"\x00", b"").decode("utf-8")
            key_type: KeyType = KeyType(int.from_bytes(data.read(4), "big"))
            subject: str = data.read(64).replace(b"\x00", b"").decode("utf-8")
            key_id: int = int.from_bytes(data.read(4), "big")
            key_length, has_public_exponent, padding = self.__i_need_a_function_name_2(key_type)
            public_exponent: Optional[int] = None
            public_key: bytes = data.read(key_length)
            if has_public_exponent:
                public_exponent = int.from_bytes(data.read(4), "big")
            data.read(padding)
            self.__certificates.append(CertificateRecord(signature_type, signature, signature_issuer, key_type, subject, key_id, public_key, public_exponent))

    def dump(self) -> bytes:
        tmd = BytesIO(b"")
        tmd.write(self.__signature_type.value.to_bytes(4, "big"))
        tmd.write(self.__signature)
        _, padding = self.__i_need_a_function_name(self.__signature_type)
        tmd.write(b"\x00" * padding)
        signature_issuer = self.__signature_issuer.encode(encoding="utf-8")
        while len(signature_issuer) < 64:
            signature_issuer += b"\x00"
        tmd.write(signature_issuer)
        tmd.write(self.__tmd_version.to_bytes(1, "big"))
        tmd.write(self.__ca_crl_version.to_bytes(1, "big"))
        tmd.write(self.__signer_crl_version.to_bytes(1, "big"))
        if self.get_platform() == Platform.WII_U and int.from_bytes(self.__reserved, "big") == 1:
            tmd.write(b"\x01")
        else:
            tmd.write(b"\x00")
        tmd.write(self.__system_version) # help
        tmd.write(binascii.unhexlify(self.__title_id))
        tmd.write(self.__title_type)
        tmd.write(self.__group_id.to_bytes(2, "big"))
        tmd.write(self.__unknown_2) # not 100% sure
        tmd.write(b"\x00" * 18)
        tmd.write(self.__access_rights)
        tmd.write(self.__title_version.to_bytes(2, "big"))
        tmd.write(len(self.__contents).to_bytes(2, "big"))
        tmd.write(self.__boot_index.to_bytes(2, "big"))
        tmd.write(self.__unknown_3) # not 100% sure

        if self.__tmd_version == 1: # i don't care at the moment
            tmd.write(self.__irrelevant)

        for content in self.__contents:
            tmd.write(binascii.unhexlify(content.content_id))
            tmd.write(content.index.to_bytes(2, "big"))
            tmd.write(content.content_type.to_bytes(2, "big"))
            tmd.write(content.content_size.to_bytes(8, "big"))
            tmd.write(content.content_hash)
            if self.get_platform() == Platform.WII_U:
                tmd.write(b"\x00" * 12)

        for certificate in self.__certificates:
            tmd.write(certificate.signature_type.value.to_bytes(4, "big"))
            tmd.write(certificate.signature)
            _, padding = self.__i_need_a_function_name(certificate.signature_type)
            tmd.write(b"\x00" * padding)
            signature_issuer = certificate.signature_issuer.encode(encoding="utf-8")
            while len(signature_issuer) < 64:
                signature_issuer += b"\x00"
            tmd.write(signature_issuer)
            tmd.write(certificate.key_type.value.to_bytes(4, "big"))
            subject = certificate.subject.encode(encoding="utf-8")
            while len(subject) < 64:
                subject += b"\x00"
            tmd.write(subject)
            tmd.write(certificate.key_id.to_bytes(4, "big"))
            tmd.write(certificate.public_key)
            if certificate.public_exponent:
                tmd.write(certificate.public_exponent.to_bytes(4, "big"))
            _, _, padding = self.__i_need_a_function_name_2(certificate.key_type)
            tmd.write(b"\x00" * padding)
        return tmd.getvalue()

    def get_signature(self) -> tuple[SignatureType, bytes]:
        return self.__signature_type, self.__signature

    def get_signature_issuer(self) -> str:
        return self.__signature_issuer

    def get_tmd_version(self) -> int:
        return self.__tmd_version

    def get_ca_crl_version(self) -> int:
        return self.__ca_crl_version

    def get_signer_crl_version(self) -> int:
        return self.__signer_crl_version

    def get_system_version(self) -> bytes: # help
        return self.__system_version

    def get_title_id(self) -> str:
        return self.__title_id

    def get_title_type(self) -> bytes:
        return self.__title_type

    def get_group_id(self) -> int:
        return self.__group_id

    def get_access_rights(self) -> bytes:
        return self.__access_rights

    def get_title_version(self) -> int:
        return self.__title_version

    def get_boot_index(self) -> int:
        return self.__boot_index

    def get_contents(self) -> List[ContentRecord]:
        return self.__contents

    def get_certificates(self) -> List[CertificateRecord]:
        return self.__certificates

    def get_platform(self) -> Platform:
        platform = Platform(int.from_bytes(binascii.unhexlify(self.__title_id[:4].replace("0000", "0001")), "big"))
        if platform == Platform.WII and int.from_bytes(self.__reserved, "big") == 1:
            platform = Platform.WII_U
        return platform
