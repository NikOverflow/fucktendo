from enum import Enum
from dataclasses import dataclass
from typing import List
from io import BytesIO

import binascii, struct

class TitleType(Enum):
    UNKNOWN          = 0
    DEMO_APPLICATION = 1
    APPLICATION      = 2
    UPDATE           = 3
    DLC              = 4

@dataclass
class ContentRecord:
    content_id: str
    index: int
    content_type: int
    content_size: int
    content_hash: bytes

class TitleMetadata:
    def __init__(self):
        self.signature_type: bytes = b""
        self.signature: bytes = b""
        self.signature_issuer: str = ""
        self.tmd_version: int = 0
        self.ca_crl_version: int = 0
        self.signer_crl_version: int = 0
        #self.system_version: int = 0
        self.title_id: str = ""
        self.title_type: bytes = b""
        self.group_id: int = 0
        self.access_rights: int = 0
        self.title_version: int = 0
        self.boot_index: int = 0
        self.minor_version: int = 0
        self.contents: List[ContentRecord] = []

    def load(self, tmd: bytes):
        self.signature_type = tmd[0x00:0x04]
        self.signature = tmd[0x04:0x104]
        self.signature_issuer = tmd[0x140:0x180].decode("utf-8")
        self.tmd_version = tmd[0x180]
        self.ca_crl_version = tmd[0x181]
        self.signer_crl_version = tmd[0x182]
        #self.system_version = int(binascii.hexlify(tmd[0x184:0x18C])[-2:], 16) # this should be correct (if not feel free to open a pull request but please no ai slop)
        self.title_id = binascii.hexlify(tmd[0x18C:0x194]).decode("utf-8")
        self.title_type = tmd[0x194:0x198]
        self.group_id = int.from_bytes(tmd[0x198:0x19A], "big")
        self.access_rights = int.from_bytes(tmd[0x1D8:0x1DC], "big")
        self.title_version = int.from_bytes(tmd[0x1DC:0x1DE], "big")
        self.boot_index = int.from_bytes(tmd[0x1E0:0x1E2], "big")
        self.minor_version = int.from_bytes(tmd[0x1E2:0x1E4], "big")
        for content in range(0, int.from_bytes(tmd[0x1DE:0x1E0], "big")):
            with BytesIO(tmd) as data:
                if self.tmd_version == 0:
                    data.seek((content * 36) + 0x1E4)
                    content_id = binascii.hexlify(data.read(4)).decode("utf-8")
                    index, content_type, content_size = struct.unpack(">HHQ", data.read(12))
                    self.contents.append(ContentRecord(content_id, index, content_type, content_size, data.read(20)))
                elif self.tmd_version == 1:
                    data.seek((content * 48) + 0xB04)
                    content_id = binascii.hexlify(data.read(4)).decode("utf-8")
                    index, content_type, content_size = struct.unpack(">HHQ", data.read(12))
                    self.contents.append(ContentRecord(content_id, index, content_type, content_size, data.read(32)))

    def get_title_type(self) -> TitleType:
        return {
            "00050002": TitleType.DEMO_APPLICATION, # Wii U
            "00050000": TitleType.APPLICATION, # Wii U
            "0005000e": TitleType.UPDATE, # Wii U
            "00010005": TitleType.DLC, # Wii
            "0005000c": TitleType.DLC # Wii U
        }.get(self.title_id[:8], TitleType.UNKNOWN)
