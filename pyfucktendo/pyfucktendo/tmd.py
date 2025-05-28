import binascii

class TitleMetadata:
    def __init__(self):
        self.signature_type: bytes = b''
        self.signature: bytes = b''
        self.signature_issuer: str = ""
        self.tmd_version: int = 0
        self.ca_crl_version: int = 0
        self.signer_crl_version: int = 0
        self.system_version: int = 0
        self.title_id: str = ""

    def load(self, tmd: bytes):
        self.signature_type = tmd[0x00:0x04]
        self.signature = tmd[0x04:0x104]
        self.signature_issuer = tmd[0x140:0x180].decode()
        self.tmd_version = tmd[0x180]
        self.ca_crl_version = tmd[0x181]
        self.signer_crl_version = tmd[0x182]
        self.system_version = int(binascii.hexlify(tmd[0x184:0x18C])[-2:], 16) # this should be correct (if not feel free to open a pull request but please no ai slop)
        self.title_id = binascii.hexlify(tmd[0x18C:0x194]).decode()
