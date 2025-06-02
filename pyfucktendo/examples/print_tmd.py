from pyfucktendo.tmd import TitleMetadata

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python print_tmd.py <filename>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as file:
        title_metadata = TitleMetadata()
        title_metadata.load(file.read())
        signature_type, signature = title_metadata.get_signature()
        print(f"Signature Type: {signature_type}")
        print(f"Signature: {signature}")
        print(f"Signature Issuer: {title_metadata.get_signature_issuer()}")
        print(f"TMD Version: {title_metadata.get_tmd_version()}")
        print(f"CA CRL Version: {title_metadata.get_ca_crl_version()}")
        print(f"Signer CRL Version: {title_metadata.get_signer_crl_version()}")
        print(f"System Version: {title_metadata.get_system_version()}")
        print(f"Title ID: {title_metadata.get_title_id()}")
        print(f"Title Type: {title_metadata.get_title_type()}")
        print(f"Group ID: {title_metadata.get_group_id()}")
        print(f"Access Rights: {title_metadata.get_access_rights()}")
        print(f"Title Version: {title_metadata.get_title_version()}")
        print(f"Boot Index: {title_metadata.get_boot_index()}")
        print(f"Content Count: {len(title_metadata.get_contents())}")
        print(f"Contents: {title_metadata.get_contents()}")
        print(f"Certificate Count: {len(title_metadata.get_certificates())}")
        print(f"Certificates: {title_metadata.get_certificates()}")
