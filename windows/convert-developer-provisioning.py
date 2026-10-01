"""Prepare test BYOC bundles using edge-tool's existing schema and key mapping.

Host-side tool only; the native Windows application needs no Python runtime.
The output contains private key material. Use a restricted output directory.
"""
# SPDX-License-Identifier: Apache-2.0
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

# Keep host-side conversion from creating bytecode beside repository sources.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "edge-tool"))
import cbor2
from pyclibrary import CParser
from cbor_converter import CBORConverter, KEY_MAP
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def convert(credential, output):
    values = CParser([str(credential)]).defs.get("values", {})
    required = [name for name in KEY_MAP if name.startswith("MBED_CLOUD_DEV_")]
    if any(name not in values for name in required):
        raise ValueError("Missing developer credential fields")
    values = {name: values[name] for name in required}
    bundle = CBORConverter(str(credential), None, None).create_cbor_data(values)
    key = serialization.load_der_private_key(bundle["Keys"][0]["Data"], password=None)
    certificate = x509.load_der_x509_certificate(next(
        item["Data"] for item in bundle["Certificates"] if item["Name"] == "mbed.BootstrapDeviceCert"))
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("The existing developer converter expects an EC private key")
    public = lambda value: value.public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(key.public_key()) != public(certificate.public_key()):
        raise ValueError("Certificate and private key do not match")
    # Reuse the existing CBOR representation. No update credentials are needed
    # for the Windows connectivity profile, where firmware updates are disabled.
    (output / "provisioning.cbor").write_bytes(cbor2.dumps(bundle))
    file_bundle = copy.deepcopy(bundle)
    filenames = {"mbed.BootstrapDeviceCert": "bootstrap-device.der",
                 "mbed.BootstrapServerCACert": "bootstrap-ca.der",
                 "mbed.BootstrapDevicePrivateKey": "bootstrap-private-key.der"}
    for group in ("Certificates", "Keys"):
        for item in file_bundle[group]:
            filename = filenames[item["Name"]]
            (output / filename).write_bytes(item["Data"])
            item["Data"] = filename
    (output / "provisioning.json").write_text(json.dumps(file_bundle, indent=2), encoding="utf-8")
    # Record provenance and content hashes without printing credential values.
    metadata = {"sourceSha256": hashlib.sha256(credential.read_bytes()).hexdigest(),
                "schemeVersion": bundle["SchemeVersion"], "firmwareUpdateCredentials": False,
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(output.iterdir()) if path.is_file()}}
    (output / "conversion.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    if not args.output_directory.is_dir() or any(args.output_directory.iterdir()):
        parser.error("Output directory must already exist, be restricted, and be empty")
    try:
        convert(args.credential_file.resolve(strict=True), args.output_directory)
    except Exception as error:
        # Some parser exceptions contain input text; never print those details.
        print("Credential conversion failed (%s); no credential values are logged." % type(error).__name__,
              file=sys.stderr)
        sys.exit(1)
    print("Created CBOR, JSON and DER test provisioning files; no credential values logged.")
