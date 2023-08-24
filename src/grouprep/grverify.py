#!/usr/bin/env python3
import argparse
import base64
import json
import logging

import jsonschema
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.x509 import import_public_key_from_cert_file
from cryptojwt.jws.jws import JWS
from cryptojwt.utils import b64d_enc_dec

from grouprep.utils import load_file


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="Metadata verifier")

    parser.add_argument(
        "--cert",
        dest="cert",
        metavar="filename",
        help="Certificate file (PEM format)",
        required=True,
    )
    parser.add_argument(
        "--schema",
        dest="schema",
        metavar="filename",
        help="JSON schema (YAML or JSON)",
        required=False,
    )
    parser.add_argument(
        "--input",
        dest="input",
        metavar="filename",
        help="Metadata file input",
        required=True,
    )
    parser.add_argument(
        "--output",
        dest="metadata_output",
        metavar="filename",
        help="Metadata output",
        required=False,
    )
    parser.add_argument(
        "--headers",
        dest="headers_output",
        metavar="filename",
        help="Headers output",
        required=False,
    )
    parser.add_argument("--debug", dest="debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.cert, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    sha256_hash = cert.fingerprint(hashes.SHA256())
    cert_fingerprint = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode("utf-8")

    pub_key = import_public_key_from_cert_file(args.cert)
    ec = ECKey()
    trusted_keys = [ec.load_key(pub_key)]

    with open(args.input, "rt") as f:
        metadata_file = f.read()

    metadata_dict = json.loads(metadata_file)

    header_x5t_256 = [
        json.loads(b64d_enc_dec(signature["protected"])).get("x5t#256", "") for signature in metadata_dict["signatures"] if "protected" in signature
    ]

    if cert_fingerprint not in header_x5t_256:
        raise ValueError("The x5t#256 value in the metadata does not match the provided certificate.")

    jws = JWS()
    metadata = jws.verify_json(metadata_file, keys=trusted_keys)

    if args.schema:
        schema = load_file(args.schema)
        v = jsonschema.Draft4Validator(schema)
        errors = sorted(v.iter_errors(metadata), key=lambda e: e.path)
        if errors:
            for error in errors:
                print("{} {}".format(error.message, list(error.path)))
        else:
            print("Schema verification passed")
    else:
        print("Skipping schema check")

    if args.headers_output:
        with open(args.headers_output, "wt") as output_file:
            print(json.dumps(jws.protected_headers(), indent=4, sort_keys=True), file=output_file)
    else:
        print("# METADATA PROTECTED HEADERS (VERIFIED)")
        print(json.dumps(jws.protected_headers(), indent=4, sort_keys=True))

    if args.metadata_output:
        with open(args.metadata_output, "wt") as output_file:
            print(json.dumps(metadata, indent=4), file=output_file)
    else:
        print("# METADATA CONTENTS (VERIFIED)")
        print(json.dumps(metadata, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
