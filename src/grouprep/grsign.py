#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import sys
import time

import jsonschema
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptojwt.jws.jws import JWS
from cryptojwt.tools import keyconv

from grouprep.utils import load_file


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="Metadata signer")

    parser.add_argument(
        "--key",
        dest="signer",
        metavar="filename",
        help="Signer keys (JWK)",
        required=True,
    )
    parser.add_argument(
        "--cert",
        dest="cert",
        metavar="filename",
        help="Certificate file (PEM format)",
        required=False,
    )
    parser.add_argument(
        "--x5t_S256",
        dest="x5t_S256",
        metavar="thumbprint",
        help="x5t#S256 thumbprint",
        required=False,
    )
    parser.add_argument(
        "--alg",
        dest="alg",
        metavar="algorithm",
        help="Algorithm",
        default="ES256",
        required=False,
    )
    parser.add_argument(
        "--lifetime",
        dest="lifetime",
        metavar="seconds",
        help="Signature lifetime",
        default=86400,
        required=False,
    )
    parser.add_argument(
        "--schema",
        dest="schema",
        metavar="filename",
        help="JSON schema, YAML or JSON",
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
        dest="output",
        metavar="filename",
        help="Metadata output",
        required=False,
    )
    parser.add_argument("--debug", dest="debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.cert:
        with open(args.cert, "rb") as f:
            cert = load_pem_x509_certificate(f.read())
        sha256_hash = cert.fingerprint(hashes.SHA256())
        x5t_S256_cert = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode("utf-8")

        if args.x5t_S256 and x5t_S256_cert != args.x5t_S256:
            sys.exit("Error: The provided x5t_S256 argument does not match the certificate's thumbprint.")
        x5t_S256 = x5t_S256_cert
    else:
        if not args.x5t_S256:
            sys.exit("Error: At least one of --cert or --x5t_S256 must be present.")
        x5t_S256 = args.x5t_S256

    signer_keys = [keyconv.pem2jwk(filename=args.signer, kty="EC", private=True, passphrase="")]

    metadata_dict = load_file(args.input)

    if args.schema:
        schema = load_file(args.schema)
        v = jsonschema.Draft4Validator(schema)
        errors = sorted(v.iter_errors(metadata_dict), key=lambda e: e.path)
        if errors:
            for error in errors:
                print("{} {}".format(error.message, list(error.path)))
        else:
            print("Schema verification passed")
    else:
        print("Skipping schema check")

    protected_headers = {
        "alg": args.alg,
        "x5t#S256": x5t_S256,
    }

    now = int(time.time())
    metadata_dict["iat"] = now
    metadata_dict["exp"] = now + args.lifetime

    message = json.dumps(metadata_dict, sort_keys=True)
    headers = [(protected_headers, {})]
    jws = JWS(msg=message, alg=args.alg)
    signed_metadata = jws.sign_json(keys=signer_keys, headers=headers, flatten=False)

    if args.output:
        with open(args.output, "wt") as output_file:
            print(signed_metadata, file=output_file)
    else:
        print(signed_metadata)


if __name__ == "__main__":
    main()
