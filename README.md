# GRSign and GRVerify

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Description

This example code demonstrates command-line tools that enable you to sign and verify JSON metadata using private keys and certificates. 

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Installation

To install the program, follow these steps:

1. Clone the repository and change to the project directory:
```shell
git clone https://github.com/s-hal/grouprep.git
cd grouprep
```

2. Install the dependencies using Poetry:
```shell
poetry install
```

3. Create sample keys
```shell
openssl ecparam -genkey -name prime256v1 -noout -out sample_data/ec-private-key.pem
openssl req -new -x509 -key ec-private-key.pem -out sample_data/ec-cert.pem -outform pem -days 5000 -subj '/CN=my-org-metadata'
```

## Usage

The programs is executed from the command line using the following syntax:

```shell
grsign [OPTIONS]
grverify [OPTIONS]
```

### Options for grsign

| Option        | Description                                |
|---------------|--------------------------------------------|
| `-h, --help`  | Show help message and exit.                |
| `--key`       | Private key file (PEM format).             |
| `--cert`      | Certificate file (PEM format).             |
| `--x5t_S256`  | Certificate fingerprint (x5t#S256 format). |
| `--alg`       | Signature algorithm.                       |
| `--lifetime`  | Signature lifetime (seconds).              |
| `--schema`    | JSON schema file (YAML or JSON).           |
| `--input`     | Metadata file to be signed.                |
| `--output`    | Signed metadata output file.               |
| `--debug`     | Enable debugging.                          |

### Options for grverify

| Option        | Description                      |
|---------------|----------------------------------|
| `-h, --help`  | Show help message and exit.      |
| `--cert`      | Certificate file (PEM format).   |
| `--schema`    | JSON schema file (YAML or JSON). |
| `--input`     | Metadata file to be signed.      |
| `--output`    | Signed metadata output file.     |
| `--headers`   | Headers output file.             |
| `--debug`     | Enable debugging.                |

### Example Usage Sign

To run grsign, use the following command:

```shell
grsign --key sample_data/ec-private-key.pem --cert sample_data/ec-cert.pem --schema sample_data/schema.yaml --input sample_data/md.json
```

### Example Usage Verify

To run grveryfi, use the following command:

```shell
grverify --cert sample_data/ec-cert.pem --schema sample_data/schema.yaml --input sample_data/signed-md.jws
```

## License

This program is licensed under the [Apache License 2.0](LICENSE). You can find the full license text in the [LICENSE](LICENSE) file.

## Contact

For any questions or inquiries about the program, feel free to reach out to us at info@sambi.se.
