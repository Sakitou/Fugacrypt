# Fugacrypt

Fugacrypt is a Python script for file encryption and decryption using AES256. It provides a simple command-line interface to encrypt and decrypt files securely.

## Features

- AES256 encryption for file security.
- Password-based key derivation using PBKDF2HMAC.
- Random password generation with customizable options.
- Command-line interface for easy usage.

## Usage

Before you begin, run the following command:
```bash
sudo chmod +x fugacrypt.py
```
This command is used to give execution permissions.

### Encryption

To encrypt a file, use the following command:

```bash
./fugacrypt.py -e input_file output_file password
```

- `input_file`: The path to the file you want to encrypt.
- `output_file`: The path where the encrypted file will be saved.
- `password`: The password for encryption.

### Decryption

To decrypt a file, use the following command:

```bash
./fugacrypt.py -d input_file output_file password
```

- `input_file`: The path to the encrypted file.
- `output_file`: The path where the decrypted file will be saved.
- `password`: The password for decryption.

### Key Generation

To generate an AES256 key, use:

```bash
./fugacrypt.py -key
```

### Random Password Generation

To generate a random password, use:

```bash
./fugacrypt.py -pwrd length [options]
```

- `length`: The length of the generated password.
- Options:
  - `-s`: Include special characters.
  - `-nomaj`: Generate a password without uppercase letters.
  - `-nol`: Generate a password without letters.
  - `-nonum`: Generate a password without numbers.

For more details and options, refer to the [Wiki](https://github.com/Sakitou/Fugacrypt/wiki/Password-Generator).

## Wiki

https://github.com/Sakitou/Fugacrypt/wiki

## License

This project is licensed under the GNU License - see the [LICENSE](LICENSE.md) file for details.
