# Padding Oracle Attack Example

This repository demonstrates a **Padding Oracle Attack** against an AES-256-CBC encrypted API.

## Project Structure

- **`vuln/`**: A vulnerable Node.js/Express API that uses `aes-256-cbc` for encryption and decryption.
  - Exposes an `/oracle` endpoint that leaks information about the validity of PKCS7 padding during decryption.
- **`attack/`**: A Go implementation of the Padding Oracle Attack.
  - Automatically recovers the plaintext message from a base64-encoded ciphertext by querying the vulnerable oracle endpoint.
  - Uses a worker pool to speed up the brute-force process.

## How it Works

1.  **Vulnerability**: The `/oracle` endpoint in `vuln/` attempts to decrypt a ciphertext. If decryption fails (which commonly happens when the PKCS7 padding is invalid), it returns a `400 Bad Request` with the error `"bad decrypt"`. If the padding is valid, it returns a `200 OK` (even if the resulting plaintext is garbage).
2.  **Attack**: The Go program in `attack/` takes a ciphertext and iterates through each block. For each byte in a block, it manipulates the corresponding byte in the *previous* block (or IV) and sends it to the oracle.
3.  **Recovery**: By observing which manipulated bytes result in a "valid" padding response from the oracle, the attacker can deduce the "intermediate" state of the block and subsequently recover the original plaintext byte-by-byte.

## Getting Started

### 1. Start the Vulnerable API

The API requires [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/).

```bash
cd vuln
npm install
npm run dev
```

The API will start at `http://localhost:3000`.

### 2. Run the Attack

The attack is written in [Go](https://go.dev/). Ensure the API is running before executing the attack.

```bash
cd attack
go run main.go
```

The attack will:
1.  Request a secret message to be encrypted by the API.
2.  Receive the base64-encoded ciphertext.
3.  Perform the padding oracle attack to recover the original message.
4.  Print the recovered plaintext.

## API Endpoints

- `POST /encrypt`: Takes `{ "text": "..." }` and returns `{ "encrypted": "..." }`.
- `POST /oracle`: Takes `{ "encrypted": "..." }` and returns `{ "decrypted": "valid" }` if padding is correct, or `400` error if not.

## Disclaimer

This project is for **educational purposes only**. It demonstrates a well-known cryptographic vulnerability to help developers understand why they should use a MAC when encrypting with CBC mode.
