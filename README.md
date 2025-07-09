# Distributed Read-Only Filesystem over P2P

This project implements a lightweight, distributed, read-only filesystem using a custom peer-to-peer protocol with cryptographic guarantees. Peers expose their local filesystem trees to other peers while ensuring data integrity using Merkle trees and signed messages.

Key characteristics:

- Peer discovery and key distribution handled via a central REST server
- Data transfer over UDP between peers
- End-to-end data authenticity via SHA-256 and ECDSA signatures
- Basic NAT traversal mechanism
- Filesystem represented as a Merkle tree with support for chunking and directories

The project was developed as part of an advanced networking course. The focus was on protocol design, security, and efficient data transfer in a decentralized environment.

---

## Requirements
- Go 1.24

## Build
From the directory containing `go.mod`, run:
```
go build -o main src/main/main.go
```

## Additional Info
- Files to be shared should be placed in the `root/` directory, located at the same level as the executable. A sample file is included.
- Downloaded files will be saved in the `Download/` directory, also at the same level as the executable. Files will be grouped by the nickname of the peer they were fetched from.

## Running the Program
The resulting binary accepts the following options:

- `--nickname` – the nickname used to register
- `--log-to-file` – binary flag; when set, logs will be written to `app.log`
- `--log-level` – sets the minimum log level to be displayed

It is recommended to use `--log-to-file` or redirect `stderr` to avoid cluttering the terminal UI.

Example:
```
./main --log-level="INFO" --nickname="YoungG" 2>/dev/pts/2
```

> INFO: server address is provided in `main.go` as we used it during
development and project presentation. This is also the only instance of the server
that we know of. 

# Addtional info
In `Raport.pdf` you can find project report written in polish.
