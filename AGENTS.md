# asn1parse

A lightweight CLI that decodes DER-encoded ASN.1 (e.g. X.509 certificates) and prints the
structure as an indented tree, similar to `openssl asn1parse`. Early stage: single `main.go`,
no tests yet.

Language-wide conventions: ../AGENTS.md. Rules in this file take precedence.

## Commands
- Format: `gofmt -w .`
- Lint: `go vet ./...` (`golangci-lint run` if installed; not installed yet)
- Build: `go build ./...`
- Test: `go test ./...`
- Run: `go run . [-inform DER|PEM] [-offsets] [file]` (reads stdin if file is omitted or `-`; e.g. `go run . -inform PEM testdata/google-com.pem`)

## Structure
- `main.go` – everything: OID name table, tag names, recursive parser, CLI.
- `testdata/` – sample inputs (`google-com.der`, `google-com.pem`).

## Conventions
TODO: project-specific rules (only what differs from the language defaults).

## Notes
- No CI configured.
- Parsing uses `encoding/asn1`, which accepts DER only (no BER).
