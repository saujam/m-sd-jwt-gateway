# M-SD-JWT Gateway

**Merkle-tree-based SD-JWT framework for privacy-preserving SCIM attribute pagination**

Official open-source prototype for the paper:

> *"Optimizing SCIM for Cloud and Decentralized Ecosystems: A Merkle-Tree-Based SD-JWT Framework for Privacy-Preserving Attribute Pagination"*
> Saurabh Kushwaha — Cluster Computing, Springer Nature (under review)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--kushwaha--scim--attr--cursor--pagination--00-green.svg)](https://datatracker.ietf.org/doc/draft-kushwaha-scim-attr-cursor-pagination/)

---

## Overview

Enterprise cloud identity systems manage millions of high-cardinality attributes — roles, entitlements, group memberships — across distributed nodes. The [SCIM 2.0 standard](https://datatracker.ietf.org/doc/html/rfc7644) enables provisioning but its traditional offset-based pagination leaks metadata and provides no cryptographic integrity guarantees. [SD-JWT](https://datatracker.ietf.org/doc/html/rfc9901) provides attribute-level privacy but scales poorly for large attribute sets because disclosure size grows linearly.

**M-SD-JWT** solves both problems by combining:
- **SCIM cursor-based pagination** for scalable attribute access
- **Merkle tree proofs** for cryptographic integrity of paginated responses
- **SD-JWT signing** for verifiable selective disclosure

Each paginated response delivers only the requested page of attributes together with a compact Merkle authentication path and a signed root — achieving selective disclosure while preserving integrity even when the verifier never sees the full attribute set.

### Key Results

| Dataset Size | Standard SCIM | Flat SD-JWT | M-SD-JWT | Reduction |
|---|---|---|---|---|
| 1,000 attributes | 118 KB | 82 KB | 17 KB | **85%** |
| 10,000 attributes | 1,210 KB | 920 KB | 38 KB | **97%** |
| 100,000 attributes | 12,300 KB | 8,650 KB | 74 KB | **99%** |

Verification complexity: **O(log N)** — independent of total attribute set size.

---

## Architecture

```
Identity Provider          SCIM-DI Gateway              Holder / Verifier
(SCIM Source)          (Cursor Translation +          (Proof Validation +
                        Disclosure Packaging)          Root Reconstruction)

SCIM resources  ──────►  M-SD-JWT + cursor  ──────►  Verify against
                         Merkle root + proofs          signed root
```

### Components

- **SCIM-DI Gateway** — translates SCIM requests into cursor-addressable selective disclosures backed by Merkle proofs
- **Merkle Tree Engine** — builds and proves the tree using SHA-256 leaf hashing (Go implementation)
- **JWT Issuer** — signs the Merkle root using HS256 (HMAC-SHA256)

---

## Quick Start

### Prerequisites

- [Docker](https://www.docker.com/get-started) installed

### Run with Docker

```bash
# Clone the repository
git clone https://github.com/saujam/m-sd-jwt-gateway.git
cd m-sd-jwt-gateway

# Build the image
docker build -t m-sd-jwt-gateway .

# Run the gateway
docker run -p 8080:8080 -e JWT_SECRET=your-secret-key m-sd-jwt-gateway
```

You should see:
```
🚀 M-SD-JWT SCIM-DI Gateway running on http://localhost:8080
```

### Run with Go (requires Go 1.23+)

```bash
git clone https://github.com/saujam/m-sd-jwt-gateway.git
cd m-sd-jwt-gateway
go mod tidy
go run main.go
```

---

## API Reference

### Base URL
```
http://localhost:8080
```

---

### `GET /health`

Liveness probe — returns server status.

**Request:**
```bash
curl http://localhost:8080/health
```

**Response:**
```json
{"status": "ok"}
```

---

### `GET /scim/Users`

Returns a paginated, Merkle-authenticated page of SCIM attributes with a signed JWT root.

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cursor` | string | — | Base64-encoded start index for pagination |
| `count` | integer | 10 | Number of attributes per page (max 1000) |

**Request — First page:**
```bash
curl http://localhost:8080/scim/Users
```

**Response:**
```json
{
  "merkle_root": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "attributes": [
    "role:admin",
    "role:user",
    "group:engineering",
    "group:finance",
    "entitlement:cloud-storage",
    "entitlement:email",
    "entitlement:vpn",
    "entitlement:ci-cd",
    "entitlement:monitoring",
    "entitlement:billing"
  ],
  "proof": [
    {"hash": "a3f2...9c1d", "position": "right"},
    {"hash": "b7e1...4a2f", "position": "left"}
  ],
  "start_index": 0,
  "page_size": 10,
  "total_attributes": 12,
  "next_cursor": "MTA="
}
```

**Request — Next page using cursor:**
```bash
curl "http://localhost:8080/scim/Users?cursor=MTA="
```

**Request — Custom page size:**
```bash
curl "http://localhost:8080/scim/Users?count=3"
```

**Response fields:**

| Field | Type | Description |
|---|---|---|
| `merkle_root` | string | HS256-signed JWT containing the Merkle root hash, tree depth, and expiry |
| `attributes` | array | Requested page of SCIM attribute strings |
| `proof` | array | Merkle authentication path — sibling hashes to reconstruct the root |
| `start_index` | integer | Zero-based index of the first attribute in this page |
| `page_size` | integer | Number of attributes returned in this page |
| `total_attributes` | integer | Total number of attributes in the full set |
| `next_cursor` | string \| null | Base64 cursor for the next page; `null` on the last page |

---

### Cursor Pagination Flow

```
GET /scim/Users                    ← no cursor = first page
  → returns next_cursor: "MTA="

GET /scim/Users?cursor=MTA=        ← second page
  → returns next_cursor: null      ← last page reached
```

The cursor is the base64 encoding of the integer start index:
```bash
# Decode a cursor
echo "MTA=" | base64 --decode    # → 10
```

---

### JWT Payload Structure

The `merkle_root` field is a signed JWT. Decoded payload:

```json
{
  "iss": "https://idp.example.com",
  "sub": "user123",
  "merkle_root": "f3a9...2c1d",
  "tree_depth": 4,
  "total_attrs": 12,
  "iat": 1744480000,
  "exp": 1744566400
}
```

Verifiers reconstruct the Merkle root from the proof path and disclosed attributes, then compare against the signed `merkle_root` claim to verify integrity without seeing the full attribute set.

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `change-me-in-production` | HMAC secret for signing JWT tokens |

```bash
# Set a secure secret
docker run -p 8080:8080 \
  -e JWT_SECRET=your-256-bit-secret \
  m-sd-jwt-gateway
```

> ⚠️ **Warning:** Always set `JWT_SECRET` in production. A warning is logged if the default is used.

---

## Project Structure

```
m-sd-jwt-gateway/
├── main.go              # HTTP server, SCIM handler, pagination logic
├── merkle/
│   └── merkle.go        # Merkle tree construction and proof generation
├── k8s/                 # Kubernetes deployment manifests
├── Dockerfile           # Multi-stage Docker build
├── docker-compose.yml   # Local development compose file
├── go.mod               # Go module definition
└── README.md
```

---

## Deploying on Kubernetes

```bash
# Apply the Kubernetes manifests
kubectl apply -f k8s/

# Verify deployment
kubectl get pods
kubectl get service m-sd-jwt-gateway
```

---

## Security Notes

- **Proof verification:** Clients should verify the Merkle proof independently by reconstructing the root from `attributes` + `proof` and comparing against the JWT `merkle_root` claim
- **JWT validation:** Verify the JWT signature using the shared secret before trusting the `merkle_root` claim
- **Production secrets:** Use a secrets manager (Vault, AWS Secrets Manager, Kubernetes Secrets) to inject `JWT_SECRET` — never hardcode it
- **BLAKE3 upgrade:** The paper evaluates BLAKE3 for internal nodes (faster than SHA-256 on modern CPUs) — this prototype uses SHA-256 for portability

---

## Related Work

- **IETF Internet-Draft:** [draft-kushwaha-scim-attr-cursor-pagination-00](https://datatracker.ietf.org/doc/draft-kushwaha-scim-attr-cursor-pagination/) — the formal protocol specification this implementation demonstrates
- **SCIM RFC 7643/7644:** [Core Schema](https://datatracker.ietf.org/doc/html/rfc7643) / [Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- **SD-JWT RFC 9901:** [Selective Disclosure for JWTs](https://datatracker.ietf.org/doc/html/rfc9901)
- **W3C DID v1.0:** [Decentralized Identifiers](https://www.w3.org/TR/did-core/)

---

## Citation

If you use this work in your research, please cite:

```bibtex
@article{kushwaha2026msd,
  title   = {Optimizing SCIM for Cloud and Decentralized Ecosystems:
             A Merkle-Tree-Based SD-JWT Framework for
             Privacy-Preserving Attribute Pagination},
  author  = {Kushwaha, Saurabh},
  journal = {Cluster Computing},
  year    = {2026},
  note    = {Under review, Springer Nature}
}
```

---

## License

This project is released under the [Apache 2.0 License](LICENSE).

---

## Author

**Saurabh Kushwaha**
Principal Engineer, Oracle Cloud Infrastructure
IEEE Senior Member | ORCID: [0009-0004-0651-814X](https://orcid.org/0009-0004-0651-814X)

*The views expressed in this repository are those of the author and do not represent Oracle Corporation's positions, products, or services.*
