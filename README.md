# status-list-lambda

A [Bitstring Status List](https://w3c.github.io/vc-bitstring-status-list/)
service for the LCW sandbox: issuers allocate status positions for the
credentials they issue, revoke them later by token, and verifiers fetch the
published, signed `BitstringStatusListCredential` per list.

Served at `https://status.lcw-sandbox.org`.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/allocate` | `x-api-key` | Reserve a status position; returns the `credentialStatus` object and a revocation token |
| POST | `/revoke` | `x-api-key` | Revoke a position by its token; republishes the signed list |
| GET | `/{listID}` | none | The published, signed `BitstringStatusListCredential` |

### `POST /allocate`

Reserves one position: a **randomly chosen index** (the specification's
privacy recommendation) in the current list. Each list holds the
specification's default **131,072 entries**; when a list fills up, the next
one starts automatically (list ids are `1`, `2`, …) and its empty, signed
credential is published immediately so its URL always resolves.

Response:

```json
{
  "credentialStatus": {
    "id": "https://status.lcw-sandbox.org/1#94567",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://status.lcw-sandbox.org/1"
  },
  "revocationToken": "a3c1…-uuid"
}
```

Embed `credentialStatus` in the credential being issued, and **store the
`revocationToken`** — it is the only way to revoke the position later.

### `POST /revoke`

```json
{ "revocationToken": "a3c1…-uuid" }
```

Looks the token up, sets the position's bit, rebuilds the bitstring from the
table, signs the `BitstringStatusListCredential`, and republishes it to S3.
Revoking an already-revoked position responds 200 without harm; an unknown
token is 404.

### `GET /{listID}`

The signed status list credential, `Content-Type: application/json`, cached
for 60 seconds. The `encodedList` is the GZIP-compressed 16KB bitstring,
multibase-base64url encoded (`u` prefix); index 0 is the left-most bit.

## Storage

- **S3** (`dcc-status-lists`): the published signed credential per list, at
  `lists/{listID}.json`.
- **DynamoDB** (`status-list-positions`, PK `listId`, SK `sk`):
  - `pos#<index>` rows — one per allocated position: its `token`, `revoked`
    flag, and timestamps. A GSI (`by-token`) serves the revoke lookup.
  - `meta` row per list — the `allocatedCount` that triggers rotation.
  - `meta`/`current` row — the list currently being allocated from.

## Signing

Lists are signed Ed25519Signature2020, with the key derived from the
`IssuerSeed` stack parameter (64 hex characters; seed → `did:key`, the same
scheme as the sandbox issuer).

## Deploying

```sh
sam build
sam deploy --stack-name status-list --resolve-s3 --capabilities CAPABILITY_IAM \
  --parameter-overrides IssuerSeed=<64 hex> ApiKey=<shared secret>
```

The template owns the custom domain (`status.lcw-sandbox.org`): the API
Gateway domain, its mapping, and the Route 53 record, using the existing
`*.lcw-sandbox.org` certificate.

## Tests

```sh
cd src && npm install && npm test
```

DynamoDB and S3 are stubbed in-process; signing runs for real against a test
seed, and the published bitstrings are decoded and checked bit by bit.
