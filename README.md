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
| POST | `/revoke` | the token | Revoke a position by its token; republishes the signed list |
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

#### How allocations stay unique

Each allocated position is one DynamoDB row whose primary key is the pair
(`listId`, `pos#<index>`), written with
`ConditionExpression: attribute_not_exists(sk)`. DynamoDB evaluates the
condition and performs the write as a single atomic operation on the key, so
when two concurrent allocations draw the same random index, exactly one
`PutItem` succeeds and the other fails its condition — there is no window in
which both can claim the position. The loser simply draws a new random index
and tries again. Uniqueness never depends on the randomness: the random draw
is only the specification's privacy recommendation; the conditional write is
the guarantee.

The per-list `allocatedCount` that triggers rotation is maintained with an
atomic `ADD` after each successful conditional put, so it counts exactly the
rows that won their condition. Revocation tokens are `crypto.randomUUID()`
(122 random bits); their uniqueness is probabilistic, which is standard
practice — a collision is on the order of 2⁻¹²².

#### Why a blind random draw, not a draw from the free positions

Drawing from a freshly computed list of still-available positions would not
improve correctness: any such list is a snapshot, stale the instant a
concurrent allocation lands, so the atomic conditional write is still what
guarantees uniqueness. What it would buy is fewer retries — and the price is
reading the list's full allocation state (up to 131,072 rows) from DynamoDB
on every allocate call.

Retries are cheap instead. With random draws over 131,072 slots the expected
number of attempts is `1 / (1 − fill)`: under two attempts below 50% full,
about five at 80%. Collisions only matter in a list's final few percent, and
the retry cap handles exactly that tail: when 10 consecutive draws all
collide (roughly the low-90s percent fill), allocation rotates to a fresh
list. The cost is abandoning a few percent of a list's tail capacity — and
lists are effectively free (one S3 object, some table rows) — while a list
retiring at ~93% full still carries an anonymity set of ~120,000 positions,
so the privacy properties are unaffected.

### `POST /revoke`

```json
{ "revocationToken": "a3c1…-uuid" }
```

Looks the token up, sets the position's bit, rebuilds the bitstring from the
table, signs the `BitstringStatusListCredential`, and republishes it to S3.
Revoking an already-revoked position responds 200 without harm; an unknown
token is 404.

No api key: the revocation token is itself the bearer capability. It
authorizes revoking exactly the one position it was generated for, and only
whoever allocated the position holds it, so clients (e.g. the wallet's batch
issuer) can call `/revoke` directly without sharing the allocation secret.

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
