import * as vc from "@digitalbazaar/vc";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { securityLoader } from "@digitalcredentials/security-document-loader";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { encodeList } from "./bitstring.mjs";

const documentLoader = securityLoader().build();
const s3 = new S3Client({});

export const statusBaseUrl = () =>
  (process.env.STATUS_BASE_URL ?? "https://status.lcw-sandbox.org").replace(/\/+$/, "");

export const listUrl = (listId) => `${statusBaseUrl()}/${listId}`;

export const listKey = (listId) => `lists/${listId}.json`;

let cachedSuite;

// The signing suite, derived once per container from ISSUER_SEED (the same
// seed-to-did:key scheme the LCW sandbox issuer uses).
async function issuerSuite() {
  if (!cachedSuite) {
    const seed = process.env.ISSUER_SEED;
    if (!/^[0-9a-f]{64}$/i.test(seed ?? "")) {
      throw new Error("ISSUER_SEED must be 64 hex characters");
    }
    const key = await Ed25519VerificationKey2020.generate({
      seed: new Uint8Array(Buffer.from(seed, "hex")),
    });
    const did = `did:key:${key.fingerprint()}`;
    key.controller = did;
    key.id = `${did}#${key.fingerprint()}`;
    cachedSuite = { suite: new Ed25519Signature2020({ key }), did };
  }
  return cachedSuite;
}

// Builds, signs, and publishes the BitstringStatusListCredential for one
// list: the bits at revokedIndexes are set, everything else is 0. The signed
// credential lands in the bucket at the key the GET endpoint serves.
export async function publishList({ listId, revokedIndexes }) {
  const { suite, did } = await issuerSuite();
  const url = listUrl(listId);
  const credential = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: url,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: did,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: `${url}#list`,
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList: encodeList(revokedIndexes),
    },
  };
  const signed = await vc.issue({ credential, suite, documentLoader });
  await s3.send(new PutObjectCommand({
    Bucket: process.env.BUCKET_NAME,
    Key: listKey(listId),
    ContentType: "application/json",
    Body: JSON.stringify(signed),
  }));
  return signed;
}
