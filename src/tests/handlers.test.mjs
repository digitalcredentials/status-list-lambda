// In-process tests for the three handlers: DynamoDB and S3 sends are stubbed
// per test; signing runs for real against the test seed.
//
//   cd src && npm test

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

process.env.TABLE_NAME = "status-list-positions";
process.env.BUCKET_NAME = "dcc-status-lists";
process.env.STATUS_BASE_URL = "https://status.example.org";
process.env.ISSUER_SEED = "ab".repeat(32);
process.env.API_KEY = "test-key";

const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand } =
  await import("@aws-sdk/client-dynamodb");
const { S3Client, PutObjectCommand, GetObjectCommand } = await import("@aws-sdk/client-s3");
const { encodeList, decodeList, bitAt, LIST_SIZE } = await import("../lib/bitstring.mjs");
const { lambdaHandler: allocate } = await import("../allocate.mjs");
const { lambdaHandler: revoke } = await import("../revoke.mjs");
const { lambdaHandler: getList } = await import("../get.mjs");

let onDynamo, onS3;
beforeEach(() => {
  onDynamo = (command) => {
    throw new Error(`unexpected DynamoDB call: ${command.constructor.name}`);
  };
  onS3 = (command) => {
    throw new Error(`unexpected S3 call: ${command.constructor.name}`);
  };
});
DynamoDBClient.prototype.send = async (command) => onDynamo(command);
S3Client.prototype.send = async (command) => onS3(command);

const event = ({ body, headers = { "x-api-key": "test-key" }, pathParameters } = {}) => ({
  headers,
  body: body === undefined ? null : JSON.stringify(body),
  isBase64Encoded: false,
  pathParameters,
});

// --- bitstring

test("encodeList: index 0 is the left-most bit; roundtrip restores the bits", () => {
  const bytes = decodeList(encodeList([0, 7, 8, 42, LIST_SIZE - 1]));
  assert.equal(bytes.length, LIST_SIZE / 8);
  assert.equal(bytes[0], 0b10000001); // bits 0 and 7
  assert.equal(bitAt(bytes, 8), 1);
  assert.equal(bitAt(bytes, 42), 1);
  assert.equal(bitAt(bytes, LIST_SIZE - 1), 1);
  assert.equal(bitAt(bytes, 1), 0);
  assert.equal(bitAt(bytes, 43), 0);
});

test("encodeList: rejects an out-of-range index", () => {
  assert.throws(() => encodeList([LIST_SIZE]));
});

// --- /allocate

test("allocate: 401 without the api key", async () => {
  const res = await allocate(event({ headers: {} }));
  assert.equal(res.statusCode, 401);
});

test("allocate: reserves a position in the current list", async () => {
  let storedPosition;
  onDynamo = (command) => {
    if (command instanceof GetItemCommand) {
      const { sk } = command.input.Key;
      if (sk.S === "current") return { Item: { current: { S: "3" } } };
      return { Item: { allocatedCount: { N: "12" } } };
    }
    if (command instanceof PutItemCommand) {
      storedPosition = command.input.Item;
      return {};
    }
    if (command instanceof UpdateItemCommand) {
      assert.equal(command.input.Key.sk.S, "meta");
      return {};
    }
    throw new Error(`unexpected: ${command.constructor.name}`);
  };

  const res = await allocate(event());
  assert.equal(res.statusCode, 201);
  const { credentialStatus, revocationToken } = JSON.parse(res.body);
  assert.equal(credentialStatus.type, "BitstringStatusListEntry");
  assert.equal(credentialStatus.statusPurpose, "revocation");
  assert.equal(credentialStatus.statusListCredential, "https://status.example.org/3");
  const index = Number(credentialStatus.statusListIndex);
  assert.ok(index >= 0 && index < LIST_SIZE);
  assert.equal(credentialStatus.id, `https://status.example.org/3#${index}`);
  assert.equal(storedPosition.sk.S, `pos#${String(index).padStart(6, "0")}`);
  assert.equal(storedPosition.token.S, revocationToken);
  assert.match(revocationToken, /^[0-9a-f-]{36}$/);
});

test("allocate: first use creates list 1 and publishes its empty credential", async () => {
  let published;
  let listMetaCreated = false;
  onS3 = (command) => {
    assert.ok(command instanceof PutObjectCommand);
    published = JSON.parse(command.input.Body);
    return {};
  };
  onDynamo = (command) => {
    if (command instanceof GetItemCommand) {
      const { listId, sk } = command.input.Key;
      if (sk.S === "current") return {};
      // the list meta row just created
      assert.equal(listId.S, "1");
      return { Item: { allocatedCount: { N: "0" } } };
    }
    if (command instanceof PutItemCommand) {
      if (command.input.Item.sk.S === "meta") listMetaCreated = true;
      return {};
    }
    if (command instanceof UpdateItemCommand) return {};
    throw new Error(`unexpected: ${command.constructor.name}`);
  };

  const res = await allocate(event());
  assert.equal(res.statusCode, 201);
  assert.ok(listMetaCreated);
  const { credentialStatus } = JSON.parse(res.body);
  assert.equal(credentialStatus.statusListCredential, "https://status.example.org/1");

  // The published credential: signed, spec-shaped, all bits zero
  assert.equal(published.id, "https://status.example.org/1");
  assert.ok(published.type.includes("BitstringStatusListCredential"));
  assert.equal(published.credentialSubject.type, "BitstringStatusList");
  assert.equal(published.credentialSubject.statusPurpose, "revocation");
  assert.equal(published.proof.type, "Ed25519Signature2020");
  const bytes = decodeList(published.credentialSubject.encodedList);
  assert.ok(bytes.every((b) => b === 0));
});

test("allocate: a full list rotates to the next one", async () => {
  let pointerMovedTo;
  let publishedListId;
  onS3 = (command) => {
    publishedListId = JSON.parse(command.input.Body).id.split("/").pop();
    return {};
  };
  onDynamo = (command) => {
    if (command instanceof GetItemCommand) {
      const { listId, sk } = command.input.Key;
      if (sk.S === "current") return { Item: { current: { S: pointerMovedTo ?? "1" } } };
      return {
        Item: { allocatedCount: { N: listId.S === "1" ? String(LIST_SIZE) : "0" } },
      };
    }
    if (command instanceof UpdateItemCommand) {
      if (command.input.Key.sk.S === "current") {
        pointerMovedTo = command.input.ExpressionAttributeValues[":next"].S;
      }
      return {};
    }
    if (command instanceof PutItemCommand) return {};
    throw new Error(`unexpected: ${command.constructor.name}`);
  };

  const res = await allocate(event());
  assert.equal(res.statusCode, 201);
  assert.equal(pointerMovedTo, "2");
  assert.equal(publishedListId, "2");
  const { credentialStatus } = JSON.parse(res.body);
  assert.equal(credentialStatus.statusListCredential, "https://status.example.org/2");
});

// --- /revoke

test("revoke: 400 without a token, 404 for an unknown one", async () => {
  // No api key on /revoke: the token itself is the bearer capability
  assert.equal((await revoke(event({ headers: {}, body: {} }))).statusCode, 400);
  onDynamo = (command) => {
    assert.ok(command instanceof QueryCommand);
    return { Items: [] };
  };
  assert.equal(
    (await revoke(event({ body: { revocationToken: "nope" } }))).statusCode,
    404
  );
});

test("revoke: sets the bit and republishes the signed list", async () => {
  let published;
  onS3 = (command) => {
    assert.ok(command instanceof PutObjectCommand);
    assert.equal(command.input.Key, "lists/3.json");
    published = JSON.parse(command.input.Body);
    return {};
  };
  let marked = false;
  onDynamo = (command) => {
    if (command instanceof QueryCommand) {
      if (command.input.IndexName === "by-token") {
        return {
          Items: [
            { listId: { S: "3" }, sk: { S: "pos#000042" }, token: { S: "tok" } },
          ],
        };
      }
      // the rebuild query: every revoked position in list 3
      return {
        Items: [
          { sk: { S: "pos#000042" }, revoked: { BOOL: true } },
          { sk: { S: "pos#000007" }, revoked: { BOOL: true } },
        ],
      };
    }
    if (command instanceof UpdateItemCommand) {
      assert.equal(command.input.Key.sk.S, "pos#000042");
      marked = true;
      return {};
    }
    throw new Error(`unexpected: ${command.constructor.name}`);
  };

  const res = await revoke(event({ headers: {}, body: { revocationToken: "tok" } }));
  assert.equal(res.statusCode, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.revoked, true);
  assert.equal(body.statusListIndex, "42");
  assert.equal(body.statusListCredential, "https://status.example.org/3");
  assert.ok(marked);

  assert.equal(published.proof.type, "Ed25519Signature2020");
  const bytes = decodeList(published.credentialSubject.encodedList);
  assert.equal(bitAt(bytes, 42), 1);
  assert.equal(bitAt(bytes, 7), 1);
  assert.equal(bitAt(bytes, 0), 0);
});

// --- GET /{list_id}

test("get: serves the published credential", async () => {
  onS3 = (command) => {
    assert.ok(command instanceof GetObjectCommand);
    assert.equal(command.input.Key, "lists/5.json");
    return { Body: { transformToString: async () => '{"id":"list-5"}' } };
  };
  const res = await getList(event({ headers: {}, pathParameters: { list_id: "5" } }));
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers["Content-Type"], "application/json");
  assert.equal(JSON.parse(res.body).id, "list-5");
});

test("get: 404 for a missing list or a non-numeric id", async () => {
  onS3 = () => {
    const err = new Error("NoSuchKey");
    err.name = "NoSuchKey";
    throw err;
  };
  assert.equal(
    (await getList(event({ headers: {}, pathParameters: { list_id: "9" } }))).statusCode,
    404
  );
  assert.equal(
    (await getList(event({ headers: {}, pathParameters: { list_id: "../x" } }))).statusCode,
    404
  );
});
