import { randomUUID, randomInt } from "node:crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { LIST_SIZE } from "./lib/bitstring.mjs";
import { publishList, listUrl } from "./lib/publish.mjs";
import { authorized, json } from "./lib/auth.mjs";

const dynamo = new DynamoDBClient({});
const TABLE_NAME = process.env.TABLE_NAME;

// Random allocation (the specification's privacy recommendation) collides
// only when a list is nearly full; after this many collisions the list is
// treated as exhausted and a new one is started.
const MAX_TRIES = 10;

const posKey = (index) => `pos#${String(index).padStart(6, "0")}`;

async function getItem(listId, sk) {
  const { Item } = await dynamo.send(new GetItemCommand({
    TableName: TABLE_NAME,
    Key: { listId: { S: listId }, sk: { S: sk } },
  }));
  return Item;
}

// Creates a list's meta row and publishes its (empty, signed) credential so
// the list URL resolves before any credential references it. Racing creators
// are harmless: the conditional put loses quietly, and republishing an empty
// list changes nothing.
async function createList(listId) {
  try {
    await dynamo.send(new PutItemCommand({
      TableName: TABLE_NAME,
      Item: {
        listId: { S: listId },
        sk: { S: "meta" },
        allocatedCount: { N: "0" },
        createdAt: { S: new Date().toISOString() },
      },
      ConditionExpression: "attribute_not_exists(sk)",
    }));
  } catch (error) {
    if (error.name !== "ConditionalCheckFailedException") {
      throw error;
    }
  }
  await publishList({ listId, revokedIndexes: [] });
}

// The list currently being allocated from. The pointer row is created with
// list "1" on first use.
async function currentListId() {
  const pointer = await getItem("meta", "current");
  if (pointer?.current?.S) {
    return pointer.current.S;
  }
  try {
    await dynamo.send(new PutItemCommand({
      TableName: TABLE_NAME,
      Item: { listId: { S: "meta" }, sk: { S: "current" }, current: { S: "1" } },
      ConditionExpression: "attribute_not_exists(sk)",
    }));
  } catch (error) {
    if (error.name !== "ConditionalCheckFailedException") {
      throw error;
    }
    return (await getItem("meta", "current")).current.S;
  }
  await createList("1");
  return "1";
}

// Advances the pointer past a full list. The conditional update makes racing
// allocators agree on the successor; the loser just rereads the pointer.
async function startNextList(fromListId) {
  const next = String(Number(fromListId) + 1);
  try {
    await dynamo.send(new UpdateItemCommand({
      TableName: TABLE_NAME,
      Key: { listId: { S: "meta" }, sk: { S: "current" } },
      UpdateExpression: "SET #c = :next",
      ConditionExpression: "#c = :from",
      ExpressionAttributeNames: { "#c": "current" },
      ExpressionAttributeValues: { ":next": { S: next }, ":from": { S: fromListId } },
    }));
  } catch (error) {
    if (error.name !== "ConditionalCheckFailedException") {
      throw error;
    }
    return (await getItem("meta", "current")).current.S;
  }
  await createList(next);
  return next;
}

// POST /allocate -> reserves one status list position: a random index in the
// current list, recorded with a freshly generated revocation token. Responds
// with the credentialStatus object to embed in the credential being issued,
// plus the token the issuer must keep to revoke it later.
export const lambdaHandler = async (event) => {
  if (!authorized(event)) {
    return json(401, { error: "Unauthorized." });
  }

  try {
    let listId = await currentListId();

    for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
      const meta = await getItem(listId, "meta");
      if (Number(meta?.allocatedCount?.N ?? "0") >= LIST_SIZE) {
        listId = await startNextList(listId);
        continue;
      }

      const index = randomInt(LIST_SIZE);
      const token = randomUUID();
      try {
        await dynamo.send(new PutItemCommand({
          TableName: TABLE_NAME,
          Item: {
            listId: { S: listId },
            sk: { S: posKey(index) },
            token: { S: token },
            revoked: { BOOL: false },
            allocatedAt: { S: new Date().toISOString() },
          },
          ConditionExpression: "attribute_not_exists(sk)",
        }));
      } catch (error) {
        if (error.name === "ConditionalCheckFailedException") {
          // Position already taken; near-certain sign the list is filling up
          if (attempt === MAX_TRIES - 2) {
            listId = await startNextList(listId);
          }
          continue;
        }
        throw error;
      }

      await dynamo.send(new UpdateItemCommand({
        TableName: TABLE_NAME,
        Key: { listId: { S: listId }, sk: { S: "meta" } },
        UpdateExpression: "ADD allocatedCount :one",
        ExpressionAttributeValues: { ":one": { N: "1" } },
      }));

      const credentialUrl = listUrl(listId);
      return json(201, {
        credentialStatus: {
          id: `${credentialUrl}#${index}`,
          type: "BitstringStatusListEntry",
          statusPurpose: "revocation",
          statusListIndex: String(index),
          statusListCredential: credentialUrl,
        },
        revocationToken: token,
      });
    }

    return json(503, { error: "Could not allocate a position; try again." });
  } catch (error) {
    console.error("Allocation failed:", error);
    return json(500, { error: "Server error." });
  }
};
