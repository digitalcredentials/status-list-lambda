import {
  DynamoDBClient,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { publishList, listUrl } from "./lib/publish.mjs";
import { authorized, parseBody, json } from "./lib/auth.mjs";

const dynamo = new DynamoDBClient({});
const TABLE_NAME = process.env.TABLE_NAME;

// The position the token was issued for, via the by-token index.
async function findPosition(token) {
  const { Items = [] } = await dynamo.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: "by-token",
    KeyConditionExpression: "#t = :token",
    ExpressionAttributeNames: { "#t": "token" },
    ExpressionAttributeValues: { ":token": { S: token } },
  }));
  return Items[0];
}

// Every revoked index in the list, read strongly from the base table so the
// rebuilt bitstring includes the write that just happened.
async function revokedIndexes(listId) {
  const indexes = [];
  let ExclusiveStartKey;
  do {
    const page = await dynamo.send(new QueryCommand({
      TableName: TABLE_NAME,
      ConsistentRead: true,
      KeyConditionExpression: "listId = :list AND begins_with(sk, :pos)",
      FilterExpression: "revoked = :true",
      ExpressionAttributeValues: {
        ":list": { S: listId },
        ":pos": { S: "pos#" },
        ":true": { BOOL: true },
      },
      ExclusiveStartKey,
    }));
    for (const item of page.Items ?? []) {
      indexes.push(Number(item.sk.S.slice(4)));
    }
    ExclusiveStartKey = page.LastEvaluatedKey;
  } while (ExclusiveStartKey);
  return indexes;
}

// POST /revoke {revocationToken} -> flips the position's bit and republishes
// the signed status list credential. Revoking an already-revoked position is
// a no-op that still responds 200.
export const lambdaHandler = async (event) => {
  if (!authorized(event)) {
    return json(401, { error: "Unauthorized." });
  }

  let token;
  try {
    ({ revocationToken: token } = parseBody(event));
  } catch {
    return json(400, { error: "Request body must be JSON." });
  }
  if (!token || typeof token !== "string") {
    return json(400, { error: "Missing revocationToken." });
  }

  try {
    const position = await findPosition(token);
    if (!position) {
      return json(404, { error: "Unknown revocation token." });
    }
    const listId = position.listId.S;
    const index = Number(position.sk.S.slice(4));

    await dynamo.send(new UpdateItemCommand({
      TableName: TABLE_NAME,
      Key: { listId: { S: listId }, sk: { S: position.sk.S } },
      UpdateExpression: "SET revoked = :true, revokedAt = :now",
      ExpressionAttributeValues: {
        ":true": { BOOL: true },
        ":now": { S: new Date().toISOString() },
      },
    }));

    await publishList({ listId, revokedIndexes: await revokedIndexes(listId) });

    return json(200, {
      revoked: true,
      statusListCredential: listUrl(listId),
      statusListIndex: String(index),
    });
  } catch (error) {
    console.error("Revocation failed:", error);
    return json(500, { error: "Server error." });
  }
};
