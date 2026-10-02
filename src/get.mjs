import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { listKey } from "./lib/publish.mjs";
import { json } from "./lib/auth.mjs";

const s3 = new S3Client({});

// GET /{list_id} -> the published, signed BitstringStatusListCredential, as
// referenced by every issued credentialStatus.statusListCredential. Served
// with a short cache so revocations propagate quickly.
export const lambdaHandler = async (event) => {
  const listId = event.pathParameters?.list_id;
  if (!/^\d+$/.test(listId ?? "")) {
    return json(404, { error: "Not found." });
  }

  try {
    const { Body } = await s3.send(new GetObjectCommand({
      Bucket: process.env.BUCKET_NAME,
      Key: listKey(listId),
    }));
    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=60",
      },
      body: await Body.transformToString(),
    };
  } catch (error) {
    if (error.name === "NoSuchKey" || error.name === "NoSuchBucket") {
      return json(404, { error: "Not found." });
    }
    console.error("Status list GET failed:", error);
    return json(500, { error: "Server error." });
  }
};
