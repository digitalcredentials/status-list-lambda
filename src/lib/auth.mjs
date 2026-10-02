// The write endpoints (/allocate, /revoke) are gated by a shared secret in
// the x-api-key header, configured as the stack's ApiKey parameter. Reading a
// published list needs no key.
export function authorized(event) {
  const provided = Object.entries(event.headers ?? {}).find(
    ([name]) => name.toLowerCase() === "x-api-key"
  )?.[1];
  return Boolean(process.env.API_KEY) && provided === process.env.API_KEY;
}

export function parseBody(event) {
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body ?? "", "base64").toString("utf8")
    : event.body ?? "";
  return raw.trim() === "" ? {} : JSON.parse(raw);
}

export const json = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});
