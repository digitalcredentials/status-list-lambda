import { gzipSync, gunzipSync } from "node:zlib";

// The default status list size from the Bitstring Status List specification:
// 131,072 single-bit entries (a 16KB bitstring), the minimum that gives
// adequate group privacy.
export const LIST_SIZE = 131072;

// Builds the encodedList value: a bitstring with the given indexes set,
// GZIP-compressed, multibase-base64url-encoded with no padding (the "u"
// prefix). Index 0 is the left-most bit of the bitstring, i.e. the most
// significant bit of the first byte.
export function encodeList(setIndexes, size = LIST_SIZE) {
  const bytes = new Uint8Array(size / 8);
  for (const index of setIndexes) {
    if (!Number.isInteger(index) || index < 0 || index >= size) {
      throw new Error(`Index out of range: ${index}`);
    }
    bytes[index >> 3] |= 0x80 >> (index & 7);
  }
  return "u" + Buffer.from(gzipSync(bytes)).toString("base64url");
}

// The inverse, for tests and debugging: the uncompressed bitstring bytes.
export function decodeList(encodedList) {
  if (typeof encodedList !== "string" || !encodedList.startsWith("u")) {
    throw new Error("encodedList must be multibase base64url (u-prefixed)");
  }
  return new Uint8Array(gunzipSync(Buffer.from(encodedList.slice(1), "base64url")));
}

export function bitAt(bytes, index) {
  return (bytes[index >> 3] >> (7 - (index & 7))) & 1;
}
