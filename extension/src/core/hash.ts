import { hex } from "./b64.ts";
import { md5Hex } from "./md5.ts";

export interface Hashes { sha256: string; sha1: string; md5: string; size: number }

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}
export async function sha1Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-1", bytes as BufferSource)));
}
export async function sha512(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", bytes as BufferSource));
}

/** All three digests a `file` fact carries. */
export async function hashAll(bytes: Uint8Array): Promise<Hashes> {
  const [sha256, sha1] = await Promise.all([sha256Hex(bytes), sha1Hex(bytes)]);
  return { sha256, sha1, md5: md5Hex(bytes), size: bytes.byteLength };
}
