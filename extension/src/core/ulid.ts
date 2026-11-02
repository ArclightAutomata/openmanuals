// ULID: 48-bit ms timestamp + 80 random bits, Crockford base32, 26 chars, uppercase.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(now: number = Date.now()): string {
  let time = "";
  let t = now;
  for (let i = 0; i < 10; i++) { time = ALPHABET[t % 32] + time; t = Math.floor(t / 32); }
  const rnd = new Uint8Array(10);
  crypto.getRandomValues(rnd);
  // 80 bits → 16 base32 chars
  let bits = 0, value = 0, out = "";
  for (const b of rnd) {
    value = ((value << 8) | b) >>> 0; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return time + out;
}

export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
