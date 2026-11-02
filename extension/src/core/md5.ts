// MD5 (RFC 1321). WebCrypto has no MD5, and archive.org reports md5 per file,
// so the file facts carry it. Small, straightforward implementation.

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

export class Md5 {
  private a = 0x67452301;
  private b = 0xefcdab89;
  private c = 0x98badcfe;
  private d = 0x10325476;
  private buf = new Uint8Array(64);
  private bufLen = 0;
  private total = 0;
  private words = new Uint32Array(16);

  update(data: Uint8Array): this {
    this.total += data.length;
    let off = 0;
    if (this.bufLen) {
      const take = Math.min(64 - this.bufLen, data.length);
      this.buf.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      off = take;
      if (this.bufLen === 64) { this.block(this.buf, 0); this.bufLen = 0; }
    }
    for (; off + 64 <= data.length; off += 64) this.block(data, off);
    if (off < data.length) { this.buf.set(data.subarray(off)); this.bufLen = data.length - off; }
    return this;
  }

  private block(p: Uint8Array, off: number): void {
    const w = this.words;
    for (let i = 0; i < 16; i++) w[i] = p[off + i * 4] | (p[off + i * 4 + 1] << 8) | (p[off + i * 4 + 2] << 16) | (p[off + i * 4 + 3] << 24);
    let a = this.a, b = this.b, c = this.c, d = this.d;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const t = d; d = c; c = b;
      const x = (a + f + K[i] + w[g]) >>> 0;
      b = (b + ((x << S[i]) | (x >>> (32 - S[i])))) >>> 0;
      a = t;
    }
    this.a = (this.a + a) >>> 0; this.b = (this.b + b) >>> 0; this.c = (this.c + c) >>> 0; this.d = (this.d + d) >>> 0;
  }

  digestHex(): string {
    const bitLen = this.total * 8;
    const pad = new Uint8Array(((this.bufLen < 56 ? 56 : 120) - this.bufLen) + 8);
    pad[0] = 0x80;
    const lo = bitLen >>> 0, hi = Math.floor(bitLen / 2 ** 32) >>> 0;
    const n = pad.length - 8;
    pad[n] = lo & 255; pad[n + 1] = (lo >>> 8) & 255; pad[n + 2] = (lo >>> 16) & 255; pad[n + 3] = (lo >>> 24) & 255;
    pad[n + 4] = hi & 255; pad[n + 5] = (hi >>> 8) & 255; pad[n + 6] = (hi >>> 16) & 255; pad[n + 7] = (hi >>> 24) & 255;
    this.update(pad);
    let out = "";
    for (const v of [this.a, this.b, this.c, this.d]) for (let i = 0; i < 4; i++) out += ((v >>> (i * 8)) & 255).toString(16).padStart(2, "0");
    return out;
  }
}

export function md5Hex(bytes: Uint8Array): string {
  return new Md5().update(bytes).digestHex();
}
