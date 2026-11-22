// PEM armor and the little DER that reading private keys takes, shared by jwt.ts (the Worker) and
// pkcs8.ts (the console), so nothing here may use Node's Buffer. Every reader throws on malformed
// input; the caller turns that into its own error.

/** The first PEM block whose label ends in "PRIVATE KEY" (blocks such as EC PARAMETERS before it are
 * skipped), with the text between its armor lines. Null when the value holds none. */
export function privateKeyPem(value: string) {
  const match = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/.exec(value);
  return match && { label: match[1], body: match[2] };
}
/** Base64 with every whitespace character removed first (the lax reading of RFC 7468), so a PEM
 * whose line breaks were lost in a single-line field still reads. Throws on anything else. */
export function base64Bytes(text: string) {
  return Uint8Array.from(atob(text.replace(/\s+/g, '')), (c) => c.charCodeAt(0));
}
export function writePem(label: string, der: Uint8Array) {
  const lines = btoa(String.fromCharCode(...der)).match(/.{1,64}/g)!;
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export type Element = { tag: number; content: Uint8Array; end: number };
/** The DER element at offset at: its tag, its content and the offset just past it. */
export function element(bytes: Uint8Array, at = 0): Element {
  const tag = bytes[at];
  let length = bytes[at + 1];
  let start = at + 2;
  if (length >= 0x80) {
    // 0x80 is BER's indefinite length; more than four length bytes never occur in a key.
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new RangeError('der');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + bytes[start + i];
    start += n;
  }
  // Past the end of bytes, a length byte reads as undefined and the comparison fails.
  if (tag === undefined || !(start + length <= bytes.length)) throw new RangeError('der');
  return { tag, content: bytes.subarray(start, start + length), end: start + length };
}
/** The elements a constructed content consists of, which must fill it exactly. */
export function children(content: Uint8Array) {
  const out: Element[] = [];
  for (let at = 0; at < content.length; at = out[out.length - 1].end) out.push(element(content, at));
  return out;
}
/** One whole DER value: an element that spans all of bytes. */
export function whole(bytes: Uint8Array) {
  const top = element(bytes);
  if (top.end !== bytes.length) throw new RangeError('der');
  return top;
}
export function encodeElement(tag: number, ...parts: Uint8Array[]) {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const size: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) size.unshift(n & 0xff);
  const head = length < 0x80 ? [tag, length] : [tag, 0x80 | size.length, ...size];
  const out = new Uint8Array(head.length + length);
  out.set(head);
  let at = head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
export const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
/** An object identifier's content in dotted form, for naming one this code does not know. */
export function dotted(content: Uint8Array) {
  const arcs: number[] = [];
  let value = 0;
  for (const byte of content) {
    value = value * 128 + (byte & 0x7f);
    if (byte < 0x80) {
      arcs.push(value);
      value = 0;
    }
  }
  const first = Math.min(Math.floor(arcs[0] / 40), 2);
  return [first, arcs[0] - first * 40, ...arcs.slice(1)].join('.');
}
