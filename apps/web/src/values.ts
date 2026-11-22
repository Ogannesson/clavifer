// What the console makes of a file or a paste before it becomes a credential value. Nothing here
// touches the page, so the tests run it as it is.
import { authField } from '../../../packages/core/auth';
import { children, hex, privateKeyPem, whole } from '../../../packages/core/pem';
import { decryptKey, encryptedKey, type UnsupportedKeyEncryption } from '../../../packages/core/pkcs8';

/** Text pasted or read from a file as a credential value: one line with a line break after it (a line
 * copied in a terminal, a token file) is that line alone, since the services it goes to read the break
 * as part of the value; text of several lines (a PEM key) stays exactly as it is. */
export function asValue(text: string) {
  const line = text.replace(/\r?\n$/, '');
  return /[\r\n]/.test(line) ? text : line;
}
/** A private key copied out of a JSON file (a service account's private_key), which holds it as one line
 * with its line breaks written \n, with or without the quotes around it: the text that JSON string
 * stands for. Undefined for any other text, which is used as it is. */
export function unescapedKey(text: string) {
  if (/[\r\n]/.test(text) || !text.includes('\\') || !privateKeyPem(text)) return undefined;
  try {
    return JSON.parse(/^".*"$/.test(text) ? text : `"${text}"`) as string;
  } catch {
    return undefined;
  }
}

/** A JSON file read as credential fields. */
export type Flattened = {
  /** Every string value, at any depth, named by its own (innermost) key. */
  fields: Record<string, string>;
  /** Key paths of the values that are not strings (numbers, booleans, null, arrays), left out. */
  skipped: string[];
  /** Each name that more than one string value has, with all of their key paths. */
  conflicts: string[][];
  /** Key paths of string values whose key is not a field name. */
  invalid: string[];
  /** The values of keys named passphrase (in any case), which decrypt a key and are never a field. */
  passphrases: string[];
};
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** Reads a JSON object as fields: nested objects are walked level by level and a string takes the name
 * of its own key (boxAppSettings.appAuth.privateKey becomes privateKey). Null when text is not a JSON
 * object. Two strings under one name are a conflict, never a guess. */
export function flattenJson(text: string): Flattened | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isObject(root)) return null;
  const paths = new Map<string, string[]>();
  const result: Flattened = { fields: {}, skipped: [], conflicts: [], invalid: [], passphrases: [] };
  const walk = (node: Record<string, unknown>, at: string[]) => {
    for (const [key, value] of Object.entries(node)) {
      const path = [...at, key].join('.');
      if (isObject(value)) walk(value, [...at, key]);
      else if (typeof value !== 'string') result.skipped.push(path);
      else if (key.toLowerCase() === 'passphrase') result.passphrases.push(value);
      else if (!authField.safeParse(key).success) result.invalid.push(path);
      else {
        paths.set(key, [...(paths.get(key) ?? []), path]);
        result.fields[key] = value;
      }
    }
  };
  walk(root, []);
  for (const [name, found] of paths)
    if (found.length > 1) {
      result.conflicts.push(found);
      delete result.fields[name];
    }
  return result;
}

/** Opens each passphrase-protected key among fields with the file's passphrases, in place; returns what
 * the Owner is told. A key the console cannot decrypt, or none of the passphrases opens, stays as it is,
 * and its field shows why. */
async function openKeys(fields: Record<string, string>, passphrases: string[]) {
  const opened: string[] = [];
  const closed: string[] = [];
  for (const [name, value] of Object.entries(fields)) {
    let key;
    try {
      key = encryptedKey(value);
    } catch {
      closed.push(name);
      continue;
    }
    if (!key) continue;
    let plain: string | undefined;
    for (const passphrase of passphrases) plain ??= await decryptKey(key, passphrase).catch(() => undefined);
    if (plain) {
      fields[name] = plain;
      opened.push(name);
    } else closed.push(name);
  }
  return (
    '文件里的 passphrase 只用于解开私钥，没有保存。' +
    (opened.length ? `已用它解开 ${opened.join('、')}。` : '') +
    (closed.length ? `${closed.join('、')} 没能解开，原因见字段旁的说明。` : '')
  );
}
/** The fields a JSON file fills in, and what the Owner is told about the rest; on a setup's approval card
 * (only: the draft's fields) just those fields, and a key outside them is merely not used. A passphrase in
 * the file opens the encrypted keys it holds and is dropped. Throws the reason when it fills in nothing. */
export async function jsonFields(text: string, only?: string[]) {
  const found = flattenJson(text);
  if (!found) throw new Error('这个文件不是 JSON 对象，没有填入任何字段。');
  const conflicts = only
    ? found.conflicts.filter((paths) => only.includes(paths[0].split('.').at(-1)!))
    : found.conflicts;
  if (conflicts.length)
    throw new Error(
      `不同层级有同名的键，无法确定用哪一个，没有填入任何字段：${conflicts.map((p) => p.join(' 和 ')).join('；')}。`,
    );
  if (!only && found.invalid.length)
    throw new Error(
      `这些键不能当字段名（以字母或下划线开头，只含字母、数字、_ 和 -，最长 64 个字符），没有填入任何字段：${found.invalid.join('、')}。`,
    );
  const fields = only
    ? Object.fromEntries(Object.entries(found.fields).filter(([name]) => only.includes(name)))
    : found.fields;
  const unused = only ? [...Object.keys(found.fields).filter((name) => !only.includes(name)), ...found.invalid] : [];
  const keys = found.passphrases.length ? await openKeys(fields, found.passphrases) : '';
  const notes = [
    `已填入 ${Object.keys(fields).length} 个字段${Object.keys(fields).length ? `：${Object.keys(fields).join('、')}` : ''}。`,
    keys,
    found.skipped.length ? `跳过了不是字符串的值：${found.skipped.join('、')}。` : '',
    unused.length ? `草案没有列出、因此没有使用：${unused.join('、')}。` : '',
  ];
  return { fields, notice: notes.filter(Boolean).join('') };
}

const PKCS7 = '2a864886f70d0107';
const der = (bytes: Uint8Array) => {
  try {
    return children(whole(bytes).content);
  } catch {
    return null;
  }
};
/** Whether a file is a PKCS#12 bundle (.p12, .pfx): by its name, or by its content, a DER PFX
 * (RFC 7292: SEQUENCE { version 3, ContentInfo of PKCS#7 data or signed data, ... }). */
export function isPkcs12(name: string, bytes: Uint8Array) {
  if (/\.(p12|pfx)$/i.test(name)) return true;
  const [version, authSafe] = der(bytes) ?? [];
  try {
    return (
      version?.tag === 0x02 &&
      hex(version.content) === '03' &&
      authSafe?.tag === 0x30 &&
      hex(children(authSafe.content)[0].content).startsWith(PKCS7)
    );
  } catch {
    return false;
  }
}
/** Whether a file is binary DER rather than text: one DER SEQUENCE spanning the whole file, as a key
 * written with -outform DER is. A PEM or JSON file never reads as one. */
export const isDer = (bytes: Uint8Array) => bytes[0] === 0x30 && der(bytes) !== null;
export const pkcs12Text =
  '不支持 PKCS#12（.p12 / .pfx）文件。请先取出其中的私钥：openssl pkcs12 -in in.p12 -nocerts -nodes -out out.pem（会要求输入文件的导入口令；OpenSSL 3 打开旧的 .p12 时可能要再加 -legacy），再载入得到的 out.pem。';
export const derText =
  '这是二进制（DER）格式的文件，请先转成 PEM：openssl pkey -inform DER -in key.der -out key.pem（带口令的私钥会要求输入口令），再载入得到的 key.pem。';
/** Why a key the console cannot decrypt is refused, and how to convert it: the command pkcs8.ts names,
 * which keeps a passphrase the console can use, or for a PKCS#8 key the same with -nocrypt, which drops
 * it. A traditional PEM key's command already writes it without one. */
export function unsupportedText(e: Pick<UnsupportedKeyEncryption, 'algorithm' | 'command'>) {
  const pkcs8 = e.command.includes(' -topk8 ');
  return (
    `这个私钥用 ${e.algorithm} 加密，浏览器解不开。请先转换：${e.command}（会要求输入原口令` +
    (pkcs8
      ? '和新口令），再载入 out.pem 用新口令解开；或者把命令里的 -v2 aes-256-cbc -v2prf hmacWithSHA256 换成 -nocrypt，直接得到不加密的私钥。'
      : '），得到不加密的私钥后再载入 out.pem。')
  );
}
