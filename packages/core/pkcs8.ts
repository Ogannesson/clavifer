// Decrypts a passphrase-protected PKCS#8 private key in the console, so that the secret stores the plain
// key and the passphrase is neither stored nor sent. Only crypto.subtle is used, which decides what
// can be decrypted: PBES2 (RFC 8018) with PBKDF2, hmacWithSHA1/256/384/512 and aes-128-cbc or
// aes-256-cbc. OpenSSL's defaults since 1.1.0 (PBKDF2, hmacWithSHA256, aes-256-cbc) are among them.
// Anything else (3DES, scrypt, SHA-224, AES-192, which Chrome refuses, PBES1, PKCS#12 PBE, traditional
// PEM encryption) needs an algorithm WebCrypto lacks; by the Owner's decision the console carries no
// cryptography of its own or a library's, so the error names the algorithm and the openssl command
// that converts the key.
import { Fault } from './errors';
import { base64Bytes, children, dotted, hex, privateKeyPem, whole, writePem } from './pem';

const CONVERT = 'openssl pkcs8 -topk8 -in in.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -out out.pem';
const CONVERT_TRADITIONAL = 'openssl pkey -in in.pem -out out.pem';
/** A key encrypted with a scheme the console cannot decrypt. algorithm is the name read from the key and
 * command the openssl command that converts it (asking for the passphrase): with CONVERT to a scheme the
 * console decrypts (-nocrypt instead drops the passphrase), with CONVERT_TRADITIONAL to a plain key. */
export class UnsupportedKeyEncryption extends Fault {
  constructor(
    public algorithm: string,
    public command: string,
  ) {
    super(
      'unsupported_key_encryption',
      400,
      `The key is encrypted with ${algorithm}, which WebCrypto cannot decrypt. Convert it with: ${command}`,
    );
  }
}
// A wrong passphrase and a damaged file cannot be told apart.
const damaged = () =>
  new Fault('key_decryption_failed', 400, 'The passphrase is wrong or the encrypted key is damaged.');

const PBES2 = '1.2.840.113549.1.5.13';
const PBKDF2 = '1.2.840.113549.1.5.12';
const prfs: Record<string, string> = {
  '1.2.840.113549.2.7': 'SHA-1',
  '1.2.840.113549.2.9': 'SHA-256',
  '1.2.840.113549.2.10': 'SHA-384',
  '1.2.840.113549.2.11': 'SHA-512',
};
const ciphers: Record<string, number> = { '2.16.840.1.101.3.4.1.2': 128, '2.16.840.1.101.3.4.1.42': 256 };
// The names of what is recognized but cannot be decrypted; any other identifier is named by its OID.
const names: Record<string, string> = {
  '1.2.840.113549.1.5.1': 'PBES1 pbeWithMD2AndDES-CBC',
  '1.2.840.113549.1.5.4': 'PBES1 pbeWithMD2AndRC2-CBC',
  '1.2.840.113549.1.5.3': 'PBES1 pbeWithMD5AndDES-CBC',
  '1.2.840.113549.1.5.6': 'PBES1 pbeWithMD5AndRC2-CBC',
  '1.2.840.113549.1.5.10': 'PBES1 pbeWithSHA1AndDES-CBC',
  '1.2.840.113549.1.5.11': 'PBES1 pbeWithSHA1AndRC2-CBC',
  '1.2.840.113549.1.12.1.1': 'PKCS#12 pbeWithSHA1And128BitRC4',
  '1.2.840.113549.1.12.1.2': 'PKCS#12 pbeWithSHA1And40BitRC4',
  '1.2.840.113549.1.12.1.3': 'PKCS#12 pbeWithSHA1And3-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.4': 'PKCS#12 pbeWithSHA1And2-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.5': 'PKCS#12 pbeWithSHA1And128BitRC2-CBC',
  '1.2.840.113549.1.12.1.6': 'PKCS#12 pbeWithSHA1And40BitRC2-CBC',
  '1.3.6.1.4.1.11591.4.11': 'scrypt',
  '1.2.840.113549.2.8': 'hmacWithSHA224',
  '1.2.840.113549.2.12': 'hmacWithSHA512-224',
  '1.2.840.113549.2.13': 'hmacWithSHA512-256',
  '1.2.840.113549.3.7': 'des-ede3-cbc',
  '1.3.14.3.2.7': 'des-cbc',
  '1.2.840.113549.3.2': 'rc2-cbc',
  '2.16.840.1.101.3.4.1.22': 'aes-192-cbc',
};
const unsupported = (oid: string) => new UnsupportedKeyEncryption(names[oid] ?? `OID ${oid}`, CONVERT);

/** An encrypted private key read from a PEM, ready for decryptKey. */
export type EncryptedKey = {
  salt: Uint8Array;
  iterations: number;
  hash: string;
  bits: number;
  iv: Uint8Array;
  data: Uint8Array;
};
/** The encrypted private key in value, or null when value holds no encrypted private key (an
 * unencrypted one included). Throws UnsupportedKeyEncryption for a scheme that cannot be decrypted, so
 * the console can say so before it asks for the passphrase. */
export function encryptedKey(value: string): EncryptedKey | null {
  const pem = privateKeyPem(value);
  if (!pem) return null;
  // RFC 1421 encryption of a traditional key: the key is derived with MD5, which WebCrypto lacks.
  if (/Proc-Type:\s*4,ENCRYPTED/.test(pem.body)) {
    const dek = /DEK-Info:\s*([A-Za-z0-9-]+)/.exec(pem.body)?.[1] ?? 'unknown';
    throw new UnsupportedKeyEncryption(`traditional PEM encryption (DEK-Info ${dek})`, CONVERT_TRADITIONAL);
  }
  if (pem.label !== 'ENCRYPTED PRIVATE KEY') return null;
  // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
  let scheme: string, params: Uint8Array, data: Uint8Array;
  try {
    const [algorithm, encrypted] = children(whole(base64Bytes(pem.body)).content);
    const [oid, parameters] = children(algorithm.content);
    [scheme, params, data] = [dotted(oid.content), parameters.content, encrypted.content];
  } catch {
    throw damaged();
  }
  if (scheme !== PBES2) throw unsupported(scheme);
  // PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier }
  // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER, keyLength INTEGER OPTIONAL,
  //   prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
  let kdf: string, kdfParams: ReturnType<typeof children>, cipher: string, iv: Uint8Array;
  try {
    const [derivation, encryption] = children(params);
    const [kdfOid, kdfParameters] = children(derivation.content);
    const [cipherOid, cipherIv] = children(encryption.content);
    kdf = dotted(kdfOid.content);
    kdfParams = kdf === PBKDF2 ? children(kdfParameters.content) : [];
    cipher = dotted(cipherOid.content);
    iv = cipherIv.content;
  } catch {
    throw damaged();
  }
  if (kdf !== PBKDF2) throw unsupported(kdf);
  const [salt, count] = kdfParams;
  const prfElement = kdfParams.slice(2).find((e) => e.tag === 0x30);
  let prf = '1.2.840.113549.2.7';
  try {
    if (prfElement) prf = dotted(children(prfElement.content)[0].content);
  } catch {
    throw damaged();
  }
  if (!prfs[prf]) throw unsupported(prf);
  if (!ciphers[cipher]) throw unsupported(cipher);
  // The AES-CBC IV is one 16-byte block.
  if (salt?.tag !== 0x04 || count?.tag !== 0x02 || count.content.length > 4 || iv.length !== 16) throw damaged();
  const iterations = count.content.reduce((n, b) => n * 256 + b, 0);
  return { salt: salt.content, iterations, hash: prfs[prf], bits: ciphers[cipher], iv, data };
}

const bytes = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
/** The decrypted key as an unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY). The passphrase is taken as its
 * UTF-8 bytes without Unicode normalization, as openssl in a UTF-8 terminal does. */
export async function decryptKey(key: EncryptedKey, passphrase: string) {
  try {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, [
      'deriveKey',
    ]);
    const aes = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: bytes(key.salt), iterations: key.iterations, hash: key.hash },
      base,
      { name: 'AES-CBC', length: key.bits },
      false,
      ['decrypt'],
    );
    const der = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bytes(key.iv) }, aes, bytes(key.data)),
    );
    // A wrong passphrase nearly always fails the padding check; the rest of the time this does:
    // OneAsymmetricKey ::= SEQUENCE { version INTEGER 0 or 1, AlgorithmIdentifier, OCTET STRING, ... }
    // (RFC 5958; version 1 adds the public key, and is still the PKCS#8 the signer reads).
    const [version, algorithm, privateKey] = children(whole(der).content);
    if (
      version.tag !== 0x02 ||
      !['00', '01'].includes(hex(version.content)) ||
      algorithm.tag !== 0x30 ||
      privateKey.tag !== 0x04
    )
      throw damaged();
    return writePem('PRIVATE KEY', der);
  } catch {
    throw damaged();
  }
}
