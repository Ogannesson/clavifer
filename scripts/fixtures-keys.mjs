// Writes the private keys tests/jwt.test.ts and tests/pkcs8.test.ts read into tests/fixtures/keys/.
// Every key is a throwaway test key generated here; running this again replaces them all.
// Needs OpenSSL 3 on PATH; the PBES1 sample also needs its legacy provider, which a Windows build
// keeps next to openssl.exe (set OPENSSL_MODULES to that directory when openssl cannot find it).
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = 'tests/fixtures/keys';
const encrypted = join(dir, 'encrypted');
mkdirSync(encrypted, { recursive: true });
const openssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'inherit'] });
const at = (name) => join(dir, name);

// Unencrypted keys in the formats vendors hand out.
openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', at('rsa-pkcs8.pem'));
openssl('rsa', '-in', at('rsa-pkcs8.pem'), '-traditional', '-out', at('rsa-pkcs1.pem'));
// ecparam writes an EC PARAMETERS block ahead of the key, as a key made by hand usually has.
openssl('ecparam', '-name', 'prime256v1', '-genkey', '-out', at('p256-sec1.pem'));
openssl('pkey', '-in', at('p256-sec1.pem'), '-out', at('p256-pkcs8.pem'));
openssl('ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', at('p384-sec1.pem'));
openssl('ecparam', '-name', 'secp521r1', '-genkey', '-noout', '-out', at('p521-sec1.pem'));
openssl('genpkey', '-algorithm', 'ed25519', '-out', at('ed25519-pkcs8.pem'));

// Encrypted copies of the P-256 key (and one of the RSA key). The passphrase goes through a file so
// that its UTF-8 bytes reach openssl unchanged, whatever the console's code page.
const passes = mkdtempSync(join(tmpdir(), 'clavifer-keys-'));
const pass = (value) => {
  const file = join(passes, `${Buffer.from(value).toString('hex')}.txt`);
  writeFileSync(file, value);
  return `file:${file}`;
};
const encrypt = (name, args, passphrase = 'fixture-passphrase', input = at('p256-pkcs8.pem')) =>
  openssl('pkcs8', '-topk8', '-in', input, ...args, '-passout', pass(passphrase), '-out', join(encrypted, name));
try {
  for (const prf of ['sha1', 'sha256', 'sha384', 'sha512'])
    for (const bits of ['128', '256'])
      encrypt(`pbkdf2-${prf}-aes-${bits}-cbc.pem`, [
        '-v2',
        `aes-${bits}-cbc`,
        '-v2prf',
        `hmacWith${prf.toUpperCase()}`,
      ]);
  encrypt('iter-1000000.pem', ['-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA256', '-iter', '1000000']);
  encrypt('unicode-passphrase.pem', ['-v2', 'aes-256-cbc'], 'päss密码🔑');
  encrypt('rsa-defaults.pem', [], undefined, at('rsa-pkcs8.pem'));
  // Schemes WebCrypto cannot decrypt.
  encrypt('des-ede3-cbc.pem', ['-v2', 'des3']);
  encrypt('aes-192-cbc.pem', ['-v2', 'aes-192-cbc']);
  encrypt('scrypt.pem', ['-scrypt']);
  encrypt('hmac-sha224.pem', ['-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA224']);
  encrypt('pbes1.pem', ['-v1', 'PBE-MD5-DES', '-provider', 'legacy', '-provider', 'default']);
  encrypt('pkcs12-pbe.pem', ['-v1', 'PBE-SHA1-3DES']);
  openssl(
    'ec',
    '-in',
    at('p256-pkcs8.pem'),
    '-aes256',
    '-passout',
    pass('fixture-passphrase'),
    '-out',
    join(encrypted, 'traditional.pem'),
  );
} finally {
  rmSync(passes, { recursive: true });
}
