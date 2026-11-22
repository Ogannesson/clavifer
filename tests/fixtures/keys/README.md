# Test keys

Every private key here is a throwaway test key that `scripts/fixtures-keys.mjs` generated with OpenSSL. They are used only by `tests/jwt.test.ts`, `tests/pkcs8.test.ts` and `tests/examples.test.ts`, sign nothing anywhere else, and running the script again replaces them all. The encrypted copies under `encrypted/` use the passphrase written in `tests/pkcs8.test.ts`.
