import crypto from 'crypto';

const SALT_LEN = 8;
const KEY_LEN = 32;
const IV_LEN = 16;
const CIPHER = 'aes-256-cbc';
const OPENSSL_MAGIC = Buffer.from('Salted__');

function evpBytesToKey(password: string, salt: Buffer): { key: Buffer; iv: Buffer } {
  const total = KEY_LEN + IV_LEN;
  const data = Buffer.alloc(total);
  const passwordBuf = Buffer.from(password);
  let prev = Buffer.alloc(0);
  let offset = 0;

  while (offset < total) {
    prev = crypto.createHash('md5').update(Buffer.concat([prev, passwordBuf, salt])).digest();
    prev.copy(data, offset);
    offset += prev.length;
  }

  return { key: data.subarray(0, KEY_LEN), iv: data.subarray(KEY_LEN) };
}

function encryptOpenSSL(plaintext: string, password: string): string {
  const salt = crypto.randomBytes(SALT_LEN);
  const { key, iv } = evpBytesToKey(password, salt);

  const cipher = crypto.createCipheriv(CIPHER, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return Buffer.concat([OPENSSL_MAGIC, salt, encrypted]).toString('base64');
}

function decryptOpenSSL(encBase64: string, password: string): string {
  const enc = Buffer.from(encBase64, 'base64');

  if (!enc.subarray(0, SALT_LEN).equals(OPENSSL_MAGIC)) {
    throw new Error('Missing OpenSSL salt header');
  }

  const salt = enc.subarray(SALT_LEN, SALT_LEN * 2);
  const { key, iv } = evpBytesToKey(password, salt);

  const decipher = crypto.createDecipheriv(CIPHER, key, iv);
  let decrypted = decipher.update(enc.subarray(SALT_LEN * 2));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function opensslHint(ciphertext: string, key: string): string {
  return `\nopenssl equivalent (to decrypt):\n  echo '${ciphertext}' | openssl enc -d -aes-256-cbc -a -md md5 -pass pass:'${key}'`;
}

function printHelp() {
  console.log(`Usage: crypt.ts -e|-d -k <key> -v <value>

Options:
  -e, --encrypt   Encrypt the value
  -d, --decrypt   Decrypt the value
  -k, --key       Passphrase for encryption/decryption
  -v, --value     Value to encrypt or decrypt
  -h, --help      Show this help message

Examples:
  pnpm tsx crypt.ts -e -k "mypassword" -v "hello world"
  pnpm tsx crypt.ts -d -k "mypassword" -v "U2FsdGVkX1..."
`);
}

function parseArgs(argv: string[]): { mode: 'encrypt' | 'decrypt'; key: string; value: string } {
  let mode: 'encrypt' | 'decrypt' | undefined;
  let key: string | undefined;
  let value: string | undefined;

  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '-e' || arg === '--encrypt') {
      mode = 'encrypt';
    } else if (arg === '-d' || arg === '--decrypt') {
      mode = 'decrypt';
    } else if (arg === '-k' || arg === '--key') {
      key = args[++i];
    } else if (arg === '-v' || arg === '--value') {
      value = args[++i];
    }
  }

  if (!mode) {
    console.error('Error: specify -e/--encrypt or -d/--decrypt');
    process.exit(1);
  }
  if (!key) {
    console.error('Error: missing -k/--key');
    process.exit(1);
  }
  if (value === undefined) {
    console.error('Error: missing -v/--value');
    process.exit(1);
  }

  return { mode, key, value };
}

const { mode, key, value } = parseArgs(process.argv);

try {
  if (mode === 'encrypt') {
    const result = encryptOpenSSL(value, key);
    console.log(result);
    console.error(opensslHint(result, key));
  } else {
    const result = decryptOpenSSL(value, key);
    console.log(result);
    console.error(opensslHint(value, key));
  }
} catch (err) {
  console.error('Error:', (err as Error).message);
  process.exit(1);
}
