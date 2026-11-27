// The fee payer: the classic account that is the source of, and pays the fee for, every transaction
// the backend submits. By default on testnet it is a disposable key generated in memory and funded
// through Friendbot. On mainnet, and on testnet when the operator configures one, it is the operator's
// own key, read from a file the operator funds; nothing else funds or creates it. Either way the secret never leaves this object: it is not printed,
// logged, serialized, returned or journaled, and it signs only a transaction envelope handed to
// `signTransaction` by WalletNetwork, after that envelope's checks.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { isAbsolute, normalize } from 'node:path';
import { inspect } from 'node:util';
import { Keypair, StrKey } from '@stellar/stellar-sdk';

const refused = (detail) => Object.assign(new Error('fee payer key refused'), { startup: detail });

export class FeePayer {
  #key;
  /** `operator` says whether the key is the operator's own (operator-funded, as mainnet always is) or a disposable one (testnet). */
  constructor(key, operator) {
    if (!(key instanceof Keypair) || !key.canSign()) throw refused('The fee payer key is not an Ed25519 secret key.');
    this.#key = key;
    this.address = key.publicKey();
    this.operator = operator === true;
    Object.freeze(this);
  }
  static disposable() { return new FeePayer(Keypair.random(), false); }
  xdrPublicKey() { return Keypair.fromPublicKey(this.address).xdrPublicKey(); }
  /** Signs exactly `transaction` (a built TransactionBuilder transaction) with the fee payer key. */
  signTransaction(transaction) { transaction.sign(this.#key); }
  toJSON() { return { address: this.address, operator: this.operator }; }
  [inspect.custom]() { return `FeePayer(${this.address})`; }
}

/**
 * A secret key the operator supplied in a file, held so that it never shows: it serializes and
 * inspects as its address, and only the code it is handed to can take the Keypair (`keypair()`).
 */
export class OperatorKey {
  #key;
  constructor(key) {
    if (!(key instanceof Keypair) || !key.canSign()) throw refused('The key is not an Ed25519 secret key.');
    this.#key = key;
    this.address = key.publicKey();
    Object.freeze(this);
  }
  keypair() { return this.#key; }
  toJSON() { return { address: this.address }; }
  [inspect.custom]() { return `OperatorKey(${this.address})`; }
}

/** The operator's delegate key file (`delegateKeyPath`), under the same file checks as the fee payer's. */
export function loadDelegateKey(path) {
  return new OperatorKey(readKeyFile(path, 'delegate'));
}

/**
 * The operator's own fee payer key, from `path`: an absolute, canonical regular file that is no
 * symlink, owned by this user and readable by no one else (mode 0600 or stricter), holding one
 * Stellar secret seed (`S…`) and an optional trailing newline. Anything else refuses with a reason
 * the operator can act on; the reason never contains the file's content.
 */
export function loadFeePayerKey(path) {
  return new FeePayer(readKeyFile(path, 'fee payer'), true);
}

function readKeyFile(path, what) {
  if (typeof path !== 'string' || path.length > 4096 || !isAbsolute(path) || normalize(path) !== path) {
    throw refused(`The ${what} key path must be absolute and normalized.`);
  }
  let stat;
  try { stat = lstatSync(path); } catch { throw refused(`The ${what} key file does not exist.`); }
  if (stat.isSymbolicLink() || !stat.isFile() || realpathSync(path) !== path) {
    throw refused(`The ${what} key file must be a regular file, not a symlink.`);
  }
  if (typeof process.getuid !== 'function' || stat.uid !== process.getuid()) {
    throw refused(`The ${what} key file must be owned by the user running the wallet backend.`);
  }
  if (stat.mode & 0o077) throw refused(`The ${what} key file must have mode 0600: no access for group or others.`);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const buffer = Buffer.alloc(128);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== stat.ino || opened.dev !== stat.dev || (opened.mode & 0o077)) {
      throw refused(`The ${what} key file changed while it was read.`);
    }
    if (opened.size > 64) throw refused(`The ${what} key file must hold one Stellar secret seed (S…).`);
    const length = readSync(fd, buffer, 0, buffer.length, 0);
    const text = buffer.subarray(0, length).toString('latin1');
    const seed = /^(S[A-Z2-7]{55})\n?$/.exec(text)?.[1];
    if (!seed || !StrKey.isValidEd25519SecretSeed(seed)) throw refused(`The ${what} key file must hold one Stellar secret seed (S…).`);
    return Keypair.fromSecret(seed);
  } finally {
    buffer.fill(0);
    closeSync(fd);
  }
}
