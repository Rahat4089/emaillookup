#!/usr/bin/env node
"use strict";

/**
 * Build FashionGo login payload using only Node built-in libraries.
 *
 * Edit these variables directly:
 * - username (email)
 * - password (plaintext)
 * - keyId
 * - modulus (hex string)
 * - exponent (hex string)
 */

const crypto = require("crypto");

function toBase64UrlFromHex(hexString) {
  const normalized = hexString.length % 2 === 0 ? hexString : `0${hexString}`;
  const b64 = Buffer.from(normalized, "hex").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generateHexString(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("length must be a positive integer");
  }
  const bytesNeeded = Math.ceil(length / 2);
  return crypto.randomBytes(bytesNeeded).toString("hex").slice(0, length);
}

function aesEncryptPassword(plaintextPassword, passphrase) {
  const key = Buffer.from(passphrase, "latin1");
  const iv = Buffer.from(passphrase.slice(0, 16), "latin1");
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintextPassword, "utf8"),
    cipher.final(),
  ]);
  return encrypted.toString("base64");
}

function rsaEncryptPassphrase(passphrase, modulusHex, exponentHex) {
  const jwk = {
    kty: "RSA",
    n: toBase64UrlFromHex(modulusHex),
    e: toBase64UrlFromHex(exponentHex),
  };

  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const encryptedBytes = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(passphrase, "utf8")
  );

  // Browser JS returns RSA ciphertext as hex text, then base64 of that hex string.
  let encryptedHex = encryptedBytes.toString("hex").replace(/^0+/, "");
  if (encryptedHex.length === 0) {
    encryptedHex = "0";
  }
  if (encryptedHex.length % 2 !== 0) {
    encryptedHex = `0${encryptedHex}`;
  }

  return Buffer.from(encryptedHex, "ascii").toString("base64");
}

function buildLoginPayload({ username, password, keyId, modulus, exponent }) {
  const passphrase = generateHexString(32);

  return {
    userName: username,
    password: aesEncryptPassword(password, passphrase),
    secureKey: keyId,
    passphrase: rsaEncryptPassphrase(passphrase, modulus, exponent),
  };
}

function assertRequiredInputs({ username, password, keyId, modulus, exponent }) {
  const missing = [];
  if (!username || !String(username).trim()) missing.push("username");
  if (!password || !String(password).trim()) missing.push("password");
  if (!keyId || !String(keyId).trim()) missing.push("keyId");
  if (!modulus || !String(modulus).trim()) missing.push("modulus");
  if (!exponent || !String(exponent).trim()) missing.push("exponent");

  if (missing.length > 0) {
    throw new Error(`Missing required inputs: ${missing.join(", ")}`);
  }

  if (!/^[0-9a-fA-F]+$/.test(modulus)) {
    throw new Error("modulus must be a valid hex string");
  }
  if (!/^[0-9a-fA-F]+$/.test(exponent)) {
    throw new Error("exponent must be a valid hex string");
  }
}

// ====== Set your inputs here ======
const username = "user@example.com";
const password = "plaintext-password";
const keyId = "d32ec93f0cb943d2a757e2cb30ff3b28";
const modulus = "PUT_MODULUS_HEX_HERE";
const exponent = "10001";
// ==================================

try {
  assertRequiredInputs({ username, password, keyId, modulus, exponent });

  const payload = buildLoginPayload({
    username,
    password,
    keyId,
    modulus,
    exponent,
  });

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`Error: ${error.message}\n`);
  process.exit(1);
}
