#!/usr/bin/env node
"use strict";

/**
 * Build FashionGo login payload using only Node built-in libraries.
 *
 * Required inputs:
 * - username (email)
 * - password (plaintext)
 * - keyId
 * - modulus (hex string)
 * - exponent (hex string)
 *
 * Usage:
 *   node build_login_payload.js \
 *     --username "user@example.com" \
 *     --password "plaintext-password" \
 *     --keyId "d32ec93f0cb943d2a757e2cb30ff3b28" \
 *     --modulus "<hex modulus>" \
 *     --exponent "10001"
 */

const crypto = require("crypto");

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      continue;
    }

    const eqIndex = token.indexOf("=");
    if (eqIndex !== -1) {
      const key = token.slice(2, eqIndex);
      const value = token.slice(eqIndex + 1);
      parsed[key] = value;
      continue;
    }

    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = "true";
    } else {
      parsed[key] = next;
      i += 1;
    }
  }
  return parsed;
}

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

  // Browser JS produces an RSA hex string before base64-encoding that string.
  // Matching that flow:
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

function assertRequiredInputs(input) {
  const required = ["username", "password", "keyId", "modulus", "exponent"];
  const missing = required.filter((key) => !input[key] || !String(input[key]).trim());
  if (missing.length > 0) {
    throw new Error(
      `Missing required inputs: ${missing.join(", ")}\n` +
        "Required: username, password, keyId, modulus, exponent"
    );
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const input = {
    username: args.username,
    password: args.password,
    keyId: args.keyId,
    modulus: args.modulus,
    exponent: args.exponent,
  };

  assertRequiredInputs(input);

  const payload = buildLoginPayload(input);
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`Error: ${error.message}\n`);
  process.exit(1);
}

