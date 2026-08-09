import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HacashKey, hexToBytes } from "../src/crypto.js";

describe("HacashKey", () => {
  it("deterministic address from password", () => {
    const a = HacashKey.fromPassword("agent-sdk-test");
    const b = HacashKey.fromPassword("agent-sdk-test");
    assert.equal(a.address, b.address);
    assert.ok(a.address.length > 20);
    assert.equal(a.publicKey.length, 33);
  });

  it("sign and verify hash", () => {
    const key = HacashKey.fromPassword("agent-sdk-sign");
    const hash = "ab".repeat(32);
    const sig = key.signHashHex(hash);
    assert.equal(sig.length, 194); // 97 bytes hex
    assert.ok(HacashKey.verifySignHex(hash, sig, key.address));
  });

  it("rejects odd-length and non-hex input", () => {
    assert.throws(() => hexToBytes("abc"), /even number/);
    assert.throws(() => hexToBytes("0g"), /hexadecimal/);
    assert.deepEqual(hexToBytes("00ff"), new Uint8Array([0, 255]));
  });
});
