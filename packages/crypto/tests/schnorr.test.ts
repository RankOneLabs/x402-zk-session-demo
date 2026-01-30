import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  derivePublicKey,
  schnorrSign,
  schnorrVerify,
} from '../src/schnorr.js';

describe('Schnorr Signatures', () => {
  it('should generate valid keypairs', () => {
    const { secretKey, publicKey } = generateKeypair();
    
    expect(typeof secretKey).toBe('bigint');
    expect(typeof publicKey.x).toBe('bigint');
    expect(typeof publicKey.y).toBe('bigint');
  });
  
  it('should derive public key from secret key', () => {
    const { secretKey, publicKey } = generateKeypair();
    const derived = derivePublicKey(secretKey);
    
    expect(derived.x).toBe(publicKey.x);
    expect(derived.y).toBe(publicKey.y);
  });
  
  it('should sign and verify a message', () => {
    const { secretKey, publicKey } = generateKeypair();
    const message = 12345n;
    
    const signature = schnorrSign(secretKey, message);
    const valid = schnorrVerify(publicKey, message, signature);
    
    expect(valid).toBe(true);
  });
  
  it('should reject signature with wrong message', () => {
    const { secretKey, publicKey } = generateKeypair();
    const message = 12345n;
    
    const signature = schnorrSign(secretKey, message);
    const valid = schnorrVerify(publicKey, message + 1n, signature);
    
    expect(valid).toBe(false);
  });
  
  it('should reject signature with wrong public key', () => {
    const { secretKey } = generateKeypair();
    const { publicKey: wrongPk } = generateKeypair();
    const message = 12345n;
    
    const signature = schnorrSign(secretKey, message);
    const valid = schnorrVerify(wrongPk, message, signature);
    
    expect(valid).toBe(false);
  });
  
  it('different messages should produce different signatures', () => {
    const { secretKey } = generateKeypair();
    
    const sig1 = schnorrSign(secretKey, 1n);
    const sig2 = schnorrSign(secretKey, 2n);
    
    // R points should be different (random nonces)
    // Actually, they might be the same if we get unlucky, but s should differ
    expect(sig1.s !== sig2.s || sig1.r.x !== sig2.r.x).toBe(true);
  });
});

describe('Schnorr input validation', () => {
  it('should reject negative secret key', () => {
    expect(() => schnorrSign(-1n, 123n)).toThrow('secretKey must be non-negative');
  });

  it('should reject zero secret key', () => {
    expect(() => schnorrSign(0n, 123n)).toThrow('secretKey cannot be zero');
  });

  it('should reject negative message in sign', () => {
    const { secretKey } = generateKeypair();
    expect(() => schnorrSign(secretKey, -1n)).toThrow('message must be non-negative');
  });

  it('should reject secret key >= FIELD_MODULUS', () => {
    const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    expect(() => schnorrSign(FIELD_MODULUS, 123n)).toThrow('secretKey must be less than field modulus');
  });

  it('should reject negative message in verify', () => {
    const { secretKey, publicKey } = generateKeypair();
    const sig = schnorrSign(secretKey, 123n);
    expect(() => schnorrVerify(publicKey, -1n, sig)).toThrow('message must be non-negative');
  });

  it('should reject invalid public key point', () => {
    const { secretKey } = generateKeypair();
    const sig = schnorrSign(secretKey, 123n);
    // (2, 2) is definitely not on BN254 G1: y^2 = x^3 + 3 -> 4 ≠ 11
    const invalidPk = { x: 2n, y: 2n };
    expect(() => schnorrVerify(invalidPk, 123n, sig)).toThrow('publicKey is not a valid point on the curve');
  });

  it('should reject public key at infinity', () => {
    const { secretKey } = generateKeypair();
    const sig = schnorrSign(secretKey, 123n);
    const infinity = { x: 0n, y: 0n };
    expect(() => schnorrVerify(infinity, 123n, sig)).toThrow('publicKey cannot be the point at infinity');
  });
});
