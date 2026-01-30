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
