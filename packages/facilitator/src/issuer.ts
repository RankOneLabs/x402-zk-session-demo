/**
 * Credential Facilitator
 * 
 * Issues signed ZK session credentials after verifying x402 payment.
 * Compliant with x402 zk-session spec v0.1.0
 */

import {
  schnorrSign,
  derivePublicKey,
  poseidonHash7,
  bigIntToHex,
  hexToBigInt,
  parseSchemePrefix,
  addSchemePrefix,
  type Point,
  type ZKSessionScheme,
} from '@demo/crypto';
import type { SettlementRequest, SettlementResponse, PaymentResult, IssuanceRequest, IssuanceResponse } from './types.js';
import { PaymentVerifier, type PaymentVerificationConfig } from './payment-verifier.js';

/** Configuration for a single tier */
export interface TierConfig {
  /** Minimum payment amount in USDC cents (e.g., 10 = $0.10) */
  minAmountCents: number;
  /** Tier level (0 = basic, 1 = pro, etc.) */
  tier: number;
  /** Maximum presentations allowed */
  maxPresentations: number;
  /** Duration in seconds */
  durationSeconds: number;
}

/** Issuer configuration */
export interface IssuerConfig {
  /** Unique service identifier */
  serviceId: bigint;
  /** Issuer's secret key for signing */
  secretKey: bigint;
  /** Pricing tiers (sorted by minAmountCents descending by the issuer) */
  tiers: TierConfig[];
  /** Enable mock payments for testing */
  allowMockPayments?: boolean;
  /** On-chain payment verification config */
  paymentVerification?: PaymentVerificationConfig;
}

export class CredentialIssuer {
  private publicKey: Point | null = null;
  private initializationPromise: Promise<void> | null = null;
  private readonly tiers: TierConfig[];
  private readonly paymentVerifier?: PaymentVerifier;

  constructor(private readonly config: IssuerConfig) {
    this.tiers = [...config.tiers].sort((a, b) => b.minAmountCents - a.minAmountCents);

    // Initialize payment verifier if configured
    if (config.paymentVerification) {
      this.paymentVerifier = new PaymentVerifier(config.paymentVerification);
      console.log(`[Issuer] On-chain verification enabled for chain ${config.paymentVerification.chainId}`);
    }
  }

  /**
   * Initialize the issuer (derive public key)
   */
  async initialize(): Promise<void> {
    // Return existing promise if initialization is in progress
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    if (!this.publicKey) {
      this.initializationPromise = (async () => {
        try {
          this.publicKey = await derivePublicKey(this.config.secretKey);
        } finally {
          // Clear promise on error, but keep it if successful so we don't re-run.
          // Actually, if we succeed, this.publicKey is set, so subsequent calls check that.
          // But to be completely safe against re-entrancy even after success:
          // We can just leave the promise or use the double-check locking pattern properly.
          // However, simpler is just to await the promise.
        }
      })();

      await this.initializationPromise;
    }
  }

  /**
   * Get the issuer's public key
   */
  async getPublicKey(): Promise<Point> {
    if (!this.publicKey) {
      await this.initialize();
    }
    return this.publicKey!;
  }

  /**
   * Get the scheme-prefixed public key string for x402 responses
   */
  async getPublicKeyPrefixed(): Promise<string> {
    const pubKey = await this.getPublicKey();
    // Encode as uncompressed point: 04 + x + y (each 32 bytes, 64 hex chars)
    const xHex = pubKey.x.toString(16).padStart(64, '0');
    const yHex = pubKey.y.toString(16).padStart(64, '0');
    return addSchemePrefix('pedersen-schnorr-bn254', `0x04${xHex}${yHex}`);
  }

  /**
   * Settle payment and issue credential (spec §7.2, §7.3)
   * This is the x402 spec-compliant endpoint.
   */
  async settle(request: SettlementRequest): Promise<SettlementResponse> {
    await this.initialize();

    // 1. Parse scheme-prefixed commitment
    const { scheme, value: commitmentHex } = parseSchemePrefix(request.zk_session.commitment);
    if (scheme !== 'pedersen-schnorr-bn254') {
      throw new Error(`Unsupported scheme: ${scheme}`);
    }

    // Parse commitment point from hex (expects "0x04" + x (64 chars) + y (64 chars))
    const commitmentBytes = commitmentHex.startsWith('0x') ? commitmentHex.slice(2) : commitmentHex;
    if (!commitmentBytes.startsWith('04') || commitmentBytes.length !== 130) {
      throw new Error('Invalid commitment format: expected uncompressed point (04 + 64 hex x + 64 hex y)');
    }
    const userCommitment: Point = {
      x: hexToBigInt('0x' + commitmentBytes.slice(2, 66)),
      y: hexToBigInt('0x' + commitmentBytes.slice(66, 130)),
    };

    // 2. Verify payment
    const payment = await this.verifyPayment(request.payment);
    if (!payment.valid) {
      throw new Error('Invalid payment proof');
    }

    // 3. Determine tier from payment amount
    const amountCents = Math.round(payment.amountUSDC * 100);
    const tierConfig = this.tiers.find(t => amountCents >= t.minAmountCents);
    if (!tierConfig) {
      throw new Error(`Payment amount $${payment.amountUSDC} below minimum tier`);
    }

    // 4. Build credential
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + tierConfig.durationSeconds;

    // 5. Compute message hash for signature (spec §9)
    // Signs: (service_id, tier, max_presentations, issued_at, expires_at, commitment_x, commitment_y)
    const message = poseidonHash7(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.maxPresentations),
      BigInt(now),
      BigInt(expiresAt),
      userCommitment.x,
      userCommitment.y,
    );

    // 6. Sign with Schnorr
    const signature = await schnorrSign(this.config.secretKey, message);

    // 7. Encode signature as hex string: r.x (64) + r.y (64) + s (64) = 192 hex chars
    const sigHex = '0x' +
      signature.r.x.toString(16).padStart(64, '0') +
      signature.r.y.toString(16).padStart(64, '0') +
      signature.s.toString(16).padStart(64, '0');

    // 8. Encode commitment as hex (without scheme prefix, spec §7.3)
    const commitmentOutHex = '0x04' +
      userCommitment.x.toString(16).padStart(64, '0') +
      userCommitment.y.toString(16).padStart(64, '0');

    // 9. Return settlement response (spec §7.3)
    // NOTE: Facilitator MUST NOT store or log commitment-to-payment mappings beyond operational needs
    const response: SettlementResponse = {
      payment_receipt: {
        status: 'settled',
        txHash: payment.txHash,
        amountUSDC: payment.amountUSDC,
      },
      zk_session: {
        credential: {
          scheme: 'pedersen-schnorr-bn254',
          service_id: bigIntToHex(this.config.serviceId),
          tier: tierConfig.tier,
          max_presentations: tierConfig.maxPresentations,
          issued_at: now,
          expires_at: expiresAt,
          commitment: commitmentOutHex,
          signature: sigHex,
        },
      },
    };

    console.log('[Facilitator] Issued credential for tier', tierConfig.tier);
    return response;
  }

  /**
   * Issue a credential after verifying payment
   * @deprecated Use settle() instead for spec-compliant API
   */
  async issueCredential(request: IssuanceRequest): Promise<IssuanceResponse> {
    // Ensure initialized (public key derived) to prevent race conditions
    await this.initialize();

    // 1. Verify payment
    const payment = await this.verifyPayment(request.paymentProof);
    if (!payment.valid) {
      throw new Error('Invalid payment proof');
    }

    // 2. Determine tier from payment amount
    // Convert to integer cents to avoid floating-point precision issues
    const amountCents = Math.round(payment.amountUSDC * 100);
    const tierConfig = this.tiers.find(t => amountCents >= t.minAmountCents);
    if (!tierConfig) {
      throw new Error(`Payment amount $${payment.amountUSDC} below minimum tier`);
    }

    // 3. Build credential
    const now = Math.floor(Date.now() / 1000);
    const userCommitment: Point = {
      x: hexToBigInt(request.userCommitment.x),
      y: hexToBigInt(request.userCommitment.y),
    };

    // 4. Compute message hash for signature
    const message = poseidonHash7(
      this.config.serviceId,
      BigInt(tierConfig.tier),
      BigInt(tierConfig.maxPresentations),
      BigInt(now),
      BigInt(now + tierConfig.durationSeconds),
      userCommitment.x,
      userCommitment.y,
    );

    // 5. Sign with Schnorr
    const signature = await schnorrSign(this.config.secretKey, message);

    const pubKey = await this.getPublicKey();

    // 6. Return signed credential
    const response = {
      credential: {
        serviceId: bigIntToHex(this.config.serviceId),
        tier: tierConfig.tier,
        maxPresentations: tierConfig.maxPresentations,
        issuedAt: now,
        expiresAt: now + tierConfig.durationSeconds,
        userCommitment: {
          x: bigIntToHex(userCommitment.x),
          y: bigIntToHex(userCommitment.y),
        },
        signature: {
          r: {
            x: bigIntToHex(signature.r.x),
            y: bigIntToHex(signature.r.y),
          },
          s: bigIntToHex(signature.s),
        },
        issuerPubkey: {
          x: bigIntToHex(pubKey.x),
          y: bigIntToHex(pubKey.y),
        },
      },
    };
    console.log('[Issuer] Returning signature:', response.credential.signature);
    return response;
  }

  /**
   * Verify an x402 payment
   */
  private async verifyPayment(
    proof: IssuanceRequest['paymentProof']
  ): Promise<PaymentResult> {
    // Mock payments for development/testing
    if (proof.mock && this.config.allowMockPayments) {
      console.log(`[Issuer] Accepting mock payment: $${proof.mock.amountUSDC} from ${proof.mock.payer}`);
      return {
        valid: true,
        amountUSDC: proof.mock.amountUSDC,
        payer: proof.mock.payer,
      };
    }

    // On-chain payment verification
    if (proof.txHash) {
      if (!this.paymentVerifier) {
        console.error(`[Issuer] On-chain verification requested but not configured`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      const txHash = proof.txHash;
      if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
        console.error(`[Issuer] Invalid txHash format for on-chain verification: ${txHash}`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      const result = await this.paymentVerifier.verifyTransaction(txHash as `0x${string}`);

      if (!result.valid) {
        console.error(`[Issuer] Payment verification failed: ${result.error}`);
        return { valid: false, amountUSDC: 0, payer: '' };
      }

      return {
        valid: true,
        amountUSDC: result.amountUSDC,
        payer: result.from,
        txHash: result.txHash,
      };
    }

    if (proof.facilitatorReceipt) {
      // TODO: Verify with x402 facilitator API
      console.log(`[Issuer] Facilitator verification not yet implemented`);
      return { valid: false, amountUSDC: 0, payer: '' };
    }

    return { valid: false, amountUSDC: 0, payer: '' };
  }
}
