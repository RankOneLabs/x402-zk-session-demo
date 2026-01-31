/**
 * ZK Session Client
 * 
 * Manages credentials and generates authenticated requests.
 */

import {
  pedersenCommit,
  randomFieldElement,
  poseidonHash3,
  stringToField,
  bigIntToHex,
  hexToBigInt,
} from '@demo/crypto';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { CompiledCircuit } from '@noir-lang/types';
import { CredentialStorage, type StoredCredential } from './storage.js';
import x402Circuit from './circuits/x402_zk_session.json' with { type: 'json' };
import { ProofCache, type CachedProof } from './cache.js';

export type PresentationStrategy =
  | 'max-privacy'      // Always increment index
  | 'max-performance'  // Always reuse index=0
  | 'per-origin'       // One index per origin
  | 'time-bucketed';   // New index every N seconds

export interface ClientConfig {
  /** Presentation strategy */
  strategy: PresentationStrategy;
  /** Time bucket size in seconds (for time-bucketed strategy) */
  timeBucketSeconds: number;
  /** Enable proof caching */
  enableProofCache: boolean;
  /** Storage path (optional) */
  storagePath?: string;
}

const DEFAULT_CONFIG: ClientConfig = {
  strategy: 'time-bucketed',
  timeBucketSeconds: 300, // 5 minutes
  enableProofCache: true,
};

export class ZkSessionClient {
  private readonly config: ClientConfig;
  private readonly storage: CredentialStorage;
  private readonly proofCache: ProofCache;
  private readonly originIndices: Map<string, number> = new Map();

  constructor(config: Partial<ClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.storage = new CredentialStorage(this.config.storagePath);
    this.proofCache = new ProofCache();
  }

  /**
   * Obtain a credential from an issuer
   */
  async obtainCredential(
    issuerUrl: string,
    paymentProof: {
      mock?: { amountUSDC: number; payer: string };
      txHash?: string;
    }
  ): Promise<StoredCredential> {
    // Generate secrets
    const nullifierSeed = randomFieldElement();
    const blindingFactor = randomFieldElement();

    // Compute commitment (async - uses Barretenberg)
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);

    // Request credential from issuer
    const response = await fetch(`${issuerUrl}/credentials/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        paymentProof,
        userCommitment: {
          x: bigIntToHex(commitment.point.x),
          y: bigIntToHex(commitment.point.y),
        },
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText })) as { error: string };
      throw new Error(`Failed to obtain credential: ${error.error}`);
    }

    const data = await response.json() as { credential: any };
    const { credential } = data;

    // Store with secrets
    const stored: StoredCredential = {
      ...credential,
      nullifierSeed: bigIntToHex(nullifierSeed),
      blindingFactor: bigIntToHex(blindingFactor),
      presentationCount: 0,
      obtainedAt: Date.now(),
      issuerUrl,
    };

    this.storage.set(stored);
    return stored;
  }

  /**
   * Make an authenticated request
   */
  async makeAuthenticatedRequest(
    url: string,
    options: RequestInit & { forceUnlinkable?: boolean } = {}
  ): Promise<Response> {
    const urlObj = new URL(url);
    const originId = stringToField(urlObj.pathname);

    // Find credential for this service
    // For demo, use the first available credential
    const credentials = this.storage.list();
    if (credentials.length === 0) {
      throw new Error('No credentials available. Obtain one first.');
    }

    const credential = credentials[0];

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (credential.expiresAt < now) {
      throw new Error('Credential expired. Obtain a new one.');
    }

    // Select presentation index based on strategy
    const { index, timeBucket } = this.selectPresentationIndex(
      credential,
      originId,
      options.forceUnlinkable
    );

    // Check if we have a cached proof
    const cachedProof = this.config.enableProofCache
      ? this.proofCache.get(
        credential.serviceId,
        originId.toString(),
        index,
        timeBucket
      )
      : undefined;

    let proof: CachedProof;

    if (cachedProof) {
      console.log('[Client] Cache hit, reusing proof');
      proof = cachedProof;
    } else {
      console.log('[Client] Generating new proof...');
      proof = await this.generateProof(credential, originId, index, timeBucket);

      // Cache the proof
      if (this.config.enableProofCache) {
        this.proofCache.set(
          credential.serviceId,
          originId.toString(),
          index,
          proof,
          timeBucket
        );
      }
    }

    // Add ZK session headers
    const headers = new Headers(options.headers);
    headers.set('ZK-SESSION-PROOF', proof.proof);
    headers.set('ZK-SESSION-TOKEN', proof.originToken);
    headers.set('ZK-SESSION-TIER', proof.tier.toString());

    return fetch(url, { ...options, headers });
  }

  /**
   * Generate a ZK proof
   */
  private async generateProof(
    credential: StoredCredential,
    originId: bigint,
    presentationIndex: number,
    timeBucket?: number
  ): Promise<CachedProof> {
    const circuit = x402Circuit as any;
    // Use UltraHonk backend matching the verifier
    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir = new Noir(circuit);

    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    const expiresAt = timeBucket
      ? timeBucket + this.config.timeBucketSeconds
      : Number(currentTime) + 60;

    // Helper to format as hex string for Noir (0x prefix)
    const fmt = (n: bigint | number | string) => bigIntToHex(BigInt(n));

    // Prepare inputs matching circuit ABI
    const input = {
      // Public inputs
      // Note: Noir expects these to be part of the witness generation
      service_id: fmt(credential.serviceId),
      current_time: fmt(currentTime),
      origin_id: fmt(originId),
      issuer_pubkey_x: fmt(credential.issuerPubkey.x),
      issuer_pubkey_y: fmt(credential.issuerPubkey.y),

      // Private inputs
      cred_service_id: fmt(credential.serviceId),
      cred_tier: fmt(credential.tier),
      cred_max_presentations: fmt(credential.maxPresentations),
      cred_issued_at: fmt(credential.issuedAt),
      cred_expires_at: fmt(credential.expiresAt),
      cred_commitment_x: fmt(credential.userCommitment.x),
      cred_commitment_y: fmt(credential.userCommitment.y),

      sig_r_x: fmt(credential.signature.r.x),
      sig_r_y: fmt(credential.signature.r.y),
      sig_s_lo: fmt(hexToBigInt(credential.signature.s) & ((1n << 128n) - 1n)),
      sig_s_hi: fmt(hexToBigInt(credential.signature.s) >> 128n),

      nullifier_seed: fmt(credential.nullifierSeed),
      blinding_factor: fmt(credential.blindingFactor),

      presentation_index: fmt(presentationIndex),
    };

    try {
      console.log('[Client] Issuer Pubkey:', credential.issuerPubkey);
      console.log('[Client] User Commitment:', credential.userCommitment);
      console.log('[Client] Signature:', credential.signature);

      console.log('[Client] Generating witness with Noir...');
      const { witness } = await noir.execute(input);

      console.log('[Client] Generating proof with Barretenberg...');
      const proofData = await backend.generateProof(witness);
      console.log('[Client] Proof generation successful');

      const { proof, publicInputs } = proofData;
      console.log(`[Client] Proof size: ${proof.length} bytes, ${publicInputs.length} public inputs`);

      // Extract outputs from public inputs
      // Layout: [service_id, current_time, origin_id, issuer_pubkey_x, issuer_pubkey_y, origin_token, tier]
      // We need last 2
      const originToken = publicInputs[5];
      const tier = publicInputs[6];

      // Format proof data for transmission (JSON with base64 proof)
      const transmissionData = {
        proof: Buffer.from(proof).toString('base64'),
        publicInputs
      };

      const proofB64 = Buffer.from(JSON.stringify(transmissionData)).toString('base64');

      return {
        proof: proofB64,
        originToken: originToken,
        tier: Number(hexToBigInt(tier)),
        expiresAt,
        meta: {
          serviceId: credential.serviceId,
          originId: originId.toString(),
          presentationIndex,
          timeBucket,
        },
      };
    } finally {
      // Cleanup to prevent memory leaks/hanging processes
      await backend.destroy();
    }
  }

  /**
   * Select presentation index based on strategy
   */
  private selectPresentationIndex(
    credential: StoredCredential,
    originId: bigint,
    forceUnlinkable?: boolean
  ): { index: number; timeBucket?: number } {
    // Force unlinkable overrides strategy
    if (forceUnlinkable) {
      const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
      return { index };
    }

    switch (this.config.strategy) {
      case 'max-privacy': {
        const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
        return { index };
      }

      case 'max-performance':
        return { index: 0 };

      case 'per-origin': {
        const originKey = originId.toString();
        if (!this.originIndices.has(originKey)) {
          const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
          this.originIndices.set(originKey, index);
        }
        return { index: this.originIndices.get(originKey)! };
      }

      case 'time-bucketed': {
        const now = Math.floor(Date.now() / 1000);
        const bucket = Math.floor(now / this.config.timeBucketSeconds);
        const timeBucket = bucket * this.config.timeBucketSeconds;

        // Use hash(timeBucket, serviceId, obtainedAt) for deterministic but unpredictable index
        const hash = poseidonHash3(
          BigInt(timeBucket),
          BigInt(credential.serviceId),
          BigInt(credential.obtainedAt)
        );

        const index = Number(hash % BigInt(credential.maxPresentations));
        return { index, timeBucket };
      }

      default:
        return { index: 0 };
    }
  }

  /**
   * List stored credentials
   */
  listCredentials(): StoredCredential[] {
    return this.storage.list();
  }

  /**
   * Get credential status
   */
  getCredentialStatus(serviceId?: string): {
    credential: StoredCredential;
    status: 'valid' | 'expired' | 'exhausted';
    remainingPresentations: number;
    expiresIn: number;
  } | undefined {
    const credentials = this.storage.list();
    const credential = serviceId
      ? credentials.find(c => c.serviceId === serviceId)
      : credentials[0];

    if (!credential) {
      return undefined;
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = credential.expiresAt - now;
    const remaining = credential.maxPresentations - credential.presentationCount;

    let status: 'valid' | 'expired' | 'exhausted';
    if (expiresIn <= 0) {
      status = 'expired';
    } else if (remaining <= 0) {
      status = 'exhausted';
    } else {
      status = 'valid';
    }

    return {
      credential,
      status,
      remainingPresentations: Math.max(0, remaining),
      expiresIn: Math.max(0, expiresIn),
    };
  }

  /**
   * Clear all stored credentials
   */
  clearCredentials(): void {
    this.storage.clear();
    this.proofCache.clear();
    this.originIndices.clear();
  }
}
