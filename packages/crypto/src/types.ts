/**
 * Common types for cryptographic operations
 */

/** A point on the BN254 curve */
export interface Point {
  x: bigint;
  y: bigint;
}

/** A Schnorr signature */
export interface SchnorrSignature {
  r: Point;
  s: bigint;
}

/** A Pedersen commitment with opening */
export interface Commitment {
  point: Point;
  secret: bigint;
  blinding: bigint;
}

/** Credential as signed by issuer */
export interface SignedCredential {
  serviceId: bigint;
  tier: number;
  maxPresentations: number;
  issuedAt: number;
  expiresAt: number;
  userCommitment: Point;
  signature: SchnorrSignature;
}

/** Full credential with user secrets */
export interface FullCredential extends SignedCredential {
  nullifierSeed: bigint;
  blindingFactor: bigint;
}

/** Public inputs to the circuit */
export interface PublicInputs {
  serviceId: bigint;
  currentTime: number;
  originId: bigint;
  issuerPubkeyX: bigint;
  issuerPubkeyY: bigint;
}

/** Public outputs from the circuit */
export interface ProofOutputs {
  originToken: bigint;
  tier: number;
}
