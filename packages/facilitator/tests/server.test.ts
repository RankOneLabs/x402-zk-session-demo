import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createFacilitatorServer } from '../src/server.js';
import type { ZKCredentialKeysResponse } from '@demo/crypto';

describe('Facilitator Server', () => {
    const port = 3002; // Use a different port to avoid conflicts
    const serverConfig = {
        port,
        serviceId: 123n,
        secretKey: 123456789n,
        kid: 'test-key-1',
        tiers: [
            { minAmountCents: 10, tier: 1, identityLimit: 10, durationSeconds: 3600 }
        ]
    };

    let server: ReturnType<typeof createFacilitatorServer>;

    beforeAll(async () => {
        server = createFacilitatorServer(serverConfig);
        await server.start();
    });

    afterAll(async () => {
        await server.stop();
    });

    it('should expose .well-known/zk-credential-keys', async () => {
        const response = await fetch(`http://localhost:${port}/.well-known/zk-credential-keys`);
        expect(response.status).toBe(200);

        const data = await response.json() as ZKCredentialKeysResponse;
        expect(data.keys).toBeDefined();
        expect(data.keys.length).toBeGreaterThan(0);

        const key = data.keys[0];
        expect(key.kid).toBe('test-key-1');
        expect(key.kty).toBe('ZK');
        expect(key.crv).toBe('BN254');
        expect(key.alg).toBe('pedersen-schnorr-poseidon-ultrahonk');
        expect(key.x).toMatch(/^0x[0-9a-f]{64}$/);
        expect(key.y).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it('should return 404 for unknown endpoints', async () => {
        const response = await fetch(`http://localhost:${port}/unknown`);
        expect(response.status).toBe(404);
    });
});
