import { SHA3 } from 'sha3';
import * as secp from 'noble-secp256k1';
const crypto = require('crypto');
const atob = require('atob');

import { ILogger } from '../logging/logging.types';
import { ConfigInterface, KeySplittingConfigSchema } from './keysplitting.service.types';
import { BZECert } from './keysplitting-types';

export class KeySplittingService {
    private config: ConfigInterface
    private data: KeySplittingConfigSchema
    private logger: ILogger;
    private publicKey: Uint8Array;
    private privateKey: Uint8Array;

    constructor(config: ConfigInterface, logger: ILogger) {
        this.config = config;
        this.logger = logger;
        this.data = this.config.loadKeySplitting();

        // Load our keys if they are there
        this.loadKeys();
    }

    public setInitialIdToken(latestIdToken: string) {
        this.data.initialIdToken = latestIdToken;
        this.config.updateKeySplitting(this.data);
        this.logger.debug('Updated latestIdToken');
    }

    public getConfig() {
        return this.data;
    }

    public async getBZECert(currentIdToken: string): Promise<BZECert> {
        if (this.data.initialIdToken == undefined || this.data.publicKey == undefined || this.data.cerRand == undefined || this.data.cerRandSig == undefined)
            throw new Error('Undefined values in BZECert!');
        return {
            InitialIdToken: this.data.initialIdToken,
            CurrentIdToken: currentIdToken,
            ClientPublicKey: this.data.publicKey,
            Rand: this.data.cerRand,
            SignatureOnRand: this.data.cerRandSig
        };
    }

    public async getBZECertHash(currentIdToken: string): Promise<string> {
        let BZECert = this.getBZECert(currentIdToken);
        return this.hashHelper(BZECert.toString());
    }

    public async generateCerRand() {
        // Helper function to generate and store our cerRand and cerRandSig
        var cerRand = crypto.randomBytes(32);
        this.data.cerRand = cerRand.toString('base64');

        var cerRandSig = await secp.sign(cerRand, this.privateKey);
        this.data.cerRandSig = Buffer.from(cerRandSig).toString('base64');

        // Update our config
        this.config.updateKeySplitting(this.data);
        this.logger.debug('Generated cerRand and cerRandSig');
    }


    public createNonce() {
        // Helper function to create a Nonce
        const hashClient = new SHA3(256);
        const hashString = ''.concat(this.data.publicKey, this.data.cerRandSig, this.data.cerRand);

        // Update and return
        hashClient.update(hashString);

        let nonce = hashClient.digest('base64');
        this.logger.debug(`Creating new nonce: ${nonce}`);
        return nonce;
    }

    public async generateKeysplittingLoginData() {
        // Reset our keys and recreate them
        this.generateKeys();
        this.generateCerRand();
        this.logger.debug('Reset keysplitting service');
    }

    private hashHelper(toHash: string) {
        // Helper function to hash a string for us
        const hashClient = new SHA3(256);
        hashClient.update(toHash);
        return hashClient.digest('base64');
    }

    private loadKeys() {
        // Helper function to check if keys are undefined and, generate new ones
        if (this.data.privateKey != undefined) {
            // We need to load in our keys
            this.privateKey = Buffer.from(this.data.privateKey, 'base64');
            this.publicKey = secp.getPublicKey(this.privateKey);

            // Validate the public key
            if (Buffer.from(this.publicKey).toString('base64') != this.data.publicKey) {
                throw new Error('Error loading keys, please check your key configuration');
            }
            this.logger.debug('Loaded keysplitting keys');
        }
    }

    private generateKeys() {
        // Create our keys
        this.privateKey = crypto.randomBytes(32);
        this.publicKey = secp.getPublicKey(this.privateKey);

        // Update our config
        this.data.privateKey = Buffer.from(this.privateKey).toString('base64');
        this.data.publicKey = Buffer.from(this.publicKey).toString('base64');
        this.config.updateKeySplitting(this.data);
        this.logger.debug('Generated keysplitting keys');
    }
}