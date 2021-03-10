import { SHA3 } from 'sha3';
import * as secp from 'noble-secp256k1';
const crypto = require('crypto');
const atob = require('atob');

import { ILogger } from '../logging/logging.types';
import { ConfigInterface, KeySplittingConfigSchema } from './keysplitting.service.types';
import { BZECert, SynMessagePayload, DataMessagePayload, SynMessage, DataMessageWrapper, SynMessageWrapper, KeySplittingMessage } from './keysplitting-types';

export class KeySplittingService {
    private config: ConfigInterface
    private data: KeySplittingConfigSchema
    private logger: ILogger;
    private publicKey: Uint8Array;
    private privateKey: Uint8Array;
    private expectedHPointer: string;
    private currentHPointer: string;

    constructor(config: ConfigInterface, logger: ILogger) {
        this.config = config;
        this.logger = logger;
        this.data = this.config.loadKeySplitting();

        // Initially our expected HPointer is null
        this.expectedHPointer = null;
        this.currentHPointer = null;

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
            initialIdToken: this.data.initialIdToken,
            currentIdToken: currentIdToken,
            clientPublicKey: this.data.publicKey,
            rand: this.data.cerRand,
            signatureOnRand: this.data.cerRandSig
        };
    }

    public async getBZECertHash(currentIdToken: string): Promise<string> {
        let BZECert = await this.getBZECert(currentIdToken);
        return this.hashHelper(this.JSONstringifyOrder(BZECert));
    }

    public async generateCerRand() {
        // Helper function to generate and store our cerRand and cerRandSig
        var cerRand = crypto.randomBytes(32);
        this.data.cerRand = cerRand.toString('base64');

        var cerRandSig = await this.signHelper(cerRand);
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

    public async setExpectedHPointerSyn(synMessage: SynMessagePayload) {
        // Helper function to save our syn hash
        this.expectedHPointer = this.hashHelper(this.JSONstringifyOrder(synMessage));
    }

    public async setExpectedHPointerData(dataMessage: DataMessagePayload) {
        // Helper function to save our data hash
        this.expectedHPointer = this.hashHelper(this.JSONstringifyOrder(dataMessage));
    }

    public validateHPointer(hPointer: string) {
        if (this.expectedHPointer != null)
            if (this.expectedHPointer == hPointer) {
                // Update the current HPointer
                this.currentHPointer = this.expectedHPointer;

                // Return True
                return true;
            } else {
                // Else they don't equal each other, return False
                return false;
            }
        throw Error('Expected HPointer is not set!');
    }

    private JSONstringifyOrder(obj: any) {
        // Ref: https://stackoverflow.com/a/53593328/9186330
        let allKeys: string[] = [];
        JSON.stringify(obj, function (key, value) { allKeys.push(key); return value; });
        allKeys.sort();
        return JSON.stringify( obj, allKeys);
    }

    public async buildDataMessage(targetId: string, action: string, currentIdToken: string): Promise<DataMessageWrapper> {
        // Build our payload
        let dataMessage = {
            payload: {
                type: 'DATA',
                action: action,
                hPointer: 'placeholder',
                targetId: targetId,
                BZECert: await this.getBZECertHash(currentIdToken),
                payload: 'payload'
            },
            signature: ''
        };

        // Then calculate our signature
        let signature = await this.signMessagePayload<DataMessagePayload>(dataMessage);

        // Then build and return our wrapped object
        dataMessage.signature = signature;
        return {
            dataPayload : dataMessage
        };
    }

    public async buildSynMessage(targetId: string, action: string, currentIdToken: string): Promise<SynMessageWrapper> {
        // Build our payload
        let synMessage = {
            payload: {
                type: 'SYN',
                action: action,
                nonce: crypto.randomBytes(32).toString('base64'),
                targetId: targetId,
                BZECert: await this.getBZECert(currentIdToken)
            },
            signature: ''
        };

        // Then calculate our signature
        let signature = await this.signMessagePayload<SynMessagePayload>(synMessage);

        // Then build and return our wrapped object
        synMessage.signature = signature;
        return {
            synPayload : synMessage
        };
    }

    private async signMessagePayload<T>(messagePayload: KeySplittingMessage<T>) {
        return await this.signHelper(this.JSONstringifyOrder(messagePayload.payload));
    }

    private hashHelper(toHash: string) {
        // Helper function to hash a string for us
        const hashClient = new SHA3(256);
        hashClient.update(toHash);
        return hashClient.digest('base64');
    }

    private async signHelper(toSign: string) {
        // Helper function to sign a string for us
        return await secp.sign(toSign, this.privateKey);
    }

    private loadKeys() {
        // Helper function to check if keys are undefined and load them in
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