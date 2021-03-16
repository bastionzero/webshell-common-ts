import { SHA3 } from 'sha3';
import * as ed from 'noble-ed25519';
const crypto = require('crypto');

import { ILogger } from '../logging/logging.types';
import { ConfigInterface, KeySplittingConfigSchema } from './keysplitting.service.types';
import { BZECert, SynMessagePayload, DataMessagePayload, DataMessageWrapper, SynMessageWrapper, KeySplittingMessage } from './keysplitting-types';

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
    }

    public async init() {
        // Init function so we can wait on async function calls
        // Load our keys if they are there
        await this.loadKeys();
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

    public setExpectedHPointer(message: any) {
        // Helper function to set our expected HPointer
        this.expectedHPointer = this.hashHelper(this.JSONstringifyOrder(message));
    }

    public setCurrentHPointer(message: any) {
        // Helper function to set our current HPointer
        this.currentHPointer = this.hashHelper(this.JSONstringifyOrder(message));
    }

    public validateHPointer(hPointer: string) {
        if (this.expectedHPointer != null)
            if (this.expectedHPointer == hPointer) {
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

    public async buildDataMessage<TDataPayload>(targetId: string, action: string, currentIdToken: string, payload: TDataPayload): Promise<DataMessageWrapper> {
        // Build our payload
        let dataMessage = {
            payload: {
                type: 'DATA',
                action: action,
                hPointer: this.currentHPointer,
                targetId: targetId,
                BZECert: await this.getBZECertHash(currentIdToken),
                payload: this.JSONstringifyOrder(payload)
            },
            signature: ''
        };

        // Then calculate our signature
        let signature = await this.signDataPayload(dataMessage.payload);

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
        let signature = await this.signSynMessage(synMessage.payload);

        // Then build and return our wrapped object
        synMessage.signature = signature;
        return {
            synPayload : synMessage
        };
    }

    private async signDataPayload(payload: DataMessagePayload) {
        // When signing data message we have to sign the hash
        let toSign = this.hashHelper(this.JSONstringifyOrder(payload), 'hex')
        return await ed.sign(toSign, this.privateKey);
    }
    private async signSynMessage(payload: SynMessagePayload) {
        return await this.signHelper(this.JSONstringifyOrder(payload));
    }

    private hashHelper(toHash: string, format: BufferEncoding = 'base64') {
        // Helper function to hash a string for us
        const hashClient = new SHA3(256);
        hashClient.update(toHash);
        return hashClient.digest(format);
    }

    // private hashBufferHelper(toHash: Buffer) {
    //     // Helper function to hash a buffer for us
    //     const hashClient = new SHA3(256);
    //     hashClient.update(toHash);
    //     return hashClient.digest('base64');
    // }

    private async signHelper(toSign: string) {
        // Helper function to sign a string for us
        return await ed.sign(toSign, this.privateKey);
    }

    private async loadKeys() {
        // Helper function to check if keys are undefined and load them in
        if (this.data.privateKey != undefined) {
            // We need to load in our keys
            this.privateKey = Buffer.from(this.data.privateKey, 'hex');
            this.publicKey = await ed.getPublicKey(this.privateKey);

            // Validate the public key
            if (Buffer.from(this.publicKey).toString('hex') != this.data.publicKey) {
                throw new Error('Error loading keys, please check your key configuration');
            }
            this.logger.debug('Loaded keysplitting keys');
        }
    }

    private async generateKeys() {
        // Create our keys
        this.privateKey = ed.utils.randomPrivateKey(); 
        this.publicKey = await ed.getPublicKey(this.privateKey);

        // Update our config
        this.data.privateKey = Buffer.from(this.privateKey).toString('hex');
        this.data.publicKey = Buffer.from(this.publicKey).toString('hex');
        this.config.updateKeySplitting(this.data);
        this.logger.debug('Generated keysplitting keys');
    }

    // private arrayBufferToBase64(arrayBuffer: Uint8Array) {
    //     var byteArray = new Uint8Array(arrayBuffer);
    //     var byteString = '';
    //     for(var i=0; i < byteArray.byteLength; i++) {
    //         byteString += String.fromCharCode(byteArray[i]);
    //     }
    //     var b64 = Buffer.from(byteString).toString('base64');
    
    //     return b64;
    // }
    
    // private addNewLines(str: string) {
    //     var finalString = '';
    //     while(str.length > 0) {
    //         finalString += str.substring(0, 64) + '\n';
    //         str = str.substring(64);
    //     }
    
    //     return finalString;
    // }
    
    // private toPem(privateKey: Uint8Array) {
    //     var b64 = this.addNewLines(this.arrayBufferToBase64(privateKey));
    //     var pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "-----END PRIVATE KEY-----";
        
    //     return pem;
    // }
}