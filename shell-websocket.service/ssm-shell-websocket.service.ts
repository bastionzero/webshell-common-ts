import { Observable, Subject } from 'rxjs';
import { timeout } from 'rxjs/operators';
import { ShellEventType, ShellHubIncomingMessages, ShellHubOutgoingMessages, TerminalSize } from './shell-websocket.service.types';
import { BaseShellWebsocketService } from './base-shell-websocket.service';

import { AuthConfigService } from '../auth-config-service/auth-config.service';
import { ILogger } from '../logging/logging.types';
import { KeySplittingService } from '../keysplitting.service/keysplitting.service';
import { DataAckMessageWrapper, DataAckPayload, DataMessageWrapper, ErrorMessageWrapper, ShellActions, ShellTerminalSizeActionPayload, SsmTargetInfo, SynAckMessageWrapper, SynAckPayload, SynMessageWrapper, KeysplittingErrorTypes } from '../keysplitting.service/keysplitting-types';

interface ShellMessage {
    inputType: ShellActions,
    inputPayload: any;
    seqNum: number;
}

// bzero-agent version >= 3.0.732.16 is keysplitting compatible for interactive shells
const KeysplittingMinimumAgentVersion = 16;

export function isAgentKeysplittingReady(agentVersion: string): boolean {
    try {
        const version = parseInt(agentVersion.split('.')[3]);
        return version >= KeysplittingMinimumAgentVersion;
    } catch(err) {
        return false;
    }
}

const KeysplittingHandshakeTimeout = 45; // in seconds

export class SsmShellWebsocketService extends BaseShellWebsocketService
{
    private keysplittingHandshakeCompleteSubject = new Subject<boolean>();
    private keysplittingHandshakeComplete: Observable<boolean> = this.keysplittingHandshakeCompleteSubject.asObservable();

    private synShellOpenMessageHPointer: string;
    private synAckShellOpenMessageHPointer: string;
    private dataShellOpenMessageHPointer: string;
    private dataAckShellOpenMessageHPointer: string;

    private sequenceNumber = 0;
    private currentInputMessage: ShellMessage;
    private lastAckHPointer: string;

    private inputMessageBuffer: ShellMessage[] = [];
    private outgoingShellInputMessages: { [h: string]: ShellMessage } = {};

    private isActiveClient = false;

    private currentIdToken: string = undefined;

    constructor(
        private keySplittingService: KeySplittingService,
        private targetInfo: SsmTargetInfo,
        protected logger: ILogger,
        protected authConfigService: AuthConfigService,
        protected connectionId: string,
        inputStream: Subject<string>,
        resizeStream: Subject<TerminalSize>
    ) {
        super(logger, authConfigService, connectionId, inputStream, resizeStream);
    }

    public async start() {
        await super.start();

        // Make sure keysplitting service is initialized (keys loaded)
        await this.keySplittingService.init();

        this.websocket.on(ShellHubIncomingMessages.synAck, (synAck) => this.handleSynAck(synAck));
        this.websocket.on(ShellHubIncomingMessages.dataAck, (dataAck) => this.handleDataAck(dataAck));
        this.websocket.on(ShellHubIncomingMessages.keysplittingError, (ksError) => this.handleKeysplittingError(ksError));

        await this.websocket.start();
    }

    public dispose() : void {
        super.dispose();
    }

    private resetKeysplittingState() {
        this.sequenceNumber = 0;
        this.currentInputMessage = undefined;
        this.lastAckHPointer = undefined;
        this.inputMessageBuffer = [];
        this.outgoingShellInputMessages = {};
        this.isActiveClient = false;
    }

    public async shellReattach(): Promise<void> {
        if(this.isActiveClient) {
            this.logger.warn('Cannot reattach shell already the active client');
            return;
        }

        this.resetKeysplittingState();
        await this.performKeysplittingHandshake();
    }

    protected async handleShellStart(): Promise<void> {
        // reset all keysplitting state in case this is a reconnect attempt
        // after a previous error occurred
        this.resetKeysplittingState();
        await this.performKeysplittingHandshake();
    }

    protected async handleInput(data: string): Promise<void> {
        this.logger.debug(`got new input ${data}`);

        // Skip new input messages if we are not the active client
        if(! this.isActiveClient) {
            this.logger.debug(`[handleInput] received when not active client...skipping.`);
            return;
        }

        const inputPayload = data;

        // Add to input message buffer
        const shellInput: ShellMessage = {
            inputType: ShellActions.Input,
            inputPayload: inputPayload,
            seqNum: this.sequenceNumber++,
        };
        this.inputMessageBuffer.push(shellInput);

        await this.processInputMessageQueue();
    }

    protected async handleResize(terminalSize: TerminalSize): Promise<void> {
        this.logger.debug(`New terminal resize event (rows: ${terminalSize.rows} cols: ${terminalSize.columns})`);

        // Skip new resize messages if we are not the active client
        if(! this.isActiveClient) {
            this.logger.debug(`[handleResize] received when not active client...skipping.`);
            return;
        }

        const inputPayload: ShellTerminalSizeActionPayload = {
            rows: terminalSize.rows,
            cols: terminalSize.columns
        };

        // Add to input message buffer
        const shellInput: ShellMessage = {
            inputType: ShellActions.Resize,
            inputPayload: inputPayload,
            seqNum: this.sequenceNumber++,
        };
        this.inputMessageBuffer.push(shellInput);

        await this.processInputMessageQueue();
    }

    private async processInputMessageQueue() {
        if (! this.currentInputMessage && this.inputMessageBuffer.length > 0) {
            this.currentInputMessage = this.inputMessageBuffer[0];

            await this.sendShellInputDataMessage(this.currentInputMessage);
        }
    }

    private async performKeysplittingHandshake(): Promise<boolean> {
        if(this.targetInfo.agentVersion === '') {
            throw new Error(`Unable to perform keysplitting handshake: agentVersion is not known for target ${this.targetInfo.id}`);
        }
        if(this.targetInfo.agentId === '' ) {
            throw new Error(`Unknown agentId in sendOpenShellSynMessage for target ${this.targetInfo.id}`);
        }

        this.logger.debug(`Starting keysplitting handshake with ${this.targetInfo.id}`);
        this.logger.debug(`Agent Version ${this.targetInfo.agentVersion}, Agent ID: ${this.targetInfo.agentId}`);

        return new Promise(async (res, rej) => {
            this.keysplittingHandshakeComplete
                .pipe(timeout(KeysplittingHandshakeTimeout * 1000))
                .subscribe(
                    completedSuccessfully => res(completedSuccessfully),
                    _ => rej(`Keyspliting handshake timed out after ${KeysplittingHandshakeTimeout} seconds`)
                );

            // start the keysplitting handshake
            await this.sendShellOpenSynMessage();
        });
    }

    private async sendShellOpenSynMessage() {
        this.currentIdToken = await this.authConfigService.getIdToken();
        const synMessage = await this.keySplittingService.buildSynMessage(
            this.targetInfo.agentId,
            ShellActions.Open,
            this.currentIdToken
        );

        this.synShellOpenMessageHPointer = this.keySplittingService.getHPointer(synMessage.synPayload.payload);
        await this.sendSynMessage(synMessage);
    }

    private async sendShellOpenDataMessage() {
        // Check whether current BZCert's idtoken has been refreshed
        // If yes we need to perform a new handshake before sending data
        const IdToken = await this.authConfigService.getIdToken();
        if (this.currentIdToken !== IdToken){
            this.logger.debug(`Current idtoken has expired, requesting new and performing new ks handshake`);
            await this.performKeysplittingHandshake();
            return;
        }
        const shellOpenDataPayload = {};
        const dataMessage = await this.keySplittingService.buildDataMessage(
            this.targetInfo.agentId,
            ShellActions.Open,
            this.currentIdToken,
            shellOpenDataPayload,
            this.synAckShellOpenMessageHPointer
        );

        this.dataShellOpenMessageHPointer = this.keySplittingService.getHPointer(dataMessage.dataPayload.payload);
        await this.sendDataMessage(dataMessage);
    }

    private async sendShellInputDataMessage(input: ShellMessage) {
        // Check whether current BZCert's idtoken has been refreshed
        // If yes we need to perform a new handshake before sending data
        const IdToken = await this.authConfigService.getIdToken();
        if (this.currentIdToken !== IdToken){
            this.logger.debug(`Current idtoken has expired, requesting new and performing new ks handshake`);
            await this.performKeysplittingHandshake();
        }

        this.logger.debug(`Sending new input data message. ${JSON.stringify(input)}`);

        if(! this.lastAckHPointer) {
            throw new Error(`prevHPointer is not known for input ${JSON.stringify(input)}`);
        }

        const dataMessage = await this.keySplittingService.buildDataMessage(
            this.targetInfo.agentId,
            input.inputType,
            this.currentIdToken,
            input.inputPayload,
            this.lastAckHPointer
        );

        const hPointer = this.keySplittingService.getHPointer(dataMessage.dataPayload.payload);
        this.outgoingShellInputMessages[hPointer] = input;

        await this.sendDataMessage(dataMessage);
    }

    private async sendSynMessage(synMessage: SynMessageWrapper): Promise<void> {
        this.logger.debug(`Sending syn message: ${JSON.stringify(synMessage)}`);
        await this.sendWebsocketMessage<SynMessageWrapper>(
            ShellHubOutgoingMessages.synMessage,
            synMessage
        );
    }

    private async sendDataMessage(dataMessage: DataMessageWrapper): Promise<void> {
        this.logger.debug(`Sending data message: ${JSON.stringify(dataMessage)}`);
        await this.sendWebsocketMessage<DataMessageWrapper>(
            ShellHubOutgoingMessages.dataMessage,
            dataMessage
        );
    }

    private async handleSynAck(synAckMessage: SynAckMessageWrapper) {
        try {
            this.logger.debug(`Received SynAck message: ${JSON.stringify(synAckMessage)}`);

            // For now we only only a single client to be attached to the shell
            // at a time so if we see another synack message we dont recognize
            // immediately disconnect
            if (synAckMessage.synAckPayload.payload.hPointer != this.synShellOpenMessageHPointer) {
                this.logger.debug('[SynAck] received message from another client.');
                this.isActiveClient = false;
                this.shellEventSubject.next({ type: ShellEventType.Unattached});
                return;
            }

            // For out SynAck message we need to set the public key of the target
            this.keySplittingService.setTargetPublicKey(synAckMessage.synAckPayload.payload.targetPublicKey);

            // Validate our signature
            if (await this.keySplittingService.validateSignature<SynAckPayload>(synAckMessage.synAckPayload) != true) {
                const errorString = '[SynAck] Error Validating Signature!';
                this.logger.error(errorString);
                throw new Error(errorString);
            }

            this.synAckShellOpenMessageHPointer = this.keySplittingService.getHPointer(synAckMessage.synAckPayload.payload);
            this.lastAckHPointer = this.synAckShellOpenMessageHPointer;
            this.isActiveClient = true;

            await this.sendShellOpenDataMessage();
        } catch(e) {
            this.logger.error(`Error in handleSynAck: ${e}`);
        }
    }

    private async handleDataAck(dataAckMessage: DataAckMessageWrapper) {
        try {
            this.logger.debug(`Received DataAck message: ${JSON.stringify(dataAckMessage)}`);

            // Skip processing all data ack messages if we are not the active client
            if(! this.isActiveClient) {
                this.logger.debug(`[DataAck] received when not active client...skipping.`);
                return;
            }

            const action = dataAckMessage.dataAckPayload.payload.action;
            switch(action) {
            case ShellActions.Open:
                await this.handleShellOpenDataAck(dataAckMessage);
                break;
            case ShellActions.Input:
            case ShellActions.Resize:
                await this.handleShellInputOrResizeDataAck(dataAckMessage);
                break;
            default:
                throw new Error(`Unhandled data ack action ${action}`);
            }
        } catch(e) {
            this.logger.error(`Error in handleDataAck: ${e}, ${e.stack}`);
        }
    }

    private async handleShellOpenDataAck(dataAckMessage: DataAckMessageWrapper) {
        // Validate our HPointer
        if ( dataAckMessage.dataAckPayload.payload.hPointer !== this.dataShellOpenMessageHPointer) {
            const errorString = '[DataAck] Error Validating HPointer!';
            this.logger.error(errorString);
            throw new Error(errorString);
        }

        // Validate our signature
        if (! await this.keySplittingService.validateSignature<DataAckPayload>(dataAckMessage.dataAckPayload)) {
            const errorString = '[DataAck] Error Validating Signature!';
            this.logger.error(errorString);
            throw new Error(errorString);
        }

        this.dataAckShellOpenMessageHPointer = this.keySplittingService.getHPointer(dataAckMessage.dataAckPayload.payload);
        this.lastAckHPointer = this.dataAckShellOpenMessageHPointer;

        // Mark the keysplitting handshake as completed successfully
        this.keysplittingHandshakeCompleteSubject.next(true);
    }

    private async handleShellInputOrResizeDataAck(dataAckMessage: DataAckMessageWrapper) {
        const hPointer = dataAckMessage.dataAckPayload.payload.hPointer;
        const inputMessage = this.outgoingShellInputMessages[hPointer];

        if(! inputMessage) {
            this.logger.error(`Unrecognized shell input data ack with hpointer ${hPointer}`);
            return;
        }

        if (inputMessage != this.currentInputMessage) {
            this.logger.error('Data ack is not for not the current input message');
            return;
        }

        this.lastAckHPointer = this.keySplittingService.getHPointer(dataAckMessage.dataAckPayload.payload);

        // Remove from outgoing message map and input message buffer
        this.currentInputMessage = undefined;
        this.inputMessageBuffer.shift();
        delete this.outgoingShellInputMessages[hPointer];

        await this.processInputMessageQueue();
    }

    private async handleKeysplittingError(errorMessage: ErrorMessageWrapper) {
        const errorPayload = errorMessage.errorPayload.payload;

        this.logger.error(`Got agent keysplitting error on message ${errorPayload.hPointer}`);
        this.logger.error(`Type: ${errorPayload.errorType}`);
        this.logger.error(`Error Message: ${errorPayload.message}`);

        switch(errorPayload.errorType) {
            case KeysplittingErrorTypes.HandlerNotReady:
                await new Promise(resolve => setTimeout(resolve, 1000))
                this.currentInputMessage = undefined;
                await this.processInputMessageQueue();
                break;
            default:
                this.shellEventSubject.next({ type: ShellEventType.Disconnect});
        }
    }
}