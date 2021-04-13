import { Observable, Subject } from 'rxjs';
import { timeout } from 'rxjs/operators';
import { ShellHubIncomingMessages, ShellHubOutgoingMessages, TerminalSize } from './shell-websocket.service.types';
import { BaseShellWebsocketService } from './base-shell-websocket.service';

import { AuthConfigService } from '../auth-config-service/auth-config.service';
import { ILogger } from '../logging/logging.types';
import { KeySplittingService } from '../keysplitting.service/keysplitting.service';
import { DataAckMessageWrapper, DataAckPayload, DataMessageWrapper, ErrorMessageWrapper, ShellActions, ShellTerminalSizeActionPayload, SsmTargetInfo, SynAckMessageWrapper, SynAckPayload, SynMessageWrapper } from '../keysplitting.service/keysplitting-types';

interface ShellMessage {
    inputType: ShellActions,
    inputPayload: any;
    seqNum: number;
}

// TODO: change this after we release keysplitting agent version
// This is bzero agent version only "3.0.732.15" => 15
const KeysplittingMinimumAgentVersion = 0;
export function isAgentKeysplittingReady(agentVersion: string): boolean {
    try {
        const version = parseInt(agentVersion.split('.')[3]);
        return version >= KeysplittingMinimumAgentVersion;
    } catch(err) {
        return false;
    }
}

const KeysplittingHandshakeTimeout = 15; // in seconds

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

    protected async handleShellStart(): Promise<void> {
        // reset all keysplitting state in case this is a reconnect attempt
        // after a previous error occurred
        this.resetKeysplittingState();
        await this.performKeysplittingHandshake();
    }

    protected async handleInput(data: string): Promise<void> {
        this.logger.debug(`got new input ${data}`);

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

            // If another client has attached to the same shell then we must
            // perform keysplitting handshake in order to send new input
            if (!this.isActiveClient) {
                await this.performKeysplittingHandshake();
            }

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
        const synMessage = await this.keySplittingService.buildSynMessage(
            this.targetInfo.agentId,
            ShellActions.Open,
            await this.authConfigService.getIdToken()
        );

        this.synShellOpenMessageHPointer = this.keySplittingService.getHPointer(synMessage.synPayload.payload);
        await this.sendSynMessage(synMessage);
    }

    private async sendShellOpenDataMessage() {
        const shellOpenDataPayload = {};
        const dataMessage = await this.keySplittingService.buildDataMessage(
            this.targetInfo.agentId,
            ShellActions.Open,
            await this.authConfigService.getIdToken(),
            shellOpenDataPayload,
            this.synAckShellOpenMessageHPointer
        );

        this.dataShellOpenMessageHPointer = this.keySplittingService.getHPointer(dataMessage.dataPayload.payload);
        await this.sendDataMessage(dataMessage);
    }

    private async sendShellInputDataMessage(input: ShellMessage) {
        this.logger.debug(`Sending new input data message. ${JSON.stringify(input)}`);

        if(! this.lastAckHPointer) {
            throw new Error(`prevHPointer is not known for input ${JSON.stringify(input)}`);
        }

        const dataMessage = await this.keySplittingService.buildDataMessage(
            this.targetInfo.agentId,
            input.inputType,
            await this.authConfigService.getIdToken(),
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

            // First handle case where this is a synack message from another
            // client that has now attached to the shell
            if (synAckMessage.synAckPayload.payload.clientId != this.keySplittingService.getClientId()) {
                this.logger.debug('Saw SynAck message from another client. Setting isActiveClient to false.');
                this.isActiveClient = false;
                return;
            }

            // Validate our HPointer
            if (synAckMessage.synAckPayload.payload.hPointer !== this.synShellOpenMessageHPointer) {
                const errorString = '[SynAck] Error Validating HPointer!';
                this.logger.error(errorString);
                throw new Error(errorString);
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

            // Do not process data ack messages from other clients
            if (dataAckMessage.dataAckPayload.payload.clientId != this.keySplittingService.getClientId()) {
                this.logger.debug(`Skipping data ack message with different clientId`);
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

        this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
    }
}