import { Observable, Subject } from 'rxjs';
import { timeout } from 'rxjs/operators';
import { ShellHubIncomingMessages, ShellHubOutgoingMessages, TerminalSize } from './shell-websocket.service.types';
import { BaseShellWebsocketService } from './base-shell-websocket.service';

import { AuthConfigService } from '../auth-config-service/auth-config.service';
import { ILogger } from '../logging/logging.types';
import { KeySplittingService } from '../keysplitting.service/keysplitting.service';
import { ConfigInterface } from '../keysplitting.service/keysplitting.service.types';
import { DataAckMessageWrapper, DataAckPayload, DataMessageWrapper, ErrorMessageWrapper, SsmTargetInfo, SynAckMessageWrapper, SynAckPayload, SynMessageWrapper } from '../keysplitting.service/keysplitting-types';

const KeysplittingHandshakeTimeout = 15; // in seconds

export class SsmShellWebsocketService extends BaseShellWebsocketService
{
    private keySplittingService: KeySplittingService;

    private keysplittingHandshakeCompleteSubject = new Subject<boolean>();
    private keysplittingHandshakeComplete: Observable<boolean> = this.keysplittingHandshakeCompleteSubject.asObservable();

    constructor(
        private configInterface: ConfigInterface,
        private targetInfo: SsmTargetInfo,
        protected logger: ILogger,
        protected authConfigService: AuthConfigService,
        protected connectionId: string,
        inputStream: Subject<string>,
        resizeStream: Subject<TerminalSize>
    ) {
        super(logger, authConfigService, connectionId, inputStream, resizeStream);
        this.keySplittingService = new KeySplittingService(this.configInterface, logger);
    }

    protected async handleShellStart(): Promise<void> {
        await this.performKeysplittingHandshake();
    }

    protected async handleInput(data: string): Promise<void> {
        this.logger.debug(`got new input ${data}`);

        // TODO: wrap in keysplitting message
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellInput, { Data: data });
    }

    protected async handleResize(terminalSize: TerminalSize): Promise<void> {
        this.logger.debug(`New terminal resize event (rows: ${terminalSize.rows} cols: ${terminalSize.columns})`);

        // TODO: wrap in keysplitting message
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellGeometry, terminalSize);
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

    private async performKeysplittingHandshake(): Promise<boolean> {
        if(this.targetInfo.agentVersion === '') {
            throw new Error(`Unable to perform keysplitting handshake: agentVersion is not known for target ${this.targetInfo.id}`);
        }

        this.logger.debug(`Starting keysplitting handshake with ${this.targetInfo.id}`);
        this.logger.debug(`Agent Version ${this.targetInfo.agentVersion}, Agent ID: ${this.targetInfo.agentId}`);

        await this.sendCreateShellSynMessage();

        return new Promise((res, rej) => {
            this.keysplittingHandshakeComplete
                .pipe(timeout(KeysplittingHandshakeTimeout * 1000))
                .subscribe(
                    completedSuccessfully => res(completedSuccessfully),
                    _ => rej(`Keyspliting handshake timed out after ${KeysplittingHandshakeTimeout} seconds`)
                );
        });
    }

    private async sendCreateShellSynMessage() {
        if(this.targetInfo.agentId === '') {
            throw new Error(`Unknown agentId in sendOpenShellSynMessage for target ${this.targetInfo.id}`);
        }

        await this.sendSynMessage(await this.keySplittingService.buildSynMessage(
            this.targetInfo.agentId, 'shell/open', await this.authConfigService.getIdToken()
        ));
    }

    private async sendCreateShellDataMessage() {
        if(this.targetInfo.agentId === '') {
            throw new Error(`Unknown agentId in sendOpenShellDataMessage for target ${this.targetInfo.id}`);
        }

        await this.sendDataMessage(await this.keySplittingService.buildDataMessage(
            this.targetInfo.agentId, 'shell/open',
            await this.authConfigService.getIdToken(),
            {}
        ));
    }

    private async sendSynMessage(synMessage: SynMessageWrapper): Promise<void> {
        this.logger.debug('Sending syn message...');
        this.keySplittingService.setExpectedHPointer(synMessage.synPayload.payload);
        await this.sendWebsocketMessage<SynMessageWrapper>(
            ShellHubOutgoingMessages.synMessage,
            synMessage
        );
    }

    private async sendDataMessage(dataMessage: DataMessageWrapper): Promise<void> {
        this.logger.debug('Sending data message...');
        this.keySplittingService.setExpectedHPointer(dataMessage.dataPayload.payload);
        await this.sendWebsocketMessage<DataMessageWrapper>(
            ShellHubOutgoingMessages.dataMessage,
            dataMessage
        );
    }

    private async handleSynAck(synAckMessage: SynAckMessageWrapper) {
        try {
            this.logger.debug(`Received SynAck message: ${JSON.stringify(synAckMessage)}`);

            // Validate our HPointer
            if (this.keySplittingService.validateHPointer(synAckMessage.synAckPayload.payload.hPointer) != true) {
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

            // Update Current HPointer
            this.keySplittingService.setCurrentHPointer(synAckMessage.synAckPayload.payload);

            this.sendCreateShellDataMessage();
        } catch(e) {
            this.logger.error(`Error in handleSynAck: ${e}`);
        }
    }

    private async handleDataAck(dataAckMessage: DataAckMessageWrapper) {
        try {
            this.logger.debug(`Received DataAck message: ${JSON.stringify(dataAckMessage)}`);

             // Validate our HPointer
             if (this.keySplittingService.validateHPointer(dataAckMessage.dataAckPayload.payload.hPointer) != true) {
                const errorString = '[DataAck] Error Validating HPointer!';
                this.logger.error(errorString);
                throw new Error(errorString);
            }

            // Validate our signature
            if (await this.keySplittingService.validateSignature<DataAckPayload>(dataAckMessage.dataAckPayload) != true) {
                const errorString = '[DataAck] Error Validating Signature!';
                this.logger.error(errorString);
                throw new Error(errorString);
            }

            // Update the expected HPointer
            this.keySplittingService.setCurrentHPointer(dataAckMessage.dataAckPayload.payload);

            // Mark the keysplitting handshake as completed successfully
            this.keysplittingHandshakeCompleteSubject.next(true);
        } catch(e) {
            this.logger.error(`Error in handleDataAck: ${e}`);
        }
    }

    private async handleKeysplittingError(errorMessage: ErrorMessageWrapper) {
        const errorPayload = errorMessage.errorPayload.payload;

        this.logger.error(`Got agent keysplitting error on message ${errorPayload.hPointer}`);
        this.logger.error(`Type: ${errorPayload.errorType}`);
        this.logger.error(`Error Message: ${errorPayload.message}`);
    }
}