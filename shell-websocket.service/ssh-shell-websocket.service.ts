import { Subject } from 'rxjs';

import { AuthConfigService } from '../auth-config-service/auth-config.service';
import { ILogger } from '../logging/logging.types';
import { BaseShellWebsocketService } from './base-shell-websocket.service';
import { ShellHubOutgoingMessages, TerminalSize } from './shell-websocket.service.types';

export class SshShellWebsocketService extends BaseShellWebsocketService
{
    constructor(
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
        await this.websocket.start();
    }

    public dispose() : void {
        super.dispose();
    }

    protected async handleShellStart(): Promise<void> {
        return;
    }

    protected async handleInput(data: string): Promise<void> {
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellInput, { Data: data });
    }

    protected async handleResize(terminalSize: TerminalSize): Promise<void> {
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellGeometry, terminalSize);
    }

    public shellReattach(): Promise<void> {
        return;
    }
}