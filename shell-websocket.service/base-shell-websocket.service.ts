import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';
import { Observable, Subject, Subscription } from 'rxjs';
import { IShellWebsocketService, ShellHubIncomingMessages, ShellHubOutgoingMessages, ShellEvent, TerminalSize, ShellEventType } from './shell-websocket.service.types';

import { AuthConfigService } from '../auth-config-service/auth-config.service';
import { ILogger } from '../logging/logging.types';
import { SignalRLogger } from '../logging/signalr-logger';

export abstract class BaseShellWebsocketService implements IShellWebsocketService
{
    protected websocket : HubConnection;

    // Input subscriptions
    private inputSubscription: Subscription;
    private resizeSubscription: Subscription;

    // Output Observables
    private outputSubject: Subject<string>;
    public outputData: Observable<string>;

    private replaySubject: Subject<string>;
    public replayData: Observable<string>;

    protected shellEventSubject: Subject<ShellEvent>;
    public shellEventData: Observable<ShellEvent>;

    protected abstract handleInput(data: string): Promise<void>;
    protected abstract handleResize(terminalSize: TerminalSize): Promise<void>;
    protected abstract handleShellStart(): Promise<void>;

    public abstract shellReattach() : Promise<void>;

    constructor(
        protected logger: ILogger,
        protected authConfigService: AuthConfigService,
        protected connectionId: string,
        inputStream: Subject<string>,
        resizeStream: Subject<TerminalSize>
    )
    {
        this.outputSubject = new Subject<string>();
        this.outputData = this.outputSubject.asObservable();
        this.replaySubject = new Subject<string>();
        this.replayData = this.replaySubject.asObservable();
        this.shellEventSubject = new Subject<ShellEvent>();
        this.shellEventData = this.shellEventSubject.asObservable();

        this.connectionId = connectionId;
        this.inputSubscription = inputStream.asObservable().subscribe((data) => this.handleInput(data));
        this.resizeSubscription = resizeStream.asObservable().subscribe((data) => this.handleResize(data));
    }

    public async start()
    {
        this.websocket = await this.createConnection();

        this.websocket.on(
            ShellHubIncomingMessages.shellReplay,
            req =>
            {
                this.replaySubject.next(req.data);
            }
        );

        this.websocket.on(
            ShellHubIncomingMessages.shellOutput,
            req =>
            {
                // ref: https://git.coolaj86.com/coolaj86/atob.js/src/branch/master/node-atob.js
                this.outputSubject.next(req.data);
            }
        );

        this.websocket.on(ShellHubIncomingMessages.shellStart, async () => {
            this.logger.trace('got shellStart message');

            try {
                await this.handleShellStart();
                this.shellEventSubject.next({ type: ShellEventType.Start });
            } catch(err) {
                this.logger.error(err);
                this.shellEventSubject.next({ type: ShellEventType.Disconnect });
            }
        });

        this.websocket.on(
            ShellHubIncomingMessages.shellDisconnect,
            () => {
                this.logger.trace('got shellDisconnect message');
                this.shellEventSubject.next({ type: ShellEventType.Disconnect });
            }
        );

        // If a connection was closed via API/UI then we will see a shellDelete message
        this.websocket.on(
            ShellHubIncomingMessages.shellDelete,
            () => {
                this.logger.trace('got shellDelete message');
                this.shellEventSubject.next({ type: ShellEventType.Delete });
            }
        );

        this.websocket.on(
            ShellHubIncomingMessages.connectionReady,
            _ => {
                this.logger.trace('got connectionReady message');
                this.shellEventSubject.next({ type: ShellEventType.Ready });
            }
        );

        // this is called if the server closes the websocket
        this.websocket.onclose(() => {
            this.logger.debug('websocket closed by server');
            this.shellEventSubject.next({ type: ShellEventType.Disconnect });
        });
    }

    public async sendShellConnect(rows: number, cols: number, version: number)
    {
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellConnect, { TerminalRows: rows, TerminalColumns: cols, Version: version });
    }

    public async sendReplayDone(rows: number, cols: number)
    {
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.replayDone, { TerminalRows: rows, TerminalColumns: cols});
    }

    public async dispose() : Promise<void>
    {
        await this.destroyConnection();
        this.inputSubscription.unsubscribe();
        this.resizeSubscription.unsubscribe();
        this.shellEventSubject.complete();
    }

    protected async sendWebsocketMessage<TReq>(methodName: string, message: TReq): Promise<void> {
        if(this.websocket === undefined || this.websocket.state == HubConnectionState.Disconnected)
            throw new Error('Hub disconnected');

        await this.websocket.invoke(methodName, message);
    }

    private async createConnection(): Promise<HubConnection> {
        // connectionId is related to terminal session
        // sessionId is for user authentication
        const queryString = `?connectionId=${this.connectionId}&session_id=${this.authConfigService.getSessionId()}`;

        const connectionUrl = `${this.authConfigService.getServiceUrl()}hub/ssh/${queryString}`;

        return new HubConnectionBuilder()
            .withUrl(
                connectionUrl,
                { accessTokenFactory: async () => await this.authConfigService.getIdToken()}
            )
            .configureLogging(new SignalRLogger(this.logger))
            .withAutomaticReconnect()
            .configureLogging(LogLevel.Warning)
            .build();
    }

    private async destroyConnection() {
        if(this.websocket) {
            await this.websocket.stop();
            this.websocket = undefined;
        }
    }
}