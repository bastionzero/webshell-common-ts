import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';
import { BehaviorSubject, Observable, Subject, Subscription } from 'rxjs';
import { IShellWebsocketService, ShellHubIncomingMessages, ShellHubOutgoingMessages, ShellState, TerminalSize } from './shell-websocket.service.types';

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
    private outputSubject: BehaviorSubject<string>;
    public outputData: Observable<string>;

    protected shellStateSubject: BehaviorSubject<ShellState>;
    public shellStateData: Observable<ShellState>;

    protected abstract handleInput(data: string): Promise<void>;
    protected abstract handleResize(terminalSize: TerminalSize): Promise<void>;
    protected abstract handleShellStart(): Promise<void>;

    constructor(
        protected logger: ILogger,
        protected authConfigService: AuthConfigService,
        protected connectionId: string,
        inputStream: Subject<string>,
        resizeStream: Subject<TerminalSize>
    )
    {
        this.outputSubject = new BehaviorSubject<string>('');
        this.outputData = this.outputSubject.asObservable();
        this.shellStateSubject = new BehaviorSubject<ShellState>({start: false, disconnect: false, delete: false, ready: false});
        this.shellStateData = this.shellStateSubject.asObservable();

        this.connectionId = connectionId;
        this.inputSubscription = inputStream.asObservable().subscribe((data) => this.handleInput(data));
        this.resizeSubscription = resizeStream.asObservable().subscribe((data) => this.handleResize(data));
    }

    public async start()
    {
        this.websocket = await this.createConnection();

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
                this.shellStateSubject.next({start: true, disconnect: false, delete: false, ready: false});
            } catch(err) {
                this.logger.error(err);
                this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
            }
        });

        this.websocket.on(
            ShellHubIncomingMessages.shellDisconnect,
            () => {
                this.logger.trace('got shellDisconnect message');
                this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
            }
        );

        // If a connection was closed via API/UI then we will see a shellDelete message
        this.websocket.on(
            ShellHubIncomingMessages.shellDelete,
            () => {
                this.logger.trace('got shellDelete message');
                this.shellStateSubject.next({start: false, disconnect: true, delete: true, ready: false});
            }
        );

        this.websocket.on(
            ShellHubIncomingMessages.connectionReady,
            _ => {
                this.logger.trace('got connectionReady message');
                this.shellStateSubject.next({start: false, disconnect: false, delete: false, ready: true});
            }
        );

        // this is called if the server closes the websocket
        this.websocket.onclose(() => {
            this.logger.debug('websocket closed by server');
            this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
        });
    }

    public async sendShellConnect(rows: number, cols: number)
    {
        await this.sendWebsocketMessage(ShellHubOutgoingMessages.shellConnect, { TerminalRows: rows, TerminalColumns: cols });
    }

    public dispose() : void
    {
        this.destroyConnection();
        this.inputSubscription.unsubscribe();
        this.resizeSubscription.unsubscribe();
        this.shellStateSubject.complete();
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
            .configureLogging(LogLevel.Warning)
            .build();
    }

    private destroyConnection() {
        if(this.websocket) {
            this.websocket.stop(); // maybe await on this for server not to complain
            this.websocket = undefined;
        }
    }
}