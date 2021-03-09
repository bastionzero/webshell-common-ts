import { HubConnection, HubConnectionBuilder } from '@microsoft/signalr';
import { BehaviorSubject, Observable, Subscription } from 'rxjs';
import { ShellHubIncomingMessages, ShellHubOutgoingMessages, ShellState } from './websocket.service.types';

import { AuthConfigService } from '../auth-config-service/auth-config.service';

// ref: https://gist.github.com/dsherret/cf5d6bec3d0f791cef00
export interface IDisposable
{
    dispose() : void;
}

export interface TerminalSize
{
    rows: number;
    columns: number;
}

// Reflects the IShell interface
export class WebsocketStream implements IDisposable
{
    private connectionId : string;
    private websocket : HubConnection;

    // stdout
    private outputSubject: BehaviorSubject<string>;
    public outputData: Observable<string>;
    // stdin
    private inputSubscription: Subscription;
    private resizeSubscription: Subscription;

    // shell state
    private shellStateSubject: BehaviorSubject<ShellState>;
    public shellStateData: Observable<ShellState>;

    constructor(
        private authConfigService: AuthConfigService,
        connectionId: string,
        inputStream: BehaviorSubject<string>,
        resizeStream: BehaviorSubject<TerminalSize>
    )
    {
        this.outputSubject = new BehaviorSubject<string>('');
        this.outputData = this.outputSubject.asObservable();
        this.shellStateSubject = new BehaviorSubject<ShellState>({start: false, disconnect: false, delete: false, ready: false});
        this.shellStateData = this.shellStateSubject.asObservable();


        this.connectionId = connectionId;

        this.inputSubscription = inputStream.asObservable().subscribe(
            async (data) =>
            {
                if(this.websocket && this.websocket.connectionId)
                    this.websocket.invoke(
                        ShellHubOutgoingMessages.shellInput,
                        {Data: data}
                    );
            }
        );

        this.resizeSubscription = resizeStream.asObservable().subscribe(
            async (terminalSize) => {
                if(this.websocket && this.websocket.connectionId)
                    this.websocket.invoke(
                        ShellHubOutgoingMessages.shellGeometry,
                        terminalSize
                    );
            }
        );
    }

    public async start() // take in terminal size?
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
        this.websocket.on(
            ShellHubIncomingMessages.shellStart,
            () => {
                this.shellStateSubject.next({start: true, disconnect: false, delete: false, ready: false});
            }
        );

        this.websocket.on(
            ShellHubIncomingMessages.shellDisconnect,
            () => {
                this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
            }
        );

        // If a connection was closed via API/UI then we will see a shellDelete message
        this.websocket.on(
            ShellHubIncomingMessages.shellDelete,
            () => {
                this.shellStateSubject.next({start: false, disconnect: true, delete: false, ready: false});
            }
        );

        this.websocket.on(
            ShellHubIncomingMessages.connectionReady,
            _ => {
                this.shellStateSubject.next({start: false, disconnect: false, delete: false, ready: true});
            }
        );

        // won't get called at the moment since closing connection does not imply closing websocket
        this.websocket.onclose(() => this.shellStateSubject.next({start: false, disconnect: false, delete: false, ready: false}));

        await this.websocket.start();
    }

    public sendShellConnect(rows: number, cols: number)
    {
        if(this.websocket && this.websocket.connectionId)
            this.websocket.invoke(
                ShellHubOutgoingMessages.shellConnect,
                { TerminalRows: rows, TerminalColumns: cols }
            );
    }

    public async createConnection(): Promise<HubConnection> {
        // connectionId is related to terminal session
        // sessionId is for user authentication
        const queryString = `?connectionId=${this.connectionId}&session_id=${this.authConfigService.getSessionId()}`;

        const connectionUrl = `${this.authConfigService.getServiceUrl()}hub/ssh/${queryString}`;

        const connectionBuilder = new HubConnectionBuilder();
        connectionBuilder.withUrl(
            connectionUrl,
            { accessTokenFactory: async () => await this.authConfigService.getIdToken()}
        ).configureLogging(6); // log level 6 is no websocket logs
        return connectionBuilder.build();
    }

    private destroyConnection() {
        if(this.websocket) {
            this.websocket.stop(); // maybe await on this for server not to complain
            this.websocket = undefined;
        }
    }

    public dispose() : void
    {
        this.destroyConnection();
        this.inputSubscription.unsubscribe();
        this.resizeSubscription.unsubscribe();
        this.shellStateSubject.complete();
    }
}