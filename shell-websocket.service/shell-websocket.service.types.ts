import { Observable } from 'rxjs';
import { IDisposableAsync } from '../utility/disposable';

export interface IShellWebsocketService extends IDisposableAsync{
    start() : Promise<void>;

    // Terminal dimensions provided in the shell connect are only used by ssh
    // and non-keysplitting ssm shells where terminal size is set from the
    // backend. Keysplitting ssm shells must send a separate resize input event
    sendShellConnect(rows: number, cols: number, replayOutput: boolean): void;

    sendReplayDone(rows: number, cols: number): void;

    shellReattach() : Promise<void>;

    outputData: Observable<string>;
    replayData: Observable<string>;
    shellEventData: Observable<ShellEvent>;
}

export const ShellHubIncomingMessages = {
    shellOutput: 'ShellOutput',
    shellReplay: 'ShellReplay',
    shellDisconnect: 'ShellDisconnect',
    shellStart: 'ShellStart',
    shellDelete: 'ShellDelete',
    connectionReady: 'ConnectionReady',

    // keysplitting
    synAck: 'SynAck',
    dataAck: 'DataAck',
    keysplittingError: 'KeysplittingError',
};

export const ShellHubOutgoingMessages = {
    shellConnect: 'ShellConnect',
    replayDone: 'ReplayDone',
    shellInput: 'ShellInput',
    shellGeometry: 'ShellGeometry',

    // keysplitting
    synMessage: 'SynMessage',
    dataMessage: 'DataMessage',
};

export enum ShellEventType {
    Start = 'Start',
    Disconnect = 'Disconnect',
    Delete = 'Delete',
    Ready = 'Ready',
    Unattached = 'Unattach'
}

export interface ShellEvent {
    type: ShellEventType;
}

export interface TerminalSize
{
    rows: number;
    columns: number;
}
