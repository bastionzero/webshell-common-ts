import { Observable } from 'rxjs';
import { IDisposable } from '../utility/disposable';

export interface IShellWebsocketService extends IDisposable{
    start() : Promise<void>;
    sendShellConnect(rows: number, cols: number): void;

    outputData: Observable<string>;
    shellEventData: Observable<ShellEvent>;
}

export const ShellHubIncomingMessages = {
    shellOutput: 'ShellOutput',
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
