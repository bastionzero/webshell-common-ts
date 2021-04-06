import { Observable } from 'rxjs';
import { IDisposable } from '../utility/disposable';

export interface IShellWebsocketService extends IDisposable{
    start() : Promise<void>;
    sendShellConnect(rows: number, cols: number): void;

    outputData: Observable<string>;
    shellStateData: Observable<ShellState>;
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

export interface ShellState {
    start: boolean;
    disconnect: boolean;
    delete: boolean;
    ready: boolean;
}

export interface TerminalSize
{
    rows: number;
    columns: number;
}
