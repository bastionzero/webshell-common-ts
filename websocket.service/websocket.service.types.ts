export const ShellHubIncomingMessages = {
    shellOutput: 'ShellOutput',
    shellDisconnect: 'ShellDisconnect',
    shellStart: 'ShellStart',
    shellDelete: 'ShellDelete',
    connectionReady: 'ConnectionReady'
};
    
export const ShellHubOutgoingMessages = {
    shellConnect: 'ShellConnect',
    shellInput: 'ShellInput',
    shellGeometry: 'ShellGeometry'
};

export interface ShellState {
    start: boolean;
    disconnect: boolean; 
    delete: boolean;
    ready: boolean;
}