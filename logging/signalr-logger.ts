import { ILogger } from './logging.types';
import { LogLevel } from '@microsoft/signalr';

// Class that wraps our ILogger in order to conform to signalR's ILogger interface
export class SignalRLogger implements signalR.ILogger
{
    private logger: ILogger;
    private logLevelFilter: signalR.LogLevel; // Everything below this level will be ignored

    constructor(logger: ILogger, logLevelFilter: signalR.LogLevel) {
        this.logger = logger;
        this.logLevelFilter = logLevelFilter;
    }

    log(logLevel: signalR.LogLevel, message: string): void {
        if(logLevel < this.logLevelFilter || this.logLevelFilter == LogLevel.None)
            return;

        switch(logLevel) {
        case LogLevel.Trace:
            this.logger.trace(message);
            break;
        case LogLevel.Debug:
            this.logger.debug(message);
            break;
        case LogLevel.Information:
            this.logger.info(message);
            break;
        case LogLevel.Warning:
            this.logger.warn(message);
            break;
        case LogLevel.Error:
            this.logger.error(message);
            break;
        case LogLevel.Critical:
            this.logger.error(message);
            break;
        case LogLevel.None:
            break;
        default:
            throw new Error('Unhandled signal log level');
        }
    }
}