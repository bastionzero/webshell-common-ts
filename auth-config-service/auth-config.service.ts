export interface AuthConfigService {
    getServiceUrl: () => string;
    getSessionId: () => string;
    getIdToken: () => Promise<string>;
}