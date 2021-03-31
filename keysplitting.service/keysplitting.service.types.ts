export interface KeySplittingConfigSchema {
    initialIdToken: string,
    cerRand: string,
    cerRandSig: string,
    privateKey: string,
    publicKey: string
}

export function getDefaultKeysplittingConfig(): KeySplittingConfigSchema {
    return {
        initialIdToken: undefined,
        cerRand: undefined,
        cerRandSig: undefined,
        privateKey: undefined,
        publicKey: undefined
    };
}

export interface ConfigInterface {
    updateKeySplitting(data: KeySplittingConfigSchema): void
    loadKeySplitting(): KeySplittingConfigSchema
}
