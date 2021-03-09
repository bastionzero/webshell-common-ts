export interface KeySplittingConfigSchema {
    initialIdToken: string,
    cerRand: string,
    cerRandSig: string,
    privateKey: string,
    publicKey: string
}

export interface ConfigInterface {
    updateKeySplitting(data: KeySplittingConfigSchema): void
    loadKeySplitting(): KeySplittingConfigSchema
}