/// <reference types="node" />
export declare type SignatureType = 'ed25519' | 'secp256k1';
interface DecodeSeedOpts {
    versions?: (number | number[])[];
    expectedLength?: number;
    versionTypes?: ['ed25519', 'secp256k1'];
}
interface DecodedSeed {
    bytes: Buffer;
    version: number[];
    type?: SignatureType;
}
interface GenerateOpts {
    algorithm?: SignatureType;
    entropy?: Buffer | number[] | Uint8Array;
}
export declare const isValidHex: (string: string) => boolean;
export declare const sha512Half: (hashables: (string | Buffer | number[])[]) => Buffer;
export declare const publicKeyFromPrivateKey: (privateKey: string) => string;
export declare const encodeSeed: (entropy: Buffer | Uint8Array | number[], algorithm?: SignatureType) => string;
export declare const generateSeed: (options?: GenerateOpts) => string;
export declare const decodeSeed: (seed: string, opts?: DecodeSeedOpts) => DecodedSeed;
export declare const deriveKeypair: (encodedSeed: string, accountIndex?: number) => {
    privateKey: string;
    publicKey: string;
};
export declare const sign: (messageHex: string, privateKey: string) => string;
export declare const verify: (msg: string | Buffer, signature: string, publicKey: string) => boolean;
export declare const encodeAccountID: (bytes: Buffer | number[]) => string;
export declare const deriveAddress: (publicKey: string | Buffer) => string;
export declare const decodeNodePublic: (base58string: string) => Buffer;
export declare const encodeNodePublic: (bytes: Buffer | number[]) => string;
export declare const deriveNodeAddress: (publicKey: string) => string;
export declare const decodeAccountID: (accountId: string) => Buffer;
export declare const isValidAddress: (address: string) => boolean;
declare const _default: {
    sha512Half: (hashables: (string | Buffer | number[])[]) => Buffer;
    isValidHex: (string: string) => boolean;
    publicKeyFromPrivateKey: (privateKey: string) => string;
    encodeSeed: (entropy: Buffer | Uint8Array | number[], algorithm?: SignatureType) => string;
    generateSeed: (options?: GenerateOpts) => string;
    decodeSeed: (seed: string, opts?: DecodeSeedOpts) => DecodedSeed;
    deriveKeypair: (encodedSeed: string, accountIndex?: number) => {
        privateKey: string;
        publicKey: string;
    };
    sign: (messageHex: string, privateKey: string) => string;
    verify: (msg: string | Buffer, signature: string, publicKey: string) => boolean;
    encodeAccountID: (bytes: Buffer | number[]) => string;
    deriveAddress: (publicKey: string | Buffer) => string;
    decodeNodePublic: (base58string: string) => Buffer;
    encodeNodePublic: (bytes: Buffer | number[]) => string;
    deriveNodeAddress: (publicKey: string) => string;
    decodeAccountID: (accountId: string) => Buffer;
    isValidAddress: (address: string) => boolean;
};
export default _default;
