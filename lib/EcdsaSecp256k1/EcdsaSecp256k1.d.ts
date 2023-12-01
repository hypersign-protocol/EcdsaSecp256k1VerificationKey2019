import { LDKeyPair } from "crypto-ld";
import { PrivKeySecp256k1, PubKeySecp256k1 } from "@keplr-wallet/crypto";
export declare class EcdsaSecp256k1VerificationKey2019 extends LDKeyPair {
    type: string;
    publicKeyMultibase: string | undefined;
    privateKeyMultibase: string | undefined;
    controller: string | undefined;
    id: any;
    privateKey: PrivKeySecp256k1 | undefined;
    publicKey: PubKeySecp256k1;
    mnemonic: string | undefined;
    address: string;
    keplr: any | undefined;
    chainId: string | undefined;
    constructor(options: {
        id?: any;
        controller?: any;
        revoked?: any;
        publicKeyMultibase?: string;
        privateKeyMultibase?: string;
        address: string;
        privateKey?: PrivKeySecp256k1;
        publicKey: PubKeySecp256k1;
        mnemonic?: string;
        keplr?: any;
        chainId?: string;
    });
    private static convertMultiBase;
    private static decodeMultiBase;
    fingerprint(): string | undefined;
    static from(mnemonic: string, prefix: string, options?: {
        id?: any;
        controller?: any;
        hdPath?: string;
    }): EcdsaSecp256k1VerificationKey2019;
    static fromKeplr(keplr: any, chainId: string, options?: {
        id: any;
        controller: any;
    }): Promise<EcdsaSecp256k1VerificationKey2019>;
    static fromKeys(params: {
        publicKeyMultibase: string;
        privateKeyMultibase?: string;
        address: string;
        options?: {
            id: any;
            controller: any;
        };
    }): EcdsaSecp256k1VerificationKey2019;
    verifyFingerprint(options: {
        fingerprint: string;
    }): boolean;
    signer(): {
        sign(options: {
            data: Uint8Array;
        }): Promise<{
            readonly r: Uint8Array;
            readonly s: Uint8Array;
            readonly v: number | null;
        }>;
        id: any;
    };
    verifier(): {
        verify(options: {
            data: Uint8Array;
            signature: Uint8Array;
        }): Promise<boolean>;
        id: any;
    };
}
