// @ts-ignore
import { LDKeyPair } from "crypto-ld";
import {
  PrivKeySecp256k1,
  PubKeySecp256k1,
  Mnemonic,
  Hash,
} from "@keplr-wallet/crypto";
import multibase from "multibase";
import { Bech32Address } from "@keplr-wallet/cosmos";
const SUITE_ID = "EcdsaSecp256k1VerificationKey2019";

export class EcdsaSecp256k1VerificationKey2019 extends LDKeyPair {
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
  }) {
    super({ ...options });
    this.id = options.id;
    this.controller = options.controller;

    this.type = SUITE_ID;
    this.mnemonic = options.mnemonic;
    const { publicKeyMultibase, privateKeyMultibase } = options;
    const { privateKey, publicKey } = options;

    if (!publicKey) {
      throw new Error("publicKey required");
    }

    this.privateKey = privateKey;
    this.publicKey = publicKey;

    this.publicKeyMultibase =
      EcdsaSecp256k1VerificationKey2019.convertMultiBase(publicKey.toBytes());
    this.privateKeyMultibase = privateKey
      ? EcdsaSecp256k1VerificationKey2019.convertMultiBase(privateKey.toBytes())
      : "";

    if (this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }

    this.address = options.address;
    this.keplr = options.keplr;
    this.chainId = options.chainId;
  }
  private static convertMultiBase(arg0: Uint8Array): string | undefined {
    const multibaseEncoded = Buffer.from(multibase.encode("z", arg0));
    return multibaseEncoded.toString();
  }

  private static decodeMultiBase(arg0: string | Uint8Array): Uint8Array {
    const multibaseDecoded = multibase.decode(arg0);
    return multibaseDecoded;
  }

  fingerprint() {
    return this.publicKeyMultibase;
  }

  static from(
    mnemonic: string,
    prefix: string,
    options?: {
      id?: any;
      controller?: any;
      hdPath?: string;
    }
  ): EcdsaSecp256k1VerificationKey2019 {
    const privateKey = Mnemonic.generateWalletFromMnemonic(
      mnemonic,
      options?.hdPath
    );
    const privateKeySecp256k1 = new PrivKeySecp256k1(privateKey);
    const publicKey = privateKeySecp256k1.getPubKey();
    const address = new Bech32Address(publicKey.getCosmosAddress()).toBech32(
      prefix
    );
    return new EcdsaSecp256k1VerificationKey2019({
      privateKey: privateKeySecp256k1,
      publicKey,
      address,
      mnemonic,
      ...options,
    });
  }

  static async fromKeplr(
    keplr: any,
    chainId: string,
    options?: {
      id: any;
      controller: any;
    }
  ): Promise<EcdsaSecp256k1VerificationKey2019> {
    try {
      await keplr.enable(chainId);
      const keys = await keplr.getKey(chainId);

      const bech32Address = keys.bech32Address;
      const publicKey: Uint8Array = keys.pubKey;
      const publicKeySecp256k1 = new PubKeySecp256k1(publicKey);

      return new EcdsaSecp256k1VerificationKey2019({
        publicKey: publicKeySecp256k1,
        address: bech32Address,
        chainId: chainId,
        ...options,
      });
    } catch (error) {
      throw error;
    }
  }

  static fromKeys(params: {
    publicKeyMultibase: string;
    privateKeyMultibase?: string;
    address: string;
    options?: {
      id: any;
      controller: any;
    };
  }) {
    if (!params.publicKeyMultibase) {
      throw new Error("PublicKeyMultibase must be specified");
    }

    const { publicKeyMultibase, privateKeyMultibase } = params;

    const publicKey = new PubKeySecp256k1(
      EcdsaSecp256k1VerificationKey2019.decodeMultiBase(publicKeyMultibase)
    );

    if (privateKeyMultibase) {
      const privateKey = new PrivKeySecp256k1(
        EcdsaSecp256k1VerificationKey2019.decodeMultiBase(privateKeyMultibase)
      );
      return new EcdsaSecp256k1VerificationKey2019({
        publicKey,
        privateKey: privateKey,
        address: params.address,
        ...params.options,
      });
    } else {
      return new EcdsaSecp256k1VerificationKey2019({
        publicKey,
        address: params.address,
        ...params.options,
      });
    }
  }
  verifyFingerprint(options: { fingerprint: string }) {
    return this.publicKeyMultibase === options.fingerprint;
  }

  signer() {
    const privateKey = this.privateKey;
    const keplr = this.keplr;
    const chainId = this.chainId;
    const address = this.address;
    return {
      async sign(options: { data: Uint8Array }): Promise<{
        readonly r: Uint8Array;
        readonly s: Uint8Array;
        readonly v: number | null;
      }> {
        if (!privateKey && !keplr) {
          throw new Error(
            "Private key or instance of keplr is not available for signing"
          );
        }
        if (privateKey) {
          const signature = privateKey.signDigest32(options.data);
          return signature;
        } else {
          if (!chainId) {
            throw new Error("chainId is required to sign with keplr");
          }
          const signature = await keplr.signArbitrary(
            chainId,
            address,
            options.data
          );
          const signatureBuffer = Buffer.from(signature, "base64");
          const signatureUint8Array = new Uint8Array(signatureBuffer);
          const r = signatureUint8Array.slice(0, 32);
          const s = signatureUint8Array.slice(32, 64);
          const v = signatureUint8Array.slice(
            64,
            signatureUint8Array.length
          ) as any;
          return {
            r,
            s,
            v,
          };
        }
      },
      id: this.id,
    };
  }

  verifier() {
    const pubKey = this.publicKey;
    return {
      async verify(options: { data: Uint8Array; signature: Uint8Array }) {
        if (!pubKey) {
          throw new Error("Public key is not available for verification");
        }

        const verified = pubKey.verifyDigest32(options.data, options.signature);
        return verified;
      },
      id: this.id,
    };
  }
}
