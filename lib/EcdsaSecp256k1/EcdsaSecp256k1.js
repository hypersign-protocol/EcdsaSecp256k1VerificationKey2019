"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcdsaSecp256k1VerificationKey2019 = void 0;
// @ts-ignore
const crypto_ld_1 = require("crypto-ld");
const crypto_1 = require("@keplr-wallet/crypto");
const multibase_1 = __importDefault(require("multibase"));
const cosmos_1 = require("@keplr-wallet/cosmos");
const SUITE_ID = "EcdsaSecp256k1VerificationKey2019";
class EcdsaSecp256k1VerificationKey2019 extends crypto_ld_1.LDKeyPair {
    constructor(options) {
        super(Object.assign({}, options));
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
    static convertMultiBase(arg0) {
        const multibaseEncoded = Buffer.from(multibase_1.default.encode("z", arg0));
        return multibaseEncoded.toString();
    }
    static decodeMultiBase(arg0) {
        const multibaseDecoded = multibase_1.default.decode(arg0);
        return multibaseDecoded;
    }
    fingerprint() {
        return this.publicKeyMultibase;
    }
    static from(mnemonic, prefix, options) {
        const privateKey = crypto_1.Mnemonic.generateWalletFromMnemonic(mnemonic, options === null || options === void 0 ? void 0 : options.hdPath);
        const privateKeySecp256k1 = new crypto_1.PrivKeySecp256k1(privateKey);
        const publicKey = privateKeySecp256k1.getPubKey();
        const address = new cosmos_1.Bech32Address(publicKey.getCosmosAddress()).toBech32(prefix);
        return new EcdsaSecp256k1VerificationKey2019(Object.assign({ privateKey: privateKeySecp256k1, publicKey,
            address,
            mnemonic }, options));
    }
    static fromKeplr(keplr, chainId, options) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield keplr.enable(chainId);
                const keys = yield keplr.getKey(chainId);
                const bech32Address = keys.bech32Address;
                const publicKey = keys.pubKey;
                const publicKeySecp256k1 = new crypto_1.PubKeySecp256k1(publicKey);
                return new EcdsaSecp256k1VerificationKey2019(Object.assign({ publicKey: publicKeySecp256k1, address: bech32Address, chainId: chainId }, options));
            }
            catch (error) {
                throw error;
            }
        });
    }
    static fromKeys(params) {
        if (!params.publicKeyMultibase) {
            throw new Error("PublicKeyMultibase must be specified");
        }
        const { publicKeyMultibase, privateKeyMultibase } = params;
        const publicKey = new crypto_1.PubKeySecp256k1(EcdsaSecp256k1VerificationKey2019.decodeMultiBase(publicKeyMultibase));
        if (privateKeyMultibase) {
            const privateKey = new crypto_1.PrivKeySecp256k1(EcdsaSecp256k1VerificationKey2019.decodeMultiBase(privateKeyMultibase));
            return new EcdsaSecp256k1VerificationKey2019(Object.assign({ publicKey, privateKey: privateKey, address: params.address }, params.options));
        }
        else {
            return new EcdsaSecp256k1VerificationKey2019(Object.assign({ publicKey, address: params.address }, params.options));
        }
    }
    verifyFingerprint(options) {
        return this.publicKeyMultibase === options.fingerprint;
    }
    signer() {
        const privateKey = this.privateKey;
        const keplr = this.keplr;
        const chainId = this.chainId;
        const address = this.address;
        return {
            sign(options) {
                return __awaiter(this, void 0, void 0, function* () {
                    if (!privateKey && !keplr) {
                        throw new Error("Private key or instance of keplr is not available for signing");
                    }
                    if (privateKey) {
                        const signature = privateKey.signDigest32(options.data);
                        return signature;
                    }
                    else {
                        if (!chainId) {
                            throw new Error("chainId is required to sign with keplr");
                        }
                        const signature = yield keplr.signArbitrary(chainId, address, options.data);
                        const signatureBuffer = Buffer.from(signature, "base64");
                        const signatureUint8Array = new Uint8Array(signatureBuffer);
                        const r = signatureUint8Array.slice(0, 32);
                        const s = signatureUint8Array.slice(32, 64);
                        const v = signatureUint8Array.slice(64, signatureUint8Array.length);
                        return {
                            r,
                            s,
                            v,
                        };
                    }
                });
            },
            id: this.id,
        };
    }
    verifier() {
        const pubKey = this.publicKey;
        return {
            verify(options) {
                return __awaiter(this, void 0, void 0, function* () {
                    if (!pubKey) {
                        throw new Error("Public key is not available for verification");
                    }
                    const verified = pubKey.verifyDigest32(options.data, options.signature);
                    return verified;
                });
            },
            id: this.id,
        };
    }
}
exports.EcdsaSecp256k1VerificationKey2019 = EcdsaSecp256k1VerificationKey2019;
