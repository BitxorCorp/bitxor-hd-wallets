/// <reference types="node" />
import { BIP32 } from 'bip32';
import { KeyEncoding, MACType, Network, NodeEd25519 } from '../index';
/**
 * Class `ExtendedKey` describes a hierarchical deterministic extended
 * key that can be derived. This hierarchical deterministic child key
 * derivation feature is described in the Bitcoin BIP32 standard which
 * can be found at following URL:
 *
 *     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * This class *uses* features provided by the `bitcoinjs/bip32` package
 * and therefor is licensed under the BSD-2 Clause License as mentioned
 * [here](https://github.com/bitcoinjs/bip32/blob/master/LICENSE).
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/bitcoinjs/bip32
 * @see https://github.com/bitxorcorp/NIP/issues/12
 * @since 0.1.0
 */
export declare class ExtendedKey {
    readonly node: BIP32 | NodeEd25519;
    /**
     * The hyper-deterministic node network.
     * @var {Network}
     */
    network: Network;
    /**
     * The Message Authentication Code type to use.
     * Possible values include HMAC and KMAC.
     * @var {MACType}
     */
    readonly macType: MACType;
    /**
     * Static property to define which type of
     * message authentication code must be used.
     *
     * @var {MACType}
     */
    static DEFAULT_MAC_TYPE: MACType;
    /**
     * Construct an `ExtendedKey` object out of its' base58 payload.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts
     * @param   node   {BIP32}
     */
    constructor(/**
                 * The hyper-deterministic node.
                 * @var {BIP32 | NodeEd25519}
                 */ node: BIP32 | NodeEd25519, 
    /**
     * The hyper-deterministic node network.
     * @var {Network}
     */
    network: Network, 
    /**
     * The Message Authentication Code type to use.
     * Possible values include HMAC and KMAC.
     * @var {MACType}
     */
    macType?: MACType);
    /**
     * Create an extended key hyper-deterministic node by its' Base58
     * payload.
     *
     * This method uses the `bitcoinjs/bip32` function named `fromBase58`
     * and creates an extended key node by parsing the Base58 binary
     * representation.
     *
     * @param payload
     */
    static createFromBase58(payload: string, network: Network, macType?: MACType): ExtendedKey;
    /**
     * Create an extended key hyper-deterministic node with the master
     * seed.
     *
     * This method uses the `bitcoinjs/bip32` function named `fromSeed`
     * and creates an extended key node by creating HMAC-SHA512 hash
     * of the words 'Bitcoin seed' appended with the `seed` binary
     * representation.
     *
     * The result is split in 2 parts where the left most 32 bytes are
     * the private and right most 32 bytes are the public key.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L265
     * @param   seed    {string}
     * @param   network {Network}
     * @return  {ExtendedKey}
     */
    static createFromSeed(seed: string, network: Network, macType?: MACType): ExtendedKey;
    /**
     * Derive hyper-deterministic node by `path`.
     *
     * Default account layer should derive path `m/44'/43'/0'/0/0`.
     *
     * @see https://github.com/bitxorcorp/NIP/issues/12
     * @param path
     */
    derivePath(path: string): ExtendedKey;
    /**
     * Return whether an extended key node is neutered or not.
     *
     * Neutered = Public Key only
     * Not Neutered = Private Key available
     *
     * @return {boolean}
     */
    isNeutered(): boolean;
    /**
     * Return whether the current `node` is a master key node or not.
     *
     * @return {boolean}
     */
    isMaster(): boolean;
    /**
     * Get a neutered hyper-deterministic node. This corresponds to
     * a public key only extended key.
     *
     * From a neutered HD-node, users can only generate **public child
     * keys** and no **private child keys**.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L118
     * @return {ExtendedKey}    The neutered HD-node
     */
    getPublicNode(): ExtendedKey;
    /**
     * This method proxies the conversion to base58 format
     * to the `bitcoinjs/bip32` library.
     *
     * @return {string}
     */
    toBase58(): string;
    /**
     * Get the private key of the HD-node.
     *
     * This method defaults to returning the hexadecimal notation of
     * the key. Use `KeyEncoding.ENC_BIN` if you need the binary form.
     *
     * @see {KeyEncoding}
     * @return  {string}
     * @throws  {Error}     On use of this method with neutered extended keys (public keys).
     */
    getPrivateKey(encoding?: KeyEncoding): string | Buffer;
    /**
     * Get the public key in hexadecimal notation.
     *
     * This method defaults to returning the hexadecimal notation of
     * the key. Use `KeyEncoding.ENC_BIN` if you need the binary form.
     *
     * @see {KeyEncoding}
     * @return  {string}
     * @throws  {Error}     On use of this method with neutered extended keys (public keys).
     */
    getPublicKey(encoding?: KeyEncoding): string | Buffer;
    /**
     * Encode a key into `encoding`. Default `encoding` is `KeyEncoding.ENC_HEX`
     * which results in a hexadecimal notation of the key.
     *
     * @param key
     * @param encoding
     */
    protected encodeAs(key: Buffer, encoding?: KeyEncoding): string | Buffer;
}
