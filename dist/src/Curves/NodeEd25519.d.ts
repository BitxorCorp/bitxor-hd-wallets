/// <reference types="node" />
import { DeterministicKey, MACType, NodeInterface, Network } from '../../index';
/**
 * Class `NodeEd25519` describes a hyper-deterministic BIP32 node
 * implementation, compatible with ed25519 EC-curve.
 *
 * It is an implementation of BIP32 that is adapted to work with
 * ED25519 ellyptic curve keys rather than secp256k1 keys.
 *
 * This class *uses* features provided by the `bitcoinjs/bip32` package
 * and therefor is licensed under the BSD-2 Clause License as mentioned
 * [here](https://github.com/bitcoinjs/bip32/blob/master/LICENSE).
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 * @see https://github.com/bitcoinjs/bip32
 * @see https://github.com/bitxorcorp/NIP/issues/12
 * @since 0.2.0
 */
export declare class NodeEd25519 extends DeterministicKey implements NodeInterface {
    /**
     * Hardened key derivation uses HIGHEST_BIT.
     * @var number
     */
    static readonly HIGHEST_BIT = 2147483648;
    /**
     * Create a hyper-deterministic ED25519 node from a
     * binary seed.
     *
     * Depending on the curve algorithm, the seed is prepended with one of:
     *
     * - `ed25519 seed` for ed25519[-sha512] implementation (Network.BITXOR)
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L258
     * @param   seed    {Buffer}
     * @param   network {Network}
     * @return  {NodeInterface}
     */
    static fromSeed(seed: Buffer, network: Network, macType?: MACType): NodeEd25519;
    /**
     * Decode a base58 extended key payload into its'
     * `NodeEd25519` object representation.
     *
     * This method parses the base58 binary data and
     * uses read fields to initialize a BIP32-ED25519
     * hyper-deterministic node.
     *
     * No ED25519 changes have been done here.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L286
     * @param   inString    {string}    The base58 payload of the extended key.
     * @param   network     {Network}   (Optional) The network of the key.
     * @return  {NodeEd25519}
     */
    static fromBase58(inString: string, network: Network): NodeEd25519;
    /**
     * Getter for the `publicKey` of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get publicKey(): Buffer;
    /**
     * Get the neutered node.
     *
     * @access public
     * @return {NodeInterface}
     */
    neutered(): NodeInterface;
    /**
     * Generic child derivation.
     *
     * This method reads the derivation paths and uses `derive`
     * and `deriveHardened` accordingly.
     *
     * Derivation paths starting with `m/` are only possible
     * with master nodes (for example created from seed).
     *
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    derivePath(path: string): NodeInterface;
    /**
     * Hardened child derivation (derives private key).
     *
     * @internal Do not use this method directly, please use the `derivePath()` method instead.
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    deriveHardened(index: number): NodeInterface;
    /**
     * Derive a child node with `index`.
     *
     * When the node is *not neutered*, an extended private
     * key will be created and when the node is *neutered*,
     * an extended public key will be created.
     *
     * This method  is an overload of the `bitcoinjs/bip32`
     * package's `derive` method adapted to use *our* child
     * key derivation functions `CKDPriv` and `CKDPub`.
     *
     * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
     * @internal Do not use this method directly, please use the `derivePath()` method instead.
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    derive(index: number): NodeInterface;
    /**
     * Sign binary data with current node.
     *
     * Overloads the `bitcoinjs/bip32` method named `sign` in order to
     * be ED25519 compliant and use `tweetnacl` with ed25519 instead
     * of secp256k1.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L277
     * @param   hash    {Buffer}    The binary data to sign.
     * @return  {NodeInterface}
     */
    sign(hash: Buffer): Buffer;
    /**
     * Verify a signature `signature` for data
     * `hash` with the current node.
     *
     * Overloads the `bitcoinjs/bip32` method named `verify` in order to
     * be ED25519 compliant and use `tweetnacl` with ed25519 instead
     * of secp256k1.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L281
     * @param   hash        {Buffer}    The binary data that was supposedly signed.
     * @param   signature   {Buffer}    The signature binary data that needs to be verified.
     * @return  {boolean}   Returns true for a valid signature, false otherwise.
     */
    verify(hash: Buffer, signature: Buffer): boolean;
    /**
     * Validate a BIP32/BIP44 path by regular expression.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L26
     * @param   path    {string}
     * @return  {boolean}
     */
    protected isValidPath(path: string): boolean;
}
