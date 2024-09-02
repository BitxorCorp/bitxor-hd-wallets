/// <reference types="node" />
import { Network, NodeInterface } from '../../index';
/**
 * Class `DeterministicKey` describes hierarchical deterministic
 * keys that are compatible with the `bitcoinjs/bip32` implementation.
 *
 * This class is used to provide with compatibility for both schemes:
 * BIP32 and NIP6.
 *
 * @see https://github.com/bitxorcorp/NIP/issues/12
 * @since 0.2.0
 */
export declare abstract class DeterministicKey implements NodeInterface {
    private readonly __D;
    private __Q;
    readonly chainCode: Buffer;
    readonly network: Network;
    private readonly __DEPTH;
    private readonly __INDEX;
    private readonly __PARENT_FINGERPRINT;
    /**
     * Construct a `NodeEd25519` object.
     *
     * @param ___D      {Buffer|undefined}  The private key of the node.
     * @param ___Q      {Buffer|undefined}  The public key of the node.
     * @param chainCode {Buffer}            The chain code of the node (32 bytes).
     * @param network   {Network}           The network of the node
     * @param ___DEPTH  {number}            The depth of the node (0 for master).
     * @param ___INDEX  {number}            The account index (0 for master).
     * @param ___PARENT_FINGERPRINT     {number}    The parent fingerprint (0x00000000 for master)
     */
    constructor(__D: Buffer | undefined, // private Key
    __Q: Buffer | undefined, // public Key
    chainCode: Buffer, network: Network, __DEPTH?: number, __INDEX?: number, __PARENT_FINGERPRINT?: number);
    /**
     * Generic child derivation.
     *
     * This method reads the derivation paths and uses `derive`
     * and `deriveHardened` accordingly.
     *
     * Derivation paths starting with `m/` are only possible
     * with master nodes (for example created from seed).
     *
     * @abstract
     * @access public
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    abstract derivePath(path: string): NodeInterface;
    /**
     * Hardened child derivation (derives private key).
     *
     * @internal Do not use this method directly, please use the `derivePath()` method instead.
     *
     * @abstract
     * @access public
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    abstract deriveHardened(index: number): NodeInterface;
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
     * @abstract
     * @access public
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    abstract derive(index: number): NodeInterface;
    /**
     * Get the neutered node.
     *
     * @abstract
     * @access public
     * @return {NodeInterface}
     */
    abstract neutered(): NodeInterface;
    /**
     * Sign binary data with current node.
     *
     * Overloads the `bitcoinjs/bip32` method named `sign` in order to
     * be ED25519 compliant and use `tweetnacl` with ed25519 instead
     * of secp256k1.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L277
     * @abstract
     * @access public
     * @param   hash    {Buffer}    The binary data to sign.
     * @return  {NodeInterface}
     */
    abstract sign(hash: Buffer): Buffer;
    /**
     * Verify a signature `signature` for data
     * `hash` with the current node.
     *
     * Overloads the `bitcoinjs/bip32` method named `verify` in order to
     * be ED25519 compliant and use `tweetnacl` with ed25519 instead
     * of secp256k1.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L281
     * @abstract
     * @access publics
     * @param   hash        {Buffer}    The binary data that was supposedly signed.
     * @param   signature   {Buffer}    The signature binary data that needs to be verified.
     * @return  {boolean}   Returns true for a valid signature, false otherwise.
     */
    abstract verify(hash: Buffer, signature: Buffer): boolean;
    /**
     * Getter for the `publicKey` of the key.
     *
     * In case the publicKey is not set, this method
     * should derive from private key.
     *
     * @abstract
     * @access public
     * @return {Buffer}
     */
    abstract get publicKey(): Buffer;
    /**
     * Getter for the `depth` of the key.
     *
     * @access private
     * @return {number}
     */
    private get depth();
    /**
     * Getter for the `index` (account index) of the key.
     *
     * @access private
     * @return {number}
     */
    private get index();
    /**
     * Getter for the `parentFingerprint` parent fingerprint of the key.
     *
     * @access private
     * @return {number}
     */
    private get parentFingerprint();
    /**
     * Getter for the `privateKey` of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get privateKey(): Buffer;
    /**
     * Getter for the `identifier` of the key.
     *
     * The identifier is build as follows:
     * - Step 1: Sha3-256 of the public key
     * - Step 2: RIPEMD160 of the sha3 hash
     *
     * @access public
     * @return {Buffer}
     */
    get identifier(): Buffer;
    /**
     * Getter for the `fingerprint` of the key.
     *
     * The fingerprint are the first 4 bytes of the
     * identifier of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get fingerprint(): Buffer;
    /**
     * Return whether the node is neutered or not.
     *
     * Neutered keys = Extended Public Keys
     * Non-Neutered keys = Extended Private Keys
     *
     * @access public
     * @return {Buffer}
     */
    isNeutered(): boolean;
    /**
     * Getter for private field `__D`.
     *
     * This method is added to explicitely expose the
     * `__D` field to allow sub-classes to make
     * use of it.
     *
     * The `__D` field represents the private key.
     *
     * @access  public
     * @return  {Buffer}
     */
    getD(): Buffer | undefined;
    /**
     * Getter for private field `__Q`.
     *
     * This method is added to explicitely expose the
     * `__Q` field to allow sub-classes to make
     * use of it.
     *
     * The `__Q` field represents the public key.
     *
     * @access  public
     * @return  {Buffer}
     */
    getQ(): Buffer | undefined;
    /**
     * Getter for private field `depth`.
     *
     * This method is added to explicitely expose the
     * `depth` field to allow sub-classes to make
     * use of it.
     *
     * @access  public
     * @return  {Buffer}
     */
    getDepth(): number;
    /**
     * Getter for private field `index`.
     *
     * This method is added to explicitely expose the
     * `index` field to allow sub-classes to make
     * use of it.
     *
     * @access  public
     * @return  {Buffer}
     */
    getIndex(): number;
    /**
     * Getter for private field `parentFingerprint`.
     *
     * This method is added to explicitely expose the
     * `parentFingerprint` field to allow sub-classes to make
     * use of it.
     *
     * @access  public
     * @return  {Buffer}
     */
    getParentFingerprint(): number;
    /**
     * Get the Base58 representation of said key.
     *
     * This method is modified to use the `Network` class to
     * determine privateKey and publicKey prefixes (version field).
     *
     * The Base58 representation is laid on 78 bytes with following
     * specification (with `||` concatenation operator) :
     *
     * `version || depth || parent || index || chain code || priv/pub`
     *
     * Private keys are prepended with `0x00`, public keys are encoded
     * in X9.62 format.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L73
     * @access  public
     * @return  {string}
     */
    toBase58(): string;
    toWIF(): string;
}
