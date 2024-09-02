"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Copyright 2022 Kriptxor Corp, Microsula S.A.
 *
 * Licensed under the BSD 2-Clause License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-2-Clause
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
const bs58check = require('bs58check');
// internal dependencies
const index_1 = require("../../index");
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
class DeterministicKey {
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
    constructor(__D, // private Key
    __Q, // public Key
    chainCode, network, __DEPTH = 0, __INDEX = 0, __PARENT_FINGERPRINT = 0x00000000) {
        this.__D = __D;
        this.__Q = __Q;
        this.chainCode = chainCode;
        this.network = network;
        this.__DEPTH = __DEPTH;
        this.__INDEX = __INDEX;
        this.__PARENT_FINGERPRINT = __PARENT_FINGERPRINT;
    }
    /// end-region: Abstract methods
    /**
     * Getter for the `depth` of the key.
     *
     * @access private
     * @return {number}
     */
    get depth() {
        return this.__DEPTH;
    }
    /**
     * Getter for the `index` (account index) of the key.
     *
     * @access private
     * @return {number}
     */
    get index() {
        return this.__INDEX;
    }
    /**
     * Getter for the `parentFingerprint` parent fingerprint of the key.
     *
     * @access private
     * @return {number}
     */
    get parentFingerprint() {
        return this.__PARENT_FINGERPRINT;
    }
    /**
     * Getter for the `privateKey` of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get privateKey() {
        if (!this.__D) {
            throw new Error('Missing private key.');
        }
        return this.__D;
    }
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
    get identifier() {
        return index_1.Cryptography.hash160(this.publicKey);
    }
    /**
     * Getter for the `fingerprint` of the key.
     *
     * The fingerprint are the first 4 bytes of the
     * identifier of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get fingerprint() {
        return this.identifier.slice(0, 4);
    }
    /**
     * Return whether the node is neutered or not.
     *
     * Neutered keys = Extended Public Keys
     * Non-Neutered keys = Extended Private Keys
     *
     * @access public
     * @return {Buffer}
     */
    isNeutered() {
        return this.__D === undefined;
    }
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
    getD() {
        return this.__D;
    }
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
    getQ() {
        return this.__Q;
    }
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
    getDepth() {
        return this.depth;
    }
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
    getIndex() {
        return this.index;
    }
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
    getParentFingerprint() {
        return this.parentFingerprint;
    }
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
    toBase58() {
        // determine whether we create a XPRV or XPUB
        const version = !this.isNeutered()
            ? this.network.privateKeyPrefix
            : this.network.publicKeyPrefix;
        // prepare extended key buffer
        const buffer = Buffer.allocUnsafe(78);
        // 4 bytes: version bytes
        buffer.writeUInt32BE(version, 0);
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
        buffer.writeUInt8(this.depth, 4);
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        buffer.writeUInt32BE(this.parentFingerprint, 5);
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        buffer.writeUInt32BE(this.index, 9);
        // 32 bytes: the chain code
        this.chainCode.copy(buffer, 13);
        // 33 bytes: the public key or private key data
        if (!this.isNeutered()) {
            // 0x00 + k for private keys
            buffer.writeUInt8(0, 45);
            this.privateKey.copy(buffer, 46);
        }
        else {
            // X9.62 encoding for public keys
            this.publicKey.copy(buffer, 45);
        }
        // return Base58 encoded buffer
        return bs58check.encode(buffer);
    }
    // XXX hidden usage of toHex() ?
    toWIF() {
        throw new TypeError('Bitxor BIP32 keys cannot be converted to WIF. Please use the toHex() method.');
    }
}
exports.DeterministicKey = DeterministicKey;
