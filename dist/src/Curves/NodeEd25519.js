"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
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
const nacl = __importStar(require("tweetnacl"));
const bs58check = require('bs58check');
// internal dependencies
const index_1 = require("../../index");
/**
 * Implementation of CKDPriv() function as described in SLIP-10
 * for multi-curve BIP32 compatibility with ED25519.
 *
 * Difference to BIP32:
 *  - Using 64-bytes master private key instead 32-bytes.
 *
 * @see https://cardanolaunch.com/assets/Ed25519_BIP.pdf
 * @see https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 * @see https://github.com/alepop/ed25519-hd-key/blob/master/src/index.ts#L36
 * @param   parent      {NodeEd25519}
 * @param   index       {number}
 * @param   macType     {MACType}
 * @return  {NodeEd25519}
 */
const CKDPriv = (parent, index, macType = index_1.MACType.HMAC) => {
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    // 0x00 || privateKey || index
    const data = Buffer.concat([Buffer.alloc(1, 0), parent.privateKey, indexBuffer]);
    // derive with said `macType` MAC algorithm
    const I = index_1.MACImpl.create(macType, parent.chainCode, data);
    // IL = privateKey ; IR = chainCode
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return new NodeEd25519(IL, undefined, IR, parent.network);
};
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
class NodeEd25519 extends index_1.DeterministicKey {
    // private readonly __D: Buffer | undefined // private Key
    // private __Q: Buffer | undefined // public Key
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
    static fromSeed(seed, network, macType = index_1.MACType.HMAC) {
        if (seed.length < 16)
            throw new TypeError('Seed should be at least 128 bits');
        if (seed.length > 64)
            throw new TypeError('Seed should be at most 512 bits');
        // (1) depending on curve algorithm, prepend the seed with one of:
        // `ed25519 seed` for ed25519[-sha512] implementation (Network.BITXOR)
        const prefix = 'ed25519 seed';
        const I = index_1.MACImpl.create(macType, Buffer.from(prefix, 'utf8'), seed);
        // (2) Split in 2 parts: privateKey and chainCode
        const kL = I.slice(0, 32);
        const kR = I.slice(32);
        // kL = privateKey ; kR = chainCode
        return new NodeEd25519(kL, undefined, kR, network);
    }
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
    static fromBase58(inString, network) {
        // decode base58
        const buffer = bs58check.decode(inString);
        if (buffer.length !== 78) {
            throw new TypeError('Base58 payload must be exactly 78 bytes, but got: ' + buffer.length + ' bytes.');
        }
        // 4 bytes: version bytes
        const version = buffer.readUInt32BE(0);
        if (version !== index_1.Network.BITXOR.privateKeyPrefix
            && version !== index_1.Network.BITXOR.publicKeyPrefix) {
            throw new TypeError('Payload Version must be one of: ' + index_1.Network.BITXOR.privateKeyPrefix
                + ' or ' + index_1.Network.BITXOR.publicKeyPrefix + '.');
        }
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
        const depth = buffer[4];
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        const parentFingerprint = buffer.readUInt32BE(5);
        // if depth is 0, parentFingerprint must be 0x00000000 (master node)
        if (depth === 0 && parentFingerprint !== 0x00000000) {
            throw new TypeError('Expected master node but got child with parentFingerprint: ' + parentFingerprint + '.');
        }
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in MSB order. (0x00000000 if master key)
        const index = buffer.readUInt32BE(9);
        // If depth is 0, index must also be 0 (master node)
        if (depth === 0 && index !== 0) {
            throw new TypeError('Expected index 0 with depth 0 but got index: ' + index + '.');
        }
        // 32 bytes: the chain code
        const chainCode = buffer.slice(13, 45);
        let hd;
        if (version === index_1.Network.BITXOR.privateKeyPrefix) {
            // 33 bytes: private key data (0x00 + k)
            if (buffer.readUInt8(45) !== 0x00) {
                throw new TypeError('Private key must start be prepended by 0x00.');
            }
            // extract private key (32 bytes)
            const k = buffer.slice(46, 78);
            // k = privateKey (createFromPrivateKey)
            hd = new NodeEd25519(k, undefined, chainCode, network, depth, index, parentFingerprint);
        }
        else {
            // 33 bytes: public key data (0x02 + X or 0x03 + X)
            // extract public key (33 bytes)
            const X = buffer.slice(45, 78);
            // X = publicKey
            hd = new NodeEd25519(undefined, X, chainCode, network, depth, index, parentFingerprint);
        }
        return hd;
    }
    /**
     * Getter for the `publicKey` of the key.
     *
     * @access public
     * @return {Buffer}
     */
    get publicKey() {
        if (this.getQ() !== undefined) {
            return this.getQ();
        }
        // use tweetnacl to generate key pair (SHA512)
        const keyPair = nacl.sign.keyPair.fromSeed(this.privateKey);
        return Buffer.from(keyPair.publicKey);
    }
    /**
     * Get the neutered node.
     *
     * @access public
     * @return {NodeInterface}
     */
    neutered() {
        return new NodeEd25519(undefined, this.publicKey, this.chainCode, this.network, this.getDepth(), this.getIndex(), this.getParentFingerprint());
    }
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
    derivePath(path) {
        if (!this.isValidPath(path)) {
            throw new TypeError('Invalid BIP32 derivation path provided.');
        }
        let splitPath = path.split('/');
        // check whether current node is a master node,
        // if not: "m/" derivation is not possible.
        if (splitPath[0] === 'm' && this.getParentFingerprint()) {
            throw new TypeError('Expected master node with "m" derivation, but got child with parentFingerprint.');
        }
        // drop first level path "m"
        if (splitPath[0] === 'm') {
            splitPath = splitPath.slice(1);
        }
        // apply derivation for each path level
        return splitPath.reduce((prevHd, indexStr) => {
            let index;
            // Always use hardened key derivation
            index = parseInt(indexStr.replace(/'/, ''), 10);
            return prevHd.deriveHardened(index);
        }, this);
    }
    /**
     * Hardened child derivation (derives private key).
     *
     * @internal Do not use this method directly, please use the `derivePath()` method instead.
     * @param   index   {number}
     * @return  {NodeInterface}
     */
    deriveHardened(index) {
        const UINT31_MAX = Math.pow(2, 31) - 1;
        if (index > UINT31_MAX) {
            throw new TypeError('Hardened derivation maximum index overflow.');
        }
        // Only derives hardened private keys by default
        return this.derive(index + NodeEd25519.HIGHEST_BIT);
    }
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
    derive(index) {
        // check derivation validity
        const isHardened = index >= NodeEd25519.HIGHEST_BIT;
        if (isHardened && this.isNeutered()) {
            throw new TypeError('Missing private key for hardened child key derivation.');
        }
        // Parent key is current node
        const parentKey = this;
        if (!this.isNeutered()) {
            // (1) Private parent key -> private child key
            // use ED25519-adapted child key derivation function
            return CKDPriv(parentKey, index);
        }
        // (2) Public parent key -> public child key
        // This is not possible with our implementation
        throw new Error('Non-Hardened key derivation is not permitted with ED25519 curve.');
    }
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
    sign(hash) {
        // use tweetnacl to generate key pair (SHA512)
        const keyPair = nacl.sign.keyPair.fromSeed(this.privateKey);
        // generate shared secret
        const secretKey = new Uint8Array(64);
        secretKey.set(this.privateKey);
        secretKey.set(keyPair.publicKey, 32);
        // use tweetnacl to sign
        const signature = nacl.sign.detached(hash, secretKey);
        return Buffer.from(signature);
    }
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
    verify(hash, signature) {
        // use tweetnacl to verify signature
        return nacl.sign.detached.verify(hash, signature, this.publicKey);
    }
    /**
     * Validate a BIP32/BIP44 path by regular expression.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L26
     * @param   path    {string}
     * @return  {boolean}
     */
    isValidPath(path) {
        return path.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
    }
}
exports.NodeEd25519 = NodeEd25519;
/**
 * Hardened key derivation uses HIGHEST_BIT.
 * @var number
 */
NodeEd25519.HIGHEST_BIT = 0x80000000;
