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
const chai_1 = require("chai");
const index_1 = require("../index");
describe('MnemonicPassPhrase -->', () => {
    const words = [
        'alpha', 'pattern', 'real', 'admit',
        'vacuum', 'wall', 'ready', 'code',
        'correct', 'program', 'depend', 'valid',
        'focus', 'basket', 'whisper', 'firm',
        'tray', 'fit', 'rally', 'day',
        'dance', 'demise', 'engine', 'mango'
    ];
    describe('constructor() should', () => {
        it('create with words given plain text pass phrase', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const expected = words.join(' ');
            chai_1.expect(mnemonic.plain).to.be.equal(expected);
        });
    });
    describe('toArray() should', () => {
        it('return words array given plain text pass phrase', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const asArray = mnemonic.toArray();
            chai_1.expect(asArray.length).to.be.equal(24);
        });
    });
    describe('isValid() should', () => {
        it('return true for valid mnemonic pass phrase', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            chai_1.expect(mnemonic.isValid()).to.be.equal(true);
        });
        it('return false for invalid mnemonic pass phrase', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.slice(1).join(' ')); // omit first word
            chai_1.expect(mnemonic.isValid()).to.be.equal(false);
        });
    });
    describe('toSeed() should', () => {
        it('return binary representation with type Buffer', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const secureSeed = mnemonic.toSeed();
            chai_1.expect(secureSeed).to.be.instanceof(Buffer);
        });
        it('use empty password when given no password', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const mnemonic2 = new index_1.MnemonicPassPhrase(words.join(' '));
            const secureSeed = mnemonic.toSeed(); // no-password = undefined
            const secureSeed2 = mnemonic2.toSeed(''); // no-password = empty-password
            chai_1.expect(secureSeed.byteLength).to.be.equal(64);
            chai_1.expect(secureSeed.toString('hex').length).to.be.equal(128);
            chai_1.expect(secureSeed.toString('hex')).to.be.equal(secureSeed2.toString('hex'));
        });
        it('use password when given valid password', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const mnemonic2 = new index_1.MnemonicPassPhrase(words.join(' '));
            const secureSeed = mnemonic.toSeed(); // no-password = undefined
            const secureSeedPw = mnemonic2.toSeed('your-password');
            chai_1.expect(secureSeed.byteLength).to.be.equal(64);
            chai_1.expect(secureSeedPw.byteLength).to.be.equal(64);
            chai_1.expect(secureSeed.toString('hex')).to.not.be.equal(secureSeedPw.toString('hex'));
        });
    });
    describe('toEntropy() should', () => {
        it('return hexadecimal seed (BIP32 extended key derivation seed) ', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const bip32Seed = mnemonic.toEntropy();
            const binarySeed = Buffer.from(bip32Seed, 'hex');
            chai_1.expect(binarySeed.byteLength).to.be.equal(32);
            chai_1.expect(bip32Seed).to.be.equal('07142acb81df09ed6cb16830957cebf865a2267ea2bae7aafac51c037474929c');
        });
    });
    describe('MnemonicPassPhrase.createRandom() should', () => {
        it('be created randomly without arguments', () => {
            const mnemonic = index_1.MnemonicPassPhrase.createRandom();
            chai_1.expect(mnemonic.toArray().length).to.be.equal(24);
        });
        it('be created randomly with valid arguments', () => {
            const mnemonic = index_1.MnemonicPassPhrase.createRandom('english', 256);
            chai_1.expect(mnemonic.toArray().length).to.be.equal(24);
        });
        it('throw given invalid pass phrase strength', () => {
            chai_1.expect(() => {
                const invalidStrength = 64;
                index_1.MnemonicPassPhrase.createRandom('english', invalidStrength);
            }).to.throw('Invalid strength, must be multiple of 32 with: 128 >= strength <= 256.');
        });
        it('throw given language not supported by BIP39', () => {
            const invalidLanguage = 'belgian';
            chai_1.expect(() => {
                index_1.MnemonicPassPhrase.createRandom(invalidLanguage);
            }).to.throw('Language "' + invalidLanguage + '" is not supported.');
        });
        it('accept strength to change number of words', () => {
            const m24 = index_1.MnemonicPassPhrase.createRandom('english', 256);
            const m18 = index_1.MnemonicPassPhrase.createRandom('english', 192);
            const m12 = index_1.MnemonicPassPhrase.createRandom('english', 128);
            chai_1.expect(m24.toArray().length).to.be.equal(24);
            chai_1.expect(m18.toArray().length).to.be.equal(18);
            chai_1.expect(m12.toArray().length).to.be.equal(12);
        });
    });
    describe('createFromEntropy() should', () => {
        it('return a valid mnemonic', () => {
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const fromEntropy = index_1.MnemonicPassPhrase.createFromEntropy('07142acb81df09ed6cb16830957cebf865a2267ea2bae7aafac51c037474929c');
            chai_1.expect(fromEntropy.toArray().length).to.be.equal(24);
            chai_1.expect(fromEntropy.plain).to.be.equal(mnemonic.plain);
        });
        it('produce mnemonic with relative length to the input entropy', () => {
            const m12 = index_1.MnemonicPassPhrase.createRandom('english', 128);
            const m18 = index_1.MnemonicPassPhrase.createRandom('english', 192);
            const fromEntropyM12 = index_1.MnemonicPassPhrase.createFromEntropy(m12.toEntropy());
            const fromEntropyM18 = index_1.MnemonicPassPhrase.createFromEntropy(m18.toEntropy());
            chai_1.expect(fromEntropyM12.toArray().length).to.not.be.equal(fromEntropyM18.toArray().length);
            chai_1.expect(fromEntropyM12.toArray().length).to.be.equal(12);
            chai_1.expect(fromEntropyM18.toArray().length).to.be.equal(18);
        });
        it('throw given language not supported by BIP39', () => {
            const invalidLanguage = 'arabic';
            const mnemonic = new index_1.MnemonicPassPhrase(words.join(' '));
            const entropy = mnemonic.toEntropy();
            chai_1.expect(() => {
                index_1.MnemonicPassPhrase.createFromEntropy(entropy, invalidLanguage);
            }).to.throw('Language "' + invalidLanguage + '" is not supported.');
        });
    });
});
