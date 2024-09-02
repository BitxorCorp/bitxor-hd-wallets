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
// internal dependencies
const index_1 = require("../index");
describe('Network -->', () => {
    describe('constructor() should', () => {
        it('set correct privateKeyPrefix and publicKeyPrefix', () => {
            const network1 = new index_1.Network(1, 2, index_1.CurveAlgorithm.secp256k1);
            const network2 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.secp256k1);
            chai_1.expect(network1.publicKeyPrefix).to.be.equal(1);
            chai_1.expect(network1.privateKeyPrefix).to.be.equal(2);
            chai_1.expect(network2.publicKeyPrefix).to.be.equal(0x0488b21e);
            chai_1.expect(network2.privateKeyPrefix).to.be.equal(0x0488ade4);
        });
        it('set correct curve algorithm', () => {
            const network1 = new index_1.Network(1, 2, index_1.CurveAlgorithm.secp256k1);
            const network2 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.ed25519);
            const network3 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.ed25519);
            chai_1.expect(network1.curve).to.be.equal(index_1.CurveAlgorithm.secp256k1);
            chai_1.expect(network2.curve).to.be.equal(index_1.CurveAlgorithm.ed25519);
            chai_1.expect(network3.curve).to.be.equal(index_1.CurveAlgorithm.ed25519);
        });
    });
    describe('equals() should', () => {
        it('return false given non-identical object', () => {
            const network1 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.ed25519);
            const network2 = new index_1.Network(1, 2, index_1.CurveAlgorithm.ed25519);
            chai_1.expect(network1.equals(network2)).to.be.equal(false);
        });
        it('return true given identical object', () => {
            const network1 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.ed25519);
            const network2 = new index_1.Network(0x0488b21e, 0x0488ade4, index_1.CurveAlgorithm.ed25519);
            chai_1.expect(network1.equals(network2)).to.be.equal(true);
        });
    });
});
