"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
const js_sha3_1 = require("js-sha3");
const createHash = require('create-hash');
const createHmac = require('create-hmac');
class Cryptography {
    /**
     *
     * @param buffer
     */
    static hash160(buffer) {
        // step 1: SHA256(buffer)
        const sha256Hash = createHash('sha256').update(buffer).digest();
        // step 2: RIPEMD160(shaHash)
        try {
            return createHash('rmd160').update(sha256Hash).digest();
        }
        catch (err) {
            return createHash('ripemd160').update(sha256Hash).digest();
        }
    }
    /**
     * Creates a Hash Message Authentication Code.
     *
     * This method uses SHA512 algorithm and `create-hmac`
     * dependency for the MAC generation.
     *
     * @param   key     {Buffer}
     * @param   data    {Buffer}
     * @return  {Buffer}
     */
    static HMAC(key, data) {
        return createHmac('sha512', key).update(data).digest();
    }
    /**
     * Creates a Keccak Message Authentication Code.
     *
     * @internal This method is used internally for key derivation
     * @param   key         {Buffer}
     * @param   data        {Buffer}
     * @param   publicSalt  {string}
     * @return  {Buffer}
     */
    static KMAC(key, data, publicSalt) {
        const hex = js_sha3_1.kmac256(key, data, 512, publicSalt || '');
        return Buffer.from(hex, 'hex');
    }
}
exports.Cryptography = Cryptography;
