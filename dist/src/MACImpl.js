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
// internal dependencies
const index_1 = require("../index");
/**
 * Enumeration `MACImpl` describes multiple message authentication
 * code implementations.
 *
 * @see https://github.com/bitxorcorp/NIP/issues/12
 * @since 0.3.0
 */
class MACImpl {
    /**
     * No-Construct
     */
    constructor() { }
    /**
     * Create a message authentication code with given `type`.
     * This will use either of HMAC or KMAC code generation.
     *
     * @access public
     * @param   type        {MACType}
     * @param   key         {Buffer}
     * @param   data        {Buffer}
     * @param   publicSalt  {Buffer|undefined}  (Optional)
     */
    static create(type, key, data, publicSalt) {
        if (index_1.MACType.KMAC === type) {
            // use KMAC256
            return index_1.Cryptography.KMAC(key, data, publicSalt);
        }
        // by default uses HMAC with SHA512
        return index_1.Cryptography.HMAC(key, data);
    }
}
exports.MACImpl = MACImpl;
