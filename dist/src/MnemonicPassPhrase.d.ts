/// <reference types="node" />
/**
 * Class `MnemonicPassPhrase` describes a mnemonic pass phrase generator
 * as defined by the Bitcoin BIP39 standard which can be found at following
 * URL:
 *
 *     https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * This class *uses* features provided by the `bitcoinjs/bip39` package
 * and therefor is licensed under the BSD-2 Clause License as mentioned
 * [here](https://github.com/bitcoinjs/bip39/blob/master/LICENSE).
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * @see https://github.com/bitcoinjs/bip39
 * @since 0.1.0
 */
export declare class MnemonicPassPhrase {
    readonly plain: string;
    /**
     * Default wordlist language used.
     *
     * @see [List of Supported Languages](https://github.com/bitcoinjs/bip39/tree/master/ts_src/wordlists)
     * @var {string}
     */
    static readonly DEFAULT_LANGUAGE = "english";
    /**
     * Default mnemonic strength.
     *
     * @see https://github.com/bitcoinjs/bip39/blob/master/ts_src/index.ts#L131
     * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
     * @var {number}
     */
    static readonly DEFAULT_STRENGTH = 256;
    /**
     * Random number generator using `nacl_bitxorcore`.
     *
     * Implicit conversion to `Buffer` is needed to comply
     * with `bitcoinjs/bip39`.
     *
     * @param   bytes   {number}    Number of bytes to generate.
     * @return  {Buffer}
     */
    static BITXORCORE_RNG: (bytes: number) => Buffer;
    /**
     * Create a `MnemonicPassPhrase` instance.
     *
     * @param plain {string}
     */
    constructor(/**
                        * The mnemonic pass phrase (plain text).
                        * @var {string}
                        */ plain: string);
    /**
     * Create a random mnemonic pass phrase. Arguments to this method are
     * all optional, default values are static variables of this class.
     *
     * This static method returns a sentence built following the Bitcoin
     * BIP39 standard using the `bitcoinjs/bip39` library.
     *
     * @todo `strength` replace by `countWords` for higher level approach
     *
     * @param   language    {string}    (Optional) The language used for the wordlist.
     * @param   strength    {number}    (Optional) Strength of mnemonic pass phrase (% 32 == 0).
     * @param   rng         {function}  (Optional) Random Number Generator to be used.
     * @return  {string}    Returns the mnemonic pass phrase in plain text format.
     * @throws  {Error}     On unsupported `language` argument.
     */
    static createRandom(language?: string, strength?: number, rng?: (size: number) => Buffer): MnemonicPassPhrase;
    /**
     * Convert an entropy value to a mnemonic pass phrase in plain text.
     *
     * If the `language` argument is ommited, the default
     * language 'english' will be used.
     *
     * The `bitcoinjs/bip39` package's `entropyToMnemonic` function
     * validates the entropy value by parsing it, then builds the mnemonic
     * pass phrase by retrieving and joining words from the wordlist.
     *
     * @param   mnemonic    {string}    The mnemonic pass phrase to validate.
     * @param   language    {string}    (Optional) The language used for the wordlist.
     * @return  {string}    Returns the mnemonic pass phrase in plain text format.
     * @throws  {Error}     On unsupported `language` argument.
     */
    static createFromEntropy(entropy: Buffer | string, language?: string): MnemonicPassPhrase;
    /**
     * Assert whether `language` is a supported language string, or not.
     *
     * @internal
     * @see https://github.com/bitcoinjs/bip39/tree/master/ts_src/wordlists
     * @return  {boolean}   True for *supported languages*, never false.
     * @throws  {Error}     On unsupported `language` argument.
     */
    protected static assertLanguageSupported(language: string): true;
    /**
     * Validate a mnemonic pass phrase with optional `language`.
     *
     * If the `language` argument is ommited, the default
     * language 'english' will be used.
     *
     * The `bitcoinjs/bip39` package's `validateMnemonic` function
     * checks the mnemonic pass phrase by internally converting
     * to an entropy bytes array with `mnemonicToEntropy`.
     *
     * Validation steps include `size`, `checksum bits` and `checksum`
     * validations.
     *
     * @param   mnemonic    {string}    The mnemonic pass phrase to validate.
     * @param   language    {string}    (Optional) The language used for the wordlist.
     * @return  {boolean}   True for *valid mnemonic*, False for *invalid mnemonic*.
     * @throws  {Error}     On unsupported `language` argument.
     */
    isValid(language?: string): boolean;
    /**
     * Get the array representation for the mnemonic pass phrase.
     *
     * Words are split using a white-space character as a separator.
     *
     * @return  {string[]}  Array of plain text words
     */
    toArray(): string[];
    /**
     * Convert a mnemonic to an **encrypted** hexadecimal seed.
     *
     * If the `password` argument is ommited, an empty password will be assumed.
     *
     * The `bitcoinjs/bip39` package's `mnemonicToSeedSync` function
     * will first *normalize* the mnemonic pass phrase Buffer to
     * [NFKD form](https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms).
     * Afterwards the buffer will be *salted* with the `password` (or empty) prepend
     * by the string 'mnemonic'.
     * In its last step, the function will then use PBKDF2 to derivate the password-
     * protected hexadecimal seed from the salted buffer.
     *
     * @see https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms
     * @param   password    {string}
     * @return  {Buffer}    Buffer containing bytes of the hexadecimal seed.
     */
    toSeed(password?: string): Buffer;
    /**
     * Converts a mnemonic to hexadecimal entropy (of `strength` bits).
     *
     * If the `language` argument is ommited, the default
     * language 'english' will be used.
     *
     * The `bitcoinjs/bip39` package's `mnemonicToEntropy` function
     * converts words into 11 bit binary strings, then validates the
     * checksum and finally, returns the built entropy hexadecimal
     * (of `strength` bits).
     *
     * It is not recommended to store the result of this function. Please,
     * have a look at `mnemonicToSeed(m, pw)` instead.
     *
     * @see {MnemonicPassPhrase}#mnemonicToSeed
     * @param   language    {string}    (Optional) The language used for the wordlist.
     * @return  {string}    Returns the hexadecimal format of the entropy value.
     * @throws  {Error}     On unsupported `language` argument.
     */
    toEntropy(language?: string): string;
}
