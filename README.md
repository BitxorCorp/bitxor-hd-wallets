# Bitxor HD Wallets

[![npm version](https://badge.fury.io/js/bitxor-hd-wallets.svg)](https://badge.fury.io/js/bitxor-hd-wallets)
[![Build Status](https://travis-ci.com/bitxorcorp/bitxor-hd-wallets.svg?branch=master)](https://travis-ci.com/bitxorcorp/bitxor-hd-wallets)
[![Slack](https://img.shields.io/badge/chat-on%20slack-green.svg)](https://bitxor.slack.com/messages/CB0UU89GS//)

Hierarchical-deterministic (HD) wallets generator library for Bitxor.

This is a PoC to validate the proposed [NIP6 Multi-Account Hierarchy for Deterministic Wallets](https://github.com/bitxorcorp/NIP/issues/12). When stable, the repository will be moved to the [bitxorcorp](https://github.com/bitxorcorp) organization.

**NOTE**: The author of this package cannot be held responsible for any loss of money or any malintentioned usage forms of this package. Please use this package with caution.

## Requirements

- Node.js 12 LTS

## Installation

`npm install bitxor-hd-wallets`

## Usage

### Generating a mnemonic pass phrase

```ts
// examples/GeneratingAMnemonicPassPhrase.ts

import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// random 24-words mnemonic
MnemonicPassPhrase.createRandom();

// random 12-words mnemonic
MnemonicPassPhrase.createRandom('english', 128);

// random 24-words mnemonic with french wordlist
MnemonicPassPhrase.createRandom('french');

// random 24-words mnemonic with japanese wordlist
MnemonicPassPhrase.createRandom('japanese');

```

### Generating a password-protected mnemonic pass phrase seed (for storage)

```ts
// examples/GeneratePasswordProtectedSeedForRandomPassPhrase.ts

import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');

```

```ts
// examples/GeneratePasswordProtectedSeedForRandomPassPhraseEmptyPassword.ts

import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 2: empty password for password-protected seed
const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed(); // omit password means empty password: ''

```

### Generating a root (master) extended key

```ts
// examples/GeneratingARootMasterExtendedKeyForKnownPassPhrase.ts

import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 2: generate BIP32 master seed for known pass phrase
const words = 'alpha pattern real admit vacuum wall ready code '
    + 'correct program depend valid focus basket whisper firm '
    + 'tray fit rally day dance demise engine mango';
const mnemonic = new MnemonicPassPhrase(words);

// the following seed can be used with `ExtendedKey.createFromSeed()`
const bip32Seed = mnemonic.toSeed(); // using empty password

```

```ts
// examples/GeneratingARootMasterExtendedKeyForRandomPassPhrase.ts

import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 1: generate BIP32 master seed for random pass phrase
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toSeed();

```

### Generating a HD wallet (BITXOR **mijin** and **mijinTest** compatible)

```ts
// examples/GeneratingAHDWalletPrivateNetworkCompatible.ts

import {NetworkType} from 'bitxor-sdk';
import {ExtendedKey} from "../src/ExtendedKey";
import {Wallet} from "../src/Wallet";
import {Network} from "../src/Network";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.BITXOR);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/4343\'/0\'/0\'/0\'', NetworkType.MIJIN_TEST);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.MIJIN_TEST);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();

```

### Generating a HD wallet (BITXOR **public** and **publicTest** compatible)

```ts
// examples/GeneratingAHDWalletPublicNetworkCompatible.ts

import {Network} from "../src/Network";
import {NetworkType} from "bitxor-sdk";
import {Wallet} from "../src/Wallet";
import {ExtendedKey} from "../src/ExtendedKey";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.BITXOR);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/4343\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.TEST_NET);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();

```

### Signing with a HD wallet (BITXOR compatible)

```ts
// examples/SigningWithAHDWalletPrivateNetworkCompatible.ts

import {Account, Deadline, EmptyMessage, NetworkType, TransferTransaction} from "bitxor-sdk";
import {Wallet} from "../src/Wallet";
import {ExtendedKey} from "../src/ExtendedKey";
import {Network} from "../src/Network";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.BITXOR);
const wallet = new Wallet(xkey);

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/4343\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// create a transfer object
const transfer = TransferTransaction.create(
    Deadline.create(),
    Account.generateNewAccount(NetworkType.TEST_NET).address,
    [],
    EmptyMessage,
    NetworkType.TEST_NET);

// sign the transaction with derived account
const generationHash = ''; // replace with network generation hash
const signedTx = childAccount.sign(transfer, generationHash);

```
## Getting help

Use the following available resources to get help:

- [Bitxor Documentation][docs]
- Join the community [slack group (#sig-client)][slack] 
- If you found a bug, [open a new issue][issues]

## Contributing

Contributions are welcome and appreciated. 
Check [CONTRIBUTING](CONTRIBUTING.md) for information on how to contribute.

## License

Copyright (c) 2019, Grégory Saive

Licensed under the [BSD-2 License](LICENSE).

[self]: https://github.com/bitxorcorp/bitxor-hd-wallets
[docs]: https://bitxorcorp.github.io
[issues]: https://github.com/bitxorcorp/bitxor-hd-wallets/issues
[slack]: https://join.slack.com/t/bitxor/shared_invite/enQtMzY4MDc2NTg0ODgyLWZmZWRiMjViYTVhZjEzOTA0MzUyMTA1NTA5OWQ0MWUzNTA4NjM5OTJhOGViOTBhNjkxYWVhMWRiZDRkOTE0YmU
