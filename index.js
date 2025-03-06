import * as bip39 from 'bip39';
import sodium from 'sodium-native';
import * as crypto from 'crypto';

const size = 128; // 12 words. Size equal to 256 is 24 words.

export function generateKeyPair(mnemonicInput) {
    let mnemonic = mnemonicInput;
    if (!mnemonic) {
        mnemonic = bip39.generateMnemonic(size);
    }
    
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
    
    const seed32 = crypto.createHash('sha256').update(seed).digest();
    const seed32buffer = Buffer.from(seed32);
    
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed32buffer);
    
    return {
        mnemonic: mnemonic,
        publicKey: publicKey,
        secretKey: secretKey
    }
}