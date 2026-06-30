// main.js

import {
    kemGenerateKeys, kemEncapsulate, kemDecapsulate,
    dsaGenerateKeys, dsaSign, dsaVerify
} from './src/pqc.js'
import { deriveKey, encrypt, decrypt } from './src/crypto.js'

const main = async () => {

    // 1. KEM: establish shared secret
    const kem = await kemGenerateKeys()
    const { sharedSecret: ss1, ciphertext } = await kemEncapsulate(kem.encapsulationKey)
    const ss2 = await kemDecapsulate(kem.decapsulationKey, ciphertext)
    console.log('Shared secrets match:', ss1 === ss2)

    // 2. KDF: derive AES key (never use raw shared secret directly)
    const senderKey = await deriveKey(ss1)
    const recipientKey = await deriveKey(ss2)

    // 3. Encrypt
    const message = 'hello from post-quantum land'
    const { iv, ciphertext: encrypted } = await encrypt(message, senderKey)
    console.log('Encrypted:', encrypted)

    // 4. Decrypt
    const decrypted = await decrypt(encrypted, iv, recipientKey)
    console.log('Decrypted:', decrypted)

    // 5. DSA: sign and verify
    const dsa = await dsaGenerateKeys()
    const signature = await dsaSign(dsa.secretKey, message)
    const valid = await dsaVerify(dsa.publicKey, message, signature)
    console.log('Signature valid:', valid)
}

main()
