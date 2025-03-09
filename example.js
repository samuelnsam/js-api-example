
import { keyGen, encaps, decaps } from "./src/ml-kem.js";
import { decryptAES, encryptAES } from './src/aesFuncs.js'

const main = async() => {
    const keys = await keyGen()
    const _encaps = await encaps(keys.publicKey, keys.verificationKey, keys.verificationSignature)
    const Ss1 = _encaps.shared_key
    console.log(Ss1)

    const Ss2 = await decaps(keys.privateKey, _encaps.cipher)
    console.log(Ss2 == Ss1)

    const message = 'hello'
    var encrypted = await encryptAES(message, Ss1)
    console.log(encrypted)
    var decrypted = await(decryptAES(encrypted.encryptedData, encrypted.iv, Ss2))
    console.log(decrypted)
}

main()