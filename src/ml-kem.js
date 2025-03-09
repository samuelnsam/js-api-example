
const AUTH_TOKEN = 'fb09ff0bb3bc8cbba2c88ed0d2b43612c579d38e1f6539b1b3'
const endpoint = 'https://api.exequantum.com'

const header = {
    'Authorization': 'bearer ' + AUTH_TOKEN,
    'Content-Type': 'application/json'
}

export async function keyGen() {
    const keys = await fetch(`${endpoint}/api/kem/generate_keys`, {
        headers: header
    }).then((data) => data.json())
    return {
        privateKey: keys.sk,
        publicKey: keys.pk,
        verificationSignature: keys.signature,
        verificationKey: keys.verification_key
    }
}

export async function encaps(publicKey, verifKey, signature) {
    const body = JSON.stringify({
        pk: publicKey,
        verification_key: verifKey,
        signature: signature
    })
    const encaps = await fetch(`${endpoint}/api/kem/encapsulate_key`, {
        method: 'POST',
        headers: header,
        body: body
    }).then((data) => data.json())

    return { 
        shared_key: encaps.shared_key,
        cipher: encaps.cipher
    }
}

export async function decaps(privateKey, cipher) {
    const body = JSON.stringify({
        sk: privateKey,
        cipher: cipher
    })
    const decaps = await fetch(`${endpoint}/api/kem/decapsulate_key`, {
        method: 'POST',
        headers: header,
        body: body
    }).then((data) => data.json())

    return decaps.shared_key
}