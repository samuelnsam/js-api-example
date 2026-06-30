const AUTH_TOKEN = process.env.AUTH_TOKEN
const endpoint = 'https://api.eqcore.io'
const headers = {
    'Authorization': 'Bearer ' + AUTH_TOKEN,
    'Content-Type': 'application/json'
}

// ── KEM ──────────────────────────────────────────────────

export async function kemGenerateKeys(algorithm = 'ML-KEM-768') {
    const res = await fetch(`${endpoint}/api/v1/pqc/kem/generate-keys/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm })
    }).then(r => r.json())
    return {
        encapsulationKey: res.encapsulation_key,
        decapsulationKey: res.decapsulation_key
    }
}

export async function kemEncapsulate(encapsulationKey, algorithm = 'ML-KEM-768') {
    const res = await fetch(`${endpoint}/api/v1/pqc/kem/encapsulate/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, encapsulation_key: encapsulationKey })
    }).then(r => r.json())
    return {
        sharedSecret: res.shared_secret,
        ciphertext: res.ciphertext
    }
}

export async function kemDecapsulate(decapsulationKey, ciphertext, algorithm = 'ML-KEM-768') {
    const res = await fetch(`${endpoint}/api/v1/pqc/kem/decapsulate/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, decapsulation_key: decapsulationKey, ciphertext })
    }).then(r => r.json())
    return res.shared_secret
}

// ── DSA ──────────────────────────────────────────────────

export async function dsaGenerateKeys(algorithm = 'ML-DSA-65') {
    const res = await fetch(`${endpoint}/api/v1/pqc/sign/generate-keys/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm })
    }).then(r => r.json())
    return {
        publicKey: res.public_key,
        secretKey: res.secret_key
    }
}

export async function dsaSign(secretKey, message, algorithm = 'ML-DSA-65') {
    const res = await fetch(`${endpoint}/api/v1/pqc/sign/sign/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, secret_key: secretKey, message })
    }).then(r => r.json())
    return res.signature
}

export async function dsaVerify(publicKey, message, signature, algorithm = 'ML-DSA-65') {
    const res = await fetch(`${endpoint}/api/v1/pqc/sign/verify/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, public_key: publicKey, message, signature })
    }).then(r => r.json())
    return res.valid
}
