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
        publicKey: res.public_key,
        secretKey: res.secret_key
    }
}

export async function kemEncapsulate(publicKey, algorithm = 'ML-KEM-768') {
    const res = await fetch(`${endpoint}/api/v1/pqc/kem/encapsulate/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, public_key: publicKey })
    }).then(r => r.json())
    return {
        sharedSecret: res.shared_secret,
        ciphertext: res.ciphertext
    }
}

export async function kemDecapsulate(secretKey, ciphertext, algorithm = 'ML-KEM-768') {
    const res = await fetch(`${endpoint}/api/v1/pqc/kem/decapsulate/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, secret_key: secretKey, ciphertext })
    }).then(r => r.json())
    return res.shared_secret
}

// ── DSA ──────────────────────────────────────────────────

export async function dsaGenerateKeys(algorithm = 'ML-DSA-65') {
    const res = await fetch(`${endpoint}/api/v1/pqc/dsa/generate-keys/`, {
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
    const res = await fetch(`${endpoint}/api/v1/pqc/dsa/sign/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, secret_key: secretKey, message })
    }).then(r => r.json())
    return res.signature
}

export async function dsaVerify(publicKey, message, signature, algorithm = 'ML-DSA-65') {
    const res = await fetch(`${endpoint}/api/v1/pqc/dsa/verify/`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ algorithm, public_key: publicKey, message, signature })
    }).then(r => r.json())
    return res.verified
}
