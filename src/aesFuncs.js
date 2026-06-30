// src/crypto.js

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
    }
    return bytes
}

export async function deriveKey(sharedSecretHex, salt = 'pqc-session-v1', info = 'aes-256-gcm') {
    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        hexToBytes(sharedSecretHex),
        'HKDF',
        false,
        ['deriveKey']
    )
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: encoder.encode(salt),
            info: encoder.encode(info),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

export async function deriveHybridKey(classicalSecret, pqcSecret, salt = 'hybrid-kex-v1', info = 'aes-256-gcm') {
    const combined = new Uint8Array([
        ...hexToBytes(classicalSecret),
        ...hexToBytes(pqcSecret)
    ])
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        combined,
        'HKDF',
        false,
        ['deriveKey']
    )
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode(salt),
            info: new TextEncoder().encode(info),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

export async function encrypt(plainText, derivedKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        new TextEncoder().encode(plainText)
    )
    return { iv, ciphertext: new Uint8Array(encrypted) }
}

export async function decrypt(ciphertext, iv, derivedKey) {
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        ciphertext
    )
    return new TextDecoder().decode(decrypted)
}
