function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

async function importAESKeyFromHex(hexKey) {
    const keyBytes = hexToBytes(hexKey);  
  
    const key = await crypto.subtle.importKey(
      "raw",  
      keyBytes,  
      {
        name: "AES-GCM",  
      },
      false, 
      ["encrypt", "decrypt"]  
    );
  
    return key;
}

export async function encryptAES(plainText, key) {
    key = await importAESKeyFromHex(key);  
  
    const encoder = new TextEncoder();
    const data = encoder.encode(plainText);  

    const iv = crypto.getRandomValues(new Uint8Array(12));
  
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv, 
      },
      key,
      data  
    );
  
    return {
      iv: iv,
      encryptedData: new Uint8Array(encrypted)
    };
  }
  

export async function decryptAES(encryptedData, iv, key) {
    key = await importAESKeyFromHex(key);
  
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,  
      },
      key,  
      encryptedData  
    );
  
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }
  