const crypto = require('crypto')

function encrypt({
    mode,
    key,
    iv = Buffer.alloc(0),
    plaintext,
    padding = true,
    inputEncoding = 'utf8',
    outputEncoding = 'hex'
}) {
    const cipher = crypto.createCipheriv(mode, key, iv)
    cipher.setAutoPadding(padding)
    let ciphertext = cipher.update(plaintext, inputEncoding, outputEncoding)
    ciphertext += cipher.final(outputEncoding)

    return {
        iv: iv.toString(outputEncoding),
        ciphertext
    }
}

function decrypt({
    mode,
    key,
    iv = Buffer.alloc(0),
    ciphertext,
    padding = true,
    inputEncoding = 'hex',
    outputEncoding = 'utf8'
}) {
    const decipher = crypto.createDecipheriv(mode, key, iv)
    decipher.setAutoPadding(padding)
    let plaintext = decipher.update(ciphertext, inputEncoding, outputEncoding)
    plaintext += decipher.final(outputEncoding)

    return { plaintext }
}

function encrypt_GCM({
    key,
    iv,
    plaintext,
    inputEncoding = 'utf8',
    outputEncoding = 'hex'
}) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    let ciphertext = cipher.update(plaintext, inputEncoding, outputEncoding)
    ciphertext += cipher.final(outputEncoding)
    const tag = cipher.getAuthTag()

    return {
        iv: iv.toString(outputEncoding),
        ciphertext,
        tag: tag.toString(outputEncoding)
    }
}

function decrypt_GCM({
    key,
    iv,
    tag,
    ciphertext,
    inputEncoding = 'hex',
    outputEncoding = 'utf8'
}) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, new Buffer.from(iv, inputEncoding))
    decipher.setAuthTag(new Buffer.from(tag, inputEncoding))
    let plaintext = decipher.update(ciphertext, inputEncoding, outputEncoding)
    plaintext += decipher.final(outputEncoding)

    return plaintext
}

exports.ecb = ({
    encrypt: params => encrypt({ mode: 'aes-256-ecb', ...params }),
    decrypt: params => decrypt({ mode: 'aes-256-ecb', ...params })
})

exports.cbc = ({
    encrypt: params => encrypt({ mode: 'aes-256-cbc', ...params }),
    decrypt: params => decrypt({ mode: 'aes-256-cbc', ...params })
})

exports.ctr = ({
    encrypt: params => encrypt({ mode: 'aes-256-ctr', ...params }),
    decrypt: params => encrypt({ mode: 'aes-256-ctr', ...params })
})

exports.gcm = ({
    encrypt: params => encrypt_GCM({ ...params }),
    decrypt: params => decrypt_GCM({ ...params })
})