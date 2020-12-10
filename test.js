const { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } = require('crypto')
const base64url = require('base64url')

const key = randomBytes(32)
const password = 'xmkCL4@J@29BDk7!'

// const password = Buffer.from(secret)
function encrypt(input, password) {
  const stringified = JSON.stringify(input)
  const salt = randomBytes(64)
  const iv = randomBytes(16)
  const key = pbkdf2Sync(password, salt, 4096, 32, 'sha512')
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(stringified), cipher.final()])
  const authTag = cipher.getAuthTag()
  const packed = Buffer.concat([salt, iv, authTag, encrypted])
  const encoded = base64url.encode(packed)
  return encoded
}

function decrypt(encoded, password) {
  const packed = base64url.toBuffer(encoded)
  const salt = packed.slice(0, 64)
  const iv = packed.slice(64, 80)
  const authTag = packed.slice(80, 96)
  const encrypted = packed.slice(96)
  const key = pbkdf2Sync(password, salt, 4096, 32, 'sha512')
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString()
  const parsed = JSON.parse(decrypted)
  return parsed
}

const data = randomBytes(1024).toString('base64')
console.log('data', data.length)
const encrypted = encrypt(data, password)
console.log('encrypted', encrypted.length)
// console.log(encrypted)
const decrypted = decrypt(encrypted, password)
console.log('ratio', encrypted.length / data.length)
// console.log('decrypted', decrypted)