import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'crypto'

const algorithm = 'aes-256-gcm'
const interations = 1024
const keyLen = 32
const digest = 'sha512'
const saltLen = 64
const ivLen = 16
const authTagLen = 16

export function encryptWithPbkdf2(data: any, password: string) {
  const stringified = JSON.stringify(data)
  const salt = randomBytes(saltLen)
  const iv = randomBytes(ivLen)
  const key = pbkdf2Sync(password, salt, interations, keyLen, digest)
  const cipher = createCipheriv(algorithm, key, iv)
  const encrypted = Buffer.concat([cipher.update(stringified), cipher.final()])
  const authTag = cipher.getAuthTag()
  return Buffer.concat([salt, iv, authTag, encrypted])
}

export function decryptWithPbkdf2(buffer: Buffer, password: string) {
  const salt = buffer.subarray(0, saltLen)
  const iv = buffer.subarray(saltLen, saltLen + ivLen)
  const authTag = buffer.subarray(saltLen + ivLen, saltLen + ivLen + authTagLen)
  const encrypted = buffer.subarray(saltLen + ivLen + authTagLen)
  const key = pbkdf2Sync(password, salt, interations, keyLen, digest)
  const decipher = createDecipheriv(algorithm, key, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString()
  const parsed = JSON.parse(decrypted)
  return parsed
}

type BufferEncoding = 'ascii' | 'utf8' | 'utf-8' | 'utf16le' | 'ucs2' | 'ucs-2' | 'base64' | 'latin1' | 'binary' | 'hex' | undefined
type Encoding = BufferEncoding | 'Buffer' | 'base64url'

export function encryptWithKey(data: any, key: Buffer) {
  const stringified = JSON.stringify(data)
  const iv = randomBytes(ivLen)
  const cipher = createCipheriv(algorithm, key, iv)
  const encrypted = Buffer.concat([cipher.update(stringified), cipher.final()])
  const authTag = cipher.getAuthTag()
  return Buffer.concat([iv, authTag, encrypted])
}

export function decryptWithKey(buffer: Buffer, key: Buffer) {
  const iv = buffer.subarray(0, ivLen)
  const authTag = buffer.subarray(ivLen, ivLen + authTagLen)
  const encrypted = buffer.subarray(ivLen + authTagLen)
  const decipher = createDecipheriv(algorithm, key, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString()
  const parsed = JSON.parse(decrypted)
  return parsed
}

function encryptBasedOnPassword(data: any, password: string | Buffer) {
  if (password instanceof Buffer) {
    if (password.length === keyLen) {
      return encryptWithKey(data, password)
    }
    return encryptWithPbkdf2(data, password.toString())
  }

  const base64Key = Buffer.from(password, 'base64')
  const hexKey = Buffer.from(password, 'hex')
  const utf8Key = Buffer.from(password, 'utf8')

  if (base64Key.length === keyLen) {
    return encryptWithKey(data, base64Key)
  }

  if (hexKey.length === keyLen) {
    return encryptWithKey(data, hexKey)
  }

  if (utf8Key.length === keyLen) {
    return encryptWithKey(data, utf8Key)
  }

  return encryptWithPbkdf2(data, password)
}

export function encrypt(data: any, password: string | Buffer, outputEncoding: Encoding = 'base64url') {
  if (!(password instanceof Buffer) && typeof password !== 'string') {
    throw new Error('Invalid password. Password must be either a string or buffer.')
  }

  const encrypted = encryptBasedOnPassword(data, password)

  switch (outputEncoding) {
    case 'Buffer': {
      return encrypted
    }
    default: {
      return encrypted.toString(outputEncoding as BufferEncoding)
    }
  }
}

function decryptBasedOnPassword(buffer: Buffer, password: string | Buffer) {
  if (password instanceof Buffer) {
    if (password.length === keyLen) {
      return decryptWithKey(buffer, password)
    }
    return decryptWithPbkdf2(buffer, password.toString())
  }

  const base64Key = Buffer.from(password, 'base64')
  const hexKey = Buffer.from(password, 'hex')
  const utf8Key = Buffer.from(password, 'utf8')

  if (base64Key.length === keyLen) {
    return decryptWithKey(buffer, base64Key)
  }

  if (hexKey.length === keyLen) {
    return decryptWithKey(buffer, hexKey)
  }

  if (utf8Key.length === keyLen) {
    return decryptWithKey(buffer, utf8Key)
  }

  return decryptWithPbkdf2(buffer, password)
}

export function decrypt(data: string | Buffer, password: string | Buffer, inputEncoding: Encoding = 'base64url') {
  if (!(password instanceof Buffer) && typeof password !== 'string') {
    throw new Error('Invalid password. Password must be either a string or buffer.')
  }

  switch (inputEncoding) {
    case 'Buffer': {
      const buffer = data instanceof Buffer ? data : Buffer.from(data)
      return decryptBasedOnPassword(buffer, password)
    }
    default: {
      const buffer = data instanceof Buffer ? data : Buffer.from(data, inputEncoding as BufferEncoding)
      return decryptBasedOnPassword(buffer, password)
    }
  }
}