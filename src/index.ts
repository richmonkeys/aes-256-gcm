import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'crypto'
import base64url from 'base64url'

export function encryptWithPbkdf2(data: any, password: string) {
  const stringified = JSON.stringify(data)
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

export function decryptWithPbkdf2(buffer: Buffer, password: string) {
  const salt = buffer.slice(0, 64)
  const iv = buffer.slice(64, 80)
  const authTag = buffer.slice(80, 96)
  const encrypted = buffer.slice(96)
  const key = pbkdf2Sync(password, salt, 4096, 32, 'sha512')
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString()
  const parsed = JSON.parse(decrypted)
  return parsed
}

type BufferEncoding = 'ascii' | 'utf8' | 'utf-8' | 'utf16le' | 'ucs2' | 'ucs-2' | 'base64' | 'latin1' | 'binary' | 'hex' | undefined
type Encoding = BufferEncoding | 'Buffer' | 'base64url'

export function encryptWithKey(data: any, key: Buffer) {
  const stringified = JSON.stringify(data)
  const iv = randomBytes(16)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(stringified), cipher.final()])
  const authTag = cipher.getAuthTag()
  return Buffer.concat([iv, authTag, encrypted])
}

export function decryptWithKey(buffer: Buffer, key: Buffer) {
  const iv = buffer.slice(0, 16)
  const authTag = buffer.slice(16, 32)
  const encrypted = buffer.slice(32)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString()
  const parsed = JSON.parse(decrypted)
  return parsed
}

function encryptBasedOnPassword(data: any, password: string | Buffer) {
  if (password instanceof Buffer) {
    return encryptWithKey(data, password)
  }

  const base64Key = Buffer.from(password, 'base64')
  const hexKey = Buffer.from(password, 'hex')
  const utf8Key = Buffer.from(password, 'utf8')

  if (base64Key.length === 32) {
    return encryptWithKey(data, base64Key)
  }

  if (hexKey.length === 32) {
    return encryptWithKey(data, hexKey)
  }

  if (utf8Key.length === 32) {
    return encryptWithKey(data, utf8Key)
  }

  return encryptWithPbkdf2(data, password)
}

export function encrypt(data: any, password: string | Buffer, outputEncoding: Encoding = 'base64url') {
  const encrypted = encryptBasedOnPassword(data, password)

  switch (outputEncoding) {
    case 'Buffer': {
      return encrypted
    }
    case 'base64url': {
      return base64url.encode(encrypted)
    }
    default: {
      return encrypted.toString(outputEncoding as BufferEncoding)
    }
  }
}

function decryptBasedOnPassword(buffer: Buffer, password: string | Buffer) {
  if (password instanceof Buffer) {
    return decryptWithKey(buffer, password)
  }

  const base64Key = Buffer.from(password, 'base64')
  const hexKey = Buffer.from(password, 'hex')
  const utf8Key = Buffer.from(password, 'utf8')

  if (base64Key.length === 32) {
    return decryptWithKey(buffer, base64Key)
  }

  if (hexKey.length === 32) {
    return decryptWithKey(buffer, hexKey)
  }

  if (utf8Key.length === 32) {
    return decryptWithKey(buffer, utf8Key)
  }

  return decryptWithPbkdf2(buffer, password)
}

export function decrypt(data: any, password: string | Buffer, inputEncoding: Encoding = 'base64url') {
  switch (inputEncoding) {
    case 'Buffer': {
      return decryptBasedOnPassword(data, password)
    }
    case 'base64url': {
      const buffer = base64url.toBuffer(data)
      return decryptBasedOnPassword(buffer, password)
    }
    default: {
      const buffer = Buffer.from(data, inputEncoding as BufferEncoding)
      return decryptBasedOnPassword(buffer, password)
    }
  }
}