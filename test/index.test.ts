import { decrypt, encrypt } from '../src'

test('encrypt `"string data"` with `"string password"`', () => {
  expect(encrypt('string', 'string password')).toBeTruthy()
})

test('encrypt `123456` with `"string password"`', () => {
  expect(encrypt(123.456, 'string password')).toBeTruthy()
})

test('encrypt `123.456` with `"string password"`', () => {
  expect(encrypt(12.345, 'string password')).toBeTruthy()
})

test('encrypt `1.2345678901234568e+29` with `"string password"`', () => {
  expect(encrypt(1.2345678901234568e+29, 'string password')).toBeTruthy()
})

test('encrypt `{ js: "object" }` with `"string password"`', () => {
  expect(encrypt({ js: "object" }, 'string password')).toBeTruthy()
})

test('encrypt `{ "json": "object" }` with `"string password"`', () => {
  expect(encrypt({ "json": "object" }, 'string password')).toBeTruthy()
})

test('encrypt `[{ js: "object" }]` with `"string password"`', () => {
  expect(encrypt([{ js: "object" }], 'string password')).toBeTruthy()
})

test('encrypt `[{ js: "object" }]` with `"string password"`, output `"hex"` encoding', () => {
  expect(encrypt([{ js: "object" }], 'string password')).toBeTruthy()
})

test('decrypt `"qmj0nM9Jx2haDzVCUNKvaAL7VOBwpPL2hQz_-4W9-Z2fv4oV5lCtcvCnm47PtFiudv6Ijs6j-q2l1aO9KqhnCAWTdJta3BNsS2OAMgnPnWJEhKes0BG-WSPhjVN-iHciwLV5NVHtDzM"` with `"string password"`', () => {
  expect(decrypt('qmj0nM9Jx2haDzVCUNKvaAL7VOBwpPL2hQz_-4W9-Z2fv4oV5lCtcvCnm47PtFiudv6Ijs6j-q2l1aO9KqhnCAWTdJta3BNsS2OAMgnPnWJEhKes0BG-WSPhjVN-iHciwLV5NVHtDzM', 'string password')).toBeTruthy()
})