import { decrypt, encrypt } from '../src'

const testPassword = 'string password'

test(`encrypt "string data" with "${testPassword}"`, () => {
  expect(decrypt(encrypt('string data', testPassword), testPassword)).toEqual('string data')
})

test(`encrypt 123456 with "${testPassword}"`, () => {
  expect(decrypt(encrypt(123456, testPassword), testPassword)).toEqual(123456)
})

test(`encrypt 123.456 with "${testPassword}"`, () => {
  expect(decrypt(encrypt(123.456, testPassword), testPassword)).toEqual(123.456)
})

test(`encrypt 1.2345678901234568e+29 with "${testPassword}"`, () => {
  expect(decrypt(encrypt(1.2345678901234568e+29, testPassword), testPassword)).toEqual(1.2345678901234568e+29)
})

test(`encrypt { js: "object" } with "${testPassword}"`, () => {
  expect(decrypt(encrypt({ js: "object" }, testPassword), testPassword)).toEqual({ js: "object" })
})

test('encrypt `{ "json": "object" }` with `"string password"`', () => {
  expect(decrypt(encrypt({ "json": "object" }, testPassword), testPassword)).toEqual({ "json": "object" })
})

test('encrypt `[{ js: "object" }]` with `"string password"`', () => {
  expect(decrypt(encrypt([{ js: "object" }], testPassword), testPassword)).toEqual([{ js: "object" }])
})