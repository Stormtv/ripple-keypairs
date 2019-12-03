'use strict'
import api from '../dist'
import { assert } from 'chai'
import 'mocha'

const toHex = (bytes: number[] | Buffer): string => {
  if (Buffer.isBuffer(bytes)) return bytes.toString('hex').toUpperCase()
  return Buffer.from(bytes).toString('hex').toUpperCase()
}

const toBytes = (hex: string): number[] => {
  return Buffer.from(hex, 'hex').toJSON().data
}

describe('ripple-address-codec', function() {

  it('can translate between BA8E78626EE42C41B46D46C3048DF3A1C3C87072 and rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN (encode AccountID)', function() {
    const actual = api.encodeAccountID(toBytes('BA8E78626EE42C41B46D46C3048DF3A1C3C87072'))
    assert.equal(actual, 'rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN')
  })

  it('can translate between rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN and BA8E78626EE42C41B46D46C3048DF3A1C3C87072 (decode AccountID)', function() {
    const buf = api.decodeAccountID('rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN')
    assert.equal(toHex(buf), 'BA8E78626EE42C41B46D46C3048DF3A1C3C87072')
  })

  it('can translate between 0388E5BA87A000CB807240DF8C848EB0B5FFA5C8E5A521BC8E105C0F0A44217828 and n9MXXueo837zYH36DvMc13BwHcqtfAWNJY5czWVbp7uYTj7x17TH (encode NodePublic)', function() {
    const actual = api.encodeNodePublic(toBytes('0388E5BA87A000CB807240DF8C848EB0B5FFA5C8E5A521BC8E105C0F0A44217828'))
    assert.equal(actual, 'n9MXXueo837zYH36DvMc13BwHcqtfAWNJY5czWVbp7uYTj7x17TH')
  })
  it('can translate between n9MXXueo837zYH36DvMc13BwHcqtfAWNJY5czWVbp7uYTj7x17TH and 0388E5BA87A000CB807240DF8C848EB0B5FFA5C8E5A521BC8E105C0F0A44217828 (decode NodePublic)', function() {
    const buf = api.decodeNodePublic('n9MXXueo837zYH36DvMc13BwHcqtfAWNJY5czWVbp7uYTj7x17TH')
    assert.equal(toHex(buf), '0388E5BA87A000CB807240DF8C848EB0B5FFA5C8E5A521BC8E105C0F0A44217828')
  })

  it('can decode arbitrary seeds', function() {
    const decoded = api.decodeSeed('sEdTM1uX8pu2do5XvTnutH6HsouMaM2')
    assert.equal(toHex(decoded.bytes), '4C3A1D213FBDFB14C7C28D609469B341')
    assert.equal(decoded.type, 'ed25519')

    const decoded2 = api.decodeSeed('sn259rEFXrQrWyx3Q7XneWcwV6dfL')
    assert.equal(toHex(decoded2.bytes), 'CF2DE378FBDD7E2EE87D486DFB5A7BFF')
    assert.equal(decoded2.type, 'secp256k1')
  })

  it('can pass a type as second arg to encodeSeed', function() {
    const edSeed = 'sEdTM1uX8pu2do5XvTnutH6HsouMaM2'
    const decoded = api.decodeSeed(edSeed)
    assert.equal(toHex(decoded.bytes), '4C3A1D213FBDFB14C7C28D609469B341')
    assert.equal(decoded.type, 'ed25519')
    assert.equal(api.encodeSeed(decoded.bytes, decoded.type), edSeed)
  })

  it('isValidAddress - secp256k1 address valid', function() {
    assert(api.isValidAddress('rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1'))
  })
  it('isValidAddress - ed25519 address valid', function() {
    assert(api.isValidAddress('rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD'))
  })
  it('isValidAddress - invalid', function() {
    assert(!api.isValidAddress('rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw2'))
  })
  it('isValidAddress - empty', function() {
    assert(!api.isValidAddress(''))
  })

})
