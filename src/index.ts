import { createHash, randomBytes } from 'crypto'
import { ec as EC, eddsa as EDDSA } from 'elliptic'
import BN from 'bn.js'

export type SignatureType = 'ed25519' | 'secp256k1'

interface BaseConverter {
  encode(buffer: Buffer): string
  decodeUnsafe(string: string): Buffer | void
  decode(string: string): Buffer
}
type Sequence = number[] | Buffer | Uint8Array

interface DecodeSeedOpts {
  versions?: (number | number[])[]
  expectedLength?: number
  versionTypes?: ['ed25519', 'secp256k1']
}

interface DecodedSeed {
  bytes: Buffer
  version: number[]
  type?: SignatureType
}

interface DecodeOpts {
  versions: (number | number[])[]
  expectedLength?: number
  versionTypes?: ['ed25519', 'secp256k1']
}

interface GenerateOpts {
  algorithm?: SignatureType
  entropy?: Buffer | number[]
}

const ACCOUNT_ID = 0
const NODE_PUBLIC = 28
const FAMILY_SEED = 0x21 // 33
const ED25519_SEED = [0x01, 0xe1, 0x4b]
const alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

const isED25519 = (key: Buffer): boolean => {
  return key.length === 33 && key[0] === 0xed
}

export const isValidHex = (string: string): boolean => {
  return (
    string.length % 2 === 0 &&
    string.match(/([0-9]|[a-f])/gi)?.length === string.length
  )
}

export const sha512Half = (
  hashables: (string | number[] | Buffer)[]
): Buffer => {
  const hash = createHash('sha512')
  for (const content of hashables) {
    if (typeof content === 'string') {
      if (isValidHex(content)) {
        hash.update(Buffer.from(content.toUpperCase(), 'hex'))
      } else {
        hash.update(Buffer.from(content))
      }
    } else if (Buffer.isBuffer(content)) {
      hash.update(content)
    } else {
      hash.update(Buffer.from(content))
    }
  }
  return hash.digest().slice(0, 32)
}

const base = (ALPHABET: string): BaseConverter => {
  if (ALPHABET.length >= 255) {
    throw new TypeError('Alphabet too long')
  }
  const BASE_MAP = new Uint8Array(256)
  for (let j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255
  }
  for (let i = 0; i < ALPHABET.length; i++) {
    const x = ALPHABET.charAt(i)
    const xc = x.charCodeAt(0)
    if (BASE_MAP[xc] !== 255) throw new TypeError(x + ' is ambiguous')
    BASE_MAP[xc] = i
  }
  const BASE = ALPHABET.length
  const LEADER = ALPHABET.charAt(0)
  const FACTOR = Math.log(BASE) / Math.log(256) // log(BASE) / log(256), rounded up
  const iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up
  const encode = (source: Buffer): string => {
    if (!Buffer.isBuffer(source)) throw new TypeError('Expected Buffer')
    if (source.length === 0) return ''
    // Skip & count leading zeroes.
    let zeroes = 0
    let length = 0
    let pbegin = 0
    const pend = source.length
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++
      zeroes++
    }
    // Allocate enough space in big-endian base58 representation.
    const size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    const b58 = new Uint8Array(size)
    // Process the bytes.
    while (pbegin !== pend) {
      let carry = source[pbegin]
      // Apply "b58 = b58 * 256 + ch".
      let i = 0
      for (
        let it1 = size - 1;
        (carry !== 0 || i < length) && it1 !== -1;
        it1--, i++
      ) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = carry % BASE >>> 0
        carry = (carry / BASE) >>> 0
      }
      if (carry !== 0) throw new Error('Non-zero carry')
      length = i
      pbegin++
    }
    // Skip leading zeroes in base58 result.
    let it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
      it2++
    }
    // Translate the result into a string.
    let str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) {
      str += ALPHABET.charAt(b58[it2])
    }
    return str
  }
  const decodeUnsafe = (source: string): Buffer | void => {
    if (typeof source !== 'string') {
      throw new TypeError('Expected String')
    }
    if (source.length === 0) return Buffer.alloc(0)
    let psz = 0
    // Skip leading spaces.
    if (source[psz] === ' ') return
    // Skip and count leading '1's.
    let zeroes = 0
    let length = 0
    while (source[psz] === LEADER) {
      zeroes++
      psz++
    }
    // Allocate enough space in big-endian base256 representation.
    const size = ((source.length - psz) * FACTOR + 1) >>> 0 // log(58) / log(256), rounded up.
    const b256 = new Uint8Array(size)
    // Process the characters.
    while (source[psz]) {
      // Decode character
      let carry = BASE_MAP[source.charCodeAt(psz)]
      // Invalid character
      if (carry === 255) return
      let i = 0
      for (
        let it3 = size - 1;
        (carry !== 0 || i < length) && it3 !== -1;
        it3--, i++
      ) {
        carry += (BASE * b256[it3]) >>> 0
        b256[it3] = carry % 256 >>> 0
        carry = (carry / 256) >>> 0
      }
      if (carry !== 0) throw new Error('Non-zero carry')
      length = i
      psz++
    }
    // Skip trailing spaces.
    if (source[psz] === ' ') return
    // Skip leading zeroes in b256.
    let it4 = size - length
    while (it4 !== size && b256[it4] === 0) {
      it4++
    }
    const vch = Buffer.allocUnsafe(zeroes + (size - it4))
    vch.fill(0x00, 0, zeroes)
    let j = zeroes
    while (it4 !== size) {
      vch[j++] = b256[it4++]
    }
    return vch
  }
  const decode = (string: string): Buffer => {
    const buffer = decodeUnsafe(string)
    if (buffer) {
      return buffer
    }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode,
    decodeUnsafe,
    decode
  }
}

const deriveScalar = (bytes: Buffer, discrim?: number): BN => {
  const secp256k1 = new EC('secp256k1')
  const order = secp256k1.curve.n
  let hashables = []
  for (let i = 0; i <= 0xffffffff; i++) {
    hashables = []
    hashables.push(bytes)
    if (discrim !== undefined) {
      hashables.push([
        (discrim >>> 24) & 0xff,
        (discrim >>> 16) & 0xff,
        (discrim >>> 8) & 0xff,
        discrim & 0xff
      ])
    }
    hashables.push([
      (i >>> 24) & 0xff,
      (i >>> 16) & 0xff,
      (i >>> 8) & 0xff,
      i & 0xff
    ])
    const hasher = sha512Half(hashables)
    const key = new BN(hasher, 'hex')
    if (key.cmpn(0) > 0 && key.cmp(order) < 0) {
      return key
    }
  }
  throw new Error('impossible unicorn ;)')
}

const derivePrivateKey = (
  seed: Buffer,
  accountIndex: number,
  validator = false
): BN => {
  const secp256k1 = new EC('secp256k1')
  const order = secp256k1.curve.n
  const privateGen = deriveScalar(seed)
  if (validator) return privateGen
  const publicGen = secp256k1.g.mul(privateGen)
  return deriveScalar(publicGen.encodeCompressed(), accountIndex)
    .add(privateGen)
    .mod(order)
}

export const publicKeyFromPrivateKey = (privateKey: string): string => {
  const skBuffer = Buffer.from(privateKey, 'hex')
  if (isED25519(skBuffer)) {
    return `ED${new EDDSA('ed25519')
      .keyFromSecret(skBuffer.slice(1))
      .getPublic('hex')
      .toUpperCase()}`
  } else {
    return new EC('secp256k1')
      .keyFromPrivate(privateKey.slice(2))
      .getPublic()
      .encodeCompressed('hex')
      .toUpperCase()
  }
}

const sha256 = (bytes: Uint8Array): Buffer => {
  return createHash('sha256')
    .update(Buffer.from(bytes))
    .digest()
}

const encodeRaw = (bytes: Buffer): string => {
  return base(alphabet).encode(bytes)
}

const isSequence = (val: Sequence | number): val is Sequence => {
  return (val as Sequence).length !== undefined
}

const concatArgs = (...args: (number | Sequence)[]): number[] => {
  const ret: number[] = []

  args.forEach(arg => {
    if (isSequence(arg)) {
      for (let j = 0; j < arg.length; j++) {
        ret.push(arg[j])
      }
    } else {
      ret.push(arg)
    }
  })
  return ret
}

const encodeChecked = (buffer: Buffer): string => {
  const check = sha256(sha256(buffer)).slice(0, 4)
  return encodeRaw(Buffer.from(concatArgs(buffer, check)))
}

const encodeVersioned = (
  bytes: Buffer,
  versions: number[],
  expectedLength: number
): string => {
  if (expectedLength && bytes.length !== expectedLength) {
    throw new Error(
      'unexpected_payload_length: bytes.length does not match expectedLength'
    )
  }
  return encodeChecked(Buffer.from(concatArgs(versions, bytes)))
}

const encode = (
  bytes: Buffer,
  opts: {
    versions: number[]
    expectedLength: number
  }
): string => {
  const versions = opts.versions
  return encodeVersioned(bytes, versions, opts.expectedLength)
}

export const encodeSeed = (
  entropy: Buffer | number[],
  algorithm: SignatureType = 'ed25519'
): string => {
  if (entropy.length !== 16) {
    throw new Error('raw seed must have length 16')
  }
  if (algorithm !== 'ed25519' && algorithm !== 'secp256k1') {
    throw new Error('type must be ed25519 or secp256k1')
  }
  const opts = {
    expectedLength: 16,
    versions: algorithm === 'ed25519' ? ED25519_SEED : [FAMILY_SEED]
  }
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy)
  }
  return encode(entropy, opts)
}

export const generateSeed = (
  options: GenerateOpts = {
    algorithm: 'ed25519'
  }
): string => {
  options.entropy = options.entropy ?? randomBytes(16)
  return encodeSeed(options.entropy, options.algorithm)
}

const decodeRaw = (base58string: string): Buffer => {
  return base(alphabet).decode(base58string)
}

const seqEqual = (arr1: Sequence, arr2: Sequence): boolean => {
  if (arr1.length !== arr2.length) {
    return false
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false
    }
  }
  return true
}

const verifyCheckSum = (bytes: Buffer): boolean => {
  const computed = sha256(sha256(bytes.slice(0, -4))).slice(0, 4)
  const checksum = bytes.slice(-4)
  return seqEqual(computed, checksum)
}

const decodeChecked = (base58string: string): Buffer => {
  const buffer = decodeRaw(base58string)
  if (buffer.length < 5) {
    throw new Error('invalid_input_size: decoded data must have length >= 5')
  }
  if (!verifyCheckSum(buffer)) {
    throw new Error('checksum_invalid')
  }
  return buffer.slice(0, -4)
}

const decode = (base58string: string, opts: DecodeOpts): DecodedSeed => {
  const versions = opts.versions
  const types = opts.versionTypes

  const withoutSum = decodeChecked(base58string)

  if (versions.length > 1 && !opts.expectedLength) {
    throw new Error(
      'expectedLength is required because there are >= 2 possible versions'
    )
  }
  const versionLengthGuess =
    typeof versions[0] === 'number' ? 1 : (versions[0] as number[]).length
  const payloadLength =
    opts.expectedLength || withoutSum.length - versionLengthGuess
  const versionBytes = withoutSum.slice(0, -payloadLength)
  const payload = withoutSum.slice(-payloadLength)

  for (let i = 0; i < versions.length; i++) {
    const version: number[] = Array.isArray(versions[i])
      ? (versions[i] as number[])
      : [versions[i] as number]
    if (seqEqual(versionBytes, version)) {
      return {
        version,
        bytes: payload,
        type: types ? types[i] : undefined
      }
    }
  }

  throw new Error(
    'version_invalid: version bytes do not match any of the provided version(s)'
  )
}

export const decodeSeed = (
  seed: string,
  opts: DecodeSeedOpts = {}
): DecodedSeed => {
  if (!opts.versionTypes || !opts.versions) {
    opts.versionTypes = ['ed25519', 'secp256k1']
    opts.versions = [ED25519_SEED, FAMILY_SEED]
  }
  if (!opts.expectedLength) {
    opts.expectedLength = 16
  }
  return decode(seed, opts as DecodeOpts)
}

export const deriveKeypair = (
  encodedSeed: string,
  accountIndex = 0
): { privateKey: string; publicKey: string } => {
  const decodedSeed = decodeSeed(encodedSeed)
  const seedBytes = decodedSeed.bytes
  if (decodedSeed.type === 'ed25519') {
    const accountIndexBytes = Buffer.from(
      accountIndex.toString(16).padStart(8, '0'),
      'hex'
    )
    const hashedPrivateKey = sha512Half([seedBytes, accountIndexBytes])
    const privateKey = `ED${hashedPrivateKey.toString('hex').toUpperCase()}`
    const publicKey = publicKeyFromPrivateKey(privateKey)
    return { privateKey, publicKey }
  } else if (decodedSeed.type === 'secp256k1') {
    const privateKey = `00${derivePrivateKey(seedBytes, accountIndex)
      .toString(16, 64)
      .toUpperCase()}`
    const publicKey = publicKeyFromPrivateKey(privateKey)
    return { privateKey, publicKey }
  } else {
    throw new Error('Invalid Signature Algo')
  }
}

export const sign = (messageHex: string, privateKey: string): string => {
  if (!isValidHex(messageHex)) {
    throw new Error('Invalid message hex')
  }
  if (!isValidHex(privateKey)) {
    throw new Error('Invalid private key')
  }
  const skBuffer = Buffer.from(privateKey, 'hex')
  const msg = Buffer.from(messageHex, 'hex')
  if (isED25519(skBuffer)) {
    return new EDDSA('ed25519')
      .sign(msg, skBuffer.slice(1))
      .toHex()
      .toUpperCase()
  } else {
    return new EC('secp256k1')
      .sign(sha512Half([msg]), skBuffer, { canonical: true })
      .toDER('hex')
      .toUpperCase()
  }
}

export const verify = (
  msg: string | Buffer,
  signature: string,
  publicKey: string
): boolean => {
  if (!isValidHex(publicKey) || !isValidHex(signature)) {
    return false
  }
  const pkBuffer = Buffer.from(publicKey, 'hex')
  if (isED25519(pkBuffer)) {
    try {
      return new EDDSA('ed25519').verify(
        msg,
        signature,
        Array.from(pkBuffer).slice(1) as any // eslint-disable-line @typescript-eslint/no-explicit-any
      )
    } catch (err) {
      return false
    }
  } else {
    try {
      return new EC('secp256k1').verify(
        sha512Half([msg]),
        signature as any, // eslint-disable-line @typescript-eslint/no-explicit-any
        pkBuffer
      )
    } catch (err) {
      return false
    }
  }
}

const computePublicKeyHash = (publicKey: Buffer | string): Buffer => {
  if (!Buffer.isBuffer(publicKey)) publicKey = Buffer.from(publicKey, 'hex')
  const hash256 = createHash('sha256')
    .update(publicKey)
    .digest()
  return createHash('ripemd160')
    .update(hash256)
    .digest()
}

export const encodeAccountID = (bytes: Buffer | number[]): string => {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes)
  const opts = { versions: [0], expectedLength: 20 }
  return encode(bytes, opts)
}

export const deriveAddress = (publicKey: string | Buffer): string => {
  return encodeAccountID(computePublicKeyHash(publicKey))
}

export const decodeNodePublic = (base58string: string): Buffer => {
  const opts = { versions: [NODE_PUBLIC], expectedLength: 33 }
  return decode(base58string, opts).bytes
}

export const encodeNodePublic = (bytes: number[] | Buffer): string => {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes)
  const opts = { versions: [NODE_PUBLIC], expectedLength: 33 }
  return encode(bytes, opts)
}

const accountPublicFromPublicGenerator = (publicGenBytes: Buffer): string => {
  const secp256k1 = new EC('secp256k1')
  const rootPubPoint = secp256k1.curve.decodePoint(publicGenBytes)
  const scalar = deriveScalar(publicGenBytes, 0)
  const point = secp256k1.g.mul(scalar)
  const offset = rootPubPoint.add(point)
  return offset.encodeCompressed()
}

export const deriveNodeAddress = (publicKey: string): string => {
  const generatorBytes = decodeNodePublic(publicKey)
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes)
  return deriveAddress(accountPublicBytes)
}

export const decodeAccountID = (accountId: string): Buffer => {
  const opts = { versions: [ACCOUNT_ID], expectedLength: 20 }
  return decode(accountId, opts).bytes
}

export const isValidAddress = (address: string): boolean => {
  try {
    decodeAccountID(address)
  } catch (e) {
    return false
  }
  return true
}

export default {
  sha512Half,
  isValidHex,
  publicKeyFromPrivateKey,
  encodeSeed,
  generateSeed,
  decodeSeed,
  deriveKeypair,
  sign,
  verify,
  encodeAccountID,
  deriveAddress,
  decodeNodePublic,
  encodeNodePublic,
  deriveNodeAddress,
  decodeAccountID,
  isValidAddress
}
