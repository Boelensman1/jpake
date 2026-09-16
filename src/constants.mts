import { secp256k1 } from '@noble/curves/secp256k1.js'

export const n = secp256k1.Point.CURVE().n // The order of the curve
export const G = secp256k1.Point.BASE // The base point (generator)
