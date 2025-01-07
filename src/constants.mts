import { secp256k1 } from '@noble/curves/secp256k1'

export const n = secp256k1.CURVE.n // The order of the curve
export const G = secp256k1.ProjectivePoint.BASE // The base point (generator)
