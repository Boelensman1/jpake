// export classes & functions
import deriveSFromPassword from './deriveSFromPassword.mjs'
import JPake from './JPake.mjs'
import JPakeThreePass from './JPakeThreePass.mjs'

export { JPake, JPakeThreePass, deriveSFromPassword }

// export types
import type { Round1Result, Round2Result } from './JPake.mjs'
import type {
  Pass1Result,
  Pass2Result,
  Pass3Result,
} from './JPakeThreePass.mjs'

export type {
  Round1Result,
  Round2Result,
  Pass1Result,
  Pass2Result,
  Pass3Result,
}
