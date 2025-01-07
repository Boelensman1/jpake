// @ts-check
import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import jsdoc from 'eslint-plugin-jsdoc'

const baseConfig = tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  jsdoc.configs['flat/recommended-typescript-error'],
)

export default [
  {
    ignores: ['**/build/**', '**/dist/**', '**/*.js'],
  },
  ...baseConfig,
  {
    rules: {
      'no-restricted-globals': [
        'error',
        {
          name: 'Error',
          message: 'Use custom error instead.',
        },
        {
          name: 'Buffer',
          message: 'Use Uint8Array instead.',
        },
      ],
      'jsdoc/require-jsdoc': [
        'error',
        {
          publicOnly: true,
          require: {
            FunctionDeclaration: true,
            MethodDefinition: true,
            ClassDeclaration: true,
            ArrowFunctionExpression: true,
            FunctionExpression: true,
          },
        },
      ],
      'jsdoc/require-param': ['error', { checkDestructured: false }],
      'jsdoc/check-param-names': ['error', { checkDestructured: false }],
    },
  },
  {
    languageOptions: {
      parserOptions: {
        project: ['tsconfig.json'],
      },
    },
  },
]
