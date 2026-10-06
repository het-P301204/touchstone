import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['**/dist', '**/node_modules', '.data', '.touchstone', 'test-results', 'playwright-report', 'coverage'] },
  {
    files: ['**/*.{ts,tsx,js}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2023, globals: { ...globals.browser, ...globals.node } },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react-refresh/only-export-components': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports', fixStyle: 'separate-type-imports' }],
      '@typescript-eslint/no-unused-expressions': ['error', { allowShortCircuit: true, allowTernary: true }],
      // The API, CLI and engine run TypeScript under Node's type stripping,
      // which cannot emit runtime code for these constructs.
      'no-restricted-syntax': [
        'error',
        { selector: 'TSEnumDeclaration', message: 'No enum: Node type stripping cannot run it.' },
        { selector: 'TSModuleDeclaration[kind!="global"]', message: 'No namespace: Node type stripping cannot run it.' },
        { selector: 'TSParameterProperty', message: 'No constructor parameter properties: assign in the body.' },
      ],
      eqeqeq: ['error', 'always'],
    },
  },
  {
    // The engine is deterministic and side-effect free: no clock, no
    // randomness, no I/O, no DOM, no network, no dynamic code.
    files: ['packages/core/src/**/*.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'document', message: 'The engine is UI-independent.' },
        { name: 'window', message: 'The engine is UI-independent.' },
        { name: 'fetch', message: 'The engine makes no network requests.' },
        { name: 'XMLHttpRequest', message: 'The engine makes no network requests.' },
        { name: 'DOMParser', message: 'HTML is reduced to text only by the hardened extractor in src/text.' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'Date', property: 'now', message: 'The engine never reads the clock: the caller passes asOf.' },
        { object: 'Math', property: 'random', message: 'The engine is deterministic.' },
      ],
      'no-restricted-imports': [
        'error',
        { patterns: [{ group: ['node:*', 'fs', 'path', 'child_process', 'http', 'https', 'net'], message: 'The engine runs in the browser too: no Node built-ins.' }] },
      ],
      'no-new-func': 'error',
      'no-eval': 'error',
    },
  },
  {
    files: ['**/test/**/*.ts', 'tests/**/*.ts', 'scripts/**/*.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
)
