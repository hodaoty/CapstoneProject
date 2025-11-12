module.exports = {
  env: { browser: true, es2021: true },
  extends: 'eslint:recommended',
  parserOptions: { ecmaVersion: 12, sourceType: 'module' },
  rules: {
    'no-console': 'warn',
    'indent': ['error', 2],
    'semi': ['error', 'always']
  }
};