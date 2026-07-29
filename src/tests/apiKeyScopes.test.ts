import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import { afterEach, beforeEach, test } from 'node:test'
import express from 'express'
import jwt from 'jsonwebtoken'
import { apiKeysRouter } from '../routes/apiKeys.js'
import { resetApiKeysTable } from '../services/apiKeys.js'

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'fallback-access-secret'

const testToken = jwt.sign({ sub: 'user-test', userId: 'user-test', role: 'user' }, ACCESS_SECRET, { expiresIn: '1h', issuer: 'disciplr', audience: 'disciplr-api' })

let baseUrl = ''
let server: ReturnType<express.Express['listen']> | null = null

beforeEach(async () => {
  await resetApiKeysTable()
  const app = express()
  app.use(express.json())
  app.use('/api/api-keys', apiKeysRouter)
  server = app.listen(0)
  await new Promise<void>((resolve) => {
    server!.once('listening', () => resolve())
  })
  const address = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${address.port}`
})

afterEach(async () => {
  if (!server) return
  await new Promise<void>((resolve, reject) => {
    server!.close((err) => (err ? reject(err) : resolve()))
  })
  server = null
})

const authHeaders = { 'content-type': 'application/json', authorization: `Bearer ${testToken}` }

test('rejects unknown scope strings when creating API keys', async () => {
  const response = await fetch(`${baseUrl}/api/api-keys`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      label: 'bad-scopes',
      scopes: ['read:vaults', 'vault.crete'],
    }),
  })

  assert.equal(response.status, 400)
  const body = await response.json()
  assert.equal(body.error.code, 'VALIDATION_ERROR')
  // ensure the invalid scope index is reported
  assert.equal(body.error.fields[0].path, 'scopes[1]')
})

test('accepts valid ApiScope values', async () => {
  const response = await fetch(`${baseUrl}/api/api-keys`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      label: 'good-scopes',
      scopes: ['read:analytics', 'read:vaults', 'write:analytics', 'write:vaults', 'admin'],
    }),
  })

  assert.equal(response.status, 201)
  const body = await response.json()
  assert.ok(body.apiKey)
  assert.deepEqual(body.apiKeyMeta.scopes, ['admin', 'read:analytics', 'read:vaults', 'write:analytics', 'write:vaults'])
})
