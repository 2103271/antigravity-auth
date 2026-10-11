import { expect, it, mock } from 'bun:test'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as actualCore from '@cortexkit/antigravity-auth-core'
import type { ClaustrumScopedClient } from '@cortexkit/antigravity-auth-core/common-auth/claustrum'
import {
  type AgentSession,
  createAgentSession,
  SessionManager,
} from '@earendil-works/pi-coding-agent'
import { PI_ANTIGRAVITY_ENROLLMENT_NAME, PiVaultSetup } from './vault-setup.ts'

const bearer = 'synthetic-native-request-vault-token'
const events: string[] = []
const sent: Array<{ authorization: string | null; body: string }> = []
const localRefresh = mock(actualCore.refreshAntigravityToken)
const localProject = mock(actualCore.ensureProjectContext)
const physicalTransport: typeof actualCore.fetchWithAgyCliTransport = async (
  _url,
  init,
) => {
  events.push('request:physical')
  sent.push({
    authorization: new Headers(init?.headers).get('authorization'),
    body: String(init?.body),
  })
  return new Response(
    'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"PI_STARTUP_OK"}]},"finishReason":"STOP"}]}}\n\n',
    { headers: { 'content-type': 'text/event-stream' } },
  )
}
mock.module('@cortexkit/antigravity-auth-core', () => ({
  ...actualCore,
  refreshAntigravityToken: localRefresh,
  ensureProjectContext: localProject,
  fetchWithAgyCliTransport: physicalTransport,
}))

const client: ClaustrumScopedClient = {
  listScoped: async () => ({
    view: 'startup-view',
    rows: [
      {
        id: 'cred-a',
        categories: ['antigravity-native'],
        credentialType: 'oauth',
        serves: [],
        providerIds: [],
        refreshAdapter: 'antigravity',
        state: 'active',
        recordVersion: 1,
        operations: ['read'],
        createdAtMs: null,
        accountId: 'account-a',
        email: 'synthetic@example.test',
      },
    ],
  }),
  getScoped: async (input) => {
    expect(input.credentialId).toBe('cred-a')
    expect(input.minTtlMs).toBe(300_000)
    return {
      material: bearer,
      recordVersion: 1,
      expiresAtMs: Date.now() + 3_600_000,
      credentialId: 'cred-a',
      projectId: 'synthetic-vault-project',
      accountId: 'account-a',
    }
  },
  reportAuthFailureScoped: async () => {},
  close: () => {},
}

it('awaits the native slot swap before the real Pi loader resolves its first google model request', async () => {
  const directory = await mkdtemp(
    join(
      process.platform === 'win32' ? tmpdir() : '/tmp',
      'antigravity-pi-startup-',
    ),
  )
  const agentDir = join(directory, 'native-agent')
  const vaultDir = join(directory, 'plugin-vault')
  const modeFile = join(vaultDir, 'pi-mode.json')
  const authPath = join(agentDir, 'auth.json')
  const stashPath = join(vaultDir, 'google-login-stash.json')
  const key = Symbol.for('antigravity.pi.startup.fixture')
  const previous = new Map(
    [
      'HOME',
      'PI_CODING_AGENT_DIR',
      'PI_AGENT_DIR',
      'PI_ANTIGRAVITY_AUTH_FILE',
      'PI_OFFLINE',
    ].map((name) => [name, process.env[name]]),
  )
  let session: AgentSession | undefined
  const savedFetch = globalThis.fetch
  let nativeRefreshes = 0
  const original = {
    type: 'oauth',
    access: 'synthetic-expired-local-access',
    refresh: 'synthetic-local-refresh|synthetic-local-project',
    expires: 1,
  }
  try {
    globalThis.fetch = Object.assign(async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (
        url.hostname === 'oauth2.googleapis.com' ||
        url.hostname === 'accounts.google.com'
      )
        nativeRefreshes++
      throw new Error('The owned Pi startup fixture refuses network fetches')
    }, savedFetch)
    events.length = 0
    sent.length = 0
    localRefresh.mockClear()
    localProject.mockClear()
    process.env.PI_OFFLINE = '1'
    process.env.HOME = directory
    process.env.PI_CODING_AGENT_DIR = agentDir
    process.env.PI_AGENT_DIR = join(directory, 'decoy-extension-agent')
    process.env.PI_ANTIGRAVITY_AUTH_FILE = join(
      directory,
      'plugin-accounts.json',
    )
    await mkdir(join(agentDir, 'extensions'), { recursive: true, mode: 0o700 })
    await mkdir(vaultDir, { recursive: true, mode: 0o700 })
    await writeFile(
      join(agentDir, 'settings.json'),
      JSON.stringify({
        defaultProvider: 'google',
        defaultModel: 'antigravity-gemini-3.8-flash',
      }),
      { mode: 0o600 },
    )
    await writeFile(authPath, JSON.stringify({ google: original }), {
      mode: 0o600,
    })
    const claustrum = await actualCore.loadCommonAuthClaustrum()
    const setup = new PiVaultSetup({
      claustrum,
      stateDir: vaultDir,
      modeFile,
      readHostSlot: () => {
        throw new Error('Approved vault setup read the native OAuth login')
      },
      connectEnrollment: async () => ({
        enrollPropose: async () => ({ requestId: 'startup-enrollment' }),
        enrollPoll: async () => ({
          status: 'approved',
          name: PI_ANTIGRAVITY_ENROLLMENT_NAME,
          token: 'b'.repeat(64),
          tokenGeneration: 1,
        }),
        close: () => {},
      }),
    })
    expect((await setup.connectStep()).state).toBe('approved')
    const slotModule = await actualCore.loadCommonAuthPiSlot()
    const loadPiSlot: typeof actualCore.loadCommonAuthPiSlot = async () => ({
      ...slotModule,
      openPiSlot: (options) => {
        const slot = slotModule.openPiSlot(options)
        return {
          ...slot,
          enterVault: async () => {
            events.push('slot:start')
            await slot.enterVault()
            events.push('slot:end')
          },
        }
      },
    })
    Reflect.set(globalThis, key, { events, client, loadPiSlot })
    const entry = fileURLToPath(new URL('./index.ts', import.meta.url))
    await writeFile(
      join(agentDir, 'extensions', 'observe.ts'),
      `
import { registerCortexKitPiAntigravity } from ${JSON.stringify(entry)}
export default async function(pi) {
  const fixture = Reflect.get(globalThis, Symbol.for('antigravity.pi.startup.fixture'))
  if (!fixture) throw new Error('Owned startup fixture missing')
  fixture.events.push('factory:start')
  await registerCortexKitPiAntigravity(pi, {
    vaultDir: ${JSON.stringify(vaultDir)}, modeFile: ${JSON.stringify(modeFile)},
    rosterFile: ${JSON.stringify(join(vaultDir, 'roster.json'))},
    nativeStashPath: ${JSON.stringify(stashPath)},
    connect: async () => fixture.client, loadPiSlot: fixture.loadPiSlot,
    readHostSlot: () => { throw new Error('Vault activation read a dormant native login') },
  })
  fixture.events.push('factory:end')
}
`,
      { mode: 0o600 },
    )
    const created = await createAgentSession({
      cwd: directory,
      agentDir,
      sessionManager: SessionManager.inMemory(directory),
      noTools: 'all',
    })
    session = created.session
    expect(created.extensionsResult.errors).toEqual([])
    expect(events.indexOf('slot:end')).toBeGreaterThan(
      events.indexOf('factory:start'),
    )
    expect(events.indexOf('slot:end')).toBeLessThan(
      events.indexOf('factory:end'),
    )
    const native = JSON.parse(await readFile(authPath, 'utf8'))
    expect(native.google).toEqual({
      type: 'api_key',
      key: 'antigravity-vault-custody',
    })
    expect(await readFile(stashPath, 'utf8')).toContain(
      'synthetic-local-refresh',
    )
    await session.bindExtensions({})
    const model = (await session.modelRuntime.getAvailable('google')).find(
      (model) => model.id === 'antigravity-gemini-3.8-flash',
    )
    expect(model).toBeDefined()
    if (!model)
      throw new Error(
        'The real Pi runtime did not offer google/antigravity-gemini-3.8-flash',
      )
    const response = await session.modelRuntime
      .streamSimple(model, {
        messages: [
          { role: 'user', content: 'startup-owned-nonce', timestamp: 0 },
        ],
      })
      .result()
    expect(response.stopReason).toBe('stop')
    expect(sent).toHaveLength(1)
    expect(sent[0]?.authorization).toBe(`Bearer ${bearer}`)
    expect(sent[0]?.body).toContain('startup-owned-nonce')
    expect(sent[0]?.body).toContain('synthetic-vault-project')
    expect(sent[0]?.body).not.toContain(original.access)
    expect(sent[0]?.body).not.toContain(original.refresh)
    expect(localRefresh).not.toHaveBeenCalled()
    expect(nativeRefreshes).toBe(0)
    expect(localProject).not.toHaveBeenCalled()
    expect(events.indexOf('request:physical')).toBeGreaterThan(
      events.indexOf('factory:end'),
    )
  } finally {
    try {
      await session?.dispose()
    } finally {
      globalThis.fetch = savedFetch
      Reflect.deleteProperty(globalThis, key)
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name]
        else process.env[name] = value
      }
      await rm(directory, { recursive: true, force: true })
    }
  }
})
