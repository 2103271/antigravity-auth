import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  spyOn,
} from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  getAntigravityOpencodeModelIds,
  loadCommonAuthClaustrum,
  OPENCODE_MODEL_DEFINITIONS,
  VAULT_ACCOUNT_REMEDY,
} from '@cortexkit/antigravity-auth-core'
import * as packageRoot from '../index'

import { ANTIGRAVITY_PROVIDER_ID } from './constants.ts'
import { ANTIGRAVITY_MENU_COMMAND } from './plugin/commands.ts'
import { GEMINI_DUMP_COMMAND_NAME } from './plugin/gemini-dump.ts'
import { createAntigravityPlugin } from './plugin/index'
import { getStoragePath } from './plugin/storage'
import type { PluginClient, PluginInput } from './plugin/types.ts'
import { V1_VAULT_ACTIVATION_LABEL } from './plugin/vault-activation'
import {
  createOpenCodeVaultCustody,
  OPENCODE_VAULT_ENROLLMENT_NAME,
  openCodeVaultPaths,
} from './plugin/vault-custody'
import { drainNotifications } from './rpc/notifications'

/**
 * A host-client stand-in for entry wiring tests. These methods record calls
 * without dispatching real sessions, authentication writes or terminal output.
 */
function createMinimalClient(): PluginClient {
  return {
    app: { log: mock(async () => {}) },
    auth: { set: mock(async () => {}) },
    session: {
      abort: mock(async () => {}),
      messages: mock(async () => ({ data: [] })),
      prompt: mock(async () => {}),
    },
    tui: {
      showToast: mock(async () => {}),
    },
  } as unknown as PluginClient
}

function createPluginInput(
  client: PluginClient,
  directory: string,
): PluginInput {
  return {
    client,
    project: {} as PluginInput['project'],
    directory,
    worktree: directory,
    experimental_workspace: { register: mock(() => {}) },
    serverUrl: new URL('http://localhost:4096'),
    $: (() => {}) as unknown as PluginInput['$'],
  }
}

describe('createAntigravityPlugin (plugin entry surface)', () => {
  let tempProjectDir: string
  let fetchSpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    tempProjectDir = mkdtempSync(join(tmpdir(), 'plugin-entry-test-'))

    // initAntigravityVersion performs a non-blocking fetch on first install.
    // Returning a non-OK response forces it to fall back to the hardcoded
    // version without hitting the network — keeping the test hermetic.
    fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
      (async () =>
        new Response('not-found', {
          status: 404,
          statusText: 'Not Found',
        })) as unknown as typeof fetch,
    )
  })

  afterEach(() => {
    fetchSpy.mockRestore()
    mock.restore()
    rmSync(tempProjectDir, { recursive: true, force: true })
  })

  it('exposes the host-visible hook contract (config, command.execute.before, event, tool.google_search, auth)', async () => {
    const client = createMinimalClient()
    const ctx = createPluginInput(client, tempProjectDir)

    const plugin = await createAntigravityPlugin(ANTIGRAVITY_PROVIDER_ID)(ctx)

    expect(typeof plugin.dispose).toBe('function')
    expect(typeof plugin.config).toBe('function')
    expect(typeof plugin['command.execute.before']).toBe('function')
    expect(typeof plugin.event).toBe('function')
    expect(plugin.tool).toBeDefined()
    expect(plugin.tool?.google_search).toBeDefined()
    expect(plugin.auth).toBeDefined()
    expect(plugin.auth.provider).toBe(ANTIGRAVITY_PROVIDER_ID)
    expect(typeof plugin.auth.loader).toBe('function')

    // Two auth methods: OAuth with Antigravity + Manual API key entry.
    const labels = plugin.auth.methods.map((m) => m.label)
    expect(labels).toContain('OAuth with Google (Antigravity)')
    expect(labels).toContain('Manually enter API Key')
    expect(plugin.auth.methods).toHaveLength(2)
    const oauthMethod = plugin.auth.methods.find(
      (method) => method.label === 'OAuth with Google (Antigravity)',
    )
    expect(oauthMethod?.type).toBe('oauth')
    expect(typeof oauthMethod?.authorize).toBe('function')

    // No network call should leak from initialization — the version check
    // falls back to the hardcoded version on non-OK.
    expect(fetchSpy).toHaveBeenCalled()
  })

  it('config hook registers the antigravity model catalog, whitelist, and the /antigravity command without deleting existing entries', async () => {
    const client = createMinimalClient()
    const ctx = createPluginInput(client, tempProjectDir)
    const plugin = await createAntigravityPlugin(ANTIGRAVITY_PROVIDER_ID)(ctx)

    // Pre-populate the opencode config with a stub provider + command so
    // the plugin must merge rather than overwrite.
    const opencodeConfig = {
      provider: {
        'other-provider': { models: { foo: { name: 'foo' } } },
      },
      command: {
        existing: { template: 'existing', description: 'pre-existing' },
      },
    } as unknown as Parameters<typeof plugin.config>[0]

    await plugin.config?.(opencodeConfig)

    // Provider catalog: the antigravity provider now carries every model
    // listed in the core model registry, and a whitelist matching those ids.
    const expectedModelIds = getAntigravityOpencodeModelIds()
    const provider = (
      opencodeConfig as unknown as {
        provider?: Record<
          string,
          { models: Record<string, unknown>; whitelist: string[] }
        >
      }
    ).provider?.[ANTIGRAVITY_PROVIDER_ID]
    expect(provider).toBeDefined()
    expect(Object.keys(provider!.models).sort()).toEqual(
      [...expectedModelIds].sort(),
    )
    expect(provider?.whitelist).toEqual([...expectedModelIds])

    // Each model definition matches the core registry values.
    for (const id of expectedModelIds) {
      expect(provider?.models[id]).toBe(OPENCODE_MODEL_DEFINITIONS[id])
    }

    // Existing providers and commands are preserved alongside the additions.
    const finalConfig = opencodeConfig as unknown as {
      provider?: Record<string, { models: Record<string, unknown> }>
      command?: Record<string, unknown>
    }
    expect(finalConfig.provider?.['other-provider']?.models).toEqual({
      foo: { name: 'foo' },
    })
    expect(finalConfig.command?.existing).toEqual({
      template: 'existing',
      description: 'pre-existing',
    })

    // Exactly one command is added beside the host's: /antigravity, which
    // opens the shared menu. The retired /gemini-dump alias is not
    // registered; the request dump switch lives in the menu's Diagnostics.
    expect(Object.keys(finalConfig.command ?? {}).sort()).toEqual(
      [ANTIGRAVITY_MENU_COMMAND, 'existing'].sort(),
    )
    const menuCommand = finalConfig.command?.[ANTIGRAVITY_MENU_COMMAND] as
      | { template: string; description: string }
      | undefined
    expect(menuCommand?.template).toBe(ANTIGRAVITY_MENU_COMMAND)
  })

  it('command.execute.before leaves other commands, the retired gemini-dump included, to the host', async () => {
    const client = createMinimalClient()
    const ctx = createPluginInput(client, tempProjectDir)
    const plugin = await createAntigravityPlugin(ANTIGRAVITY_PROVIDER_ID)(ctx)

    // Non-matching command is a no-op — must return without throwing.
    await expect(
      plugin['command.execute.before']?.(
        { command: 'unrelated-command', arguments: '', sessionID: 'ses_test' },
        { parts: [] },
      ),
    ).resolves.toBeUndefined()

    // The retired /gemini-dump name is no longer handled here either.
    await expect(
      plugin['command.execute.before']?.(
        {
          command: GEMINI_DUMP_COMMAND_NAME,
          arguments: 'status',
          sessionID: 'ses_test',
        },
        { parts: [] },
      ),
    ).resolves.toBeUndefined()
  })
})

describe('package root exports', () => {
  it('exports only the two plugin factory aliases', () => {
    expect(Object.keys(packageRoot).sort()).toEqual([
      'AntigravityCLIOAuthPlugin',
      'GoogleOAuthPlugin',
    ])
    expect('authorizeAntigravity' in packageRoot).toBe(false)
    expect('exchangeAntigravity' in packageRoot).toBe(false)
  })
})

it('the production V1 entry opens the vault menu without opening or changing dormant local accounts', async () => {
  const owned = realpathSync(
    mkdtempSync(
      join(
        process.platform === 'win32' ? tmpdir() : '/tmp',
        'agy-v1-vault-entry-',
      ),
    ),
  )
  const overrides = {
    OPENCODE_CONFIG_DIR: join(owned, 'config'),
    ANTIGRAVITY_AUTH_RPC_DIR: join(owned, 'rpc'),
    ANTIGRAVITY_AUTH_SIDEBAR_STATE_FILE: join(owned, 'sidebar.json'),
  }
  const prior = Object.fromEntries(
    Object.keys(overrides).map((key) => [key, process.env[key]]),
  )
  Object.assign(process.env, overrides)
  const fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
    Object.assign(async () => new Response('not-found', { status: 404 }), {
      preconnect: globalThis.fetch.preconnect,
    }),
  )
  const accountFile = getStoragePath()
  mkdirSync(join(owned, 'config'), { recursive: true })
  const localBytes = JSON.stringify({
    version: 4,
    accounts: [
      {
        refreshToken: 'synthetic-dormant-refresh',
        projectId: 'synthetic-local-project',
        addedAt: 1,
        lastUsed: 1,
      },
    ],
    activeIndex: 0,
    activeIndexByFamily: { claude: 0, gemini: 0 },
  })
  writeFileSync(accountFile, localBytes, { mode: 0o600 })
  const seeding = createOpenCodeVaultCustody({
    accountFile,
    reporterSource: 'direct',
    readHostSlot: async () => {
      throw new Error('enrollment must not read the native login')
    },
    connectEnrollment: async () => ({
      enrollPropose: async () => ({ requestId: 'synthetic-request' }),
      enrollPoll: async () => ({
        status: 'approved' as const,
        name: OPENCODE_VAULT_ENROLLMENT_NAME,
        token: 'ab'.repeat(32),
        tokenGeneration: 1,
      }),
      close() {},
    }),
  })
  let dispose: (() => Promise<void> | void) | undefined
  try {
    expect((await seeding.requestAccess()).state).toBe('approved')
    const claustrum = await loadCommonAuthClaustrum()
    const paths = claustrum.hostEnrollmentPaths({
      stateDir: openCodeVaultPaths(accountFile).dir,
      host: 'opencode',
    })
    unlinkSync(paths.tokenPath)
    const client = createMinimalClient()
    const plugin = await packageRoot.GoogleOAuthPlugin(
      createPluginInput(client, owned),
    )
    dispose = plugin.dispose
    expect(plugin.auth?.methods.map((method) => method.label)).toEqual([
      V1_VAULT_ACTIVATION_LABEL,
    ])
    const vaultLogin = plugin.auth?.methods[0]
    if (vaultLogin?.type !== 'oauth')
      throw new Error('the vault activation method is absent')
    const activation = await vaultLogin.authorize()
    expect(activation.url).toBe('')
    expect(activation.method).toBe('auto')
    await expect(
      plugin['command.execute.before']?.(
        {
          command: ANTIGRAVITY_MENU_COMMAND,
          arguments: '',
          sessionID: 'vault-entry-session',
        },
        { parts: [] },
      ),
    ).rejects.toThrow()
    const notifications = await drainNotifications(0, 'vault-entry-session')
    const serialized = JSON.stringify(notifications)
    expect(serialized).toContain('Vault')
    expect(serialized).toContain('Accounts')
    expect(serialized).not.toContain('synthetic-dormant-refresh')
    expect(serialized).not.toContain('synthetic-local-project')
    expect(serialized).not.toContain('migrate --offline')
    expect(readFileSync(accountFile, 'utf8')).toBe(localBytes)
    expect(client.auth.set).not.toHaveBeenCalled()
    expect(
      JSON.stringify(
        await claustrum.readClaustrumEnrollmentStatus(
          paths,
          OPENCODE_VAULT_ENROLLMENT_NAME,
        ),
      ),
    ).toContain('missing_token')
    await dispose?.()
    dispose = undefined
    expect(
      readFileSync(overrides.ANTIGRAVITY_AUTH_SIDEBAR_STATE_FILE, 'utf8'),
    ).toContain(VAULT_ACCOUNT_REMEDY)
  } finally {
    await dispose?.()
    await seeding.dispose()
    fetchSpy.mockRestore()
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    rmSync(owned, { recursive: true, force: true })
  }
})
