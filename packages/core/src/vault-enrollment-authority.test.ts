import { describe, expect, it } from 'bun:test'
import type { CommonAuthClaustrumModule } from './common-auth-runtime.ts'
import { enrollmentAuthority } from './vault-enrollment-authority.ts'

type Status = Awaited<
  ReturnType<CommonAuthClaustrumModule['readClaustrumEnrollmentStatus']>
>
const paths = { tokenPath: '/synthetic-token', statePath: '/synthetic-state' }
describe('enrollment source authority', () => {
  const cases: readonly [Status, 'local' | 'vault' | 'unreadable'][] = [
    [{ state: 'idle' }, 'local'],
    [{ state: 'pending', proposedName: 'synthetic' }, 'local'],
    [{ state: 'denied', proposedName: 'synthetic' }, 'local'],
    [
      { state: 'approved', proposedName: 'synthetic', tokenGeneration: 1 },
      'vault',
    ],
    [
      { state: 'blocked', proposedName: 'synthetic', code: 'missing_token' },
      'vault',
    ],
    [
      { state: 'blocked', proposedName: 'synthetic', code: 'invalid_state' },
      'unreadable',
    ],
    [
      { state: 'unavailable', proposedName: 'synthetic', code: 'read_failure' },
      'unreadable',
    ],
    [{ state: 'busy' }, 'unreadable'],
  ]
  for (const [status, source] of cases)
    it(`${status.state} ${'code' in status ? status.code : ''} chooses ${source}`, async () => {
      expect(
        await enrollmentAuthority(paths, 'synthetic', {
          readClaustrumEnrollmentStatus: async (received) => {
            expect(received).toEqual(paths)
            return status
          },
        }),
      ).toBe(source)
    })
  it('a failed read cannot authorize local work', async () => {
    expect(
      await enrollmentAuthority(paths, 'synthetic', {
        readClaustrumEnrollmentStatus: async () => {
          throw new Error('synthetic read failure')
        },
      }),
    ).toBe('unreadable')
  })
})
