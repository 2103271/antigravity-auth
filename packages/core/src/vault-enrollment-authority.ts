import {
  type CommonAuthClaustrumModule,
  loadCommonAuthClaustrum,
} from './common-auth-runtime.ts'

export type EnrollmentAuthority = 'vault' | 'local' | 'unreadable'
type EnrollmentPaths = Parameters<
  CommonAuthClaustrumModule['readClaustrumEnrollmentStatus']
>[0]
type EnrollmentReader = Pick<
  CommonAuthClaustrumModule,
  'readClaustrumEnrollmentStatus'
>

export const VAULT_ACCOUNT_REMEDY =
  'Vault account access is unavailable. Connect accounts in the vault, or disconnect the vault to use local accounts.'

/**
 * The operator's approval to access the vault selects its accounts instead of local OAuth accounts,
 * regardless of a saved local-mode preference.
 * An approved record whose token disappeared still excludes local accounts.
 * Failed reads never authorize local work. Call at the start of each unit of
 * work; a refresh that already started must finish saving the replacement
 * OAuth credentials.
 */
export async function enrollmentAuthority(
  paths: EnrollmentPaths,
  proposedName: string,
  reader?: EnrollmentReader,
): Promise<EnrollmentAuthority> {
  try {
    const status = await (
      reader ?? (await loadCommonAuthClaustrum())
    ).readClaustrumEnrollmentStatus(paths, proposedName)
    switch (status.state) {
      case 'approved':
        return 'vault'
      case 'blocked':
        return status.code === 'missing_token' ? 'vault' : 'unreadable'
      case 'idle':
      case 'pending':
      case 'denied':
        return 'local'
      case 'busy':
      case 'unavailable':
        return 'unreadable'
    }
  } catch {
    return 'unreadable'
  }
}
