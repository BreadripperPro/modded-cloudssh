import { t } from './i18n';
import { isEncryptedPrivateKey, PrivateKeyUnlockError, unlockPrivateKey } from './private-key-unlock';
import { confirmAction, notify, requestText } from './ui-feedback';

/** Explicit local unlock; saving an unlocked key requires separate informed consent. */
export async function preparePrivateKey(
  text: string,
  persist: boolean
): Promise<{ key: string; unlocked: boolean } | null> {
  let passphrase: string | null = null;
  try {
    if (!isEncryptedPrivateKey(text)) return { key: text, unlocked: false };
    if (persist) {
      const approved = await confirmAction({
        title: t('auth.keyUnlockTitle'),
        message: t('auth.keyUnlockSaveWarning'),
        variant: 'warning',
      });
      if (!approved) return null;
    }
    passphrase = await requestText({
      title: t('auth.keyUnlockTitle'), message: t('auth.keyUnlockHint'),
      label: t('auth.keyPassphrase'), inputType: 'password', required: false, maxLength: 1024,
    });
    if (passphrase === null) return null;
    notify(t('auth.keyUnlocking'), { variant: 'info', duration: 1200 });
    // Give the browser a paint before bounded bcrypt work begins.
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    return { key: await unlockPrivateKey(text, passphrase), unlocked: true };
  } catch (error) {
    const reason = error instanceof PrivateKeyUnlockError ? error.reason : 'invalid';
    notify(t(reason === 'unsupported' ? 'auth.keyUnlockUnsupported'
      : reason === 'budget' ? 'auth.keyUnlockBudget' : 'auth.keyUnlockError'), { variant: 'danger' });
    return null;
  } finally {
    // Strings cannot be reliably zeroized by JavaScript; do not retain them in any application state.
    passphrase = null;
  }
}
