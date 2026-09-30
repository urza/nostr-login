// A stand-in for a NIP-07 browser extension (Alby, nos2x, ...). The key lives in Node,
// the page only sees window.nostr, exactly like with a real extension.
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { chromium } from 'playwright';

export async function launch({ secretKey = generateSecretKey(), onSign } = {}) {
  const pubkey = getPublicKey(secretKey);
  const browser = await chromium.launch();
  const context = await browser.newContext();
  await context.exposeFunction('__fakeExtSign', evt => {
    onSign?.(evt);
    return finalizeEvent(evt, secretKey);
  });
  await context.exposeFunction('__fakeExtPubkey', () => pubkey);
  await context.addInitScript(() => {
    window.nostr = {
      getPublicKey: () => window.__fakeExtPubkey(),
      signEvent: evt => window.__fakeExtSign(evt),
    };
  });
  return { browser, context, pubkey, secretKey };
}

export function check(condition, message) {
  if (!condition) throw new Error('FAILED: ' + message);
  console.log('ok -', message);
}
