// Demo 1: open a protected page, log in with the extension, check the session.
import { launch, check } from './fake-extension.mjs';
import { nip19 } from 'nostr-tools';
import { execSync } from 'node:child_process';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { chromium } from 'playwright';

const base = process.env.BASE ?? 'http://localhost:5101';
let signed;
const { browser, context, pubkey } = await launch({ onSign: e => (signed = e) });
const page = await context.newPage();
try {
  await page.goto(base + '/account');
  check(page.url().startsWith(base + '/signin-nostr?state='), 'protected page redirects to the login page');
  await page.screenshot({ path: 'out/cookie-1-login.png', fullPage: true });

  await page.click('#ext-btn');
  await page.waitForURL(base + '/account');
  check(signed.kind === 27235, 'extension signed a kind 27235 event');
  check(signed.tags.some(t => t[0] === 'u' && t[1] === base + '/signin-nostr'), 'event is bound to this site');

  const body = await page.textContent('main');
  check(body.includes(pubkey), 'account page shows the hex pubkey');
  check(body.includes(nip19.npubEncode(pubkey)), 'account page shows the npub');
  await page.screenshot({ path: 'out/cookie-2-account.png', fullPage: true });

  await page.click('text=Log out');
  await page.waitForURL(base + '/');
  check(await page.isVisible('a.button:has-text("Log in with Nostr")'), 'logout works');
} finally {
  await browser.close();
}

// --- Manual signing: run the exact nak command that the page shows, paste the result. ---
// Skipped when nak is not installed.

let hasNak = true;
try { execSync('nak --version', { stdio: 'ignore' }); } catch { hasNak = false; }
if (hasNak) {
  const sk = generateSecretKey();
  const manual = await chromium.launch();
  const page2 = await (await manual.newContext()).newPage();
  try {
    await page2.goto(base + '/account');
    await page2.click('summary:has-text("Sign manually")');
    const cmd = (await page2.textContent('#manual-cmd')).replace('<your nsec>', bytesToHex(sk));
    // input: '' closes stdin; nak waits for EOF on a piped stdin.
    const eventJson = execSync(cmd, { input: '', shell: '/bin/bash' }).toString().trim();
    await page2.fill('#manual-event', eventJson);
    await page2.click('#manual-btn');
    await page2.waitForURL(base + '/account');
    check((await page2.textContent('main')).includes(getPublicKey(sk)), 'manual signing with the shown nak command works');
  } finally {
    await manual.close();
  }
} else {
  console.log('skip - manual signing (nak not installed)');
}
