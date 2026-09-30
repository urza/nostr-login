// Demo 4: a plain OIDC client app logs in through the Nostr ID provider.
import { launch, check } from './fake-extension.mjs';
import { nip19 } from 'nostr-tools';

const client = process.env.CLIENT ?? 'http://localhost:5105';
const provider = process.env.PROVIDER ?? 'http://localhost:5104';
let signed;
const { browser, context, pubkey } = await launch({ onSign: e => (signed = e) });
const page = await context.newPage();
try {
  await page.goto(client + '/account');
  await page.waitForURL(u => u.href.startsWith(provider + '/signin-nostr?state='));
  check(true, 'client app sends the user to the provider, provider shows the Nostr login');
  await page.screenshot({ path: 'out/oidc-1-provider-login.png', fullPage: true });

  await page.click('#ext-btn');
  await page.waitForURL(client + '/account');
  check(signed.tags.some(t => t[0] === 'u' && t[1] === provider + '/signin-nostr'), 'user signed a login for the provider, not for the client');

  const body = await page.textContent('body');
  check(body.includes(pubkey), 'client sees the pubkey as the OIDC sub claim');
  check(body.includes(nip19.npubEncode(pubkey)), 'client gets the npub claim from the profile scope');
  await page.screenshot({ path: 'out/oidc-2-client-account.png', fullPage: true });

  // Single sign-on: drop only the client session. The provider session still exists,
  // so the provider answers at once, without a new signature.
  const before = signed;
  await context.clearCookies({ name: 'OidcClientDemo' });
  await page.goto(client + '/account');
  await page.waitForURL(client + '/account');
  check(signed === before, 'single sign-on: provider session logs the client in again without a new signature');

  await page.goto(client + '/logout');
  await page.waitForURL(client + '/');
  check((await page.textContent('body')).includes('Log in'), 'logout at client and provider works');

  await page.goto(client + '/account');
  await page.waitForURL(u => u.href.startsWith(provider + '/signin-nostr'));
  check(true, 'after logout the provider asks for a new Nostr login');
} finally {
  await browser.close();
}
