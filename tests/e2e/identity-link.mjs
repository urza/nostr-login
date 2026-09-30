// Demo 2: Nostr as an ASP.NET Core Identity external login.
import { generateSecretKey } from 'nostr-tools/pure';
import { nip19 } from 'nostr-tools';
import { launch, check } from './fake-extension.mjs';

const base = process.env.BASE ?? 'http://localhost:5102';
const keyA = generateSecretKey();
const keyB = generateSecretKey();

async function signInWithNostr(page) {
  await page.goto(base + '/Identity/Account/Login');
  await page.click('button[name=provider][value=Nostr]');
  await page.waitForURL(/\/signin-nostr\?state=/);
  await page.click('#ext-btn');
}

async function logout(page) {
  await page.click('button:has-text("Logout")');
  await page.waitForLoadState();
}

// --- A: sign up with a new key, then log in again with the same key ---
{
  const { browser, context, pubkey } = await launch({ secretKey: keyA });
  const page = await context.newPage();
  try {
    await signInWithNostr(page);
    await page.waitForURL(/ExternalLogin/);
    check(await page.isVisible('text=is not linked to an account yet'), 'unknown key gets the new-account page');
    await page.screenshot({ path: 'out/identity-1-new-account.png', fullPage: true });
    await page.click('button:has-text("Create account")');
    await page.waitForURL(base + '/');
    const home = await page.textContent('main');
    check(home.includes(nip19.npubEncode(pubkey)), 'home page lists the Nostr login');
    check(home.includes('none'), 'Nostr-only account has no password');
    await page.screenshot({ path: 'out/identity-2-home.png', fullPage: true });

    await logout(page);
    await signInWithNostr(page);
    await page.waitForURL(base + '/');
    check((await page.textContent('main')).includes(pubkey), 'same key logs in to the same account without questions');
  } finally {
    await browser.close();
  }
}

// --- B: password account links a Nostr key, then logs in with it ---
const email = `user${Date.now()}@example.com`;
{
  const { browser, context, pubkey } = await launch({ secretKey: keyB });
  const page = await context.newPage();
  try {
    await page.goto(base + '/Identity/Account/Register');
    await page.fill('#Input_Email', email);
    await page.fill('#Input_Password', 'Passw0rd!Passw0rd');
    await page.fill('#Input_ConfirmPassword', 'Passw0rd!Passw0rd');
    await page.click('#registerSubmit');
    await page.waitForURL(base + '/');
    check((await page.textContent('main')).includes('set'), 'registered a password account');

    await page.goto(base + '/Identity/Account/Manage/ExternalLogins');
    await page.click('button[name=provider][value=Nostr]');
    await page.waitForURL(/\/signin-nostr\?state=/);
    await page.click('#ext-btn');
    await page.waitForURL(/ExternalLogins/);
    check(await page.isVisible('text=The external login was added.'), 'Nostr key linked to the password account');
    await page.screenshot({ path: 'out/identity-3-linked.png', fullPage: true });

    await logout(page);
    await signInWithNostr(page);
    await page.waitForURL(base + '/');
    const home = await page.textContent('main');
    check(home.includes(email) || (await page.textContent('nav')).includes(email), 'Nostr login opens the password account');
    check(home.includes(nip19.npubEncode(pubkey)), 'account shows the linked key');
  } finally {
    await browser.close();
  }
}

// --- C: a key that belongs to another account cannot be linked again ---
{
  const { browser, context } = await launch({ secretKey: keyA });
  const page = await context.newPage();
  try {
    await page.goto(base + '/Identity/Account/Register');
    await page.fill('#Input_Email', 'other' + email);
    await page.fill('#Input_Password', 'Passw0rd!Passw0rd');
    await page.fill('#Input_ConfirmPassword', 'Passw0rd!Passw0rd');
    await page.click('#registerSubmit');
    await page.waitForURL(base + '/');

    await page.goto(base + '/Identity/Account/Manage/ExternalLogins');
    await page.click('button[name=provider][value=Nostr]');
    await page.waitForURL(/\/signin-nostr\?state=/);
    await page.click('#ext-btn');
    await page.waitForURL(/ExternalLogins/);
    check(await page.isVisible('text=The external login was not added'), 'a key of another account is refused');
  } finally {
    await browser.close();
  }
}
