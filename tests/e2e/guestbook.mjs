// Nostr Guestbook: login, background profile loading, one message per user, public wall.
//
// Start the app with a local profile relay first, so the test controls the profile data:
//   nak serve is started by this script on port 10555, with a kind-0 profile for user A.
//   Nostr__ProfileRelays__0=ws://127.0.0.1:10555 dotnet run --project app/NostrGuestbook
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { launch, check } from './fake-extension.mjs';

const base = process.env.BASE ?? 'http://localhost:5110';
const keyA = generateSecretKey(); // has a profile
const keyB = generateSecretKey(); // has none
const profile = finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [],
  content: JSON.stringify({ name: 'Alice Test', picture: 'https://robohash.org/alice.png' }) }, keyA);
writeFileSync('out/profiles.jsonl', JSON.stringify(profile) + '\n');
const relay = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', '10555', '--events', 'out/profiles.jsonl'], { stdio: ['ignore', 'ignore', 'ignore'] });
await new Promise(r => setTimeout(r, 1000));

async function login(context) {
  const page = await context.newPage();
  await page.goto(base + '/');
  await page.click('a.btn:has-text("Log in with Nostr")');
  await page.waitForURL(/\/signin-nostr\?state=/);
  await page.click('#ext-btn');
  await page.waitForURL(base + '/#me');
  return page;
}

try {
  // --- User A: profile loads after login, then posts and edits one message ---
  {
    const { browser, context, pubkey } = await launch({ secretKey: keyA });
    try {
      const page = await login(context);
      check(await page.isVisible('#profile-panel'), 'logged in at once, profile panel is shown');
      await page.waitForFunction(() => document.getElementById('profile-panel').dataset.done === 'true', null, { timeout: 20000 });
      check((await page.textContent('#profile-title')).includes('Profile loaded'), 'background lookup found the profile');
      check((await page.textContent('.me-head .author-name')) === 'Alice Test', 'name appears without reload');
      check(await page.isVisible('.me-head .avatar img'), 'picture appears without reload');
      check((await page.textContent('#profile-steps')).includes('127.0.0.1:10555'), 'panel lists the relay it asked');
      await page.screenshot({ path: 'out/guestbook-1-profile.png', fullPage: true });

      await page.fill('#text', 'Hello from Alice!');
      await page.click('button:has-text("Post message")');
      await page.waitForURL(base + '/#me');
      check((await page.textContent('.grid')).includes('Hello from Alice!'), 'message is on the wall');

      await page.fill('#text', 'Hello again, edited.');
      await page.click('button:has-text("Update message")');
      await page.waitForURL(base + '/#me');
      const mine = await page.$$(`.msg[data-author="${pubkey}"]`);
      check(mine.length === 1, 'still exactly one message for this user');
      check((await mine[0].textContent()).includes('edited'), 'edit replaced the text and shows "edited"');
    } finally {
      await browser.close();
    }
  }

  // --- User B: no profile, posts a message ---
  {
    const { browser, context } = await launch({ secretKey: keyB });
    try {
      const page = await login(context);
      await page.waitForFunction(() => document.getElementById('profile-panel').dataset.done === 'true', null, { timeout: 20000 });
      check((await page.textContent('#profile-title')).includes('No profile found'), 'user without profile gets a clear message');
      await page.fill('#text', 'Bob was here.');
      await page.click('button:has-text("Post message")');
      await page.waitForURL(base + '/#me');
    } finally {
      await browser.close();
    }
  }

  // --- Anonymous visitor sees the wall ---
  {
    const { browser, context } = await launch();
    try {
      const page = await context.newPage();
      await page.goto(base + '/');
      const wall = await page.textContent('.grid');
      check(wall.includes('Hello again, edited.') && wall.includes('Bob was here.'), 'anonymous visitor sees both messages');
      check(wall.includes('Alice Test'), 'wall shows the profile name');
      check(await page.isVisible('.hero'), 'visitor sees the hero with the login button');
      await page.screenshot({ path: 'out/guestbook-2-public.png', fullPage: true });
    } finally {
      await browser.close();
    }
  }

  // --- User A comes back: same message, still editable, can delete ---
  {
    const { browser, context } = await launch({ secretKey: keyA });
    try {
      const page = await login(context);
      check((await page.inputValue('#text')) === 'Hello again, edited.', 'returning user finds their message in the editor');
      await page.click('button:has-text("Delete")');
      await page.waitForURL(base + '/#me');
      check(!(await page.textContent('.grid')).includes('Hello again'), 'delete removes the message');
    } finally {
      await browser.close();
    }
  }
} finally {
  relay.kill();
}
