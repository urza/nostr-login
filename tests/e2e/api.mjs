// Demo 3: the browser page signs each API call with NIP-98 through the (fake) extension.
import { launch, check } from './fake-extension.mjs';

const base = process.env.BASE ?? 'http://localhost:5103';
const signed = [];
const { browser, context, pubkey } = await launch({ onSign: e => signed.push(e) });
const page = await context.newPage();
try {
  await page.goto(base + '/');
  await page.click('#me');
  await page.waitForFunction(() => document.getElementById('out').textContent.startsWith('HTTP'));
  check((await page.textContent('#out')).startsWith('HTTP 200'), 'GET /api/me with NIP-98 header succeeds');
  check((await page.textContent('#out')).includes(pubkey), 'API sees the pubkey');

  await page.fill('#text', 'Příliš žluťoučký kůň 🐎');
  await page.click('#add');
  await page.waitForFunction(() => document.getElementById('out').textContent.includes('kůň'));
  check((await page.textContent('#out')).startsWith('HTTP 200'), 'POST with a Unicode body and payload hash succeeds');
  check(signed.at(-1).tags.some(t => t[0] === 'payload'), 'POST event has a payload tag');
  await page.screenshot({ path: 'out/api-1.png', fullPage: true });
} finally {
  await browser.close();
}
