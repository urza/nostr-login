// Nostr Guestbook page script: local times, the character counter, copy npub,
// and the live "fetching your profile" panel.
(() => {
  const $ = id => document.getElementById(id);

  // Server renders UTC; show the reader's local time instead.
  for (const t of document.querySelectorAll('time[datetime]')) {
    const d = new Date(t.getAttribute('datetime'));
    if (!isNaN(d)) t.textContent = d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  const text = $('text');
  if (text) {
    const update = () => { $('counter').textContent = text.value.length; };
    text.addEventListener('input', update);
    update();
  }

  for (const b of document.querySelectorAll('[data-copy]')) {
    b.addEventListener('click', async () => {
      await navigator.clipboard.writeText(b.dataset.copy);
      const old = b.textContent;
      b.textContent = 'copied';
      setTimeout(() => (b.textContent = old), 1500);
    });
  }

  const panel = $('profile-panel');
  if (!panel || panel.dataset.done === 'true') return;

  const icons = { Started: '…', Found: '✓', NotFound: '–', Failed: '✕' };
  const label = s => (s === 'NIP-05' ? 'NIP-05' : s.replace(/^wss?:\/\//, ''));

  // Replace the avatar and name in every place that shows the current user (header, card, wall).
  const applyProfile = (me, p) => {
    for (const el of document.querySelectorAll(`[data-author="${me}"]`)) {
      if (p.name) for (const n of el.querySelectorAll('.author-name')) n.textContent = p.name;
      if (p.picture) {
        for (const a of el.querySelectorAll('.avatar')) {
          if (a.querySelector('img')) continue;
          const img = document.createElement('img');
          img.alt = '';
          img.referrerPolicy = 'no-referrer';
          img.onerror = () => img.remove();
          img.src = p.picture;
          a.appendChild(img);
        }
      }
    }
    if (p.nip05) {
      $('me-nip05').querySelector('span').textContent = p.nip05;
      $('me-nip05').hidden = false;
    }
  };

  const render = p => {
    const list = $('profile-steps');
    list.replaceChildren(...p.steps.map(s => {
      const li = document.createElement('li');
      li.className = s.outcome;
      li.innerHTML = '<span class="icon"></span><span class="src"></span><span class="muted"></span>';
      li.children[0].textContent = icons[s.outcome] ?? '?';
      li.children[1].textContent = label(s.source);
      li.children[2].textContent = s.outcome === 'Started' ? (s.source === 'NIP-05' ? `checking ${s.detail}…` : 'asking…') : (s.detail ?? '');
      return li;
    }));
    if (!p.done) return;

    panel.dataset.done = 'true';
    const me = document.querySelector('.me-head').dataset.author;
    if (p.status === 'Found') {
      $('profile-title').textContent = 'Profile loaded';
      $('profile-text').textContent = 'Name and picture come from your Nostr profile. They update at each login. Your identity is your key, not this data.';
      applyProfile(me, p);
    } else {
      $('profile-title').textContent = 'No profile found';
      $('profile-text').textContent = 'No relay had a profile for your key. You appear with your npub and a generated avatar. Set a name and picture in any Nostr app, then refresh.';
    }
  };

  const started = Date.now();
  const poll = async () => {
    try {
      const res = await fetch('/api/me/profile', { cache: 'no-store' });
      if (res.ok) {
        const p = await res.json();
        render(p);
        if (p.done) return;
      }
    } catch { /* network hiccup: try again */ }
    // The server gives up after its own timeout; stop polling a bit after that.
    if (Date.now() - started < 30000) setTimeout(poll, 700);
  };
  poll();
})();
