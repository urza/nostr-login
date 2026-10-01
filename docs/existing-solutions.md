# Existing "Log in with Nostr" and NIP-46 solutions (research, 2026-10-01)

Research done by an agent on 2026-10-01 for this project. Links were checked at that date. Tags: **[code]** read in the source, **[doc]** README or docs, **[PR]** text of a PR or issue, not checked in code.

Source tags: **[code]** = we read the source (shallow clones, dates are last commits). **[doc]** = project README or docs. **[PR]** = PR or issue text, not checked in code.

## 1. .NET / C# implementations

- **btcpay-nostr-login** (pretyflaco), [NostrLoginService.cs](https://github.com/pretyflaco/btcpay-nostr-login/blob/main/src/BTCPayServer.Plugins.NostrLogin/NostrLoginService.cs), [RelayPool.cs](https://github.com/pretyflaco/btcpay-nostr-login/blob/main/src/BTCPayServer.Plugins.NostrLogin/RelayPool.cs). MIT, 2026-09-29, active. The only other server-side NIP-46 login in .NET. The server makes a session key, shows a QR plus an "Open signer app" link, and runs connect, get_public_key, sign_event; the browser polls every 2 s. It signs kind 27235 (u = login URL, method POST, challenge tag) and falls back to kind 22242 after 20 s or on a signer error. Relays: nos.lol, relay.damus.io, relay.primal.net, offchain.pub (admin can change). No `since`. It republishes the same event every 4 s and reconnects dead relays first. It does not read OK (NNostr `PublishEvent` only queues). Browser binding by SameSite=Strict cookie, 10 sessions/min/IP, 5 min sessions. A GET NIP-98 "magic link" serves same-device signers (90 s freshness, replay store). [code]
- **NNostr** (Kukks), [repo](https://github.com/Kukks/NNostr). MIT, 2026-08. Relay and client, NIP-04/44, no NIP-46. Base of the BTCPay plugin. [code]
- **Nostr.Client** (Marfusios), [repo](https://github.com/Marfusios/nostr-client), Apache-2.0, 2025-11, and its Blockcore fork (2026-01). No NIP-46 or NIP-98. [code]
- **Nostr.Sdk** (rust-nostr FFI, NuGet 0.45.1, MIT, alpha), [connect.rs](https://github.com/rust-nostr/nostr-sdk-ffi/blob/master/src/connect.rs). Exposes the rust `NostrConnect` NIP-46 client to C#. The client ([client.rs](https://github.com/rust-nostr/nostr/blob/master/signer/nostr-connect/src/client.rs)) subscribes with `limit 0`, sends each request once, waits with a timeout, and has an auth_url hook. No resend. Native binaries. [code]
- **NostrNet** (Galaxoid-Labs), [Nip98HttpAuth.cs](https://github.com/Galaxoid-Labs/NostrNet/blob/main/src/NostrNet.Core/HttpAuth/Nip98HttpAuth.cs). MIT, preview, 2026-05. NIP-98 builder, validator (60 s window) and HttpClient handler. No ASP.NET handler, no NIP-46. [code]
- **void.cat NostrAuthHandler** (v0l), [NostrAuth.cs](https://github.com/v0l/void.cat/blob/main/VoidCat/Services/NostrAuth.cs). Archived 2024. ASP.NET `AuthenticationHandler` for NIP-98: kind 27235, ±60 s, method, but compares only the path of `u` to `Request.Path`. Same idea in v0l's [2023 gist](https://gist.github.com/v0l/74346ae530896115bfe2504c8cd018d3). [code]
- **NostrSharp**, [repo](https://github.com/smaciullator/NostrSharp). GPL-3.0, 2023. Only builds the old nostrconnect URI format (metadata JSON). [code]
- **BlazeJump.NostrConnect**, [repo](https://github.com/drmikesamy/BlazeJump.NostrConnect). MIT, 2026-01. Demo: Blazor WASM client plus MAUI Android signer. NIP-46 runs in the browser, relay.damus.io, `since` now-30 s. [code]
- **nokandro**, [repo](https://github.com/betonetojp/nokandro). MIT, 2026-07. C# Android NIP-46 bunker (signer side). Its last commit adds sticky restart and a battery-optimization exemption to stay reachable. [code]
- Not found: OpenIddict, IdentityServer, Keycloak or NuGet "Nostr login" packages.

## 2. Non-.NET NIP-46 clients

| Client (file) | Relays in nostrconnect URI | Resend | Waits for OK | `since` | Other |
|---|---|---|---|---|---|
| [nostr-tools nip46.ts](https://github.com/nbd-wtf/nostr-tools/blob/master/nip46.ts) | caller | no | first OK (`Promise.any`, 4.4 s) | none, `limit 0` | calls `switch_relays` after connect; NIP-42 only if the pool has `automaticallyAuth` |
| [NDK nip46](https://github.com/nostr-dev-kit/ndk/blob/master/core/src/signers/nip46/index.ts) | one relay | no | NDK publish | none | timeout off by default; `switch_relays` with 5 s timeout |
| [nostr-login](https://github.com/nostrband/nostr-login/blob/main/packages/auth/src/modules/AuthNostrService.ts) (2025-03) | relay.nsec.app for all apps | no | NDK | none | nsec.app opens `https://use.nsec.app/<nostrconnect>`; an iframe MessagePort carries requests with no relay |
| [Coracle / welshman](https://github.com/coracle-social/welshman/blob/master/packages/signer/src/signers/nip46.ts) | relay.nsec.app, ephemeral.snowflare.cc, bucket.coracle.social ([.env.template](https://github.com/coracle-social/coracle/blob/master/.env.template)) | no | no | none | accepts "ack" with a warning |
| [Jumble](https://github.com/CodyTseng/jumble/blob/master/src/components/AccountManager/NostrConnectionLogin.tsx) | bucket.coracle.social, relay.primal.net, relay.ditto.pub | no | yes | none | the QR is an `<a href="nostrconnect:...">`; 30 s request timeout |
| [noStrudel](https://github.com/hzrd149/nostrudel/blob/master/src/views/signin/connect/index.tsx) / [applesauce](https://github.com/hzrd149/applesauce/blob/master/packages/signers/src/signers/nostr-connect-signer.ts) | bucket.coracle.social, user can edit, live relay status | no | publish method | none | "Open signer" button; subscription `repeat()`+`retry()` |
| [Snort](https://github.com/v0l/snort/blob/main/packages/system/src/impl/nip46.ts) | first default relay | no | not checked | now-10 s | [sign-in.tsx](https://github.com/v0l/snort/blob/main/packages/app/src/Pages/onboarding/sign-in.tsx) opens the URI only after the REQ is sent, and opens it again on `visibilitychange`; 30 s timeout |
| [Primal web](https://github.com/PrimalHQ/primal-web-app/blob/main/src/lib/PrimalNip46.ts) | nrs.primal.net | no | yes | none | client key and URI kept in localStorage (survives reload) |
| [Stacker News](https://github.com/stackernews/stacker.news/blob/master/components/nostr-auth.js) | bunker:// or NIP-05 only | no | NDK | none | kind 27235 with challenge, u, method GET; the [server](https://github.com/stackernews/stacker.news/blob/master/pages/api/auth/%5B...nextauth%5D.js) checks sig and one-time k1, not kind, u, method or created_at |

All rows are [code]. Other findings:
- **Alby Hub**: no NIP-46 client code (no nostrconnect, 24133 or bunker). [code]
- **signet-login**, [repo](https://github.com/forgesworn/signet-login): browser-side NIP-07/46/49/55, persists in-flight sign-in across backgrounding, default nos.lol. [doc]
- No client uses Universal Links or App Links. All use the custom `nostrconnect:` scheme. No client corrects created_at for clock skew.

## 3. Signer apps and NIP-46 relays

**Amber** (v6.6.6, 2026-09-28) [code]:
- It uses the URI relays for a new nostrconnect connection, and its defaults only when the URI has none ([BunkerRequestUtils.kt](https://github.com/greenart7c3/Amber/blob/master/app/src/main/java/com/greenart7c3/nostrsigner/service/BunkerRequestUtils.kt)). Defaults: auth.nostr1.com, bucket.coracle.social, nrs.primal.net, relay.nip46.com ([AmberSettings.kt](https://github.com/greenart7c3/Amber/blob/master/app/src/main/java/com/greenart7c3/nostrsigner/models/AmberSettings.kt)).
- It makes a new key per connection, so the reply author is not the user.
- Replies go out with `publishAndConfirm` (OK, 5 s), up to 5 tries with backoff, re-signed with a new created_at.
- It listens with `since` = now, or the newest created_at it has seen, and `limit 1` ([NotificationSubscription.kt](https://github.com/greenart7c3/Amber/blob/master/app/src/main/java/com/greenart7c3/nostrsigner/service/NotificationSubscription.kt)). A client clock behind Amber's clock gets filtered out.
- A code comment says the listening REQ must exist before the connect reply; before that fix a 30 s timer could lose `get_public_key`.
- Foreground service "keep the connection to the relays active" (free flavor), battery-optimization request, relay "dead" after 10 failed connects, answers NIP-42 AUTH, registers `nostrconnect:` and `nostrsigner:`.
- The README documents none of this. [Issue #526](https://github.com/greenart7c3/Amber/issues/526): `=` in a URI parameter value breaks parsing. [PR] A hoot PR claims Amber falls back to damus, nostr.band, nostr.wine; current code does not show that. [PR]

**nsec.app** ([noauth](https://github.com/nostrband/noauth), 2025-05) [code+doc]: the signer listens only on `NIP46_RELAYS = [relay.nsec.app]`. Its `nostrConnect()` ([backend.ts](https://github.com/nostrband/noauth/blob/main/packages/backend/src/backend.ts)) reads only pubkey and secret, so URI relays are ignored. A push server wakes the service worker. The README says cross-device use is unreliable when the phone is locked, and public relays "hit rate limits very fast". Our sandbox could not reach nsec.app or relay.nsec.app either (possibly our firewall).

**Primal Android** (2026-09-01) [code]: NIP-46 signer with foreground `PrimalRemoteSignerService`. It registers `nostrconnect:`, `primalconnect:`, `nostrsigner:`. It rebroadcasts only the connect reply (5 times, every 2 s, max 30 s) and listens without `since`. We found no public NIP-46 docs.

**Dedicated relays** [code]:
- relay.nip46.com runs [nip46-relay](https://github.com/Letdown2491/nip46-relay): only kinds 24133/24135, keeps them 10 min in memory and serves them to later REQs, rejects created_at outside ±1 min, 100 events/min per pubkey (defaults; live config unknown).
- bucket.coracle.social ([index.js](https://github.com/coracle-social/bucket/blob/master/src/index.js)): stores every event, clears all every 30 s, replays stored events to new REQs.
- nrs.primal.net: strfry, NIP-11 name "Primal Nostr Remote Signer Relay".

## 4. Server-side NIP-46 login

- It is a known but rare pattern: btcpay-nostr-login, blink-terminal and our NostrAuth. [nostr-nip46 (PHP)](https://github.com/johninnis/nostr-nip46) supports the client role with nostrconnect. [doc]
- **blink-terminal** [issue #70](https://github.com/blinkbitcoin/blink-terminal/issues/70), [PR #71](https://github.com/blinkbitcoin/blink-terminal/pull/71) (merged 2026-09-04): Android froze the tab and dropped its WebSocket when Amber opened. Amber logged "Signed event (kind 27235) Approved" while the page said "timed out". They moved key and subscription to the server, show the URI only after the REQ is written, and let the browser poll. Rate tiers: 10/min create, 240/min poll. The earlier [PR #66](https://github.com/blinkbitcoin/blink-terminal/pull/66) fought bfcache and `visibilitychange`, and saw 2 of 3 default relays fail (damus 503, primal DNS). [PR]
- Known problems: the one-shot connect reply (listen first), QRLjacking (bind the session to the browser), session-creation abuse, relays the server network cannot reach (btcpay notes damus 503 behind Cloudflare), 2FA bypass (btcpay 0.7.0 enforces 2FA on all Nostr paths), and an extra signer prompt for kind 27235.
- **Keycast** ([relays.md](https://github.com/marmot-protocol/keycast/blob/master/docs/relays.md), [relay investigation](https://github.com/marmot-protocol/keycast/blob/master/docs/development/history/RELAY_INVESTIGATION_2026-09-08.md)) is a server-side signer, the opposite role. It counts a relay as ready only after the REQ is accepted, probes relays with a throwaway ephemeral event, uses a 5 min lookback on resubscribe, caches replies for client retries, and treats AUTH-required relays as unusable. [doc]

## What we should copy or change

1. Add relays that hold kind 24133 for a short time: relay.nip46.com (10 min) and bucket.coracle.social (up to 30 s), plus nrs.primal.net. All three are Amber defaults. A late signer then gets the request without our next resend. Keep relay.nsec.app for nsec.app only.
2. Respect the ±60 s window of relay.nip46.com. Our "signer clock ahead" shift can push created_at out of it. Cap the shift for that relay or send it an unshifted copy, and log its OK reason.
3. Send `switch_relays` right after the connect reply (2-5 s timeout, accept `null` or an error). Send later requests on our relays plus the returned ones.
4. Add a NIP-55 web path for Android on the same device: `nostrsigner:<event>?type=sign_event&returnType=event&callbackUrl=...`. Amber and Primal register `nostrsigner:`, and no relay is involved. Verify the result like NIP-98 (u, method, challenge, single use, short window), as BTCPay's GET magic link does.
5. Answer NIP-42 AUTH with the session client key. It needs no user action and keeps AUTH relays usable. Today we only log AUTH.
6. nsec.app ignores URI relays. Add an nsec.app button that opens `https://use.nsec.app/<nostrconnect>`, and read its relays from `nsec.app/.well-known/nostr.json?name=_`. If the server cannot reach relay.nsec.app, say so on the page.
7. After `sign_event` goes out, show "Open signer app" again with a short hint. Snort reopens the URI on `visibilitychange`. Amber and Primal use a foreground service to stay connected, so tell users not to block it.
8. Log stages per session: no relay, no signer reply, reply but no signature (btcpay), and connected, REQ accepted, OK, reply received (Keycast). Record which relay delivered each signer event, and pick defaults from that data.
9. Keep the server-side design. blink-terminal moved to it for our exact phone problem. Make "REQ accepted before the QR is shown" a tested invariant.
10. If not present, copy btcpay's browser-binding cookie and per-IP session limit. Always check kind, u, method and created_at, unlike Stacker News.

## 5. nostrautica (jooray), compared on 2026-10-01

[nostrautica](https://github.com/jooray/nostrautica) is a static SvelteKit PWA with no server. Its NIP-46 client runs in the browser with nostr-tools `BunkerSigner.fromURI` ([`packages/app/src/lib/signer/nip46.ts`](https://github.com/jooray/nostrautica/blob/main/packages/app/src/lib/signer/nip46.ts)). [code]

- Login methods: NIP-07, `nostrconnect://` with a QR code and a plain `<a href={uri}>` button, a pasted `bunker://`, a pasted key. No NIP-55, no nostr-login library.
- Relays in the URI ([`relays.ts`](https://github.com/jooray/nostrautica/blob/main/packages/app/src/lib/nostr/relays.ts)): `nostr.cypherpunk.today`, `relay.primal.net`, `nos.lol`. They removed `relay.nsec.app` on 2026-07-25 ("HTTP 502 on every probe") and always set `skipSwitchRelays`.
- Filter during connect: `kinds 24133, #p client pubkey, limit 0`, no `since`. After the reply: `authors` added. On a socket reconnect nostr-tools sets `since = lastEmitted + 1`.
- After connect it sends only `get_public_key`. There is no signed login event and no server check: the identity is whatever the signer says. Our login needs `sign_event` too, which is an approval prompt.
- Resends: none on a timer. When the tab comes back to the foreground, or a relay recovers, it sends `ping`, and on an answer it sends the request again under a **new id**, at most 3 times. Their comment: re-asking under a fresh id "filled the phone with approval prompts". Deadlines count only time while the tab is visible.
- Same-device: the link has no return URL. Three seconds after the tab is visible again the page says "Didn't get the approval? Keep this tab open while approving, or retry with a fresh code."
- On a timeout the page says which relays it could not reach.

Differences that matter for us: their client is in the browser, so a backgrounded tab is their problem and the server is ours; they ask the signer for nothing that needs a prompt during login; their copies of a request get a new id after a `ping`, ours kept the same id (changed for `get_public_key` after this comparison); they list three relays and dropped the dead one.

## 6. nostr-auth-middleware (HumanjavaEnterprises), checked 2026-10-01

[nostr-auth-middleware](https://github.com/HumanjavaEnterprises/nostr-auth-middleware) is an Express router for Node (npm 0.6.0, MIT, last commit 2026-07-21, 5 stars, open issues are Dependabot only). [code]

- One flow: `GET /challenge/:pubkey` gives a random challenge (one live challenge per pubkey; a new request deletes the old one), the client signs a **kind 22242** event with tags `p` and `challenge`, and `POST /verify` checks the signature, the kind, `created_at` (−300 s to +60 s), and that the challenge exists for that pubkey, then deletes it. It returns an HS256 JWT in the JSON body; the docs put it in `localStorage`. No cookie, no NIP-98 for APIs, no NIP-05, no relay code in `src/`.
- NIP-46: a browser-side `Nip46AuthHandler` for `bunker://` only (the app supplies the relay transport). Each request is sent once with a 30 s timeout; no resend, no OK/CLOSED handling, no `auth_url`; replies it cannot decrypt are dropped silently. A `Nip46SignerMiddleware` makes the server a bunker over HTTP, the opposite role from ours. No `nostrconnect://`, no QR code.
- Weak points found by reading the code (not tested): no origin or URL binding and the NIP-42 AUTH kind is reused, so a hostile relay or a phishing page can get a client that auto-signs AUTH to produce a valid login event; anyone can cancel a victim's pending challenge; the Supabase single-use check is a select followed by a delete, not atomic; several documented routes and options do not exist in the code.
- Nothing in it bears on the phone/NIP-46 stall. Its NIP-46 client would time out on a rate-limited relay. Its silent drop of undecryptable replies is the blind spot that commit 3b16008 closed here.
- Worth copying: its end-to-end tests without mocks, with rejection cases. Ours already reject a wrong kind, a wrong URL and a replay; the challenge is consumed with one atomic `TryRemove`.
