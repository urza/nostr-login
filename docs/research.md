# Nostr as a login and identity layer for ASP.NET Core

Research date: 2026-09-29.

## 1. Summary

A Nostr identity is a secp256k1 key pair. The public key (hex, or `npub1...` in bech32) is the identity. The private key never leaves the user's signer. A web app can use this identity without being a Nostr client.

The login is a challenge and response:

1. The server makes a random, single-use challenge.
2. The user's signer signs a small Nostr event that contains the challenge and the site URL.
3. The server verifies the BIP-340 Schnorr signature and the event content.
4. The server stores the public key as the user's external login key and issues a normal session cookie.

After step 4, the app uses standard ASP.NET Core authentication. Nostr is not needed again until the next login.

The signature verification is simple and runs fully on the server. The hard part is the client side: how the user's signer receives the event and returns the signature. There are five practical signer channels (see section 4).

## 2. Relevant NIPs

| NIP | Title | Status | Use for web login |
|---|---|---|---|
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol | final | Event format, event id (SHA-256 of canonical JSON), Schnorr signature. |
| [05](https://github.com/nostr-protocol/nips/blob/master/05.md) | DNS identifiers | final | `name@domain` handle. Optional, for display and trust. |
| [07](https://github.com/nostr-protocol/nips/blob/master/07.md) | `window.nostr` | final | Browser extension signer. The main desktop channel. |
| [19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32 entities | final | `npub`, `nsec`, `nprofile` encodings. |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Relay AUTH | final | Kind `22242`. Designed for relays. Some sites reuse it for login. |
| [44](https://github.com/nostr-protocol/nips/blob/master/44.md) | Encrypted payloads v2 | final | Needed only for a server-side NIP-46 client. |
| [46](https://github.com/nostr-protocol/nips/blob/master/46.md) | Remote signing | final | Phone or cloud signer (bunker). Kind `24133`. |
| [49](https://github.com/nostr-protocol/nips/blob/master/49.md) | `ncryptsec` | final | Encrypted key backup. Not needed by the web app. |
| [55](https://github.com/nostr-protocol/nips/blob/master/55.md) | Android signer | final | `nostrsigner:` URL scheme with a callback URL. |
| [98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP Auth | final | Kind `27235`. Signed event in the `Authorization: Nostr <base64>` header. |

There is no final NIP for "log in to a website with Nostr". The discussion in [nips#154](https://github.com/nostr-protocol/nips/issues/154) is still open. Existing sites use one of these event kinds:

- **Kind 22242** (NIP-42 shape) with `relay` = site origin and `challenge` = server nonce. [Stacker News](https://stacker.news) uses this.
- **Kind 27235** (NIP-98 shape) with `u` = login URL and `method` = `POST`. Services that already speak NIP-98 use this.
- **Custom kinds**, for example kind `21236` in [signet-login](https://github.com/forgesworn/signet-login).

### Decision for the demos

The demos use **kind 27235 (NIP-98) plus a `challenge` tag**:

```json
{
  "kind": 27235,
  "created_at": 1790000000,
  "content": "",
  "tags": [
    ["u", "https://app.example.com/signin-nostr"],
    ["method", "POST"],
    ["challenge", "k3J9...random..."]
  ]
}
```

Reasons:

- NIP-98 is final and exists to authenticate HTTP requests. A login request is an HTTP request.
- The `u` tag binds the signature to one site. A signature made for site A does not work at site B. This does not stop a live phishing proxy (see section 8).
- The `challenge` tag makes the event single-use. Plain NIP-98 is replayable inside its 60-second window.
- The same verification code also protects APIs with plain NIP-98 (demo 3).

The demos accept kind 27235 only. Stacker News compatibility (kind 22242) would need a second tag rule (`relay` instead of `u` and `method`). It is a small change, but no demo needs it.

## 3. Server-side verification rules

The server MUST check all of these. Each check has a reason.

| Check | Reason |
|---|---|
| JSON parses, all fields exist, hex lengths are correct | Reject junk before crypto. |
| `id` = SHA-256 of `[0, pubkey, created_at, kind, tags, content]` | The signature covers the id, not the JSON. A wrong id means a forged body. |
| BIP-340 Schnorr signature is valid for `id` and `pubkey` | Proof of key control. |
| `kind` is the expected kind | A signed note (kind 1) must not work as a login. |
| `created_at` is within a small window (demo: 5 minutes back, 1 minute ahead) | Limits the value of a leaked event. |
| `u` equals the expected absolute URL | Site binding. A signature made for another site fails. |
| `method` equals `POST` | Follows NIP-98. |
| `challenge` was issued by this server, is not expired, and is consumed now | Single use. Blocks replay. The server must not accept a challenge that the browser chose. |

The server uses the event's `pubkey` as the identity. It MUST NOT trust a pubkey that the browser sends in a separate field.

Behind a reverse proxy, the "expected URL" must use the public scheme and host. Use `ForwardedHeaders` middleware, or configure a fixed public origin.

## 4. Client-side signer channels

| Channel | Where it works | Web app work | Demo |
|---|---|---|---|
| NIP-07 extension | Desktop browsers with an extension (Alby, nos2x, Flamingo, Keys.band, nostr-keyx and others) | ~20 lines of JS: `window.nostr.signEvent(evt)` | 1, 2, 4 |
| NIP-46 in the browser | Any browser. Signer is a phone app (Amber) or a web/cloud signer (nsec.app, nsecBunker, Keycast) | Use a JS library ([nostr-login](https://github.com/nostrband/nostr-login), [nostr-tools](https://github.com/nbd-wtf/nostr-tools) `BunkerSigner`). The library exposes the same `window.nostr`. | Research only |
| NIP-46 on the server | Any browser, even with no JS crypto. Signer is Amber, nsec.app and similar | The server is the NIP-46 client. It shows a `nostrconnect://` QR code, waits on a relay, and asks the signer to sign the challenge. Needs NIP-44 and a relay client in .NET. | 1, 2, 4 |
| NIP-55 Android signer | Mobile browser on Android with Amber | Link `nostrsigner:<event>?type=sign_event&callbackUrl=...`. The signer opens the callback URL with the result. | Research only |
| Manual paste | Any signer that can sign arbitrary JSON (for example `nak event`) | A text box for a signed event | 1, 2, 4 |

The demos use the server-side NIP-46 channel. It needs no third-party JavaScript on the login page (no CDN script with access to the page), and Amber supports NIP-46 too, so it also covers Android. NIP-55 needs a callback URL design and a real Android device to test, so it stays research only.

Notes:

- The NIP-46 browser channel and the NIP-46 server channel produce the same result. The browser channel needs JS libraries on the page. The server channel needs a long-lived relay connection on the server, and one pending session per login attempt.
- A NIP-46 `connect` response alone does not prove the user's key. The remote-signer key can differ from the user key. The login must use `sign_event` on the challenge, and the server must verify the returned event like any other proof.
- Kind `27235` events are ephemeral (20000-29999 range). A signer does not publish them to relays.

## 5. Linking a Nostr key to an app account

The Nostr key maps well to the ASP.NET Core Identity "external login" model:

| Identity column | Value |
|---|---|
| `AspNetUserLogins.LoginProvider` | `Nostr` |
| `AspNetUserLogins.ProviderKey` | 64-char lowercase hex pubkey |
| `AspNetUserLogins.ProviderDisplayName` | `Nostr` |

With this model the app gets these flows for free:

- **Sign up with Nostr.** No password and no email. The account has only the external login.
- **Sign in with Nostr.** `SignInManager.ExternalLoginSignInAsync("Nostr", pubkey, ...)`.
- **Link Nostr to an existing account.** A signed-in user proves a key. The app calls `UserManager.AddLoginAsync`.
- **Unlink.** `UserManager.RemoveLoginAsync`, only if the user keeps another way to sign in.

Store the hex key, not the `npub`. The hex form is canonical. Show `npub` in the UI.

### Profile data

The app can read the user's kind-0 metadata (name, picture, NIP-05) from public relays. This data is signed but can change at any time. Use it only as display data. Never use a name or NIP-05 handle as the account key.

NIP-05 (`name@domain`) maps a handle to a pubkey through `https://domain/.well-known/nostr.json?name=name`. The server can check it at login. A verified NIP-05 handle is useful to show, and for organisations that want to allow only keys under their own domain.

## 6. Architecture options for .NET apps

### Option A: Nostr login in each app

Each app has the challenge endpoint, the JS, and the verifier. It is simple for one app. Demos 1 and 2 use this option. In the demos all of it sits behind one call, `AddAuthentication().AddNostr()`, which registers a normal ASP.NET Core remote authentication scheme (like `AddGoogle()`).

### Option B: NIP-98 on APIs

An API accepts `Authorization: Nostr <base64 event>` on every request. This fits API clients that hold a signer (bots, CLIs, Nostr-native SPAs). Every request needs a new signature, so it is not practical for a normal browser session. Demo 3 uses this option with a custom `AuthenticationHandler`.

### Option C: Nostr identity provider behind OpenID Connect

One small service handles the Nostr login and acts as an OpenID Connect provider. The `sub` claim is the hex pubkey. Every other app uses the standard `AddOpenIdConnect()` handler and knows nothing about Nostr. This is the best fit for organisations with many .NET apps, and for off-the-shelf software that supports OIDC. Demo 4 uses this option with [OpenIddict](https://documentation.openiddict.com/).

No public, maintained Nostr-to-OIDC bridge was found in this research.

## 7. .NET building blocks

| Need | Package | Notes |
|---|---|---|
| BIP-340 Schnorr verify, ECDH | [NBitcoin.Secp256k1](https://www.nuget.org/packages/NBitcoin.Secp256k1) 4.x | Pure C#, maintained by the BTCPay/NBitcoin team. |
| ChaCha20 (NIP-44) | [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) 2.x | .NET has only ChaCha20-Poly1305. NIP-44 needs raw ChaCha20. |
| HKDF, SHA-256, HMAC | `System.Security.Cryptography` | Built in. |
| Relay WebSocket | `System.Net.WebSockets.ClientWebSocket` | Built in. |
| Full Nostr clients | [NNostr.Client](https://www.nuget.org/packages/NNostr.Client) 0.0.55, [Nostr.Client](https://www.nuget.org/packages/Nostr.Client) 2.1.0 | Useful for a full Nostr app. Too much for a login. |
| OIDC provider | [OpenIddict](https://www.nuget.org/packages/OpenIddict.AspNetCore) | Demo 4. |

The demos use a small shared library (`src/NostrAuth`) with only the code a login needs. The library is short enough to read and audit.

## 8. Security notes

- **Key loss.** There is no password reset for a lost Nostr key. An app that allows Nostr-only accounts must accept this, or offer a second login (email, passkey) and account recovery.
- **Key theft.** A stolen `nsec` gives full access. The app cannot rotate the key for the user. A link to a second login method helps here too.
- **Phishing.** The login is not phishing-resistant in the way passkeys are.
  - What it stops: stolen passwords and keys (the site never sees the private key), replay of a signed event, and reuse of a signature made for another site.
  - What it does not stop: a live phishing proxy. A fake site can fetch a fresh challenge from the real site and ask the user's signer to sign an event with the **real** site's URL. Then it sends that event to the real site and gets a session.
  - Why: NIP-07 does not require the extension to compare the `u` tag with the page's origin. A NIP-46 signer does not know the page at all, and the app name in a `nostrconnect://` URI is chosen by whoever makes the QR code.
  - With passkeys (WebAuthn), the browser puts the real origin into the signature, so this attack fails. No Nostr signer channel has this today.
  - Defence today: the user must read the prompt. Extensions show the site that asks, and the `u` tag shows the site the event is for. The login page says: "Only sign it if this address is in your browser's address bar."
  - The attacker gets one session, not the key, and cannot log in again later without a new phish. This is about the level of password + one-time code.
  - A fix would need signers to check `u` against the requesting origin (possible for extensions, not for NIP-46).
  - Do not offer `nsec` paste as a login method in production. A fake site can steal a pasted key.
- **Blind signing.** Some signers show a raw JSON event. Keep the login event small and readable. The `u` tag shows the user which site asks.
- **Challenge storage.** Use a store that all app instances share (distributed cache) when the app runs on more than one node. The demos use `IMemoryCache`.
- **Session.** After login, use normal cookie security (Secure, HttpOnly, SameSite, anti-forgery on forms). The Nostr proof does not replace these.
- **Server-side NIP-46 costs.** Each Nostr Connect login holds WebSocket connections to relays for up to 5 minutes, and anyone can open a login page. The demo library allows one session per login page and caps active sessions (default 100 per instance).
- **Outbound connections.** Profile lookup and NIP-46 make the server connect to public relays. The relays see the server's IP address and the pubkeys it asks about. Use your own relay if that matters, or turn the features off.
- **Privacy.** The pubkey is a public, global identifier. Two apps that see the same pubkey can correlate the user. Users who care can use a separate key per site.

## 9. Findings from the implementation

These came up while building and testing the demos (2026-09-29).

1. **Event id serialization differs between libraries at the edges.** NIP-01 lists seven escapes and says "all other characters verbatim". nostr-tools (2.25.2) uses `JSON.stringify`, which also escapes other control characters (U+0000 to U+001F) as `\u00XX`. nak (v0.20.7, go-nostr) escapes backspace and form feed as `\u0008` and `\u000c` instead of `\b` and `\f`. So a few rare events have ids that one library accepts and another rejects. The login event has empty content and URL tags, so login is not affected. The demo verifier follows the NIP-01 text.
2. **A NIP-98 replay cache must use the signature, not the event id.** Two honest requests to the same URL in the same second have the same id (same pubkey, time, tags, content). BIP-340 signers add fresh randomness, so the signatures differ. A replayed header is byte-identical.
3. **The NIP-98 payload check must read the body even without length headers.** An HTTP/2 request can carry a body with neither `Content-Length` nor `Transfer-Encoding`. The first version skipped the body in that case, so a swapped body passed. A test now covers this.
4. **A NIP-46 `connect` reply proves nothing about the user.** The remote-signer key can differ from the user key. Only the signed challenge event counts. The `secret` in the `nostrconnect://` URI must be checked, or anyone who watches the relay can answer first. After `connect`, the service asks `get_public_key` and requires the signed login event to come from that key. New Amber uses a separate signer key per connection, so this check catches a signer that signs with the wrong key.
5. **ASP.NET Core Identity UI needs one page override.** The built-in "external login, new account" page requires an email. A Nostr key has no email, so Demo 2 overrides `Account/ExternalLogin` to make the email optional and to use the `npub` as the user name. Linking, unlinking and "this key belongs to another account" work with no changes.
6. **Browsers share cookies across ports.** All demos run on `localhost`, so two apps with the default cookie name overwrite each other's session. Each demo sets its own cookie name. This is a demo issue only, not a production issue.
7. **Primal answered only on the first relay of the QR code.** In three tries with Primal for iPhone, the login worked only when the first relay in the `nostrconnect://` URI was one that the server could reach. The server now connects to the relays first and puts only the reachable ones into the URI.
8. **A relay can accept NIP-46 events and still not deliver them.** On 2026-09-30, `relay.damus.io` answered "OK" to kind-24133 events but never sent them to a live subscriber (three tries). `nos.lol`, `relay.primal.net`, `nostr.mom` and `offchain.pub` delivered them. A working WebSocket connection proves nothing: test a relay with a publish on one connection and a subscription on another. Users of the guestbook could not log in with Amber while damus was the first relay in the QR code.
9. **Remote-authentication defaults do not fit a same-site flow.** ASP.NET Core sets `SameSite=None; Secure` on correlation cookies because OAuth callbacks come from another site. The Nostr login POST comes from the app's own page, so the handler uses `SameSite=Lax`. This also makes plain-http development work.
10. **The login form must post to a relative path.** The first version set the form action to the same absolute URL as the `u` tag. Behind a TLS proxy without forwarded headers the server sees `http`, so an https page posted to `http://`. Chrome then warns "the information you're about to submit is not secure" and stops at a "Send anyway" page. Whether the login works after that depends on the proxy: a 301 to https turns the POST into a GET without state; a plain http POST loses the `SameSite=Lax` correlation cookie, because Chrome treats `http://host` and `https://host` as different sites (Schemeful Same-Site); only a 307/308 to https keeps the POST intact. So the same deployment worked for one tester and failed for others. The form now posts to a relative path, the Docker image turns forwarded headers on, and the login page shows a notice when the address in the browser differs from the address the app knows.
11. **A NIP-46 request must be sent more than once.** Kind 24133 is ephemeral: a relay delivers it to the subscriptions open at that moment and then forgets it. Amber (checked in its source on 2026-10-01) answers `connect`, and only then creates the subscription for requests, with `since` set to the phone's clock. The server sent `get_public_key` once, within milliseconds of the connect reply and with its own clock. Amber's activity log showed "Connect" and nothing after it, while the page said "Connected". Now a request without a reply goes out again every 3 seconds as a fresh event (`get_public_key`, which the signer answers without a prompt), and every request goes out again, as the same event, to each relay that (re)connects. `sign_event` gets no fresh copies: a second prompt would confuse the user. The service also reads `OK` and `CLOSED` messages now; a relay that refuses an event or a subscription was invisible before, and it is shown with the timeout error. The default relays changed to the relays that signer apps use for NIP-46 (relay.primal.net, relay.nsec.app, theforest.nostr1.com, nostr.oxtr.dev, nostr.cypherpunk.today). On 2026-10-01 all of them except relay.nsec.app (not reachable from the test network) accepted and delivered kind 24133 from a fresh key within 0.4 to 1.6 s; so did nos.lol, nostr.mom and offchain.pub.
12. **Copies need a backoff, and the signer's clock is in its connect reply.** The first resend version sent a copy every 3 s for the whole session. The production log then showed nostr.oxtr.dev answering "rate limited" to every event of a later session, while the other relays accepted them (the server's IP had sent about a hundred copies per stuck session). Copies now go out every 3 s five times, then every 15 s. On an older phone the login still stopped at "Connected": the server had no line in the log for it, because the connect reply, the copies and the timeout were logged at debug level. Those lines are at information level now, with the relay that delivered each reply and the signer's clock offset. The offset comes from `created_at` of the connect reply; requests are dated one second past it, so a phone minutes ahead gets the request at once instead of after the server's clock passes its `since`. A relay that did not answer is skipped for a minute, so one dead relay (relay.nsec.app at the time) does not delay every QR code by the connect timeout.
13. **On one phone, the signer app may be gone the moment the user switches back.** The users with the stall logged in on the phone with "Open signer app on this device", not with the QR code. Two explanations fit, and the data so far (the page text "Connected", no server log lines) does not separate them. (a) The signer app answers `connect` and `get_public_key` while it is in front; the user switches back to the browser; the app loses its relay connection; `sign_event`, sent once after the `get_public_key` reply, reaches nobody. (b) The signer listens for requests on a relay that the server cannot reach: nsec.app reads only the pubkey and the secret from the `nostrconnect://` URI and talks through relay.nsec.app alone, and an older Amber may use its own saved relays; its connect reply can still reach the server through a shared relay. relay.nsec.app accepts TCP from the test network and from the user's server, then ends the TLS handshake with an EOF, so the server never connects to it. Against (a) and (b) both, `sign_event` is now sent again too, as fresh copies every 10 s, and the login page shows which request waits, how often it went out, and which relays accepted it, so the next report settles it.
14. **Dedicated NIP-46 relays keep the request for a late signer.** Checked 2026-10-01 with a publish before any subscription: relay.nip46.com (keeps kinds 24133 and 24135 for 10 minutes, refuses `created_at` outside ±60 s and says so in the OK), bucket.coracle.social (30 s) and nrs.primal.net (strfry with an ephemeral-event lifetime) all handed the earlier event to a subscriber that came 3 s later. General relays do not. The defaults are now relay.primal.net, nrs.primal.net, relay.nip46.com and bucket.coracle.social; the three last ones are Amber's own defaults. relay.nsec.app is out: it accepts TCP and then ends the TLS handshake from servers (nostrautica dropped it in July 2026 for "HTTP 502 on every probe"), so a server cannot serve nsec.app users through it anyway. Two more changes from the comparison with other clients: the REQ is on every relay before `StartAsync` returns the QR code, and each copy of `get_public_key` carries a fresh request id, because Amber drops a request id it already holds. This is safe with signers that ignore a request id they already have: Amber (`BunkerRequestUtils.addRequest`) and nsec.app (`allowPermitCallback`: "same reqs usually come on reconnects") do. A signer without that check shows one prompt per copy; that is why the copies of `sign_event` are slower than those of `get_public_key`. nsec.app (noauth) reads only the pubkey and the secret from a `nostrconnect://` URI and ignores its relays: it talks through its own NIP-46 relays. A server that cannot reach those relays cannot log in nsec.app users.

## 10. Signers on iPhone (checked 2026-09-30)

Amber is Android only. iOS limits apps in the background, so an iOS signer must find a way to receive NIP-46 requests while it is not on screen.

| Signer | Type | Channel for web login | Status | Background method |
|---|---|---|---|---|
| [Clave](https://apps.apple.com/us/app/clave-nostr-signer/id6762104155) | Native app, MIT | NIP-46 (`nostrconnect://`, Universal Link `https://clave.casa/connect/?uri=...`) | App Store, free, iOS 17.6+ | APNs push wakes a Notification Service Extension. Signs while closed. |
| [Primal](https://primal.net) | Nostr client with "Remote Login" | NIP-46 | App Store. **Tested 2026-09-30 with Demo 1: login works** (NIP-44, correct secret, signs kind 27235). | Plays background audio to stay alive (can be muted). |
| [nsec.app](https://nsec.app) | Web app (PWA) | NIP-46 | Works in Safari | Web push. Needs "Add to Home Screen" and iOS 16.4+. |
| [Nostash](https://apps.apple.com/us/app/nostash/id6744309333) | Safari extension, fork of Nostore | NIP-07 (`window.nostr` in Safari) | App Store, iPhone, iPad, Mac | Not needed: runs inside Safari. |
| [NostrKey](https://apps.apple.com/us/app/nostrkey-web-extension/id6759624317) | Safari extension, fork of Nostore | NIP-07 | App Store | Not needed. |
| [Aegis](https://github.com/ZharlieW/Aegis) | Cross-platform app, LGPL | NIP-46 (`bunker://`, iOS URL scheme), NIP-07 in its own browser | TestFlight only | Not documented. |
| [Signeur](https://github.com/guaka/signeur) | Native iOS/macOS, AGPL | NIP-46 (QR scan) | Build from source, 0.1 | Not documented. |
| [Nostore](https://github.com/ursuscamp/nostore) | Safari extension | NIP-07 | No longer maintained | - |

What this means for the demos:

- **Safari extension users** (Nostash, NostrKey) get the "Browser extension" button on iPhone with no change.
- **Server-side NIP-46 suits iOS.** When the user switches from Safari to the signer app, iOS can suspend Safari. A browser-side NIP-46 client then loses its relay connection ([a Clave integration PR](https://github.com/btcforplebs/nostr-vault/pull/90) describes this problem). In the demos the server holds the NIP-46 session, so nothing breaks while Safari waits in the background. The page continues to poll when the user comes back.
- **Same-phone login needs a deep link.** On one iPhone the user cannot scan a QR code on the same screen. The "Open signer app" link uses `nostrconnect://`, which any installed app can claim. Clave also accepts a Universal Link (`https://clave.casa/connect/?uri=<nostrconnect URI>`), which opens Clave or its install page. The demos do not offer this link yet.
- **To check with a real device:** one App Store review of Clave says it cannot handle "HTTP Auth" requests. If Clave refuses to sign kind 27235, the demo login fails with Clave. This is not confirmed.

## 11. Existing solutions (checked 2026-10-01)

[existing-solutions.md](existing-solutions.md) has the full report: the other .NET implementations (btcpay-nostr-login is the only other server-side NIP-46 login in .NET), what the JavaScript NIP-46 clients do about resends, relays and phones, what Amber, nsec.app and Primal do on their side, and a comparison with [nostrautica](https://github.com/jooray/nostrautica). The points that changed this project:

- Dedicated NIP-46 relays hold kind 24133 for a short time and send it to a subscriber that comes late: relay.nip46.com (10 minutes, created_at within ±60 s) and bucket.coracle.social (about 30 s). nrs.primal.net is Primal's own NIP-46 relay. All three are Amber's defaults.
- Older Amber had a 30 s timer that could make it miss `get_public_key` after its connect reply; current Amber subscribes before it replies.
- Amber drops a request whose id it already holds. Copies of `get_public_key` therefore carry a fresh id each (nostrautica resends under a new id after a `ping`); copies of `sign_event` keep their id, or the user would see a second prompt.
- blink-terminal moved its NIP-46 client from the browser to the server for the same phone problem, and shows the QR code only after the relay has the REQ. The REQ is now sent before `StartAsync` returns.
- Android has a relay-free path, NIP-55 `nostrsigner:` links with a callback URL, which Amber and Primal register. Not built yet.

## 12. Sources

- NIPs repository: <https://github.com/nostr-protocol/nips>
- "Login with Nostr" discussion: <https://github.com/nostr-protocol/nips/issues/154>
- Stacker News Nostr login: <https://www.nobsbitcoin.com/stacker-news-update-nostr-login/>
- nostr-login library: <https://github.com/nostrband/nostr-login>
- nostr-tools: <https://github.com/nbd-wtf/nostr-tools>
- signet-login: <https://github.com/forgesworn/signet-login>
- NIP-98 site: <https://nip98.com/>
- NNostr: <https://github.com/Kukks/NNostr>
- nak CLI (used for tests): <https://github.com/fiatjaf/nak>
