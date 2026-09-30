---
name: nostr-amber-auth
description: Implement NIP-46 Nostr authentication with Amber (Android remote signer) via QR code. Covers server-side and browser flows, multi-relay subscriptions, NIP-44, event verification, exact-secret validation, auth challenges, persistence, reconnection, and frontend polling. Use when adding Nostr login to a server-side app (Rails examples included) or a browser/PWA client.
---

# NIP-46 Nostr Authentication with Amber

Implement login via Amber (Android Nostr signer) using the NIP-46 remote signing protocol. The user scans a QR code containing a `nostrconnect://` URI, approves in Amber, and the app detects the response through an already-active relay subscription. The server-side walkthrough uses Rails; browser/PWA clients use the same protocol checks but keep the subscription directly.

## Critical: `event.pubkey` is NOT the user's npub

Newer versions of Amber (and other NIP-46 signers) generate a dedicated per-connection remote-signer keypair. The `event.pubkey` on kind-24133 frames is therefore a routing identity, not the user's Nostr identity. Treating it as the user's npub silently logs the user in under an ephemeral key. Per the NIP-46 spec, clients must differentiate between remote-signer-pubkey and user-pubkey, and must call `get_public_key` after the connect response to learn the real user pubkey.

### Terminology

- **client-key** — the app's ephemeral keypair, embedded in `nostrconnect://`. Used to encrypt and Schnorr-sign every outgoing NIP-46 envelope.
- **remote-signer-pubkey** — the `event.pubkey` on kind-24133 events sent by the signer. The NIP-46 transport/routing identity. In old Amber this happened to equal the user pubkey; in new Amber it is a per-connection key with no standalone meaning.
- **user-pubkey** — the real Nostr identity of the logged-in user. Only learned via an explicit `get_public_key` NIP-46 request. This is what goes into `users.pubkey_hex` / `accounts.pubkey_hex`, is displayed as npub, and is used for profile lookups and ownership checks.

Always call `get_public_key`. Old signers simply return their own pubkey (which happens to equal `event.pubkey`); new signers return the true user pubkey. No version detection is needed.

## Critical: Kind 24133 is EPHEMERAL

**Kind 24133 falls in the Nostr ephemeral event range (20000-29999).** Under NIP-01 these events are not expected to be stored, so interoperable clients must not rely on later replay even if a particular relay happens to retain one. This drives the architecture:

- Poll-based relay checks cannot reliably recover missed responses
- A server-side implementation should hold an active WebSocket subscription in a background worker; a browser implementation holds it in the client while the page is running
- The poll endpoint should **only check the DB** — no relay fallback needed
- The subscription must stay open through **both** handshake phases — the `get_public_key` response is itself kind 24133 and will be dropped if the subscription is torn down after the connect response

## Critical: Ruby 4.0 / OpenSSL 3 break SMALL non-blocking SSL reads

**This one silently kills every relay connection and is invisible in normal logs.** If you implement the WebSocket client yourself with raw sockets + `read_nonblock(exception: false)` (rather than a WS gem), be aware: on **Ruby 4.0 + OpenSSL 3**, a *small* non-blocking read on a TLS socket — `ssl_socket.read_nonblock(1, exception: false)` or `read_nonblock(2, ...)` — can return `:wait_readable` (or a bare `""` empty string) **forever, even when a full TLS record is decrypted and ready**. Large reads (e.g. 64 KB) return the data correctly. The same code works on Ruby 3.x, so a Ruby upgrade turns login (and signing, publishing, profile/relay fetching — anything reading a relay) into 100 % failures with only a generic "connection failed / timed out" symptom.

Two places bite:
- The **HTTP-101 upgrade** is commonly read one byte at a time to stop exactly at `\r\n\r\n`.
- The **WebSocket frame reader** reads the 2-byte frame header, then the length, then the payload.

Both issue tiny reads → both hang to their deadline → `open` returns nil → no relay ever connects.

**Fix: never issue small socket reads. Use a per-socket buffered reader that always reads a big chunk and hands out exact slices.**

```ruby
READ_CHUNK = 64 * 1024

def read_buffer(sock) = sock.instance_variable_get(:@__rbuf) || sock.instance_variable_set(:@__rbuf, +"".b)

# Tolerate every would-block shape Ruby 4.0 surfaces: :wait_readable, :wait_writable, and "".
def fill_buffer(sock, deadline)
  loop do
    chunk = sock.read_nonblock(READ_CHUNK, exception: false)
    case chunk
    when String then chunk.empty? ? wait_io(sock, :wait_readable, deadline) : (return read_buffer(sock) << chunk)
    when :wait_readable, :wait_writable then wait_io(sock, chunk, deadline)
    when nil then raise "closed"
    else wait_io(sock, :wait_readable, deadline)
    end
  end
end

def read_exact(sock, n, deadline)     # frame headers, lengths, payloads all go through this
  buf = read_buffer(sock)
  fill_buffer(sock, deadline) while buf.bytesize < n
  buf.slice!(0, n)
end

def read_until(sock, term, deadline, max) # HTTP-101 upgrade; trailing bytes stay buffered
  buf = read_buffer(sock)
  fill_buffer(sock, deadline) until (i = buf.index(term)) || buf.bytesize >= max
  buf.slice!(0, i + term.bytesize)
end
```

Also make `wait_io` for the TLS handshake wait on **both** read and write when it gets a bare `""` (a handshake can need either direction; waiting on read only will deadlock). And because one big read can buffer **several** frames, any read loop that gates on `IO.select([sock], …)` must also treat "buffer non-empty OR `sock.pending > 0`" as readable — otherwise buffered frames sit unseen until the next network packet. (Prefer a mature WebSocket library, which handles all of this, unless you specifically need the zero-dependency raw-socket approach shown throughout this skill.)

## Architecture Overview

```
1. User visits login page
   -> Rails generates session + nostrconnect:// URI with multiple relays
   -> Enqueues Nip46AuthJob on dedicated "auth" queue (never starved by other jobs)
   -> Renders QR code

2. Background job (Nip46AuthJob) on dedicated auth queue
   -> Nip46Listener connects to ALL auth relays simultaneously (one thread per relay)
   -> Each thread reconnects with exponential backoff if connection drops
   -> Maintains persistent WebSocket subscription for kind 24133
   -> Phase A (connect response):
        verify the NIP-01 event, decrypt (NIP-44; optional legacy inbound NIP-04 fallback),
        require result == exact secret,
        record remote-signer-pubkey = event.pubkey
   -> Phase B (identity lookup, same socket, same subscription):
         build one logical `get_public_key` request and publish the same signed
         event through the active relays,
        await the kind-24133 response, match by JSON-RPC id,
        validate result is 64-char hex
   -> Atomically persist BOTH remote-signer-pubkey and user-pubkey
   -> First relay to complete both phases wins; remaining threads are killed

3. Browser polls /auth/poll every 3s
   -> DB-only check for authenticated_user_pubkey (sub-millisecond)
   -> No relay connections from poll endpoint
   -> On success: redirect to callback
```

## Multi-Relay Support

**Never rely on a single relay.** Relays go down (e.g., relay.nsec.app was observed down during production debugging). Use multiple relays for redundancy.

### Configuration

```yaml
# config/myapp.yml
nostr:
  auth_relays:
    - wss://relay.nsec.app
    - wss://relay.damus.io
    - wss://relay.primal.net
```

```ruby
# AuthService
@auth_relays = config.dig(:nostr, :auth_relays) ||
               [config.dig(:nostr, :auth_relay)].compact.presence ||
               ["wss://relay.nsec.app"]
```

### nostrconnect:// URI with multiple relays

```ruby
relay_params = @auth_relays.map { |r| "relay=#{CGI.escape(r)}" }.join("&")
uri = "nostrconnect://#{pubkey_hex}?#{relay_params}&secret=#{secret}&name=#{CGI.escape(app_name)}"
```

### Database storage

The `relay_url` column stores a JSON array. If an already-shipped schema contains single strings, normalize those rows during migration or retain a narrow reader compatibility path:

```ruby
# Model
def relay_urls
  parsed = JSON.parse(relay_url)
  parsed.is_a?(Array) ? parsed : [parsed]
rescue JSON::ParserError
  [relay_url]
end
```

## Database: NostrAuthSession

```ruby
create_table :nostr_auth_sessions do |t|
  t.string :session_id, null: false, index: { unique: true }
  t.string :temp_pubkey, null: false          # client-key public (hex)
  t.string :temp_privkey, null: false         # client-key private (hex)
  t.string :secret                            # one-time nostrconnect secret; clear after validation
  t.string :relay_url, null: false            # JSON array of relay URLs
  t.string :authenticated_pubkey              # remote-signer-pubkey (routing identity)
  t.string :authenticated_user_pubkey         # user-pubkey from get_public_key (real npub)
  t.string :auth_url                          # current challenge for a known pending request
  t.datetime :expires_at, null: false         # session TTL (30 minutes)
  t.timestamps
end
```

Model scopes:

```ruby
encrypts :temp_privkey

scope :active, -> { where("expires_at > ?", Time.current) }

def authenticated?
  authenticated_pubkey.present? && authenticated_user_pubkey.present?
end
```

## Step 1: Generate nostrconnect:// URI

Generate an ephemeral keypair per login attempt. **Always generate a fresh session** — never reuse sessions across page loads.

```ruby
# AuthService
SESSION_EXPIRY = 30.minutes

def generate_connect_uri
  keypair = Nostr::Keygen.new.generate_key_pair
  secret = SecureRandom.hex(32)
  session_id = SecureRandom.uuid

  auth_session = NostrAuthSession.create!(
    session_id: session_id,
    temp_pubkey: keypair.public_key.to_s,
    temp_privkey: keypair.private_key.to_s,
    secret: secret,
    relay_url: @auth_relays.to_json,
    expires_at: SESSION_EXPIRY.from_now
  )

  relay_params = @auth_relays.map { |r| "relay=#{CGI.escape(r)}" }.join("&")
  perms = "sign_event:1,nip44_encrypt,nip44_decrypt"
  uri = "nostrconnect://#{keypair.public_key}?#{relay_params}&secret=#{secret}" \
        "&perms=#{CGI.escape(perms)}&url=#{CGI.escape('https://myapp.example')}" \
        "&name=#{CGI.escape('MyApp')}"
  { uri: uri, session_id: session_id, relay_urls: @auth_relays }
end
```

### Request minimum permissions for usable UX

`perms` is an optional, comma-separated request in the NIP-46 `method[:params]` format, such as `sign_event:1,nip44_encrypt,nip44_decrypt`. Request only the methods and event kinds the remote signer will actually perform. Do not request kinds signed locally, such as a NIP-59 outer gift wrap signed with a throwaway key.

Permissions improve consent UX and may reduce repeated prompts, but they are not an authorization guarantee. A signer may prompt again, deny a previously requested operation, apply stricter policy, or interpret unsupported permissions differently. The client must handle an error or `auth_url` challenge for every request and must never infer that an operation is authorized merely because it appeared in `perms`.

## Step 2: Dedicated Auth Queue

The `Nip46AuthJob` runs on a dedicated `auth` queue so it is never starved by long-running jobs (e.g., `SourceIngestionJob` blocking on relay timeouts).

### queue.yml

```yaml
default: &default
  dispatchers:
    - polling_interval: 5
      batch_size: 500
  workers:
    - queues: "auth"
      threads: 1
      processes: 1
      polling_interval: 1
    - queues: "*"
      threads: 2
      processes: 1
      polling_interval: 5
```

### Nip46AuthJob

```ruby
class Nip46AuthJob < ApplicationJob
  queue_as :auth

  def perform(session_id)
    auth_session = NostrAuthSession.active.find_by(session_id: session_id)
    return unless auth_session

    pubkey = Nostr::Nip46Listener.new(auth_session).listen_for_connect
    Rails.logger.info("NIP-46 auth job completed: #{pubkey ? 'authenticated' : 'timed out'}")
  end
end
```

## Step 3: Nip46Listener — Multi-Relay with Reconnection

Connects to ALL configured relays simultaneously using threads. Each thread reconnects with exponential backoff if the connection drops.

```ruby
class Nip46Listener
  POLL_INTERVAL = 1

  def initialize(auth_session)
    @auth_session = auth_session
    @relay_urls = auth_session.relay_urls
    @temp_pubkey = auth_session.temp_pubkey
    @client = Nip46Client.new(auth_session)
  end

  def listen_for_connect
    deadline = @auth_session.expires_at
    result = nil

    threads = @relay_urls.map do |relay_url|
      Thread.new { listen_on_relay(relay_url, deadline) }
    end

    # Collect thread values BEFORE checking termination — if all threads die
    # during the sleep, a leading termination check would exit the loop
    # without ever reading their return values (race: fast responses dropped).
    loop do
      threads.each do |t|
        next if t.alive?
        value = t.value rescue nil
        result = value if value
        break if result
      end
      break if result
      break if threads.all? { |t| !t.alive? }
      sleep 0.2
    end

    threads.each { |t| t.kill if t.alive? }
    result
  end

  private

  def listen_on_relay(relay_url, deadline)
    backoff = 1

    while Time.current < deadline
      if @auth_session.reload.authenticated?
        return @auth_session.authenticated_user_pubkey
      end

      socket = @client.create_websocket(URI.parse(relay_url))

      unless socket
        sleep [backoff, deadline - Time.current].min
        backoff = [backoff * 2, 15].min
        next
      end

      backoff = 1 # reset after successful connection

      sub_id = "nip46-#{SecureRandom.hex(4)}"
      req = ["REQ", sub_id, { "kinds" => [24133], "#p" => [@temp_pubkey] }]
      socket.write(@client.frame_text(req.to_json))

      # Two-phase handshake on the same socket. The subscription must live
      # through Phase B because the get_public_key response is ALSO kind 24133.
      result = run_handshake(socket, relay_url, deadline)
      close_socket(socket, sub_id)

      return result if result

      # Connection dropped before handshake completed — reconnect with backoff
      sleep [backoff, [deadline - Time.current, 0].max].min
      backoff = [backoff * 2, 15].min
    end

    nil
  end

  def run_handshake(socket, relay_url, deadline)
    signer_pubkey = await_connect_response(socket, deadline)
    return nil unless signer_pubkey

    user_pubkey = await_user_pubkey(socket, signer_pubkey, deadline)
    return nil unless user_pubkey

    @auth_session.update!(
      authenticated_pubkey: signer_pubkey,
      authenticated_user_pubkey: user_pubkey
    )
    user_pubkey
  end
end
```

## Listener Lifetime, Cancellation, and Connection Budget

The dedicated `auth` queue keeps unrelated jobs from starving login, but the auth queue can starve *itself*. Each `Nip46AuthJob` holds one queue worker thread for as long as its listener runs, and `listen_for_connect` spawns one more thread per relay. Every one of those threads that touches ActiveRecord — the `@auth_session.reload` in the reconnect loop — checks out a database connection and holds it for the thread's lifetime. So a single in-flight login can occupy `1 + relay_count` connections, and the whole flow draws from the same pool Puma serves web requests from.

Budget the pool and the concurrency together:

```
connections_per_login = 1 (worker thread) + relay_count (listener threads)
peak_auth_connections = auth_queue_concurrency * connections_per_login
```

With three auth relays and `AUTH_JOB_CONCURRENCY=4`, four simultaneous logins want `4 * 4 = 16` connections from a pool that defaults to `RAILS_MAX_THREADS` (often 10) and is shared with web threads. That exhausts the pool: logins block, `reload` and status writes time out, and unrelated web requests wait behind the checkout. Keep `auth_concurrency * (1 + relay_count)` comfortably below the primary pool size, or raise the pool — and confirm the database's own connection limit — before raising concurrency.

Two changes make higher concurrency safe:

- **Do not hold a connection per relay thread.** Wrap the periodic ActiveRecord access in `ActiveRecord::Base.connection_pool.with_connection { ... }` so a connection is checked out only for the query, not for the minutes the thread spends waiting on a socket. This decouples relay count from the pool.
- **Keep the listener deadline short.** The listener deadline is a human-approval window, not the session-row TTL. A listener whose `deadline` is `expires_at` (e.g. 30 minutes) pins its worker thread and its connections for the full 30 minutes even after the user has walked away. Give `listen_for_connect` a separate, short approval deadline (a couple of minutes, configurable) and let the DB row expire on its own longer schedule.

**Cancel abandoned listeners promptly.** When the same browser reopens the login page, the previous attempt's listener should stop within a poll tick rather than run to its deadline:

- In `new`, mark or delete the prior session for this browser (a `consume!` that sets `consumed_at`, or destroy the row).
- In every listener loop, reload and return as soon as the row is consumed, deleted, or expired — check for that explicitly. Do **not** rely on `reload` raising `RecordNotFound` to tear the thread down: an uncaught error can fault the job and, on retry, crash-loop against the now-missing row.

```ruby
# In listen_on_relay's loop, before reconnecting:
session = NostrAuthSession.find_by(id: @auth_session.id)
return nil if session.nil? || session.consumed_at? || session.expired?
return session.authenticated_user_pubkey if session.authenticated?
```

A lease guards against two jobs listening for one session at once: store a `listener_token` with a short lease, renew it from a heartbeat, and have the listener bail when renewal fails. This matters once `new` can be retried or the job can be re-enqueued.

**Admit only what you can service.** Cap the concurrent pending (unauthenticated, unexpired) sessions to the listener capacity and reject the excess with a clear "try again shortly" and a `Retry-After`, rather than enqueuing jobs that queue behind a busy worker. Exclude the caller's own in-flight session from the count so a reload is never rejected. Size the cap with the connection budget above, and keep the approval window short so an abandoned attempt frees its slot quickly instead of locking other users out until the row expires — with a cap of 1, one walked-away login blocks everyone else for the whole TTL.

## Scaling: one multiplexed listener for all logins

The one-job-per-login model above is simplest, but it does not scale: each pending login holds one WebSocket **and** one pooled DB connection **per relay** for the whole approval window. With a DB pool of ~10 shared with the web server, `concurrency × (1 + relay_count)` connection budget forces the admission cap down to **1** — and then a single abandoned login (or a second user) either blocks everyone with "temporarily at capacity", or its listener job queues behind the busy worker and **never subscribes to any relay**, so the QR sits on "Waiting for connection…" no matter how many relays you configured. This failure looks exactly like a relay problem but isn't.

The fix is a **single multiplexed supervisor** that serves *every* pending session at once:

- **One reader thread per distinct relay, shared across all logins** (not one socket per login). Each session gets its own kind-24133 subscription on every relay it listed (`REQ` with `"#p": [that session's temp pubkey]`), so incoming events route back to the right session by subscription id.
- **A registry thread** polls the DB for active, unauthenticated sessions and adds/removes them, so a new login is picked up within ~1s and completed/expired ones are dropped (and their subscriptions `CLOSE`d).
- **DB connections are checked out only for the brief poll/persist operations**, never held for the session lifetime. Connection use becomes **O(relays)** regardless of how many people log in, so the admission cap can be raised far above 1.
- Per-session handshake logic is unchanged (validate secret → pin one signer → every relay sends `get_public_key` → first reply on any relay wins → persist atomically). Only *where the sockets live* changes.
- Run it as a **singleton** (a cache/DB lock with a renewing heartbeat), enqueued whenever a login/pairing session is created, plus a per-minute recurring safety-net that restarts it if pending sessions exist but no supervisor is running (e.g. after a deploy). Give it a bounded max runtime so restarts recycle cleanly.

Keep the per-session job/listener as a fast rollback path while you roll the supervisor out.

## Step 4: NIP-44 Requests and Verified Incoming Events

NIP-46 specifies NIP-44 content for kind-24133 requests and responses. **Encrypt every outgoing request with NIP-44; never emit NIP-04 NIP-46 requests.** For incoming compatibility with known legacy signers, an implementation may try NIP-44 first and then NIP-04 as a decrypt-only fallback. If neither succeeds, reject the event.

Before any decryption, validate the complete outer event according to NIP-01: field types and bounds, canonical event-id serialization and hash, a valid non-zero BIP-340 pubkey, and the BIP-340 Schnorr signature. Also require kind `24133`, the expected `p` tag for this client, and, once learned, the pinned remote-signer pubkey. Use a vetted Nostr library rather than treating a hash comparison as complete NIP-01 validation.

### NIP-44 implementation guidance

Prefer a maintained NIP-44 v2 implementation and test it against the current official vectors linked from NIP-44. The following is **incomplete pseudocode**, not a production implementation: it omits strict base64 and payload bounds, full key validation, `hkdf_expand`, padding details, UTF-8 checks, resource limits, and error handling.

```ruby
module Nostr
  module Nip44
    PROTOCOL_VERSION = 2

    # Derive conversation key: ECDH + HKDF-Extract
    def self.conversation_key(privkey_hex, pubkey_hex)
      # secp256k1 ECDH to get shared x-coordinate
      group = ECDSA::Group::Secp256k1
      their_point = ECDSA::Format::PointOctetString.decode(
        ["02#{pubkey_hex}"].pack("H*"), group
      )
      shared_point = their_point.multiply_by_scalar(privkey_hex.to_i(16))
      shared_x = [shared_point.x.to_s(16).rjust(64, "0")].pack("H*")

      # HKDF-Extract: HMAC-SHA256(salt="nip44-v2", IKM=shared_x)
      OpenSSL::HMAC.digest("SHA256", "nip44-v2", shared_x)
    end

    # Decrypt: base64 decode, verify HMAC, ChaCha20, unpad
    def self.decrypt(conv_key, base64_payload)
      payload = Base64.decode64(base64_payload)
      version = payload.getbyte(0)
      raise "unsupported version" unless version == PROTOCOL_VERSION

      nonce = payload.byteslice(1, 32)
      mac = payload.byteslice(-32, 32)
      ciphertext = payload.byteslice(33, payload.bytesize - 65)

      # HKDF-Expand -> chacha_key(32) + chacha_nonce(12) + hmac_key(32)
      keys = hkdf_expand(conv_key, nonce, 76)
      chacha_key = keys.byteslice(0, 32)
      chacha_nonce = keys.byteslice(32, 12)
      hmac_key = keys.byteslice(44, 32)

      # Verify HMAC (constant-time)
      expected_mac = OpenSSL::HMAC.digest("SHA256", hmac_key, nonce + ciphertext)
      raise "HMAC failed" unless OpenSSL.fixed_length_secure_compare(mac, expected_mac)

      # ChaCha20 decrypt
      cipher = OpenSSL::Cipher.new("chacha20")
      cipher.decrypt
      cipher.key = chacha_key
      cipher.iv = "\x00\x00\x00\x00".b + chacha_nonce
      padded = cipher.update(ciphertext) + cipher.final

      unpad(padded)
    end
  end
end
```

### Two-phase handshake: connect response + `get_public_key`

Phase A verifies each kind-24133 frame before decrypting, accepts only a response whose `result` equals the **exact** one-time secret, and records the **remote-signer-pubkey** from that event. Do not accept `"ack"` and do not accept a request-shaped `{method: "connect"}` fallback in the client-initiated `nostrconnect://` flow. Phase B sends a NIP-44-encrypted `get_public_key` request and records the **user-pubkey** from the matching response. Only after both phases succeed is the session authenticated.

```ruby
# Phase A: drain events on the subscription until one decrypts and validates.
# Returns remote-signer-pubkey (hex) or nil.
def await_connect_response(socket, deadline)
  while Time.current < deadline
    if @auth_session.reload.authenticated?
      return @auth_session.authenticated_pubkey
    end

    event = read_signer_event(socket, deadline)
    return nil unless event

    decoded = @client.decrypt_signer_event(event)
    next unless decoded

    if @client.valid_connect_response?(decoded[:message])
      return decoded[:signer_pubkey]
    end
  end
  nil
end

# Phase B: send get_public_key, match the response by JSON-RPC id,
# validate 64-char hex. Returns user-pubkey or nil.
def await_user_pubkey(socket, signer_pubkey, deadline)
  request = @client.shared_request("initial-user-key", signer_pubkey, "get_public_key", [])
  socket.write(@client.frame_text(["EVENT", request[:event]].to_json))

  while Time.current < deadline
    event = read_signer_event(socket, deadline)
    return nil unless event
    next unless event["pubkey"] == signer_pubkey

    decoded = @client.decrypt_signer_event(event)
    next unless decoded
    message = decoded[:message]
    next unless message.is_a?(Hash) && message["id"] == request[:request_id]

    if message["result"] == "auth_url"
      @client.record_auth_url_for_pending_request(message, signer_pubkey)
      next
    end

    return nil if message["error"].present?

    user_pubkey = message["result"]
    return nil unless user_pubkey.is_a?(String) && user_pubkey.match?(/\A[0-9a-f]{64}\z/i)
    return user_pubkey.downcase
  end
  nil
end
```

The client-side helpers:

```ruby
# Decrypt + parse one signer-sent kind-24133 event.
# Returns { signer_pubkey:, message: } or nil.
def decrypt_signer_event(event_data)
  return nil unless valid_nip01_event?(event_data) # vetted library; verify before decrypt
  return nil unless event_data["kind"] == 24133
  return nil unless event_data["tags"].any? { |tag| tag[0] == "p" && tag[1] == @temp_pubkey }

  signer_pubkey = event_data["pubkey"]
  decrypted = try_decrypt_nip44(event_data["content"], signer_pubkey)
  decrypted ||= decrypt_nip04(event_data["content"], signer_pubkey)
  return nil unless decrypted

  { signer_pubkey: signer_pubkey, message: JSON.parse(decrypted) }
rescue JSON::ParserError
  nil
end

def valid_connect_response?(message)
  message.is_a?(Hash) && message["result"] == @secret
end
```

### NIP-04 Decryption (Legacy Inbound Fallback)

Format: `<base64_ciphertext>?iv=<base64_iv>`. This is incomplete compatibility pseudocode; use a vetted implementation with strict input validation if support for a known legacy signer is actually required.

```ruby
def decrypt_nip04(encrypted_content, sender_pubkey)
  parts = encrypted_content.split("?iv=")
  return nil unless parts.length == 2

  ciphertext = Base64.decode64(parts[0])
  iv = Base64.decode64(parts[1])
  shared_secret = compute_shared_secret(sender_pubkey)

  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.decrypt
  cipher.iv = iv
  cipher.key = shared_secret
  (+cipher.update(ciphertext) + cipher.final).force_encoding("UTF-8")
rescue OpenSSL::Cipher::CipherError
  nil
end
```

### Sending NIP-46 requests (`get_public_key`, `sign_event`, ...)

A NIP-46 request is a NIP-44-encrypted, Schnorr-signed kind-24133 event addressed to the remote signer via a `p` tag. Reuse this helper for any request. The random `request_id` lets the listener match the response frame.

```ruby
def build_request_event(signer_pubkey, method, params = [])
  request_id = SecureRandom.hex(16)
  payload = { "id" => request_id, "method" => method, "params" => params }
  encrypted = encrypt_nip44(JSON.generate(payload), signer_pubkey)
  event = build_and_sign_event(encrypted, signer_pubkey)
  { event: event, request_id: request_id }
end

# Build once per logical operation and key by every value that defines it.
# Initialize @request_mutex and @shared_requests in the client constructor.
def shared_request(operation_id, signer_pubkey, method, params = [])
  key = [operation_id, signer_pubkey, method, JSON.generate(params)]
  @request_mutex.synchronize do
    @shared_requests[key] ||= build_request_event(signer_pubkey, method, params)
  end
end
```

Publish that same signed event to each selected relay. This is one logical request with one event ID and one request ID, not one request per relay. Relays or signers may suppress duplicates, but NIP-01 and NIP-46 provide no end-to-end deduplication guarantee. The client must tolerate duplicate responses and a signer must treat repeated delivery of an identical event/request ID idempotently where possible. Never cache only by method: concurrent calls with different signer keys or params would alias and could route a request to the wrong signer.

```ruby
def build_and_sign_event(content, recipient_pubkey)
  event = {
    "pubkey" => @temp_pubkey,
    "created_at" => Time.now.to_i,
    "kind" => 24133,
    "tags" => [["p", recipient_pubkey]],
    "content" => content
  }

  serialized = [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]
  event["id"] = Digest::SHA256.hexdigest(JSON.generate(serialized))

  require "schnorr"
  signature = Schnorr.sign([event["id"]].pack("H*"), [@temp_privkey].pack("H*"))
  event["sig"] = signature.encode.unpack1("H*")
  event
end
```

## Handling `auth_url` Challenges

A remote signer may answer an already-pending request with an interim challenge:

```json
{ "id": "<same request id>", "result": "auth_url", "error": "https://signer.example/confirm/..." }
```

Accept an `auth_url` only when all of these hold: the outer NIP-01 event is valid, its author equals the already-pinned remote-signer pubkey, its `p` tag targets this client, decryption succeeds, and its response ID matches a known pending request. Never accept or surface an `auth_url` during Phase A of a `nostrconnect://` flow because no signer is pinned yet and the connect response is not a response to a client-created pending request.

Validate an allowed `https` URL according to the application's navigation policy, show it as a user-activated link, and keep the original request pending under the same ID. A later response with that same ID is the actual answer. Do not resend merely because a challenge arrived, and handle repeated challenge events idempotently. A polling callback generally cannot reliably open a popup because it lacks a user gesture.

## Step 5: Controller — Login Page + DB-Only Poll

### Login page (new action)

Always generate a fresh session. Never reuse sessions.

```ruby
def new
  @connect_data = Nostr::AuthService.new.generate_connect_uri
  session[:nostr_connect_session_id] = @connect_data[:session_id]

  Nip46AuthJob.perform_later(@connect_data[:session_id])

  @qr_code = RQRCode::QRCode.new(@connect_data[:uri])
end
```

### Poll endpoint (DB-only)

No relay fallback: kind 24133 is ephemeral and storage/replay cannot be assumed. The background job handles the active WebSocket subscription. Poll just checks the DB.

```ruby
def poll
  session_id = session[:nostr_connect_session_id]
  return render json: { authenticated: false, error: "No pending session" } if session_id.blank?

  result = Nostr::AuthService.new.check_session(session_id)
  if result&.dig(:authenticated)
    # result[:pubkey] is the USER pubkey (authenticated_user_pubkey), not the signer pubkey
    return render json: { authenticated: true, redirect_url: callback_path }
  end

  render json: { authenticated: false }
end
```

`AuthService#check_session` must return `authenticated_user_pubkey`, not `authenticated_pubkey`:

```ruby
def check_session(session_id)
  auth_session = NostrAuthSession.active.find_by(session_id: session_id)
  return nil unless auth_session
  if auth_session.authenticated?
    { authenticated: true, pubkey: auth_session.authenticated_user_pubkey }
  else
    { authenticated: false }
  end
end
```

## Step 6: Frontend Polling (JavaScript/Stimulus)

Poll every 3 seconds. The background job handles the real-time subscription; polling just checks DB.

```javascript
startPolling() {
  this.pollInterval = setInterval(async () => {
    try {
      const response = await fetch(this.pollUrl)
      const data = await response.json()
      if (data.authenticated) {
        clearInterval(this.pollInterval)
        window.location.href = data.redirect_url
      }
    } catch (error) {
      console.error("Polling error:", error)
    }
  }, 3000)
}
```

## Step 7: Callback - Create User

Use the **user-pubkey** (the one returned by `get_public_key`) for identity — that's what goes into `users.pubkey_hex`, is shown as npub, and is used for profile fetches and ownership checks. If the app also maintains per-account signer connections (e.g. a pairing flow that later issues `sign_event` requests), store the **remote-signer-pubkey** separately as the routing address.

The callback must derive identity from server-side authenticated state bound to the browser's session. Never take a pubkey, auth method, or auth-session ID from callback query parameters as proof of identity. Query parameters are attacker-controlled.

```ruby
def callback
  auth_session = NostrAuthSession.active.find_by!(
    session_id: session.delete(:nostr_connect_session_id)
  )
  return head :unauthorized unless auth_session.authenticated?

  user = AuthService.new.find_or_create_user(auth_session.authenticated_user_pubkey)
  reset_session
  session[:user_id] = user.id
  redirect_to root_path
end
```

If you're pairing an account the logged-in user already owns, the newly learned user-pubkey MUST match the one on file. A mismatch means the signer returned a different identity than the one originally paired — reject rather than silently rewrite:

```ruby
if auth_session.authenticated_user_pubkey != account.pubkey_hex
  redirect_to accounts_path, alert: "Signer returned a different Nostr identity" and return
end
account.update!(signer_pubkey: auth_session.authenticated_pubkey)  # routing key only
```

After successful Phase A, atomically clear the one-time `secret`; after the full flow, delete or expire the transient auth row promptly unless it is deliberately converted into an ongoing signer connection.

## Browser/PWA Clients

In a browser client, the page can hold the relay subscriptions directly, so the Rails job, DB row, and polling endpoint are unnecessary. Persist pending state carefully if navigation or reload recovery is required.

Mobile browsers may throttle JavaScript, suspend a page, or interrupt WebSockets when the signer app comes to the foreground. Behavior varies by browser, OS, PWA mode, memory pressure, and timing; do not state categorically that app switching always kills the socket. Because kind 24133 is ephemeral and replay cannot be assumed, treat interruption as a real failure mode:

- Enable library-supported reconnect and keepalive behavior, while recognizing that neither runs while a page is fully suspended.
- On return to the foreground, check subscription health and reconnect promptly.
- For a client-initiated `nostrconnect://` flow, a missed initial response cannot be safely reconstructed. After a configurable grace period, offer Retry that creates a fresh client key and one-time secret.
- For a `bunker://` connection with a pinned signer and a client-created pending `connect` request, retry or probe only according to that flow's request semantics. Do not transplant `bunker://` `"ack"` handling into Phase A of `nostrconnect://`.
- Multi-relay listening improves the chance that one live connection receives the response, but it cannot keep a fully suspended page running.

## Timeouts

Timeouts are product and deployment settings, not protocol constants. Make them configurable and distinguish machine-paced request timeouts, human-paced QR/approval windows, foreground-recovery grace periods, and overall session expiry. Choose defaults from observed signer, relay, network, and accessibility behavior; show progress, Cancel, and Retry rather than leaving controls disabled indefinitely. A server can reasonably keep a QR session row alive much longer than an individual request, but values such as 30 minutes or 120 seconds are examples, not universal requirements. Keep these values distinct: the background listener should run only for the approval window, not the full session-row TTL. Reusing the 30-minute row TTL as the listener deadline is what pins worker threads and database connections long after the user has left — see "Listener Lifetime, Cancellation, and Connection Budget."

## Persisting an Ongoing Connection

For an ongoing signing relationship, persist the encrypted **client private key**, client public key as needed, pinned **remote-signer pubkey**, current relay set, and expected **user pubkey**. On restore, call `get_public_key` through the pinned signer and require an exact match with the expected user key before using the connection. Consider `switch_relays` after connection and persist validated updates.

Do **not** persist the `nostrconnect://` one-time secret as ongoing connection state. It exists only to authenticate the initial client-initiated connection response and must be discarded after successful validation. Encrypt client private keys at rest, restrict access, delete them on logout, and expire abandoned setup rows. In browser/PWA storage, assess XSS and device-compromise risk before retaining a signer-capable client key.

## Puma Configuration

With the DB-only poll, Puma *thread* pressure from login is minimal. The pressure that matters is on the *database connection pool*: the listener's worker and relay threads draw from the same pool, so size it for both web threads and peak auth connections (see the connection-budget formula above), and confirm the database's own connection limit covers it.

```ruby
# config/puma.rb
threads_count = ENV.fetch("RAILS_MAX_THREADS", 10)
threads threads_count, threads_count
```

## Common Pitfalls

1. **Breaking on EOSE** — Kind 24133 is ephemeral. EOSE marks the end of the relay's initial stored-event response, not the end of the live subscription. Keep listening for the new event.
2. **Single relay** — Relays go down. Always configure multiple auth relays for redundancy.
3. **No active listener** — Poll-only relay checks miss ephemeral events. Server implementations need a background listener; browser implementations need an active in-page subscription and lifecycle recovery.
4. **Session reuse** — Reusing sessions on page refresh prevents the background job from being enqueued. Always generate a fresh session.
5. **`since` filter** — Unnecessary when temp pubkey is unique per session. Adds clock skew risk with no benefit.
6. **Not checking DB first** — The fast path avoids hitting the relay on every poll after auth succeeds.
7. **Blindly accepting events** — Never authenticate a user just because NIP-04 decryption failed. If both NIP-44 and NIP-04 fail, reject the event. This is a security hole.
8. **Loose secret validation** — In `nostrconnect://`, require `result` to equal the one-time secret exactly. Do not accept `"ack"` or a request-shaped connect message.
9. **No dedicated queue** — Long-running jobs (ingestion, AI rating) can starve the auth job. Use a dedicated `auth` queue with its own worker thread.
10. **No reconnection** — Relay connections drop. The listener must reconnect with exponential backoff until the session expires. Without this, a brief network hiccup kills the login flow.
11. **Relay fallback in poll** — Kind 24133 replay cannot be assumed. Opening short-lived WebSocket connections in the poll endpoint wastes server threads without reliable recovery. Use DB-only polling.
12. **Hard-coded timeout assumptions** — Human-paced approval, machine requests, recovery grace periods, and session expiry need separate configurable values.
13. **Treating `event.pubkey` of the connect response as the user's identity.** Under newer Amber this is a per-connection routing key, not the user's npub. Always resolve the real identity via `get_public_key` and persist it separately from the signer pubkey.
14. **Skipping `get_public_key`.** It is mandatory per NIP-46. Old signers simply return their own pubkey, so calling it unconditionally is safe and works against all signer versions with no branching.
15. **Closing the subscription on connect response.** The `get_public_key` response is also kind 24133 (ephemeral). Tearing the subscription down after Phase A means Phase B silently hangs until session expiry.
16. **Decrypting before NIP-01 verification.** Validate the complete event ID, pubkey, and signature before NIP-44 decryption, then enforce kind, recipient, pinned signer, and request ID as appropriate.
17. **Trusting callback query parameters.** Resolve the authenticated user only from a completed server-side auth record bound to the browser session.
18. **Treating `perms` as a capability grant.** Permissions are a minimum UX request; every operation can still be denied, challenged, or re-prompted.
19. **Accepting an unbound `auth_url`.** Surface a challenge only for a known pending request from the pinned signer, never during nostrconnect Phase A.
20. **Self-starving auth queue.** A dedicated queue stops *other* jobs from starving login, but each listener holds its worker thread for the whole listener deadline. If concurrency is 1 and the deadline is the 30-minute row TTL, one abandoned login blocks every later attempt. Keep the deadline short, cancel abandoned listeners, and size concurrency for real usage.
21. **Listener deadline set to the session-row TTL.** Running the listener until `expires_at` pins its worker and relay threads (and their DB connections) for the full TTL even after the user leaves. Use a short approval window for the listener; expire the row separately.
22. **A database connection per relay thread.** Relay threads that call `reload` in a loop hold a pooled connection for their lifetime. `auth_concurrency * (1 + relay_count)` can exceed the pool Puma shares, causing connection timeouts on login and on unrelated web requests. Use `with_connection`, or budget the pool and concurrency together.
23. **No cancellation on reload.** Relying on `reload` raising `RecordNotFound` to stop an abandoned listener can fault the job and crash-loop on retry. In `new`, consume or delete the prior session; in the listener loop, check explicitly for consumed/deleted/expired and return.
24. **Small non-blocking SSL reads on Ruby 4.0 / OpenSSL 3.** `ssl_socket.read_nonblock(1 or 2, exception: false)` can return `:wait_readable`/`""` forever even with data ready, so byte-at-a-time upgrade reads and 2-byte frame-header reads hang every relay connection to the deadline — a total, silent outage that a Ruby upgrade introduces. Read big chunks into a per-socket buffer and slice (see the Critical section above). This is the single most likely cause if "auth just stopped working" and "adding relays didn't help".
25. **Per-login sockets that don't scale.** One job/socket-set per login pins a DB connection per relay for the whole window and caps real concurrency at ~1. If you see "temporarily at capacity" or QRs stuck on "Waiting…", move to the multiplexed supervisor (one shared reader thread per relay for all logins) — see *Scaling* above.

## Debugging with nak

```bash
# Check relay connectivity
nak req -k 24133 wss://nos.lol

# If "connection took too long" — relay is down, that's why multi-relay matters.
# Relay availability shifts over time: relay.nsec.app (the dedicated bunker relay)
# has been down (HTTP 502) for stretches, and relay.damus.io rate-limits NIP-46
# traffic. Verify each relay actually round-trips an ephemeral kind-24133 event
# (publish on one connection, subscribe on another) before trusting it for auth —
# a successful WS handshake does NOT prove the relay relays ephemeral events.

# Check for events tagged to a specific pubkey (won't find ephemeral events after the fact)
nak req -k 24133 -p <temp_pubkey_hex> wss://relay.primal.net

# Test multiple relays
nak req -k 24133 wss://nos.lol wss://relay.primal.net wss://nostr.mom
```

Remember: `nak req` for kind 24133 will usually return nothing because replay of ephemeral events cannot be assumed. Its main value here is testing relay connectivity and observing events while the subscription is live.
