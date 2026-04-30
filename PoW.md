# Proof-of-Work (PoW) in Indidus Relay Signaling

## Table of Contents

1. [What is Proof-of-Work?](#1-what-is-proof-of-work)
2. [Why Did We Introduce It?](#2-why-did-we-introduce-it)
3. [The Problem It Solves](#3-the-problem-it-solves)
4. [The Algorithm: Exactly How It Works](#4-the-algorithm-exactly-how-it-works)
5. [Mathematical Foundation](#5-mathematical-foundation)
6. [The Full Registration Flow](#6-the-full-registration-flow)
7. [Why Is It Secure?](#7-why-is-it-secure)
8. [Attacks and Mitigations](#8-attacks-and-mitigations)
9. [Implementation Deep Dive (Rust)](#9-implementation-deep-dive-rust)
10. [Choosing Difficulty: Cost vs. Protection](#10-choosing-difficulty-cost-vs-protection)
11. [Comparison with Alternatives](#11-comparison-with-alternatives)
12. [Frequently Asked Questions](#12-frequently-asked-questions)

---

## 1. What is Proof-of-Work?

**Proof-of-Work (PoW)** is a cryptographic technique where one party (the **client**) proves to another party (the **server**) that it has expended a measurable amount of computational effort before being granted a resource or capability.

The core idea is asymmetric:
- **Hard to produce**: The client must perform real, unavoidable computation.
- **Trivial to verify**: The server can verify the result in microseconds with a single SHA-256 computation.

This asymmetry is the entire basis of its security. The server never does the expensive work — it only checks.

> 🔑 **Key Intuition**: Think of PoW as a "computational cover charge." To enter, you must prove you spent CPU cycles. This makes mass automated attacks economically unviable.

PoW was first formally described by Cynthia Dwork and Moni Naor in their 1993 paper *"Pricing via Processing or Combatting Junk Mail"* as a defense against email spam. It was later made famous by Bitcoin's consensus mechanism, though our usage here is much simpler and far less resource-intensive than Bitcoin mining.

---

## 2. Why Did We Introduce It?

The Indidus Relay Signaling server is **intentionally open and permissionless** — there is no centralized authority issuing account approvals, no payment gateway, and no email verification. Any Indidus device on the planet can register.

This openness is a feature, not a bug. It enables:
- **Censorship resistance**: No one can be blocked from registering.
- **Privacy**: No email, phone number, or personal data is required.
- **Zero admin overhead**: You can self-host without maintaining a user database with PII.

However, openness creates a direct attack surface. Without a registration barrier, anyone could write a script to register millions of identities in seconds, flooding the database and denying service to legitimate users. We needed a gate that is:

1. **Free** (no cost to legitimate users).
2. **Open** (no account required from an external authority).
3. **Painful** (expensive to abuse at scale).
4. **Stateless** (the server needs no session state to verify it).
5. **Instantaneously verifiable** (server verification must be cheap).

PoW satisfies all five requirements simultaneously. No other mechanism does.

---

## 3. The Problem It Solves

### Without PoW: Sybil Attack

A **Sybil attack** is when a single adversary creates a massive number of fake identities to gain disproportionate influence or exhaust resources. Named after the 1973 book about a woman with multiple personality disorder.

**Example without PoW**:
```
for i in 0..1_000_000 {
    POST /register { "username": format!("bot{}", i), "public_key": generate_key() }
    // Cost: Near-zero. Floods DB in minutes.
}
```

**With PoW (Difficulty = 16)**:
```
for i in 0..1_000_000 {
    // Must solve ~65,536 SHA-256 hashes FIRST
    // Cost: ~65,536,000,000 hashes ≈ hours of CPU time
    // At scale: economically infeasible
}
```

### Without PoW: DDoS via Registration

Even without storing data, a registration endpoint that performs any database write is vulnerable to computational exhaustion. PoW moves the cost burden entirely to the attacker before the server does any database work.

---

## 4. The Algorithm: Exactly How It Works

Our PoW scheme is a **Hashcash-style** algorithm. The client must find a `nonce` (a 64-bit unsigned integer) such that:

```
SHA-256(username_bytes || nonce_big_endian_bytes)
```

...produces a hash whose first `D` bits (where `D` is the **difficulty**) are all zero.

### Step-by-Step Client Algorithm

```
Input:  username (string), difficulty D (integer)
Output: nonce (u64)

1. nonce ← 0
2. LOOP:
   a. data ← CONCAT(UTF8(username), BIG_ENDIAN_U64(nonce))
   b. hash ← SHA-256(data)
   c. IF leading_zero_bits(hash) >= D:
        RETURN nonce  ← FOUND!
   d. nonce ← nonce + 1
   e. GOTO 2
```

### Step-by-Step Server Verification

```
Input:  username (string), nonce (u64), difficulty D (integer)
Output: VALID or REJECT

1. data ← CONCAT(UTF8(username), BIG_ENDIAN_U64(nonce))
2. hash ← SHA-256(data)
3. IF leading_zero_bits(hash) >= D:
     RETURN VALID
   ELSE:
     RETURN REJECT
```

Server verification is exactly **one SHA-256 computation** — regardless of how hard the client worked.

### Concrete Example (Difficulty = 8)

Let `username = "alice"`.

| Nonce | SHA-256("alice" ∥ nonce) | Leading Zeros |
|-------|--------------------------|---------------|
| 0     | `5ae6...`  (0101...) | 0 bits |
| 1     | `a3f1...`  (1010...) | 0 bits |
| ... | ... | ... |
| 183   | `00c7...`  (0000 0000 1100...) | 8 bits ✅ |

At nonce = 183, the SHA-256 hash starts with a byte `0x00`, meaning all 8 leading bits are zero. The client stops and submits `nonce = 183`.

The server computes `SHA-256("alice" ∥ 183)`, sees `0x00c7...`, counts ≥ 8 leading zero bits, and returns `201 Created`.

---

## 5. Mathematical Foundation

### SHA-256 as a Random Oracle

SHA-256 is a **cryptographic hash function**. For our purposes, the critical property is that its output is computationally indistinguishable from a **uniformly random 256-bit string**. This is the **Random Oracle Model** assumption, which is the standard model for analyzing hash-based protocols.

Formally:
```
H: {0,1}* → {0,1}^256
```
Where `H(x)` behaves as if a random oracle selects a uniformly random 256-bit string for each unique `x`.

### Probability of a Single Nonce Succeeding

For difficulty `D`, a hash must have its first `D` bits equal to zero. Since each bit is independently and uniformly `0` or `1` (by the Random Oracle assumption):

```
P(success for one nonce) = (1/2)^D = 2^{-D}
```

| Difficulty D | Probability of 1 hash succeeding |
|---|---|
| 1 | 1/2 = 50% |
| 8 | 1/256 ≈ 0.39% |
| 16 | 1/65,536 ≈ 0.0015% |
| 20 | 1/1,048,576 ≈ 0.0001% |
| 32 | 1/4,294,967,296 ≈ 0.000000023% |

### Expected Number of Hashes (Work)

This is a **geometric distribution** problem. Each trial independently succeeds with probability `p = 2^{-D}`. The expected number of trials before the first success is:

```
E[trials] = 1/p = 2^D
```

**Proof**: Let `X` be the number of trials to first success, with `P(success) = p`.

```
E[X] = Σ_{k=1}^{∞} k · (1-p)^{k-1} · p
     = p · Σ_{k=1}^{∞} k · (1-p)^{k-1}
     = p · 1/p²          (sum of k·q^{k-1} = 1/(1-q)² for |q|<1)
     = 1/p
     = 2^D
```

**Therefore**: At **Difficulty 16**, a client must compute on average **65,536 SHA-256 hashes** to find a valid nonce.

### Variance

The geometric distribution has variance `Var[X] = (1-p)/p²`. For large `D`, this is approximately `4^D`, meaning there is high variance — sometimes you get lucky and solve it in 100 hashes; sometimes it takes 300,000. This is expected and does not compromise security.

### Expected Time

Modern hardware computes approximately **500 million SHA-256 hashes per second** per CPU core.

```
Expected time at Difficulty D = 2^D / 500,000,000 seconds
```

| Difficulty | Expected Hashes | Expected Time (single core) |
|---|---|---|
| 8 | 256 | < 1 microsecond |
| 16 | 65,536 | ~0.13 milliseconds |
| 20 | 1,048,576 | ~2 milliseconds |
| 24 | 16,777,216 | ~33 milliseconds |
| 32 | 4,294,967,296 | ~8.6 seconds |

At **Difficulty 16** (the default), a legitimate user waits **~0.13 ms**. An attacker trying to register 1,000,000 fake accounts needs:
```
1,000,000 × 65,536 hashes = 65,536,000,000 hashes
65,536,000,000 / 500,000,000 ≈ 131 seconds per core
```

With 100 CPU cores (a significant botnet), this is still ~1.3 seconds per registration batch. Each registration is a database write on the server, creating a sustained load amplification attack resistance.

### Username Binding (Anti-Precomputation)

The nonce is valid **only for the specific username it was solved for**. This is the critical design decision.

```
hash = SHA-256(username_bytes ∥ nonce_bytes)
```

If an attacker precomputes millions of valid nonces without a specific target, they cannot reuse them for any username. They must re-solve the PoW challenge fresh for each identity they want to register.

**Formally**: Given a valid `(nonce, hash)` pair for username `"bob"`, this pair is computationally useless for registering username `"alice"` because:

```
SHA-256("alice" ∥ nonce_for_bob) ≠ SHA-256("bob" ∥ nonce_for_bob)
```

(with overwhelming probability, since SHA-256 is collision resistant).

---

## 6. The Full Registration Flow

```
CLIENT                                    SERVER
  │                                          │
  │  1. Generate Ed25519 keypair             │
  │     (sk, pk) ← Ed25519.keygen()         │
  │                                          │
  │  2. Solve PoW                            │
  │     nonce ← 0                            │
  │     LOOP:                               │
  │       h ← SHA-256(username ∥ nonce_be)  │
  │       IF h has ≥ 16 leading zero bits:  │
  │         BREAK                            │
  │       nonce++                            │
  │                                          │
  │  3. Send registration request           │
  │  POST /register ──────────────────────► │
  │  {                                       │
  │    "username":      "alice",             │
  │    "root_public_key": hex(pk),           │
  │    "pow_nonce":     183741               │
  │  }                                       │
  │                                          │
  │                         4. Server verifies PoW:
  │                            h = SHA-256("alice" ∥ 183741)
  │                            IF leading_zero_bits(h) < 16:
  │                              RETURN 400 Bad Request
  │                                          │
  │                         5. Server decodes & validates pk:
  │                            pk_bytes = hex_decode(root_public_key)
  │                            ASSERT len(pk_bytes) == 32
  │                                          │
  │                         6. Server persists identity:
  │                            db.create_identity_with_primary_device(
  │                              username="alice", public_key=pk_bytes)
  │                                          │
  │  ◄──────────────────────────────────────│
  │  HTTP 201 Created                        │
  │  { "id": "uuid-of-identity" }           │
  │                                          │
  │  7. Client stores (sk, identity_id)      │
  │     All future requests signed with sk  │
```

After registration, the client never submits PoW again. All subsequent API calls are authenticated via the **X-Signature protocol** (see `README.md`).

---

## 7. Why Is It Secure?

Security rests on three independent pillars:

### Pillar 1: SHA-256 Preimage Resistance

The only known way to find a valid nonce is **brute force**. There is no mathematical shortcut to construct a nonce such that `SHA-256(username ∥ nonce)` has `D` leading zero bits without actually computing many hashes.

**Formally**: If SHA-256 is a preimage-resistant function (as stated in NIST FIPS 180-4 and supported by decades of cryptanalysis), then for any target difficulty `D` and any username, no polynomial-time algorithm can find a valid nonce faster than expected `2^D` hash evaluations.

### Pillar 2: No Server State During Challenge

Unlike CAPTCHA or session-based nonce challenges, our PoW requires **zero server state**. The server does not issue a challenge and does not need to track pending sessions. The username itself is the implicit challenge. This eliminates:
- Session fixation attacks.
- Session expiry race conditions.
- Server memory exhaustion via pending challenge flooding.

### Pillar 3: Cost is Proportional to Scale

The attacker's cost scales **linearly with the number of identities they try to register**:
```
Attacker_cost(N registrations) = N × 2^D hash computations
```

There is no economy of scale for the attacker. Registering 1,000,000 identities costs exactly 1,000,000× more than registering 1.

---

## 8. Attacks and Mitigations

### Attack 1: GPU/ASIC Mining

**Attack**: An adversary uses GPU clusters or ASICs (specialized hardware) capable of trillions of SHA-256 hashes/second to solve PoW at superhuman speed.

**Our Mitigation**: This is a valid concern for Bitcoin-scale operations but not for our threat model. Even with a top-tier GPU cluster performing 10 terahashes/second:

```
At Difficulty 16: 65,536 / 10,000,000,000,000 ≈ 0.000006 seconds per registration
```

However, the **bottleneck shifts to the network** and the **database write** on the server side, which limits the practical attack rate to what the server can sustain — and the attacker gains nothing by registering millions of identities they cannot use (since the accounts must also bind an Ed25519 key that only they control).

For server administrators who deploy on under-resourced hardware, the recommended response is to **increase difficulty** to 20–24, which linearly increases the client's work and provides additional headroom.

### Attack 2: Precomputed Tables (Rainbow Tables)

**Attack**: An attacker precomputes `(nonce → hash)` pairs for every possible nonce against common usernames.

**Mitigation**: The username is baked into the input before hashing. There are no common usernames in a cryptographic sense — `"alice"` and `"Alice"` produce entirely different hash chains. More critically, Indidus does not expose a list of taken usernames, so an attacker cannot even confirm which usernames to target without attempting registration.

### Attack 3: Parallel Botnet Attack

**Attack**: An attacker controls 100,000 compromised machines, each solving PoW independently, registering in parallel to exhaust the server's resources.

**Mitigation**: Each registration requires a **database write**. The server is protected by SQLite's write serialization and the OS's TCP accept queue. Legitimate users are unaffected: their registration still succeeds in < 1 ms of CPU time on their own device. Database I/O becomes the real constraint, and the server operator can apply standard rate-limiting middleware at the network layer (e.g., via Caddy or iptables) against suspicious IP patterns, independent of the PoW system.

### Attack 4: PoW Relay (Outsourcing)

**Attack**: An attacker builds a service that pays humans or rents cloud VMs to solve PoW challenges and relay the nonces.

**Mitigation**: This attack is expensive to the attacker (real money) and slow (human/VM latency). The economics are fundamentally unfavorable: the attacker pays CPU-hours to create accounts they cannot monetize, since the accounts are bound to Ed25519 keys the attacker controls and the relay server stores no user data of value.

---

## 9. Implementation Deep Dive (Rust)

The exact implementation from `src/auth/mod.rs`:

### Server-Side Verification

```rust
fn verify_pow(username: &str, nonce: u64, difficulty: u32) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());      // Step 1: hash username bytes
    hasher.update(nonce.to_be_bytes());      // Step 2: append nonce as big-endian u64
    let result = hasher.finalize();          // Step 3: SHA-256 digest (32 bytes)

    if !check_difficulty_fast(&result, difficulty) {
        return Err(Error::BadRequest("Insufficient Proof-of-Work".to_string()));
    }
    Ok(())
}
```

**Input encoding details**:
- `username.as_bytes()` — UTF-8 encoded. A username `"alice"` becomes 5 bytes: `[0x61, 0x6c, 0x69, 0x63, 0x65]`.
- `nonce.to_be_bytes()` — Always exactly **8 bytes** in big-endian order. Nonce `183` becomes `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB7]`.

There is **no separator** between username bytes and nonce bytes. This is safe because the nonce is always a fixed 8-byte suffix, making the concatenation unambiguous.

### Fast Difficulty Check

```rust
#[inline(always)]
fn check_difficulty_fast(hash: &[u8], difficulty: u32) -> bool {
    // Fast path: read the first 8 bytes as a u64 and check leading zeros in one operation
    let first_64 = u64::from_be_bytes(hash[0..8].try_into().unwrap());

    if difficulty <= 64 {
        // All difficulties up to 64 can be checked against the first 8 bytes alone
        return first_64.leading_zeros() >= difficulty;
    }

    // Slow path for difficulty > 64 (very high security, not default):
    if first_64 != 0 {
        return false; // First 64 bits aren't all zero — no need to check further
    }

    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    // Check all required full zero-bytes
    for &byte in &hash[8..full_bytes] {
        if byte != 0 {
            return false;
        }
    }

    // Check the partially-required byte (if difficulty is not a multiple of 8)
    if remaining_bits > 0 && (hash[full_bytes] >> (8 - remaining_bits)) != 0 {
        return false;
    }

    true
}
```

**Why `u64::leading_zeros()`?**

Modern CPUs have a native instruction for counting leading zeros (`BSR`/`LZCNT` on x86, `CLZ` on ARM). The compiler emits this single instruction for `u64::leading_zeros()`, making difficulty checks for `D ≤ 64` essentially free (1-2 CPU cycles).

**Example walkthrough** at Difficulty = 16 with hash `[0x00, 0x00, 0xAB, ...]`:

```
first_64 = u64::from_be_bytes([0x00, 0x00, 0xAB, ...]) 
         = 0x0000AB...
leading_zeros(0x0000AB...) = 16  ← exactly 16!
16 >= 16 → TRUE ✅
```

**Example at Difficulty = 16** with hash `[0x00, 0x01, ...]`:

```
first_64 = 0x0001...
leading_zeros(0x0001...) = 15
15 >= 16 → FALSE ❌
```

### Client-Side Solving (Pseudocode)

The Indidus mobile client implements the mirror of this in Dart/Rust:

```rust
// Rust reference implementation (also in the test suite)
fn solve_pow(username: &str, difficulty: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();

        let first_64 = u64::from_be_bytes(result[0..8].try_into().unwrap());
        if first_64.leading_zeros() >= difficulty {
            return nonce; // Found!
        }
        nonce += 1;
    }
}
```

This is the exact algorithm from the test suite in `src/auth/mod.rs`, lines 226–245.

---

## 10. Choosing Difficulty: Cost vs. Protection

The difficulty setting lives in `config.toml`:

```toml
[auth]
registration_difficulty = 16
```

Use this table to choose the right value for your deployment:

| Difficulty | Avg. Hashes | Avg. Client Time (mobile ~50 MH/s) | Use Case |
|---|---|---|---|
| 8 | 256 | < 0.01 ms | Testing only — not secure |
| 12 | 4,096 | ~0.08 ms | Very low-resource clients |
| **16** | **65,536** | **~1.3 ms** | **Default. Recommended.** |
| 20 | 1,048,576 | ~21 ms | High-security deployments |
| 24 | 16,777,216 | ~335 ms | Under active DoS attack |

> ⚠️ **Do not exceed Difficulty 24** in production. At Difficulty 24, legitimate mobile users on slow hardware may wait up to 1–2 seconds, which is a poor user experience.

> ✅ **Difficulty 16 is the sweet spot**: It is imperceptible to a human user (~1ms on mobile) but requires a committed attacker to perform ~65,536 operations per fake account, making mass registration economically painful.

---

## 11. Comparison with Alternatives

| Mechanism | Open? | Private? | Free? | Scalable? | Stateless? |
|---|---|---|---|---|---|
| **PoW (ours)** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Email Verification | ❌ Requires email | ❌ Collects PII | ✅ Yes | ✅ Yes | ❌ No |
| Admin Token / Invite Code | ❌ Gated | ✅ Yes | ✅ Yes | ❌ No (admin bottleneck) | ✅ Yes |
| CAPTCHA | ✅ Yes | ❌ Sends to Google | ✅ Yes | ✅ Yes | ❌ No |
| Phone / SMS Verification | ❌ No | ❌ PII | ❌ Costs money | ✅ Yes | ❌ No |
| Payment | ❌ No | ❌ PII | ❌ No | ✅ Yes | ✅ Yes |

PoW is the only mechanism that simultaneously requires **no personal data**, **no external service**, **no administrator approval**, and **imposes a real cost on abusers** while being **transparent and auditable** by anyone reading this document.

---

## 12. Frequently Asked Questions

**Q: Can I mine PoW solutions on behalf of another user?**

Yes, but the username must be committed upfront. If Alice asks Bob's computer to mine the PoW for her registration, Bob's computer must know Alice's username before starting. The resulting nonce is useless for any other registration. This is by design.

---

**Q: Is this the same PoW as Bitcoin?**

The fundamental concept is the same (find a hash with N leading zero bits), but the application is different. Bitcoin's PoW is:
1. Continuous (miners solve it every ~10 minutes to produce blocks).
2. High difficulty (currently ~90 leading zero bits equivalent).
3. Competitive (multiple miners race to be first).

Our PoW is:
1. One-time (solved once during registration, never again).
2. Fixed, low difficulty (16 bits = 65,536 hashes expected).
3. Non-competitive (only you are solving for your own username).

---

**Q: Does PoW consume significant battery on mobile?**

At Difficulty 16, a mobile device performing ~50 million SHA-256 hashes/second (a conservative estimate for modern ARM chips) needs:
```
65,536 hashes / 50,000,000 hashes/second ≈ 1.3 milliseconds
```
This is **completely imperceptible** and consumes negligible battery — far less than a single network round-trip.

---

**Q: What if a user loses their device and needs to re-register?**

Re-registration requires solving PoW again for the same or a new username. This is intentional: re-registration is a rare event, and requiring PoW makes it no different from first registration. There is no "recovery code" that bypasses PoW.

---

**Q: Could the server itself be used to verify PoW solutions without doing the work?**

The server always verifies — it never assumes. Even if a client claims a nonce is valid, the server recomputes `SHA-256(username ∥ nonce)` itself (one operation) and checks the difficulty. There is no trust placed in the client's claim.

---

**Q: What is the nonce data type and what's the maximum nonce value?**

The nonce is a `u64` (64-bit unsigned integer), with a maximum value of `2^64 - 1 = 18,446,744,073,709,551,615`. At Difficulty 16, you expect to find a solution within the first 65,536 nonces, making nonce exhaustion mathematically impossible in practice.

---

**Q: Is PoW alone sufficient security for registration?**

PoW protects the registration endpoint against mass automated abuse. After registration, the security model transitions entirely to **Ed25519 signatures** — a much stronger, well-studied cryptographic primitive. PoW is the "cover charge at the door"; Ed25519 is the ongoing authentication mechanism once inside. Neither alone is sufficient; together they provide defense in depth.

---

*This document describes the PoW mechanism as implemented in `src/auth/mod.rs`. The implementation is auditable, the algorithm is standard, and the mathematical analysis above is exact.*

*Licensed under Apache-2.0.*
