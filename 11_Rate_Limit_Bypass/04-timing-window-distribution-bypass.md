# 04 — Timing Window and Distributed Request Bypass

## Prerequisite

Read `01-how-api-rate-limiting-works.md` (especially section 3, the algorithm breakdown) before this file — every technique here maps directly to one of the algorithms described there.

## PortSwigger Lab Mapping (Honest Disclosure)

**"Rate limit bypass via race condition"** (Business logic vulnerabilities topic) is the direct official lab, and it's the correct one to attempt first, in this progression: multi-endpoint distribution lab → race condition lab, since race-condition-based bypass is the most concentrated/aggressive form of the timing techniques in this file. Everything else here — window-boundary timing, token bucket refill-hugging — is industry-sourced (from CDN vendor rate-limiting documentation and public writeups) rather than Academy-lab-backed. This is flagged explicitly because window-boundary and refill-rate timing require more precise knowledge of the target's specific algorithm than Academy labs teach in the abstract.

## 1. Step One: Identify the Algorithm Before Choosing a Timing Technique

Re-derive this from file 01, section 3, against the live target — timing techniques are algorithm-specific and using the wrong one wastes requests (which may themselves count against you). A quick field-testable heuristic:

| Observation | Likely algorithm |
|---|---|
| Limit resets sharply at a round clock time (e.g., always at `:00` seconds) | Fixed window |
| Limit resets gradually — sending requests one at a time, the "oldest" one seems to "expire" individually | Sliding window log or sliding window counter |
| A burst of many requests succeeds immediately, then the rate drops to a slow, steady trickle rate | Token bucket |
| Rate feels like a smooth, constant ceiling regardless of how bursty your input is | Leaky bucket |

**How to test this without burning your entire request budget:** send a small number of requests (well under the suspected limit), wait, send a few more, and observe whether the count is measured from the wall clock (fixed window) or from your own request timestamps (sliding). This reconnaissance step should use only a handful of requests — spend them deliberately.

## 2. Fixed Window Boundary Bursting

**What's being exploited, piece by piece:** a fixed window counter is keyed to a coarse time bucket (e.g., `floor(unix_timestamp / 60)`). The counter has zero memory of anything outside the current bucket. The instant the bucket index increments, the counter resets to zero — regardless of how recently the previous bucket was maxed out.

**Mechanics:**
1. Determine the window boundary alignment. Most implementations align to either the epoch (`:00` of every minute/hour) or to the time of the *first* request in a session — test both by observing exactly when your rate limit resets relative to wall-clock time across multiple trials.
2. Time a burst to land in the final ~1-2 seconds of a window, consuming the full limit.
3. Immediately follow with a second full-limit burst in the first ~1-2 seconds of the next window.
4. Net effect: up to 2x the stated limit delivered within a ~2-4 second span, fully compliant with the "N requests per window" rule as implemented, even though it clearly violates the rule's intent.

**Precision requirement:** this technique is sensitive to clock skew between attacker and target. Before attempting it operationally, calibrate by sending a single throwaway request near a suspected boundary and observing the response headers — many implementations return `X-RateLimit-Reset` or `Retry-After` headers that tell you exactly when the window resets, removing the need to guess.

## 3. Token Bucket Refill-Rate Hugging

**What's being exploited, piece by piece:** token bucket algorithms have two independent parameters — bucket capacity (*B*, the burst allowance) and refill rate (*R*, the sustained rate). A rate limiter's *displayed* or *documented* limit is usually the sustained rate, but the actual enforced ceiling at any given moment also depends on how many tokens have accumulated since the last request.

**Mechanics:**
1. Let the bucket sit idle for a period to accumulate tokens up to capacity *B* (if the target has been unused by you, it may already be full).
2. Spend the entire bucket in one immediate burst of *B* requests.
3. From that point on, send requests at exactly the refill rate *R* (e.g., one request every `1/R` seconds) indefinitely — the bucket never accumulates a deficit, so no request is ever rejected, and you sustain the maximum possible long-run rate the algorithm allows.
4. **How to determine *R* empirically:** after exhausting the bucket, send single requests at increasing intervals (e.g., every 2s, then every 1.5s, then every 1s) and observe the point at which requests stop being throttled — that interval is `1/R`.

**Real-world note:** this technique is not really a "bypass" in the sense of exceeding the intended limit — token bucket is *designed* to permit exactly this pattern (burst + sustained trickle). It's included here because many defenders and developers mistakenly believe their "100 requests/minute" limit caps throughput at that rate at every instant, when in practice a poorly-tuned bucket capacity can make the *effective* burst-window rate far higher than the documented sustained rate. Flagging an oversized bucket capacity relative to the intended burst use case is itself a legitimate, reportable finding in many programs.

## 4. Distributed Timing — Combining With Files 02/03

Timing techniques compound with identity-key techniques rather than replacing them:

- **Per-identity-key window resets are independent.** If you're rotating IPs (file 02) or accounts (file 03), *each* identity key has its own window/bucket state. This means window-boundary bursting can be performed **simultaneously across multiple identity keys**, multiplying the effective burst size by the number of keys in rotation.
- **Jitter to evade behavioral detection (see file 05):** a perfectly periodic request interval (exactly every `1/R` seconds, to the millisecond) is itself a detectable signal to any system doing statistical analysis of request timing, independent of the rate limiter itself. Introduce small randomized jitter (e.g., ±10-15% of the base interval) to the pacing in section 3 to reduce the "obviously scripted" signature while staying under the hard threshold.
- **Distributing across time-of-day, not just seconds:** for longer-window limits (hourly/daily quotas), distributing volume across many identity keys *and* spreading it naturally across the window (rather than front-loading it) avoids triggering anomaly-detection systems that flag "quota consumed in the first minute of a daily window" as suspicious even when technically compliant.

## 5. Race-Condition-Adjacent Bursting

A related but mechanically distinct technique worth flagging explicitly (this is the direct subject of the official PortSwigger "Rate limit bypass via race condition" lab): if the rate limiter increments its counter **after** processing a request rather than before, sending many requests in near-perfect parallel (not just fast sequentially, but genuinely concurrent, e.g., via HTTP/2 multiplexing on a single connection) can result in multiple requests being processed before any of them individually observes an incremented counter — because each one reads the "current count" at nearly the same instant, before the others' increments are visible. This is the same class of bug covered in more depth under general race condition/TOCTOU notes; it is flagged here specifically because it's the highest-yield technique against poorly implemented in-application (not edge/CDN) rate limiters, where the read-then-increment logic is not atomic.

## Next File

`05-bot-protection-fingerprinting-bypass.md` — the non-CAPTCHA detection layers (behavioral, fingerprinting) that often sit alongside rate limiting and need separate treatment from everything covered so far.
