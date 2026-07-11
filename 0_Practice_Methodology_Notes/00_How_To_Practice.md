# How to Practice — Methodology

> This is the missing piece between "I have the notes" and "I can actually do this."
> Read once, then follow this workflow for every single lab/topic across the entire
> repo (Web App Security + API Security).

---

## 1. The Core Principle: Recognize, Don't Memorize

You do NOT need to try every payload in a cheatsheet file. That's not how real
pentesting or bug bounty works either — nobody has 200 SQLi payloads memorized. What
they have is:
- A clear mental model of **why** each category of payload works (the mechanism)
- The ability to **recognize** which category applies to what they're seeing
- The habit of **going back to the reference** (your notes) when they need the exact
  syntax for a specific case

Your notes exist so you don't have to memorize — they're your "second brain" you built
specifically to look things up fast. Trying to memorize all of it is wasted effort and
will slow you down. Understanding the mechanism is what actually transfers to new,
unseen targets.

---

## 2. The Practice Loop (Follow This For Every Topic)

```
1. THEORY PASS (10-20 min)
   Read the topic's overview file + one or two technique files fully.
   Don't touch a lab yet. Just build the mental model.

2. PICK THE EASIEST LAB FIRST
   Use your cheatsheet/lab-mapping file — start at Apprentice difficulty,
   work up to Practitioner, then Expert. Never skip ahead.

3. TRY TO BREAK IT BLIND FIRST (5-10 min max)
   Before looking at any specific payload, try the most generic possible test
   for that vulnerability class (e.g. a single quote for SQLi, <script>alert(1)
   for XSS, {{7*7}} for SSTI). This trains your instinct and confirms you
   understand what you're even looking for.

4. IF STUCK, PULL 2-3 PAYLOADS FROM YOUR NOTES — NOT ALL OF THEM
   Open the relevant technique file, pick a couple of matching payloads,
   and for EACH one, before pasting it, say out loud (or write down) what you
   expect it to do and why. Then test it. If it doesn't work, that mismatch
   between expectation and reality is exactly where the real learning happens.

5. SOLVE THE LAB
   Get to the actual solved state, not just "I saw the vulnerability exists."
   PortSwigger labs have a clear solved condition — reach it.

6. WRITE IT UP IMMEDIATELY (see the template file)
   Do this same day, while the request/response details are still fresh.
   Writing it up while remembering "why" is 10x faster than reconstructing later.

7. MOVE TO THE NEXT LAB IN SEQUENCE
   Repeat steps 2-6 for the next lab up in difficulty.
```

---

## 3. How Much Payload Coverage Is "Enough"? (By Priority Tier)

Use the 🔴/🟡/⚪ priority tags already assigned to every topic across both repos.

| Priority | Labs to complete | Payload variations to actually try per technique | Goal |
|---|---|---|---|
| 🔴 High | All labs in the sequence (Apprentice → Expert) | 3-5 per sub-technique, including at least one bypass variant | Deep fluency — you should be able to do this without notes eventually |
| 🟡 Medium | Apprentice + Practitioner (Expert optional) | 2-3 per sub-technique | Solid working knowledge — comfortable using notes as reference mid-engagement |
| ⚪ Low | Apprentice only, maybe one Practitioner | 1-2, just enough to see the pattern once | Recognition only — you'll relearn details from notes if it ever comes up |

**Do not force equal depth across all 60+ topics.** That's the single biggest time-waste
risk given how large this library has grown. The priority tags exist exactly to stop
you from over-investing in LDAP Injection at the same rate as BOLA.

---

## 4. What "Understanding the Mechanism" Actually Looks Like

Bad (memorization mode):
> "I pasted `' OR 1=1--` and it worked."

Good (mechanism mode):
> "The query was probably `SELECT * FROM users WHERE username='INPUT'`. My `'`
> closed the string early, `OR 1=1` made the WHERE clause always true, and `--`
> commented out the rest of the original query so it wouldn't error on the trailing
> quote. That's why this specific structure worked here, and why a numeric-context
> field wouldn't need the leading `'`."

If you can't explain the *why* in your writeup, you weren't actually done with that
lab yet — go re-read the relevant technique file before moving on.

---

## 5. When You Get Stuck (Realistic Troubleshooting Order)

1. Re-read the specific technique file for that topic — not the whole topic, just
   the section matching what you're trying
2. Check the WAF/filter bypass file for that topic, if one exists — maybe your
   payload is correct but getting filtered
3. Check the topic's automation tool file (sqlmap, commix, etc.) — confirm manually
   first, then let the tool show you what it's doing differently
4. Only after all three of the above, check PortSwigger's official lab solution —
   and when you do, don't just copy the payload, go back and explain to yourself why
   it works before marking the lab complete

---

## 6. Weekly Practice Structure (Suggested, Adjust to Your Schedule)

```
- Pick ONE topic per session block, following the repo's numbered priority sequence
  (Web Fundamentals → SQLi → XSS → ... as laid out in the main README)
- Spend one sitting on theory + easiest lab
- Spend the next sitting(s) on remaining labs for that topic, in difficulty order
- Do NOT jump between unrelated topics mid-week — context switching wastes time
  re-loading mental models
- Once a 🔴 topic is fully done (all labs + writeups), do a quick "cheatsheet skim"
  — 5 minutes scrolling the full payload list just to build passive recognition of
  variants you didn't personally test
```

---

## 7. After Finishing a Topic — Before Moving On

Ask yourself these three questions. If you can't answer all three, the topic isn't
actually done yet, regardless of how many labs you solved:

1. Could I explain this vulnerability class to someone else in 2 minutes, mechanism
   included, without looking at my notes?
2. Do I know which file in my notes to open if I needed the exact bypass syntax
   again in six months?
3. Did I actually write up at least one lab in full report format (see the
   Writeup_Template file)?

Continue to → `01_Writeup_Template.md`
