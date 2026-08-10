# Kanrin, Explained Simply

> The plain-language version of `DESIGN-EVASION.md`. No jargon, or jargon
> explained as it appears. If you want the sourced, technical version with
> citations, read `DESIGN-EVASION.md`. If you want the task list, read
> `TASKS-4.md`. If you want priorities, read `ROADMAP.md`.

---

## The story of the gate and the letters

Imagine you live in a walled city. There is one **gate**, and behind it sits a
very fussy **guard**. Every letter and parcel leaving or entering the city gets
looked at by the guard.

The guard has orders: let normal letters through (a pizza order, a cat photo),
but seize and tear up anything "suspicious."

- That **guard** is called **DPI** — *Deep Packet Inspection*. It is a machine
  that examines internet traffic closely.
- The whole censorship system is called the **GFW** — the *Great Firewall*. It
  is the strongest one in the world, and other countries copy it.

Our job is to send our own letters so the guard never notices them.

## What is a "letter"?

Anything you send on the internet is chopped into small pieces. Each piece is
called a **packet** — like mailing a book one page at a time in separate
envelopes.

**TLS** is the lock you put on the envelope. It is what the green padlock next to
a website address means. The guard **cannot read** inside a locked envelope.

So if the guard can't read it, what's the problem?

## The problem: the guard doesn't need to read it

This is where many tools go wrong. The guard learns a lot from the **outside** of
the envelope:

- What shape is it?
- How big is it?
- How often does it arrive?
- What sound does it make when you knock on it?

### Mistake #1 — "the shapeless envelope"

Some older tools said: "we'll make our envelope totally shapeless and scrambled,
so it looks like nothing!"

The guard figured out one thing:

> **Normal people's letters aren't shapeless.** A pizza order looks like a pizza
> order. If I see a letter that is *completely scrambled and shapeless*, that
> itself is suspicious!

This "scrambledness" has a name: **entropy** — the degree of randomness. The
guard learned to measure it.

**Lesson:** "looking like nothing" is itself a shape. A very suspicious one.

### Mistake #2 — "imitation"

The next tools said: "fine, we'll dress up as a pizza order!"

They copied a **fingerprint** — the special hello each program says when it
connects. Like a signature. Chrome says hello one way, Firefox another.

A tool called uTLS copied Chrome's hello. It looked great! But:

> The guard doesn't **only** look at the hello. It watches what you do
> afterwards. Someone can copy my signature, but not my walk, my handshake, my
> habits.

Copying the hello is now considered not enough.

## The big lesson: how the strongest tool got caught

This is the most important part.

A tool called **Reality** was the best in the world. Its idea was brilliant:

> "We won't *pretend* to be a real website. We'll **borrow a real website's
> handshake.**"

Its server would genuinely handshake with, say, a real popular website, so
everyone thought it was unbreakable.

In October 2025, it got caught. Here's how.

### The guard's move: **active probing**

**Active probing** means the guard no longer just watches — it **knocks on the
door itself** and sees what answer it gets.

The guard did this:

1. It called the suspicious server and **repeated the exact same thing it had
   said before** (this is called a **replay**).
2. It counted how patient the server was — **how many repeated messages it would
   tolerate** before hanging up.

And it got this answer:

```
first case:  the number 16  →  as if the server is written in one language
second case: the number 32  →  as if the server is a different one
```

**Two different numbers from one server!**

### Why is that a disaster?

Because it turned out Reality had **two personalities**:

- If you had the right secret → it answered with its own engine (number 16)
- If you didn't → it forwarded you to the real website (number 32)

The server **behaved differently** depending on whether you were a friend. The
guard didn't need to know *what* was being said — it just noticed:

> "This server acts one way for some people and another way for others. **So it's
> hiding something.**"

This is called **behavioral divergence** — two paths that should be identical but
aren't.

**The big lesson:** every tool that has ever been caught was caught because it
**imitated** something instead of **being** it. And imitation always slips
somewhere.

---

## Our turn — we thought four times and threw away three

Here is something important: **throwing away bad ideas early is the work.**

### Idea 1: "let every server look unique"

We said: let each Kanrin server have a unique-looking envelope, so the guard
can't write one rule.

**Self-critique — rejected.** Remember? The guard no longer looks for a specific
shape — it looks for **scrambledness**. If every server looks uniquely random,
they all look *more* scrambled. This idea makes us *easier* to catch! It was
solving the guard's **yesterday** problem.

### Idea 2: "make the server invisible"

We said: the server won't answer at all until it hears the secret word. To the
guard, the port looks closed.

**Self-critique — half-saved.** The "don't answer strangers" part is good, keep
it. But there's a big problem:

> A house that **never opens its door** is itself **weird**! The neighbors get
> suspicious.

On the internet it's the same. A server with the website port open that never
shows a website is a red flag. We realized our goal was wrong:

> We don't want to be **invisible**. We want to be **normal**. Those are two
> completely different targets.

### Idea 3: "actually be a website"

We said: fine, let our server **actually** be a real website. Real domain, real
content.

**Self-critique — right direction, wrong execution.** This is exactly what
Reality did, and it got caught! The problem wasn't "being a real site," it was
having **two personalities**.

And a second flaw nobody had thought about:

> If your website is a small 200 KB page, but 20 MB of data is flowing through
> it, that's like carrying a fridge out of a tiny handbag. **The volumes don't
> match.**

### Idea 4: "carrier occupancy" — this one survived

Its name is **Carrier Occupancy** — riding on a real carrier. Four rules:

**Rule 1 — have only ONE personality**

This is the direct answer to how Reality got caught. Our server has **one path
only**. Whether you're a friend or a stranger, **exactly the same code, same
speed, same behavior.** Being a friend is something discovered *inside* an
already-normal conversation, not a fork that sends you to a different engine.

And more: **we run the very tool that caught Reality against ourselves.** If we
ever see two different numbers, that's a top-severity bug.

> Like asking yourself the hardest possible exam question before the exam. Better
> to fail here than in the real test.

The technical name is **single-stack invariance** — "stack" means the software
engine, "invariance" means something that doesn't change. So: **one engine, no
exceptions.**

**Rule 2 — pick a carrier whose volume fits**

Remember the fridge in a handbag? The fix is simple: **bring a truck.**

If you want to move something heavy, do something that is *naturally* heavy.
On the internet, these carry a lot:

| Carrier (what we pretend to be doing) | Natural volume |
|---|---|
| Watching video | gigabytes — a truck |
| File sync (like Google Drive) | gigabytes — a truck |
| Video call | hundreds of MB — a van |
| Browsing websites | tens of MB — a handbag |

So if the user is downloading a movie, we pretend to be watching a movie. The
large volume is completely natural; nobody is suspicious.

A subtle point: it's not just volume, it's the **shape** of the volume. Watching
video has a rhythm — a big chunk arrives, a few seconds of silence (you're
watching), another big chunk. We must have that same rhythm.

**Rule 3 — learn from the neighbors' real traffic**

Two important ideas here.

*First: a pre-packaged imitation is useless.* Other tools have one fixed
"profile" baked in when the app is built. Like an actor who memorized one line.
But real traffic in one country differs from another; 3 a.m. differs from 9 p.m.
So Kanrin learns **right there, at that moment, from real traffic on the same
network** — same provider, same hour. Like an actor who listens to the local
accent before the show.

*Second: timing gives you away too.* Almost every tool thinks only about the
**size** of packets. But the guard sees something else: the **time gap between
packets**. Even if you can't see who's knocking, you know from the **rhythm**
whether it's your dad or a stranger.

Hysteria2 has exactly this problem: one of its modes is very fast but sends data
at a **perfectly constant rate**. No human, no real program, is that regular! The
regularity itself is a signature.

*Third — and this is the neat part:* research shows the guard can identify the
**first few seconds** of a connection best. Our answer isn't imitation:

> The first few seconds of a Kanrin connection are **genuinely** a real web page
> loading. We really download real pieces of the site. Then the tunnel starts.

So it's statistically identical to a page load, **because it is one.**

**Rule 4 — send the rules, not a new program**

The guard keeps changing its tests. For other tools, when the guard changes its
rule, a programmer must notice, change code, build a new version, ship it to the
app store, wait for approval, and the user must update — **weeks**, during which
everyone is cut off.

Our fix: we separate the shaping rules **from the code**. They become **data**,
not program. Like a toy robot that reads **instruction cards** instead of having
its behavior welded inside. Want it to behave differently? Give it a new card.
No need to buy a new robot.

So when the guard changes its test, we send a new "card." No update, no app
store, no user action. **Minutes instead of weeks.**

---

## The speed-vs-stealth decision

An honest truth:

> **Stealth is not free.** The more you look like normal traffic, the slower you
> get.

So Kanrin has three **postures** (a posture is a "stance"):

| Posture | When? | What happens |
|---|---|---|
| `Performance` | network is clean, nobody's watching | full speed, no stealth cost |
| `Balanced` | some pressure | moderate stealth |
| `Evasion` | serious pressure, everything blocked | slow but alive |

And it decides when to switch by itself. You do nothing.

**Philosophy:** only pay the cost when it's actually needed. Other tools are
either always fast (and die one day) or always slow (and the user quits).

---

## What makes all of this possible

There's a foundational piece without which none of the above works.

Say you're watching a movie and Kanrin decides to switch from `Performance` to
`Evasion`, or change its path. If that switch interrupts your movie, **the whole
idea is worthless.**

So we need **Session Continuity** — a layer that:

- gives each piece of data a **number** (like page numbers in a book)
- keeps a **copy** until the other side says "got it"
- if the path changes, **resends the missing pieces over the new path**
- reorders out-of-order pieces, drops duplicates

The result: the app on your phone **never notices** anything changed. The movie
plays on, no lag.

Then **Hot Standby**:

> **Build the new bridge before you tear down the old one.**

Kanrin always keeps a second path **ready and connected in advance**. The moment
the first path has trouble, it jumps to the second instantly. The technical term
is **make-before-break**. Target: detect trouble in under 1 second, switch in
under 200 milliseconds — faster than a blink.

---

## What we **cannot** do

Being honest matters more than making claims. These are real limits:

1. **Stealth really does slow things down.** `Evasion` posture is slower. You
   can't be both the fastest and the stealthiest. Anyone who says you can is
   lying.
2. **A real domain and website are required.** Whoever runs the server must buy a
   domain and host real content. That means their **name is registered
   somewhere**. Fine for some people, dangerous for others. We must say this up
   front.
3. **Learning from the neighbors' traffic must be quiet.** If we generate fake
   traffic to learn, that very act gives us away. We only learn from what the
   user is **already** sending.
4. **If they cut the whole internet, none of this works.** No tool is magic. For
   that case there's a very slow backup (a tunnel through DNS) good only for
   sending text, not watching movies.

---

## The whole thing in one sentence

Other tools try to **imitate** normal traffic, and every time, their imitation
slips somewhere and they get caught.

Kanrin tries to **actually be** normal traffic — one personality, plausible
volume, rhythm learned from the neighbors — and when the rules change, instead of
dying, it just gets a **new instruction card.**

And above all: whatever it changes, the user **never feels it.**
