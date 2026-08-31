# Project context

An open-source SD-WAN for a mobile teleworker. One home server (responder) and one
RV client (initiator), joined by multiple WAN links. The goal is a connection that
stays usable for real-time conferencing while driving through canyons, forests, and
dead zones.

The novel part is layer 3, path selection. Everything else is assembly of existing
open-source components. Do not spend effort reinventing tunnels, crypto, or shaping.

## Non-negotiable principles

These came from the project owner and take precedence over any optimization.

1. **Open source only.** No proprietary components anywhere in the stack.
2. **Simplicity over cleverness.** When two designs work, take the one that is easier
   to reason about at 2am in a campground.
3. **Variable bandwidth and intermittent connectivity are the normal case**, not an
   edge case. Any design that assumes a working link is wrong.
4. **Redundancy and reliability beat performance.** Take performance opportunistically
   when conditions allow, never at the cost of reliability.
5. **Fail to a working state, never to nothing.** Every component needs a defined
   behavior when the component below it is broken.

## Primary use case

A teleworker on a video call while the RV is moving. Real-time conferencing quality is
the metric that matters. Web browsing and map traffic are secondary and explicitly
sacrificial.

## Architecture in one paragraph

Each WAN link carries its own WireGuard tunnel to the home server. A userspace daemon
sits above WireGuard, adds a sequencing and timing header, measures every path
continuously, and decides which path each packet takes. Real-time traffic gets a single
low-jitter path with make-before-break switching and optional duplication. Bulk traffic
gets whatever is left. All traffic is tunneled; there is no split tunneling.

## Reading order

- `docs/scope-v1.md` — what to build, what to defer, build sequence
- `docs/architecture.md` — the layer stack and component choices
- `docs/protocol.md` — header format, measurement, scheduling algorithm
- `docs/decisions.md` — decisions made, with rationale and rejected alternatives

## Working agreements

- **Check `docs/decisions.md` before proposing an alternative approach.** Most obvious
  alternatives were considered and rejected for stated reasons. If you want to reopen
  one, say which decision and why the reasoning no longer holds.
- Prefer Go for the daemon. Rust is acceptable. The performance ceiling is far above
  what these links deliver, so choose for maintainability.
- No dependency that requires a build toolchain the RV cannot run.
- Every tunable needs a working default. The user should never have to set one.
