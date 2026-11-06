# access-gate

The admin-page gate shared by cameo and notion-rss. Each app sits behind an identity-aware proxy, and checks the proxy's word again itself.

`AdminGate::admit` decides every request to an admin path:

1. A write (any method but GET and HEAD) must send an `Origin`, or a `Referer` when it sends no `Origin`, and every one must name the app's origin. Otherwise the answer is 403. This check runs first, so a forged write costs nothing.
2. The request must pass the gate's `Auth`. A missing or bad token is 401. Keys that cannot be fetched are 503.

What passes is an `Admission`. `Admission::Write` carries a `Write`, a proof that only `admit` makes, so an app can require one for every write it runs.

## Ways to authenticate

`Auth` has one variant per way. Today there are two:

- `Auth::Cloudflare(login)`: the JWT Cloudflare Access forwards in `Cf-Access-Jwt-Assertion`, verified against the team's keys (`cloudflare` module). The token must be RS256, `iss` must be the team's origin, `aud` must be the application's, and `exp` and `nbf` must hold, with 10 seconds of leeway. The gate reads no other claim, because the Access application's Allow policy is the one check of identity. Keys are trusted for an hour and fetched at most once a minute.
- `Auth::Skip`: no check, for a debug build with no proxy in front. A release build of the crate has no such variant.

To add another way, add a variant and its module, and give its error a variant in `Refusal` with its status. An app that logs `{refusal}` and answers `refusal.status()` needs no change. An app that matches on `Refusal`, as cameo does to keep its own log text, gets a compile error at that match.

## Use

```rust
use access_gate::{AdminGate, Admission, Auth, cloudflare};

let team = cloudflare::Team::new(&team_url, |count| log_fetch(count))?;
let gate = AdminGate::new(Auth::Cloudflare(team.login(&admin_aud)), public_origin);

match gate.admit(request.method(), request.headers()).await {
    Ok(Admission::Read) => { /* serve the page */ }
    Ok(Admission::Write(write)) => { /* run one write, spending `write` */ }
    Err(refusal) => { /* log `refusal`, answer `refusal.status()` with an empty body */ }
}
```

`cloudflare::Team::service_token` verifies Access service tokens for a gate of the app's own, as cameo's upload gate does. Clones of a `Team` share one key cache. `Team::watch` reads that cache for a status page and never fetches.

The crate writes no log line. Every error is `Copy` and names only the check that failed. None quotes the token, its `kid`, or text from the keys endpoint.

## Depend on it

```toml
access-gate = { git = "https://github.com/hongyilyu/access-gate", rev = "<commit>" }
```
