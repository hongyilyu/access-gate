//! The team's signing keys, and the cache that holds them.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use http::StatusCode;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, DecodingKeyKind};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::time::Instant;
use url::Url;

/// Where an Access team publishes its signing keys.
const CERTS: &str = "/cdn-cgi/access/certs";

/// How long fetched keys are trusted, from when the request that fetched them was sent: a key
/// the team withdraws stops verifying within it.
pub const MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// The least time from the end of one fetch to the start of the next. The caller picks the
/// `kid`, and it is read before any signature is checked, and a failing fetch can take the
/// whole timeout, so without this every request could cost one. A rotation that lands inside
/// it is refused until it ends.
const REFETCH_AFTER: Duration = Duration::from_secs(60);

/// How long one fetch may take. [`FetchFailure::Timeout`]'s text names it, and the assertion
/// below keeps the two together.
const TIMEOUT: Duration = Duration::from_secs(10);
const _: () = assert!(TIMEOUT.as_secs() == 10);

/// Whether keys `age` old are still trusted. The one rule the cache and [`KeysWatch`] share.
fn trusted(age: Duration) -> bool {
    age < MAX_AGE
}

/// The team's keys: fetched when a token first needs one, trusted for [`MAX_AGE`] from when the
/// fetch that got them sent its request, and fetched again for a `kid` they lack or once that
/// is up, but never sooner than [`REFETCH_AFTER`] after the last fetch ended. Every fetch runs
/// to its end, on a task of its own, so a request dropped during one cannot cut the floor short.
/// A fetch that fails or finds no usable key keeps the keys held, which stay trusted only until
/// their own [`MAX_AGE`] is up. Both clocks are tokio's monotonic `Instant`, so a wall-clock
/// step cannot cut the floor short either.
pub(super) struct TeamKeys {
    certs: Url,
    /// The team's origin, which issues its tokens.
    issuer: String,
    http: reqwest::Client,
    fetched: fn(usize),
    /// The keys as last fetched, none before the first fetch. Never held across an `.await`,
    /// so a request the keys serve waits on nothing else. Behind an `Arc`, so a [`KeysWatch`]
    /// reads it without holding the cache.
    keys: Arc<RwLock<Option<Keys>>>,
    /// How the last fetch ended. Held across the fetch, so the requests that need its keys
    /// wait for them rather than fetch their own. Behind an `Arc`, so the fetch's own task holds
    /// the guard.
    last: Arc<Mutex<Option<Attempt>>>,
}

struct Keys {
    by_kid: HashMap<String, DecodingKey>,
    /// When the request that fetched them was sent.
    sent: Instant,
}

struct Attempt {
    ended: Instant,
    failed: bool,
}

impl TeamKeys {
    pub(super) fn new(team: &Url, fetched: fn(usize)) -> Result<TeamKeys, BuildError> {
        let mut certs = team.clone();
        certs.set_path(CERTS);
        let http = reqwest::Client::builder()
            // A redirect on the certs URL could point key fetches anywhere.
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            // Only over https in a build without debug assertions; a debug build may fetch from a
            // fake team on plain http.
            .https_only(!cfg!(debug_assertions))
            .timeout(TIMEOUT)
            .build()
            // Building loads the CA certificates. The error is dropped unread, so no text of a
            // dependency's reaches the app's log.
            .map_err(|_| BuildError)?;
        Ok(TeamKeys {
            certs,
            issuer: team.origin().ascii_serialization(),
            http,
            fetched,
            keys: Arc::default(),
            last: Arc::default(),
        })
    }

    pub(super) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(super) fn watch(&self) -> KeysWatch {
        KeysWatch(Arc::clone(&self.keys))
    }

    /// The key named `kid`, or `None` when the team's keys lack it.
    pub(super) async fn key(self: &Arc<Self>, kid: &str) -> Result<Option<DecodingKey>, KeysError> {
        // A request that starts a fetch looks again once the fetch has ended, as one that waited
        // on it would, so every answer comes from the keys held and the floor.
        loop {
            if let Some(key) = self.held(kid) {
                return Ok(Some(key));
            }
            let last = Arc::clone(&self.last).lock_owned().await;
            // The keys may have been fetched while this request waited.
            if let Some(key) = self.held(kid) {
                return Ok(Some(key));
            }
            if let Some(attempt) = last.as_ref()
                && attempt.ended.elapsed() < REFETCH_AFTER
            {
                // A fetch that ended so recently and did not fail left keys that are trusted and
                // lack `kid`.
                return if attempt.failed {
                    Err(KeysError::Unavailable)
                } else {
                    Ok(None)
                };
            }
            // Spawned, so a request dropped while it waits here still lets the fetch record its
            // end and store its keys.
            match tokio::spawn(Arc::clone(self).refresh(last)).await {
                Ok(refreshed) => refreshed?,
                // A panic in the fetch, such as one in the `fetched` callback, unwinds this
                // request as it would if the fetch ran here.
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                // Only a runtime shutting down cancels the task, before its answer was read.
                Err(_) => return Err(KeysError::Fetch(FetchFailure::Broken)),
            }
        }
    }

    /// One fetch, holding `last` until it returns. It records how the fetch ended and stores the
    /// keys it found, so a request waiting on `last` sees both, and only then calls `fetched`, so
    /// a panic there costs neither.
    async fn refresh(
        self: Arc<Self>,
        mut last: OwnedMutexGuard<Option<Attempt>>,
    ) -> Result<(), KeysError> {
        let outcome = self.fetch().await;
        *last = Some(Attempt {
            ended: Instant::now(),
            failed: outcome.is_err(),
        });
        let keys = outcome?;
        let count = keys.by_kid.len();
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Some(keys);
        (self.fetched)(count);
        Ok(())
    }

    /// The key for `kid` among the keys held, while they are trusted.
    fn held(&self, kid: &str) -> Option<DecodingKey> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let held = keys.as_ref()?;
        if !trusted(held.sent.elapsed()) {
            return None;
        }
        held.by_kid.get(kid).cloned()
    }

    /// The team's keys that name a `kid` and that [`verifies_rs256`] takes. Any other key that
    /// parses as a JWK is left out, so it cannot cost the others, and none left is
    /// [`KeysError::NoKeys`]. One that does not parse, such as a `kid` that is not a string,
    /// fails the whole set as [`FetchFailure::NotJwks`].
    async fn fetch(&self) -> Result<Keys, KeysError> {
        // Taken before the request goes out, so a key withdrawn at any time after that stops
        // verifying within `MAX_AGE` of the withdrawal, however long the answer takes.
        let sent = Instant::now();
        let set = self.jwks().await.map_err(KeysError::Fetch)?;
        let by_kid: HashMap<_, _> = set
            .keys
            .iter()
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, DecodingKey::from_jwk(jwk).ok()?)))
            .filter(|(_, key)| verifies_rs256(key))
            .collect();
        if by_kid.is_empty() {
            return Err(KeysError::NoKeys);
        }
        Ok(Keys { by_kid, sent })
    }

    async fn jwks(&self) -> Result<JwkSet, FetchFailure> {
        let request = self.http.get(self.certs.clone());
        let response = request.send().await.map_err(failure)?;
        let status = response.status();
        // A redirect, which the client does not follow, is no answer either.
        if !status.is_success() {
            return Err(FetchFailure::Status(status));
        }
        response.json().await.map_err(failure)
    }
}

/// The HTTP client for the team's keys could not be built, as when the host's CA certificates
/// cannot be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the client for the Access team's keys could not be built")]
pub struct BuildError;

/// Why the team's keys could not be had.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    /// The fetch failed, at the step named.
    #[error("the team's keys could not be fetched: {0}")]
    Fetch(FetchFailure),
    /// The keys endpoint answered with no key that names a `kid` and that the RS256 verifier
    /// takes.
    #[error("the team's keys endpoint answered with no usable key")]
    NoKeys,
    /// The keys held do not serve the token, and the last fetch, which failed, ended too
    /// recently to try another.
    #[error("the team's keys are unavailable: the last fetch failed too recently to retry")]
    Unavailable,
}

/// Which step of a key fetch failed. It holds no text from the answer or the connection, only
/// the step and a status, so a log line cannot quote what the endpoint sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FetchFailure {
    /// No connection to the team, which covers DNS and TLS failures too.
    #[error("no connection to the team")]
    Connect,
    /// No whole answer within 10 seconds.
    #[error("no answer within 10 seconds")]
    Timeout,
    /// An answer whose status is not a success, a redirect among them.
    #[error("an answer of {0}")]
    Status(StatusCode),
    /// An answer whose body could not be read as a JWKS, whether it is not one or was cut short.
    #[error("an answer that could not be read as a JWKS")]
    NotJwks,
    /// A request that failed before its answer was read.
    #[error("a request that failed before its answer was read")]
    Broken,
}

/// The step at which `error` stopped a key fetch. Only the step goes further, never the error,
/// whose text can quote the URL or what the endpoint sent.
fn failure(error: reqwest::Error) -> FetchFailure {
    if error.is_timeout() {
        FetchFailure::Timeout
    } else if error.is_connect() {
        FetchFailure::Connect
    } else if error.is_decode() {
        FetchFailure::NotJwks
    } else {
        FetchFailure::Broken
    }
}

/// Reads the team's keys as held. It has no client and no fetch attempt, so nothing reached
/// through it fetches, waits for a fetch, or changes the cache.
#[derive(Clone)]
pub struct KeysWatch(Arc<RwLock<Option<Keys>>>);

/// The key cache as one reading of tokio's monotonic clock finds it. An age, never a
/// wall-clock time, so the cache's rule and a status page agree, and a test moves both with
/// `tokio::time::advance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysState {
    /// No fetch has found keys since the process started.
    NotYet,
    /// `count` keys, `age` old and still trusted: `age` is under [`MAX_AGE`].
    Trusted {
        /// How many keys.
        count: usize,
        /// How long ago the fetch that got them sent its request.
        age: Duration,
    },
    /// `count` keys, `age` old, which is [`MAX_AGE`] or more: no longer trusted.
    Expired {
        /// How many keys.
        count: usize,
        /// How long ago the fetch that got them sent its request.
        age: Duration,
    },
}

impl KeysWatch {
    /// One read lock and one reading of the clock. Never waits on a fetch, which holds the
    /// attempt's lock while it runs and takes this one only to store its keys.
    pub fn state(&self) -> KeysState {
        let keys = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let Some(keys) = keys.as_ref() else {
            return KeysState::NotYet;
        };
        let (count, age) = (keys.by_kid.len(), keys.sent.elapsed());
        if trusted(age) {
            KeysState::Trusted { count, age }
        } else {
            KeysState::Expired { count, age }
        }
    }
}

/// Whether the RS256 verifier would take `key`. jsonwebtoken passes an RSA JWK's modulus and
/// exponent bytes as they are to aws-lc-rs, which verifies with `RSA_PKCS1_2048_8192_SHA256`,
/// and three checks on the way refuse a key:
///
/// - each number is at least one byte, with no leading zero byte (aws-lc-rs `src/rsa/key.rs`,
///   `public_component_to_bn`),
/// - the modulus has 2048 to 8192 bits (aws-lc-rs `src/rsa/signature.rs`,
///   `verify_rsa_signature`, with the algorithm's `bit_size_range`),
/// - the modulus is odd, and the exponent is odd with 2 to 33 bits (aws-lc
///   `crypto/fipsmodule/rsa/rsa.c`, `is_public_component_of_rsa_key_good`).
///
/// A key it would refuse never replaces keys it takes.
fn verifies_rs256(key: &DecodingKey) -> bool {
    let DecodingKeyKind::RsaModulusExponent { n, e } = key.kind() else {
        return false;
    };
    // A number's bit length, or `None` for one the first check refuses: empty, or with a
    // leading zero byte.
    let bits_if_minimal = |number: &[u8]| match number.first() {
        Some(&high) if high != 0 => Some(number.len() * 8 - high.leading_zeros() as usize),
        _ => None,
    };
    let odd = |number: &[u8]| number.last().is_some_and(|low| low % 2 == 1);
    bits_if_minimal(n).is_some_and(|bits| (2048..=8192).contains(&bits))
        && bits_if_minimal(e).is_some_and(|bits| (2..=33).contains(&bits))
        && odd(n)
        && odd(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two keys as a fetch would leave them, sent now by tokio's clock.
    fn two_keys() -> Keys {
        let key = || DecodingKey::from_secret(b"not an RSA key; only counted here");
        Keys {
            by_kid: HashMap::from([("k1".to_owned(), key()), ("k2".to_owned(), key())]),
            sent: Instant::now(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_watch_reads_the_caches_own_keys_by_tokios_clock_and_expires_them_at_max_age() {
        let team = TeamKeys::new(&Url::parse("https://team.test/").unwrap(), |_| {}).unwrap();
        let watch = team.watch();
        assert_eq!(watch.state(), KeysState::NotYet);
        *team.keys.write().unwrap() = Some(two_keys());
        let trusted_at_age = |age| KeysState::Trusted { count: 2, age };
        assert_eq!(watch.state(), trusted_at_age(Duration::ZERO));
        tokio::time::advance(Duration::from_secs(12 * 60)).await;
        assert_eq!(watch.state(), trusted_at_age(Duration::from_secs(12 * 60)));
        tokio::time::advance(MAX_AGE - Duration::from_secs(12 * 60 + 1)).await;
        assert_eq!(
            watch.state(),
            trusted_at_age(MAX_AGE - Duration::from_secs(1))
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            watch.state(),
            KeysState::Expired {
                count: 2,
                age: MAX_AGE
            }
        );
    }

    /// Fetches from a fake keys endpoint on plain http, which only a build with debug assertions
    /// may fetch from (`TeamKeys::new`), so a `--release` test run leaves these out.
    #[cfg(debug_assertions)]
    mod http_team {
        use super::*;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::{mpsc, oneshot};
        use tokio::task::JoinHandle;

        /// The team's keys endpoint as a test plays it, on 127.0.0.1. Each fetch arrives as a
        /// reply for the test to send, so the test decides when each fetch is answered, and how.
        struct Cloudflare {
            url: Url,
            fetches: mpsc::UnboundedReceiver<oneshot::Sender<String>>,
        }

        impl Cloudflare {
            async fn start() -> Cloudflare {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}/", listener.local_addr().unwrap());
                let (arrived, fetches) = mpsc::unbounded_channel();
                tokio::spawn(async move {
                    while let Ok((socket, _)) = listener.accept().await {
                        tokio::spawn(serve(socket, arrived.clone()));
                    }
                });
                Cloudflare {
                    url: Url::parse(&url).unwrap(),
                    fetches,
                }
            }

            /// A cache whose keys are this endpoint's.
            fn team(&self, fetched: fn(usize)) -> Arc<TeamKeys> {
                Arc::new(TeamKeys::new(&self.url, fetched).unwrap())
            }

            /// The next fetch, once it has reached the endpoint, as the reply to send it.
            async fn fetch(&mut self) -> oneshot::Sender<String> {
                let next = tokio::time::timeout(Duration::from_secs(5), self.fetches.recv());
                next.await.expect("a fetch reaches the endpoint").unwrap()
            }

            /// Whether no fetch has reached the endpoint since the last one taken.
            fn quiet(&mut self) -> bool {
                self.fetches.try_recv().is_err()
            }
        }

        /// Reads one request's head, hands its reply to the test, and writes what the test sends.
        async fn serve(
            mut socket: TcpStream,
            arrived: mpsc::UnboundedSender<oneshot::Sender<String>>,
        ) {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => head.extend_from_slice(&chunk[..read]),
                }
            }
            let (reply, answer) = oneshot::channel();
            if arrived.send(reply).is_ok()
                && let Ok(response) = answer.await
            {
                // The test may have let the request go, and its connection with it.
                socket.write_all(response.as_bytes()).await.ok();
            }
        }

        /// A JWKS with one RSA key the RS256 verifier takes per kid. Each modulus is 2048 one
        /// bits, which is no real key's, but nothing here checks a signature.
        fn jwks(kids: &[&str]) -> String {
            let modulus = format!("{}w", "_".repeat(341));
            let keys: Vec<String> = kids
                .iter()
                .map(|kid| format!(r#"{{"kty":"RSA","kid":"{kid}","n":"{modulus}","e":"AQAB"}}"#))
                .collect();
            format!(r#"{{"keys":[{}]}}"#, keys.join(","))
        }

        /// An answer with the keys named `kids`.
        fn keys(kids: &[&str]) -> String {
            let body = jwks(kids);
            let length = body.len();
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n{body}"
            )
        }

        /// An answer that is no success.
        const FAILING: &str =
            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

        /// A request for the key `kid`, on a task of its own, as a handler's call is.
        fn request(team: &Arc<TeamKeys>, kid: &'static str) -> JoinHandle<KeyAnswer> {
            let team = Arc::clone(team);
            tokio::spawn(async move { team.key(kid).await })
        }

        type KeyAnswer = Result<Option<DecodingKey>, KeysError>;

        /// How `request` ends, which it must within 5 seconds.
        async fn answer(
            request: JoinHandle<KeyAnswer>,
        ) -> Result<KeyAnswer, tokio::task::JoinError> {
            let ended = tokio::time::timeout(Duration::from_secs(5), request);
            ended.await.expect("the request is answered")
        }

        /// A request for k1 that starts a fetch and is dropped, as its client going away drops
        /// it, while the fetch waits for its answer. The fetch's reply.
        async fn dropped_mid_fetch(
            team: &Arc<TeamKeys>,
            cloudflare: &mut Cloudflare,
        ) -> oneshot::Sender<String> {
            let first = request(team, "k1");
            let reply = cloudflare.fetch().await;
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
            reply
        }

        /// Moves tokio's clock, which the cache reads, on by `by`.
        async fn later(by: Duration) {
            tokio::time::pause();
            tokio::time::advance(by).await;
            tokio::time::resume();
        }

        #[tokio::test]
        async fn keys_are_trusted_for_max_age_from_when_their_request_was_sent() {
            let mut cloudflare = Cloudflare::start().await;
            let team = cloudflare.team(|_| {});
            let first = request(&team, "k1");
            let reply = cloudflare.fetch().await;
            // The request was sent before it reached the endpoint, so before this.
            let reached = Instant::now();
            // Cloudflare answers five seconds, by tokio's clock, after the request reached it.
            later(Duration::from_secs(5)).await;
            reply.send(keys(&["k1"])).unwrap();
            assert!(answer(first).await.unwrap().unwrap().is_some());
            tokio::time::pause();
            let since_reached = reached.elapsed();
            let KeysState::Trusted { age, .. } = team.watch().state() else {
                panic!("the keys fetched are trusted");
            };
            // Both ages are of the one paused instant, so however long the test took to get here,
            // keys stamped at the answer would be five seconds younger than `since_reached`.
            assert!(
                age >= since_reached,
                "aged from the send: {age:?}, reached {since_reached:?} ago"
            );

            // Cloudflare withdraws k1. `MAX_AGE` after the request was sent, though not yet after
            // its answer came, k1 is past trusting, and the keys fetched again lack it.
            tokio::time::advance(MAX_AGE - age).await;
            tokio::time::resume();
            let next = request(&team, "k1");
            cloudflare.fetch().await.send(keys(&["k2"])).unwrap();
            assert!(answer(next).await.unwrap().unwrap().is_none());
            assert!(cloudflare.quiet());
        }

        #[tokio::test]
        async fn a_fetch_whose_request_is_dropped_runs_to_its_end_and_holds_off_the_next() {
            let mut cloudflare = Cloudflare::start().await;
            let team = cloudflare.team(|_| {});
            let reply = dropped_mid_fetch(&team, &mut cloudflare).await;

            // The next request waits for that fetch and gets k1 from it, and a kid its keys lack
            // is refused in the minute after it, with no fetch of its own.
            let next = request(&team, "k1");
            reply.send(keys(&["k1"])).unwrap();
            assert!(answer(next).await.unwrap().unwrap().is_some());
            let forged = answer(request(&team, "forged")).await.unwrap();
            assert!(forged.unwrap().is_none());
            assert!(cloudflare.quiet());
        }

        #[tokio::test]
        async fn a_failing_fetch_whose_request_is_dropped_still_holds_off_the_next() {
            let mut cloudflare = Cloudflare::start().await;
            let team = cloudflare.team(|_| {});
            let reply = dropped_mid_fetch(&team, &mut cloudflare).await;

            // The next request waits for that fetch, and in the minute after it is refused as
            // unavailable, the keys endpoint's fault, with no fetch of its own.
            let next = request(&team, "k1");
            reply.send(FAILING.to_owned()).unwrap();
            let refused = answer(next).await.unwrap();
            assert_eq!(refused.err(), Some(KeysError::Unavailable));
            assert!(cloudflare.quiet());
        }

        #[tokio::test]
        async fn a_panic_in_the_fetched_callback_reaches_the_request_and_keeps_the_fetch() {
            let mut cloudflare = Cloudflare::start().await;
            let team = cloudflare.team(|_| panic!("the app's fetched callback"));
            let first = request(&team, "k1");
            cloudflare.fetch().await.send(keys(&["k1"])).unwrap();
            let panic = answer(first).await.unwrap_err().into_panic();
            assert_eq!(
                *panic.downcast::<&str>().unwrap(),
                "the app's fetched callback"
            );

            // The fetch was recorded and its keys stored before the callback ran: k1 is served
            // from them, and a kid they lack is refused in the minute after, with no fetch.
            assert!(
                answer(request(&team, "k1"))
                    .await
                    .unwrap()
                    .unwrap()
                    .is_some()
            );
            let forged = answer(request(&team, "forged")).await.unwrap();
            assert!(forged.unwrap().is_none());
            assert!(cloudflare.quiet());
        }
    }
}
