//! The team's signing keys, and the cache that holds them.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use http::StatusCode;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, DecodingKeyKind};
use tokio::sync::Mutex;
use tokio::time::Instant;
use url::Url;

/// Where an Access team publishes its signing keys.
const CERTS: &str = "/cdn-cgi/access/certs";

/// How long fetched keys are trusted: a key the team withdraws stops verifying within it.
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

/// Whether keys fetched `age` ago are still trusted. The one rule the cache and [`KeysWatch`]
/// share.
fn trusted(age: Duration) -> bool {
    age < MAX_AGE
}

/// The team's keys: fetched when a token first needs one, trusted for [`MAX_AGE`] after the
/// fetch that got them, and fetched again for a `kid` they lack or once that is up, but never
/// sooner than [`REFETCH_AFTER`] after the last fetch ended. A fetch that fails or finds no
/// usable key keeps the keys held, which stay trusted only until their own [`MAX_AGE`] is up.
/// Both clocks are tokio's monotonic `Instant`, so a wall-clock step cannot cut the floor
/// short.
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
    /// wait for them rather than fetch their own.
    last: Mutex<Option<Attempt>>,
}

struct Keys {
    by_kid: HashMap<String, DecodingKey>,
    fetched: Instant,
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
            last: Mutex::default(),
        })
    }

    pub(super) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(super) fn watch(&self) -> KeysWatch {
        KeysWatch(Arc::clone(&self.keys))
    }

    /// The key named `kid`, or `None` when the team's keys lack it.
    pub(super) async fn key(&self, kid: &str) -> Result<Option<DecodingKey>, KeysError> {
        if let Some(key) = self.held(kid) {
            return Ok(Some(key));
        }
        let mut last = self.last.lock().await;
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
        let fetched = self.fetch().await;
        // Recorded only once the fetch has ended, so a request dropped during it, its client
        // gone or the process stopping, leaves the next free to fetch.
        *last = Some(Attempt {
            ended: Instant::now(),
            failed: fetched.is_err(),
        });
        let keys = fetched?;
        let key = keys.by_kid.get(kid).cloned();
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Some(keys);
        Ok(key)
    }

    /// The key for `kid` among the keys held, while they are trusted.
    fn held(&self, kid: &str) -> Option<DecodingKey> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let held = keys.as_ref()?;
        if !trusted(held.fetched.elapsed()) {
            return None;
        }
        held.by_kid.get(kid).cloned()
    }

    /// The team's keys that name a `kid` and that [`verifies_rs256`] takes. Any other key that
    /// parses as a JWK is left out, so it cannot cost the others, and none left is
    /// [`KeysError::NoKeys`]. One that does not parse, such as a `kid` that is not a string,
    /// fails the whole set as [`FetchFailure::NotJwks`].
    async fn fetch(&self) -> Result<Keys, KeysError> {
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
        (self.fetched)(by_kid.len());
        Ok(Keys {
            by_kid,
            fetched: Instant::now(),
        })
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
    /// `count` keys, fetched `age` ago and still trusted: `age` is under [`MAX_AGE`].
    Trusted {
        /// How many keys.
        count: usize,
        /// How long ago they were fetched.
        age: Duration,
    },
    /// `count` keys, fetched `age` ago, which is [`MAX_AGE`] or more: no longer trusted.
    Expired {
        /// How many keys.
        count: usize,
        /// How long ago they were fetched.
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
        let (count, age) = (keys.by_kid.len(), keys.fetched.elapsed());
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

    /// Two keys as a fetch would leave them, fetched now by tokio's clock.
    fn two_keys() -> Keys {
        let key = || DecodingKey::from_secret(b"not an RSA key; only counted here");
        Keys {
            by_kid: HashMap::from([("k1".to_owned(), key()), ("k2".to_owned(), key())]),
            fetched: Instant::now(),
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
}
