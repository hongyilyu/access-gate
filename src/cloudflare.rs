//! Cloudflare Access, checked again by the app behind it.
//!
//! Access checks a login, or a service token's `CF-Access-Client-Id` and
//! `CF-Access-Client-Secret`, before a request reaches the app, and forwards a signed JWT in
//! `Cf-Access-Jwt-Assertion`. The app checks that JWT again, so a tunnel or Access
//! misconfiguration cannot open a path by itself.
//!
//! - [`Team`] holds one Access team's signing keys: fetched when a token first needs one,
//!   trusted for [`MAX_AGE`], and fetched again at most once a minute. Every check an app makes
//!   against the team goes through one `Team` and its clones, so one floor holds for them all.
//! - [`Login`], from [`Team::login`], verifies a person's login to one Access application, as
//!   [`crate::Auth::Cloudflare`] does for an admin page.
//! - [`ServiceToken`], from [`Team::service_token`], verifies a service token's, for a gate of
//!   the app's own.
//!
//! A token is believed only once it is RS256, signed by one of the team's keys, issued by the
//! team's origin, names the application's audience, and is inside its `nbf` to `exp` window,
//! with 10 seconds of leeway.

mod keys;

use std::sync::Arc;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::de::{DeserializeOwned, IgnoredAny};
use url::Url;

use keys::TeamKeys;
pub use keys::{BuildError, FetchFailure, KeysError, KeysState, KeysWatch, MAX_AGE};

/// The header Access forwards its JWT in.
const ASSERTION: HeaderName = HeaderName::from_static("cf-access-jwt-assertion");

/// How far, in seconds, a token's `exp` may be past, and its `nbf` ahead, for Cloudflare's
/// clock and the host's to disagree. A host clock behind by more than this admits tokens that
/// far past their `exp`, so a unit should wait for time sync before it serves.
const LEEWAY: u64 = 10;

/// The claims a person's login must carry: each one left out would skip its check.
const LOGIN: &[&str] = &["exp", "nbf", "iss", "aud"];

/// The claims a service token must carry. Not `nbf`, since a service token has none; one that
/// is present is checked.
const SERVICE_TOKEN: &[&str] = &["exp", "iss", "aud"];

/// One Access team, by its signing keys. Clones share the keys, and the floor on fetching them.
#[derive(Clone)]
pub struct Team(Arc<TeamKeys>);

impl Team {
    /// The team at `url` (`https://{team}.cloudflareaccess.com/`), whose tokens are issued by
    /// its origin and whose keys are at `/cdn-cgi/access/certs` under it. Each fetch that finds
    /// keys calls `fetched` with how many. Fetches nothing yet.
    ///
    /// The keys come only from `url` with its path replaced: no redirect is followed and no
    /// proxy is taken from the environment, so the URL alone decides where they come from. In a
    /// build of this crate without debug assertions, as `--release` makes it, they come only over
    /// https, so an `http://` team fails its first fetch; a debug build may use a fake team on
    /// plain http for tests.
    pub fn new(url: &Url, fetched: fn(usize)) -> Result<Team, BuildError> {
        Ok(Team(Arc::new(TeamKeys::new(url, fetched)?)))
    }

    /// The verifier of logins to the Access application whose audience (its AUD tag) is
    /// `audience`.
    pub fn login(&self, audience: &str) -> Login {
        Login(Verifier::new(self, audience, LOGIN))
    }

    /// The verifier of service tokens for the Access application whose audience is `audience`.
    pub fn service_token(&self, audience: &str) -> ServiceToken {
        ServiceToken(Verifier::new(self, audience, SERVICE_TOKEN))
    }

    /// A reader of the team's keys as held, which never fetches, for a status page.
    pub fn watch(&self) -> KeysWatch {
        self.0.watch()
    }
}

/// Verifies a person's login to one Access application: `exp`, `nbf`, `iss`, and `aud` are
/// each required. A service token for the same application has no `nbf`, so it fails here.
pub struct Login(Verifier);

/// Verifies a service token for one Access application: as a [`Login`], but with `nbf` checked
/// only when present.
pub struct ServiceToken(Verifier);

impl Login {
    /// `Ok` once the request's one `Cf-Access-Jwt-Assertion` checks out. No claim is read past
    /// the four required.
    pub(crate) async fn verify(&self, headers: &HeaderMap) -> Result<(), VerifyError> {
        self.0.verify::<IgnoredAny>(headers).await.map(drop)
    }
}

impl ServiceToken {
    /// The claims of the request's one `Cf-Access-Jwt-Assertion`, as `C`, once it checks out.
    /// Claims that do not parse as `C` are [`TokenError::Malformed`].
    pub async fn verify<C: DeserializeOwned>(&self, headers: &HeaderMap) -> Result<C, VerifyError> {
        self.0.verify(headers).await
    }
}

/// What both kinds of token share: the team's keys, and what a token must pass.
struct Verifier {
    keys: Arc<TeamKeys>,
    /// Boxed, so a [`Login`] is two pointers, and `crate::Auth` stays small beside its
    /// variants that hold nothing.
    validation: Box<Validation>,
}

impl Verifier {
    /// RS256, each of `required`, `nbf` checked when present, [`LEEWAY`] seconds of leeway,
    /// `iss` the team's origin, and some `aud` entry equal to `audience`.
    fn new(team: &Team, audience: &str, required: &[&str]) -> Verifier {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(required);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY;
        validation.set_issuer(&[team.0.issuer()]);
        validation.set_audience(&[audience]);
        Verifier {
            keys: Arc::clone(&team.0),
            validation: Box::new(validation),
        }
    }

    async fn verify<C: DeserializeOwned>(&self, headers: &HeaderMap) -> Result<C, VerifyError> {
        let token = assertion(headers).ok_or(VerifyError::NoToken)?.as_bytes();
        let header = decode_header(token).map_err(|_| TokenError::Malformed)?;
        let kid = header.kid.ok_or(TokenError::Malformed)?;
        // Before the keys, so a token no key could verify never costs a fetch.
        if header.alg != Algorithm::RS256 {
            return Err(TokenError::Invalid(Check::Algorithm).into());
        }
        let key = self.keys.key(&kid).await?.ok_or(TokenError::UnknownKey)?;
        let data = decode::<C>(token, &key, &self.validation).map_err(|e| rejection(e.kind()))?;
        Ok(data.claims)
    }
}

/// The request's one `Cf-Access-Jwt-Assertion`, or `None` when it sends none or more than one,
/// so a gate never has to pick which to believe.
fn assertion(headers: &HeaderMap) -> Option<&HeaderValue> {
    let mut sent = headers.get_all(ASSERTION).iter();
    match (sent.next(), sent.next()) {
        (Some(one), None) => Some(one),
        _ => None,
    }
}

/// Why a request's JWT was not believed: none to check, the token's fault, or the keys
/// endpoint's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// No `Cf-Access-Jwt-Assertion`, or more than one.
    #[error("no Cf-Access-Jwt-Assertion, or more than one")]
    NoToken,
    /// The JWT did not verify: the caller's fault.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The keys to verify it with could not be had: the keys endpoint's fault, not the
    /// caller's.
    #[error(transparent)]
    Keys(#[from] KeysError),
}

impl VerifyError {
    /// 401 for the caller's token, and 503 for the keys, whose fault is not the caller's.
    pub fn status(&self) -> StatusCode {
        match self {
            VerifyError::NoToken | VerifyError::Token(_) => StatusCode::UNAUTHORIZED,
            VerifyError::Keys(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Why a JWT was not believed. No variant holds the `kid`, which is part of the JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Not a JWT, a header with no `kid`, or claims that do not parse as the caller's.
    #[error("a token that does not parse or names no kid")]
    Malformed,
    /// A `kid` the team's keys lack, after the fetch the floor allows.
    #[error("a kid that is not among the team's keys")]
    UnknownKey,
    /// A check the token failed.
    #[error("a token with {0}")]
    Invalid(Check),
}

/// The check a token failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Check {
    /// An algorithm other than RS256, refused before any key is looked up.
    #[error("an algorithm other than RS256")]
    Algorithm,
    /// A signature the key its `kid` names did not make.
    #[error("a bad signature")]
    Signature,
    /// An `exp` more than the leeway past.
    #[error("an exp that has passed")]
    Expired,
    /// An `nbf` more than the leeway ahead.
    #[error("an nbf still to come")]
    Immature,
    /// An `iss` other than the team's origin.
    #[error("another issuer")]
    Issuer,
    /// No `aud` entry equal to the application's.
    #[error("another audience")]
    Audience,
    /// No `exp`, `iss`, or `aud`, or for a login no `nbf`.
    #[error("a required claim missing")]
    MissingClaim,
}

/// What a token is refused as when `decode` refuses it: the check it failed, or `Malformed`
/// for anything else, claims that do not parse among them.
fn rejection(kind: &ErrorKind) -> TokenError {
    let check = match kind {
        ErrorKind::InvalidSignature => Check::Signature,
        ErrorKind::ExpiredSignature => Check::Expired,
        ErrorKind::ImmatureSignature => Check::Immature,
        ErrorKind::InvalidIssuer => Check::Issuer,
        ErrorKind::InvalidAudience => Check::Audience,
        ErrorKind::MissingRequiredClaim(_) => Check::MissingClaim,
        _ => return TokenError::Malformed,
    };
    TokenError::Invalid(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verifier_of_a_team_and_its_clones_holds_the_one_key_cache() {
        let team = Team::new(&Url::parse("https://team.test/").unwrap(), |_| {}).unwrap();
        let login = team.login("admin");
        let service = team.clone().service_token("upload");
        assert!(Arc::ptr_eq(&login.0.keys, &service.0.keys));
        assert!(Arc::ptr_eq(&login.0.keys, &team.0));
    }

    #[test]
    fn the_issuer_is_the_teams_origin_whatever_path_its_url_has() {
        let team = Team::new(&Url::parse("https://team.test/some/path").unwrap(), |_| {}).unwrap();
        assert_eq!(team.0.issuer(), "https://team.test");
    }
}
