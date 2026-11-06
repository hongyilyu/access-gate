//! An admin page's gate, for an app that sits behind an identity-aware proxy.
//!
//! [`AdminGate`] is the page's whole decision. A write must come from the app's own origin,
//! and every request must pass the gate's [`Auth`], the way it tells a signed-in operator
//! from a stranger. What passes is an [`Admission`]. What does not is a [`Refusal`], whose
//! [`Refusal::status`] is the answer.
//!
//! Each way to authenticate is an [`Auth`] variant, with its own module:
//!
//! - [`Auth::Cloudflare`]: Cloudflare Access's JWT, checked again in the app ([`cloudflare`]).
//!   The module also verifies service tokens, for a gate of the app's own.
//! - [`Auth::Skip`]: no check at all, in a debug build only.
//!
//! [`sent_from`] says which origin a request claims to come from, for a gate with its own rule.
//!
//! The crate writes no log line. A refusal names only the check that failed, never a byte of a
//! token nor text from a keys endpoint or the HTTP client, so an app can log any of them as
//! they are.

pub mod cloudflare;

use http::header::{ORIGIN, REFERER};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use url::{Origin, Url};

/// How an [`AdminGate`] tells a signed-in operator from a stranger.
pub enum Auth {
    /// A login to the admin application in Cloudflare Access, by the JWT Access forwards. It
    /// reads no claim beyond the four a login must carry: who may sign in is the application's
    /// Allow policy, the one check of identity, so a token that verifies is theirs, whatever its
    /// email, or none.
    Cloudflare(cloudflare::Login),
    /// Every request is the operator's, and nothing is read: for a debug build with no proxy in
    /// front. A build of this crate without debug assertions, as `--release` makes it, has no
    /// such variant, so the bypass cannot reach a deployed binary. An app gates its own use of
    /// it on its own `cfg(debug_assertions)`, and never matches on `Auth`, since a test profile
    /// may turn debug assertions off for the app alone.
    #[cfg(debug_assertions)]
    Skip,
}

impl Auth {
    async fn check(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        match self {
            Auth::Cloudflare(login) => Ok(login.verify(headers).await?),
            #[cfg(debug_assertions)]
            Auth::Skip => Ok(()),
        }
    }
}

/// An admin page's gate. [`AdminGate::admit`] decides in this order:
///
/// 1. For any method but GET and HEAD, the request must send an `Origin`, or a `Referer` when
///    it sends no `Origin`, and every one must name the app's origin, or the answer is
///    [`Refusal::CrossOrigin`]. A proxy's session cookie may be `SameSite=None`, as Cloudflare
///    Access's is, so authentication alone would let another site's form post arrive signed in.
///    This check comes first, so a forged write costs the [`Auth`] nothing, such as a key
///    fetch.
/// 2. The gate's [`Auth`].
pub struct AdminGate {
    /// The origin a write must come from.
    origin: Origin,
    auth: Auth,
}

impl AdminGate {
    /// The gate for an admin page served at `origin`, which admits who `auth` admits. Fetches
    /// nothing yet.
    pub fn new(auth: Auth, origin: Origin) -> AdminGate {
        AdminGate { origin, auth }
    }

    /// Admits a request with `method` and `headers`, or says why not, in the order the type
    /// names. It reads only the method and the headers, so it runs before any of the body is
    /// read.
    pub async fn admit(&self, method: &Method, headers: &HeaderMap) -> Result<Admission, Refusal> {
        let writes = !matches!(*method, Method::GET | Method::HEAD);
        if writes && sent_from(headers, &self.origin) != SentFrom::Here {
            return Err(Refusal::CrossOrigin);
        }
        self.auth.check(headers).await?;
        Ok(if writes {
            Admission::Write(Write(()))
        } else {
            Admission::Read
        })
    }
}

/// What [`AdminGate::admit`] lets an admitted request do. Only `admit` makes one.
#[must_use]
#[derive(Debug)]
pub enum Admission {
    /// GET or HEAD: read a page or an asset. It holds no [`Write`], so nothing that needs one
    /// can run on it.
    Read,
    /// Any other method, sent from the app's origin by someone the [`Auth`] admits: one write,
    /// which spends the [`Write`].
    Write(Write),
}

/// Proof that the gate admitted a write. Only [`AdminGate::admit`] makes one, since its field
/// is private to this crate. Not `Clone` or `Copy`, so an app whose writes each take one by
/// value makes at most one write per admission.
#[derive(Debug)]
pub struct Write(());

/// Why an [`AdminGate`] refused a request: its own check, or its [`Auth`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// A write whose `Origin`, or whose `Referer` when it sends no `Origin`, names another
    /// origin, `null`, or something that is not a URL, or that sends neither.
    #[error("a write whose Origin or Referer names another origin, or none")]
    CrossOrigin,
    /// [`Auth::Cloudflare`] did not verify the request's login.
    #[error(transparent)]
    Cloudflare(#[from] cloudflare::VerifyError),
}

impl Refusal {
    /// 403 for another origin, and the [`Auth`]'s own status otherwise. Every variant is named,
    /// so a new one has to be placed.
    pub fn status(&self) -> StatusCode {
        match self {
            Refusal::CrossOrigin => StatusCode::FORBIDDEN,
            Refusal::Cloudflare(error) => error.status(),
        }
    }
}

/// Which origin a request claims to come from, by [`sent_from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentFrom {
    /// It sends neither an `Origin` nor a `Referer`, as an app that is not a browser does.
    Nowhere,
    /// Every `Origin` it sends, or every `Referer` when it sends no `Origin`, names the origin.
    Here,
    /// At least one names another origin, `null`, or something that is not a URL.
    Elsewhere,
}

/// What `headers` say of where a request came from, against `origin`. Each `Origin` header is
/// read, or each `Referer` when there is no `Origin`, and every one must name `origin`, so a
/// gate never has to pick which to believe. A value names `origin` when it is UTF-8, parses as
/// a URL, and has the same scheme, host, and port, a default port written or not.
pub fn sent_from(headers: &HeaderMap, origin: &Origin) -> SentFrom {
    let named = if headers.contains_key(ORIGIN) {
        ORIGIN
    } else {
        REFERER
    };
    let mut sent = headers.get_all(named).iter().peekable();
    if sent.peek().is_none() {
        SentFrom::Nowhere
    } else if sent.all(|value| names(origin, value)) {
        SentFrom::Here
    } else {
        SentFrom::Elsewhere
    }
}

fn names(origin: &Origin, value: &HeaderValue) -> bool {
    value
        .to_str()
        .ok()
        .and_then(|value| Url::parse(value).ok())
        .is_some_and(|url| url.origin() == *origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Url::parse("https://app.test").unwrap().origin()
    }

    fn headers(sent: &[(http::HeaderName, HeaderValue)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in sent.iter().cloned() {
            headers.append(name, value);
        }
        headers
    }

    #[test]
    fn every_origin_or_else_every_referer_must_name_the_origin() {
        use SentFrom::{Elsewhere, Here, Nowhere};
        let o = |value: &str| (ORIGIN, HeaderValue::from_str(value).unwrap());
        let r = |value: &str| (REFERER, HeaderValue::from_str(value).unwrap());
        let not_text = HeaderValue::from_bytes(b"https://app.test\xff").unwrap();
        for (sent, expected) in [
            (vec![], Nowhere),
            (vec![o("https://app.test")], Here),
            (vec![o("https://app.test:443")], Here),
            (vec![r("https://app.test/admin/clients")], Here),
            (vec![o("https://app.test"), o("https://app.test")], Here),
            // The Referer is not read when there is an Origin.
            (
                vec![o("https://app.test"), r("https://evil.example/")],
                Here,
            ),
            (vec![o("null")], Elsewhere),
            (vec![o("https://evil.example")], Elsewhere),
            (vec![o("http://app.test")], Elsewhere),
            (vec![o("https://app.test.evil.example")], Elsewhere),
            (vec![o("https://app.test:8443")], Elsewhere),
            (
                vec![o("https://app.test"), o("https://evil.example")],
                Elsewhere,
            ),
            (
                vec![o("https://evil.example"), r("https://app.test/")],
                Elsewhere,
            ),
            (vec![r("https://evil.example/admin")], Elsewhere),
            (vec![r("/admin")], Elsewhere),
            (vec![(ORIGIN, not_text)], Elsewhere),
        ] {
            assert_eq!(sent_from(&headers(&sent), &origin()), expected, "{sent:?}");
        }
    }

    /// Runs without debug assertions too. The team is unreachable, so a test that got as far as
    /// a key fetch would fail with `Keys`, not the refusal it expects.
    #[tokio::test]
    async fn a_write_from_elsewhere_is_refused_before_the_token_and_a_read_needs_one() {
        let url = Url::parse("https://127.0.0.1:1/").unwrap();
        let team = cloudflare::Team::new(&url, |_| panic!("no fetch")).unwrap();
        let gate = AdminGate::new(Auth::Cloudflare(team.login("admin")), origin());
        let elsewhere = headers(&[(ORIGIN, HeaderValue::from_static("https://evil.example"))]);
        let refused = gate.admit(&Method::POST, &elsewhere).await.unwrap_err();
        assert_eq!(refused, Refusal::CrossOrigin);
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let here = headers(&[(ORIGIN, HeaderValue::from_static("https://app.test"))]);
        for (method, sent) in [(Method::GET, &elsewhere), (Method::POST, &here)] {
            let refused = gate.admit(&method, sent).await.unwrap_err();
            assert_eq!(
                refused,
                Refusal::Cloudflare(cloudflare::VerifyError::NoToken),
                "{method}"
            );
            assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "{method}");
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_gate_that_skips_auth_still_refuses_a_write_from_elsewhere() {
        let gate = AdminGate::new(Auth::Skip, origin());
        let none = HeaderMap::new();
        let here = headers(&[(ORIGIN, HeaderValue::from_static("https://app.test"))]);
        let elsewhere = headers(&[(ORIGIN, HeaderValue::from_static("https://evil.example"))]);
        assert!(matches!(
            gate.admit(&Method::GET, &none).await,
            Ok(Admission::Read)
        ));
        assert!(matches!(
            gate.admit(&Method::HEAD, &elsewhere).await,
            Ok(Admission::Read)
        ));
        assert!(matches!(
            gate.admit(&Method::POST, &here).await,
            Ok(Admission::Write(_))
        ));
        for sent in [&none, &elsewhere] {
            let refused = gate.admit(&Method::POST, sent).await.unwrap_err();
            assert_eq!(refused, Refusal::CrossOrigin);
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        }
    }
}
