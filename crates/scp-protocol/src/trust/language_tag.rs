//! BCP 47 language-tag well-formedness (RFC 5646 §2.1, §2.2.9).
//!
//! The `multilingual/v1` challenge standard (spec 07 §7.3.4.3) requires each
//! test case's `category` to be a BCP 47 language tag. The check here is
//! syntactic: a tag is well-formed when it matches the RFC 5646 `Language-Tag`
//! ABNF. Validity against the IANA subtag registry is not checked.

/// The RFC 5646 §2.2.8 grandfathered tags, lowercase. They match the
/// `grandfathered` production and none of the others.
const GRANDFATHERED: [&str; 26] = [
    // irregular
    "en-gb-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-be-fr",
    "sgn-be-nl",
    "sgn-ch-de",
    // regular
    "art-lojban",
    "cel-gaulish",
    "no-bok",
    "no-nyn",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang",
];

fn is_alpha(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_digit(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

fn is_alphanum(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `extlang = 3ALPHA`
fn is_extlang(s: &str) -> bool {
    s.len() == 3 && is_alpha(s)
}

/// `script = 4ALPHA`
fn is_script(s: &str) -> bool {
    s.len() == 4 && is_alpha(s)
}

/// `region = 2ALPHA / 3DIGIT`
fn is_region(s: &str) -> bool {
    (s.len() == 2 && is_alpha(s)) || (s.len() == 3 && is_digit(s))
}

/// `variant = 5*8alphanum / (DIGIT 3alphanum)`
fn is_variant(s: &str) -> bool {
    ((5..=8).contains(&s.len()) && is_alphanum(s))
        || (s.len() == 4 && s.as_bytes()[0].is_ascii_digit() && is_alphanum(s))
}

/// `singleton = DIGIT / ALPHA except "x"`
fn is_singleton(s: &str) -> bool {
    s.len() == 1 && is_alphanum(s) && !s.eq_ignore_ascii_case("x")
}

/// Returns `true` when `tag` is a well-formed BCP 47 language tag.
///
/// `en-US`, `zh-Hant-TW` and `x-private` are well-formed; `en_US` (underscore
/// separator), a language subtag of 9 letters, an empty string, and a tag with
/// an empty subtag (`en--US`) are not. Comparison is ASCII case-insensitive.
pub fn is_well_formed_language_tag(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    if GRANDFATHERED.contains(&lower.as_str()) {
        return true;
    }
    let subtags: Vec<&str> = lower.split('-').collect();
    if subtags
        .iter()
        .any(|s| s.is_empty() || s.len() > 8 || !is_alphanum(s))
    {
        return false;
    }
    let mut rest = subtags.as_slice();

    // Language-Tag = privateuse
    if rest[0] == "x" {
        return is_privateuse_tail(&rest[1..]);
    }

    // language = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA
    let language = rest[0];
    if !(2..=8).contains(&language.len()) || !is_alpha(language) {
        return false;
    }
    rest = &rest[1..];
    if language.len() <= 3 {
        // extlang = 3ALPHA *2("-" 3ALPHA)
        let mut extlangs = 0;
        while extlangs < 3 && rest.first().is_some_and(|s| is_extlang(s)) {
            rest = &rest[1..];
            extlangs += 1;
        }
    }
    if rest.first().is_some_and(|s| is_script(s)) {
        rest = &rest[1..];
    }
    if rest.first().is_some_and(|s| is_region(s)) {
        rest = &rest[1..];
    }
    while rest.first().is_some_and(|s| is_variant(s)) {
        rest = &rest[1..];
    }
    // extension = singleton 1*("-" (2*8alphanum))
    while rest.first().is_some_and(|s| is_singleton(s)) {
        rest = &rest[1..];
        let mut taken = 0;
        while rest.first().is_some_and(|s| s.len() >= 2) {
            rest = &rest[1..];
            taken += 1;
        }
        if taken == 0 {
            return false;
        }
    }
    match rest.first() {
        None => true,
        Some(&"x") => is_privateuse_tail(&rest[1..]),
        Some(_) => false,
    }
}

/// `privateuse = "x" 1*("-" (1*8alphanum))`, after the `x`. Subtag length and
/// alphabet were checked by the caller.
const fn is_privateuse_tail(rest: &[&str]) -> bool {
    !rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::is_well_formed_language_tag;

    #[test]
    fn accepts_well_formed_tags() {
        for tag in [
            "en",
            "en-US",
            "EN-us",
            "de",
            "zh-Hant-TW",
            "sr-Latn-RS",
            "es-419",
            "zh-yue-HK",
            "sl-rozaj-biske",
            "de-CH-1901",
            "en-US-u-ca-gregory",
            "en-a-bbb-x-a-ccc",
            "x-whatever",
            "i-klingon",
            "zh-min-nan",
            "qaa-Qaaa-QM-x-southern",
        ] {
            assert!(
                is_well_formed_language_tag(tag),
                "{tag} must be well-formed"
            );
        }
    }

    #[test]
    fn rejects_malformed_tags() {
        for tag in [
            "",
            "en_US",
            "en-",
            "-en",
            "en--US",
            "e",
            "english12",
            "en-US-",
            "en-a",
            "en-x",
            "x",
            "123",
            "en-US-a-b",
            "abcdefghi",
            "en-ü",
        ] {
            assert!(
                !is_well_formed_language_tag(tag),
                "{tag:?} must be rejected"
            );
        }
    }
}
