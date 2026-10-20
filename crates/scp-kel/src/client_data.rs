//! The strict `clientDataJSON` validator a `WebAuthnAssertion` indexed
//! signature is checked through (`09-security-model.md` §9.7.4.2, "A
//! verifier of an assertion signature parses `clientDataJSON` as RFC 8259
//! JSON").
//!
//! The acceptance set: the bytes are RFC 8259 JSON text in strict UTF-8
//! (RFC 3629 §4) with no byte-order mark; the top-level value is an object
//! followed by nothing but JSON whitespace; every control character inside a
//! string is escaped; no `\uD800`–`\uDFFF` escape appears unpaired; no depth
//! limit applies other than the input bound; a number is checked against the
//! RFC 8259 grammar and never converted, so `1e400` is accepted; no object at
//! any depth has two members whose names are equal after unescaping; `type`
//! and `challenge` are read from the top-level object only and must be
//! strings; every other member is ignored. Each rule removes one point where
//! two RFC-conforming parsers can disagree about one document, which is the
//! split §9.7.4.2 names.
//!
//! The validator is hand-written over at most `MAX_CLIENT_DATA_JSON_BYTES`
//! bytes. Nesting is held on an explicit stack, so no recursion depth is
//! driven by the input, and a general-purpose parser's own limits (a nesting
//! cap, a float conversion, last-duplicate-wins) never decide acceptance.

use crate::constants::MAX_CLIENT_DATA_JSON_BYTES;

/// The two top-level members a key-event verifier reads out of an accepted
/// `clientDataJSON`, each as its decoded JSON string value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDataMembers {
    /// The decoded value of the top-level `type` member.
    pub client_data_type: String,
    /// The decoded value of the top-level `challenge` member.
    pub challenge: String,
}

/// Why bytes are not an acceptable `clientDataJSON` (§9.7.4.2). Each
/// variant names one rule of the acceptance set; `offset` is the byte at
/// which the rule failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientDataError {
    /// The input is longer than `MAX_CLIENT_DATA_JSON_BYTES` (§9.18.17).
    #[error("clientDataJSON is {len} bytes, over MAX_CLIENT_DATA_JSON_BYTES")]
    TooLong {
        /// The input's length.
        len: usize,
    },
    /// The input begins with a UTF-8 byte-order mark.
    #[error("clientDataJSON begins with a byte-order mark")]
    ByteOrderMark,
    /// The input is not strict UTF-8 (RFC 3629 §4).
    #[error("clientDataJSON is not UTF-8 at byte {offset}")]
    InvalidUtf8 {
        /// The first byte that is not part of a valid UTF-8 sequence.
        offset: usize,
    },
    /// The input ends inside a value.
    #[error("clientDataJSON ends inside a value")]
    UnexpectedEnd,
    /// A byte the RFC 8259 grammar does not admit at its position.
    #[error("unexpected byte 0x{byte:02x} at byte {offset} of clientDataJSON")]
    UnexpectedByte {
        /// The byte's offset.
        offset: usize,
        /// The byte.
        byte: u8,
    },
    /// The top-level value is not an object.
    #[error("the top-level value of clientDataJSON is not an object")]
    TopLevelNotObject,
    /// Bytes other than JSON whitespace follow the top-level object.
    #[error("non-whitespace content follows the top-level object at byte {offset}")]
    TrailingContent {
        /// The first such byte.
        offset: usize,
    },
    /// A control character (below U+0020) appears unescaped inside a string.
    #[error("unescaped control character at byte {offset} of clientDataJSON")]
    UnescapedControl {
        /// The character's offset.
        offset: usize,
    },
    /// A backslash escape RFC 8259 does not define, or a `\u` escape
    /// without four hexadecimal digits.
    #[error("invalid escape at byte {offset} of clientDataJSON")]
    InvalidEscape {
        /// The backslash's offset.
        offset: usize,
    },
    /// A `\uD800`–`\uDBFF` escape not followed by a `\uDC00`–`\uDFFF`
    /// escape, or a `\uDC00`–`\uDFFF` escape no high surrogate precedes.
    #[error("unpaired surrogate escape at byte {offset} of clientDataJSON")]
    LoneSurrogate {
        /// The escape's offset.
        offset: usize,
    },
    /// A number does not match the RFC 8259 number grammar.
    #[error("malformed number at byte {offset} of clientDataJSON")]
    InvalidNumber {
        /// The number's first byte.
        offset: usize,
    },
    /// An object, at any depth, carries two members whose names are equal
    /// after unescaping.
    #[error("duplicate member name at byte {offset} of clientDataJSON")]
    DuplicateMember {
        /// The second name's opening quote.
        offset: usize,
    },
    /// The top-level object carries no `type` member.
    #[error("clientDataJSON carries no top-level type member")]
    MissingType,
    /// The top-level `type` member is not a string.
    #[error("the top-level type member of clientDataJSON is not a string")]
    TypeNotString,
    /// The top-level object carries no `challenge` member.
    #[error("clientDataJSON carries no top-level challenge member")]
    MissingChallenge,
    /// The top-level `challenge` member is not a string.
    #[error("the top-level challenge member of clientDataJSON is not a string")]
    ChallengeNotString,
}

/// One open container on the explicit nesting stack.
enum Container {
    /// An object, with the decoded names of the members read so far.
    Object(Vec<String>),
    /// An array.
    Array,
}

/// What the grammar admits next.
#[derive(Clone, Copy)]
enum Next {
    /// A value.
    Value,
    /// A member name, or `}` closing an empty object.
    FirstKeyOrClose,
    /// A member name.
    Key,
    /// A value, or `]` closing an empty array.
    FirstValueOrClose,
    /// `,` or the close of the innermost container, or the end of input
    /// when no container is open.
    AfterValue,
}

/// A top-level member value the verifier reads: absent, a string, or some
/// other JSON value.
enum TopLevel {
    Absent,
    String(String),
    NotString,
}

/// The validator's state over one input.
struct Validator<'a> {
    /// The input, already checked to be UTF-8.
    source: &'a str,
    /// The input's bytes.
    text: &'a [u8],
    pos: usize,
    stack: Vec<Container>,
    /// The name of the top-level member whose value is read next, if any.
    top_member: Option<String>,
    client_data_type: TopLevel,
    challenge: TopLevel,
}

/// Validates `bytes` against §9.7.4.2's `clientDataJSON` acceptance set and
/// returns the decoded top-level `type` and `challenge` strings.
///
/// Public for the `fuzz_kel_client_data` target only; a verifier reaches it
/// through [`verify_indexed`](crate::verify_indexed).
///
/// # Errors
///
/// The [`ClientDataError`] naming the first rule the bytes break.
#[doc(hidden)]
pub fn parse_client_data_json(bytes: &[u8]) -> Result<ClientDataMembers, ClientDataError> {
    let max = usize::try_from(MAX_CLIENT_DATA_JSON_BYTES).unwrap_or(usize::MAX);
    if bytes.len() > max {
        return Err(ClientDataError::TooLong { len: bytes.len() });
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(ClientDataError::ByteOrderMark);
    }
    let source = std::str::from_utf8(bytes).map_err(|e| ClientDataError::InvalidUtf8 {
        offset: e.valid_up_to(),
    })?;
    let mut validator = Validator {
        source,
        text: bytes,
        pos: 0,
        stack: Vec::new(),
        top_member: None,
        client_data_type: TopLevel::Absent,
        challenge: TopLevel::Absent,
    };
    validator.run()?;
    let client_data_type = match validator.client_data_type {
        TopLevel::Absent => return Err(ClientDataError::MissingType),
        TopLevel::NotString => return Err(ClientDataError::TypeNotString),
        TopLevel::String(value) => value,
    };
    let challenge = match validator.challenge {
        TopLevel::Absent => return Err(ClientDataError::MissingChallenge),
        TopLevel::NotString => return Err(ClientDataError::ChallengeNotString),
        TopLevel::String(value) => value,
    };
    Ok(ClientDataMembers {
        client_data_type,
        challenge,
    })
}

impl Validator<'_> {
    /// Runs the grammar over the whole input with an explicit stack.
    fn run(&mut self) -> Result<(), ClientDataError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => {}
            Some(_) => return Err(ClientDataError::TopLevelNotObject),
            None => return Err(ClientDataError::UnexpectedEnd),
        }
        let mut next = Next::Value;
        loop {
            self.skip_whitespace();
            next = match next {
                Next::Value => self.value()?,
                Next::FirstKeyOrClose => {
                    if self.peek() == Some(b'}') {
                        self.close()?
                    } else {
                        self.key()?
                    }
                }
                Next::Key => self.key()?,
                Next::FirstValueOrClose => {
                    if self.peek() == Some(b']') {
                        self.close()?
                    } else {
                        self.value()?
                    }
                }
                Next::AfterValue => match self.after_value()? {
                    Some(next) => next,
                    None => return Ok(()),
                },
            };
        }
    }

    /// Reads one value, or opens a container.
    fn value(&mut self) -> Result<Next, ClientDataError> {
        // A value read directly inside the top-level object is that member's
        // value; one read anywhere else is no top-level member's.
        let member = if self.stack.len() == 1 {
            self.top_member.take()
        } else {
            None
        };
        let offset = self.pos;
        let byte = self.peek().ok_or(ClientDataError::UnexpectedEnd)?;
        let read = match byte {
            b'{' => {
                self.pos += 1;
                self.stack.push(Container::Object(Vec::new()));
                (TopLevel::NotString, Next::FirstKeyOrClose)
            }
            b'[' => {
                self.pos += 1;
                self.stack.push(Container::Array);
                (TopLevel::NotString, Next::FirstValueOrClose)
            }
            b'"' => (TopLevel::String(self.string()?), Next::AfterValue),
            b'-' | b'0'..=b'9' => {
                self.number()?;
                (TopLevel::NotString, Next::AfterValue)
            }
            b't' => self.literal(b"true")?,
            b'f' => self.literal(b"false")?,
            b'n' => self.literal(b"null")?,
            _ => return Err(ClientDataError::UnexpectedByte { offset, byte }),
        };
        if let Some(name) = member {
            match name.as_str() {
                "type" => self.client_data_type = read.0,
                "challenge" => self.challenge = read.0,
                _ => {}
            }
        }
        Ok(read.1)
    }

    /// Reads `literal` at the current position.
    fn literal(&mut self, literal: &[u8]) -> Result<(TopLevel, Next), ClientDataError> {
        let end = self.pos + literal.len();
        match self.text.get(self.pos..end) {
            Some(found) if found == literal => {
                self.pos = end;
                Ok((TopLevel::NotString, Next::AfterValue))
            }
            Some(_) => Err(self.unexpected()),
            None => Err(ClientDataError::UnexpectedEnd),
        }
    }

    /// Reads one member name and its `:`, rejecting a name the enclosing
    /// object already carries.
    fn key(&mut self) -> Result<Next, ClientDataError> {
        let offset = self.pos;
        if self.peek() != Some(b'"') {
            return Err(self.unexpected());
        }
        let name = self.string()?;
        let depth = self.stack.len();
        let Some(Container::Object(names)) = self.stack.last_mut() else {
            return Err(ClientDataError::UnexpectedByte { offset, byte: b'"' });
        };
        if names.contains(&name) {
            return Err(ClientDataError::DuplicateMember { offset });
        }
        names.push(name.clone());
        if depth == 1 {
            self.top_member = Some(name);
        }
        self.skip_whitespace();
        if self.peek() != Some(b':') {
            return Err(self.unexpected());
        }
        self.pos += 1;
        Ok(Next::Value)
    }

    /// Reads `,` or a close after a value; `None` once the top-level object
    /// has closed and only whitespace follows.
    fn after_value(&mut self) -> Result<Option<Next>, ClientDataError> {
        match (self.stack.last(), self.peek()) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(ClientDataError::TrailingContent { offset: self.pos }),
            (Some(Container::Object(_)), Some(b',')) => {
                self.pos += 1;
                Ok(Some(Next::Key))
            }
            (Some(Container::Array), Some(b',')) => {
                self.pos += 1;
                Ok(Some(Next::Value))
            }
            (Some(Container::Object(_)), Some(b'}')) | (Some(Container::Array), Some(b']')) => {
                self.close().map(Some)
            }
            (Some(_), Some(_)) => Err(self.unexpected()),
            (Some(_), None) => Err(ClientDataError::UnexpectedEnd),
        }
    }

    /// Consumes the close byte of the innermost container and pops it.
    fn close(&mut self) -> Result<Next, ClientDataError> {
        self.pos += 1;
        self.stack.pop().ok_or(ClientDataError::UnexpectedEnd)?;
        Ok(Next::AfterValue)
    }

    /// Reads one string starting at its opening quote and returns its
    /// decoded value.
    fn string(&mut self) -> Result<String, ClientDataError> {
        self.pos += 1;
        let mut decoded = String::new();
        loop {
            let offset = self.pos;
            let byte = self.peek().ok_or(ClientDataError::UnexpectedEnd)?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(decoded);
                }
                b'\\' => decoded.push(self.escape()?),
                0x00..=0x1F => return Err(ClientDataError::UnescapedControl { offset }),
                _ => {
                    // Every position the validator stops at is a character
                    // boundary of the UTF-8 input checked on entry.
                    let character = self
                        .source
                        .get(offset..)
                        .and_then(|rest| rest.chars().next())
                        .ok_or(ClientDataError::InvalidUtf8 { offset })?;
                    decoded.push(character);
                    self.pos += character.len_utf8();
                }
            }
        }
    }

    /// Reads one escape starting at its backslash and returns the character
    /// it denotes, joining a surrogate pair.
    fn escape(&mut self) -> Result<char, ClientDataError> {
        let offset = self.pos;
        let byte = self
            .text
            .get(offset + 1)
            .copied()
            .ok_or(ClientDataError::UnexpectedEnd)?;
        self.pos += 2;
        let simple = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(offset),
            _ => return Err(ClientDataError::InvalidEscape { offset }),
        };
        Ok(simple)
    }

    /// Reads the four hex digits of a `\u` escape whose backslash is at
    /// `offset`, and the low half when they name a high surrogate.
    fn unicode_escape(&mut self, offset: usize) -> Result<char, ClientDataError> {
        let unit = self.hex4(offset)?;
        match unit {
            0xD800..=0xDBFF => {
                let low_offset = self.pos;
                if self.text.get(low_offset..low_offset + 2) != Some(b"\\u") {
                    return Err(ClientDataError::LoneSurrogate { offset });
                }
                self.pos += 2;
                let low = self.hex4(low_offset)?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(ClientDataError::LoneSurrogate { offset });
                }
                let scalar = 0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                char::from_u32(scalar).ok_or(ClientDataError::LoneSurrogate { offset })
            }
            0xDC00..=0xDFFF => Err(ClientDataError::LoneSurrogate { offset }),
            _ => char::from_u32(unit).ok_or(ClientDataError::InvalidEscape { offset }),
        }
    }

    /// Reads four hexadecimal digits at the current position.
    fn hex4(&mut self, offset: usize) -> Result<u32, ClientDataError> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .ok_or(ClientDataError::UnexpectedEnd)?;
        let mut unit = 0u32;
        for &digit in digits {
            let value = char::from(digit)
                .to_digit(16)
                .ok_or(ClientDataError::InvalidEscape { offset })?;
            unit = (unit << 4) | value;
        }
        self.pos += 4;
        Ok(unit)
    }

    /// Checks one number against the RFC 8259 grammar
    /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?` without
    /// converting it.
    fn number(&mut self) -> Result<(), ClientDataError> {
        let offset = self.pos;
        let invalid = ClientDataError::InvalidNumber { offset };
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(invalid),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid);
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid);
            }
            self.digits();
        }
        Ok(())
    }

    /// Consumes a run of decimal digits.
    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    /// Consumes JSON whitespace: space, tab, line feed, carriage return.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// The byte at the current position.
    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    /// The error for the byte at the current position.
    fn unexpected(&self) -> ClientDataError {
        self.peek().map_or(ClientDataError::UnexpectedEnd, |byte| {
            ClientDataError::UnexpectedByte {
                offset: self.pos,
                byte,
            }
        })
    }
}
