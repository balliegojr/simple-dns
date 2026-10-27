use core::hash::Hasher;

use crate::{
    dns::MAX_SERVICE_NAME_LENGTH,
    lib::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        Cow, Hash, String, ToString, Vec,
    },
};

use super::MAX_LABEL_LENGTH;

/// Represents a label in a domain name
///
/// A label is a sequence of 1 to 63 octets. On the wire it can hold any octet, including dots
/// (RFC 1035 section 3.1), so no escaping exists in the binary format.
///
/// What counts as a *valid* label depends on the role it plays in a name:
///
/// | Method | Role | Rule |
/// |---|---|---|
/// | [`Label::is_valid_hostname`] | host name | letters, digits and hyphens |
/// | [`Label::is_valid_service_label`] | service name | `_` + RFC 6335 service name |
/// | [`Label::is_valid_instance_label`] | DNS-SD instance or subtype | any content |
///
/// [`Label::new`] only checks the length. To build labels with content that is not valid for a
/// host name (unicode, dots, spaces), use [`Label::new`] or [`Label::new_unchecked`] and
/// [`Name::new_with_labels`](crate::Name::new_with_labels).
///
/// The `Display` implementation uses [`std::string::String::from_utf8_lossy`] to display the
/// label, and escapes `.` as `\.` and `\` as `\\`, so that labels joined in a [`Name`](crate::Name)
/// can be told apart from the dots that separate them (RFC 6763 section 4.3).
#[derive(Eq, Clone)]
pub struct Label<'a> {
    pub(crate) data: Cow<'a, [u8]>,
}

impl<'a> Label<'a> {
    /// Create a new [`Label`] from text that may contain escape sequences.
    ///
    /// The escapes follow the presentation format of RFC 1035 section 5.1 and RFC 4343
    /// section 2.1:
    /// - `\DDD`, exactly three decimal digits (at most `255`), is the octet with that value
    /// - `\X`, where X is not a digit, is the character X (`\.` and `\\` included)
    ///
    /// Returns [`SimpleDnsError::InvalidServiceLabel`](crate::SimpleDnsError::InvalidServiceLabel)
    /// if the label is empty or longer than 63 octets after unescaping, or if an escape is
    /// malformed (a trailing `\`, or `\` followed by fewer than three digits or a value above 255).
    ///
    /// The content is not checked against a naming rule. Use the `is_valid_*` methods for that.
    ///
    /// ```
    /// # use simple_dns::Label;
    /// let label = Label::new(r"My\.Device".as_bytes()).unwrap();
    /// assert_eq!(b"My.Device", label.as_ref());
    ///
    /// assert!(Label::new(r"bad\1".as_bytes()).is_err());
    /// ```
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T) -> crate::Result<Self> {
        let data = data.into();
        let label = if let Some((i, _)) = data.iter().enumerate().find(|(_, c)| **c == b'\\') {
            unescape_label(data, i)?
        } else {
            Self { data }
        };

        if label.data.is_empty() || label.data.len() > MAX_LABEL_LENGTH {
            return Err(crate::SimpleDnsError::InvalidServiceLabel);
        }

        Ok(label)
    }

    /// Create a new Label from raw bytes, without unescaping and without checking for size
    /// limits or valid content.
    /// This function can be used to create labels with unicode characters
    pub fn new_unchecked<T: Into<Cow<'a, [u8]>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    /// Returns the length of the label
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the label is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> Label<'b> {
        Label {
            data: self.data.into_owned().into(),
        }
    }

    /// Returns `true` if the label is a valid host name label (RFC 952, RFC 1123).
    ///
    /// It has 1 to 63 octets, made only of ASCII letters, digits and hyphens, and starts and ends
    /// with a letter or a digit.
    ///
    /// ```
    /// # use simple_dns::Label;
    /// assert!(Label::new_unchecked(&b"my-host1"[..]).is_valid_hostname());
    /// assert!(!Label::new_unchecked(&b"_srv"[..]).is_valid_hostname());
    /// assert!(!Label::new_unchecked(&b"-host"[..]).is_valid_hostname());
    /// ```
    pub fn is_valid_hostname(&self) -> bool {
        if self.data.is_empty() || self.data.len() > MAX_LABEL_LENGTH {
            return false;
        }

        if let Some(first) = self.data.first() {
            if !first.is_ascii_alphanumeric() {
                return false;
            }
        }

        if !self
            .data
            .iter()
            .skip(1)
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        {
            return false;
        }

        if let Some(last) = self.data.last() {
            if !last.is_ascii_alphanumeric() {
                return false;
            }
        }

        true
    }

    /// Returns `true` if the label is a valid DNS-SD service label, such as `_http`
    /// (RFC 6763 section 7).
    ///
    /// It is an underscore followed by a service name as defined in RFC 6335 section 5.1:
    /// 1 to 15 ASCII letters, digits or hyphens, with at least one letter, that does not begin or
    /// end with a hyphen and has no adjacent hyphens.
    ///
    /// This only checks the service name. The `_tcp` or `_udp` label that follows it is checked
    /// by [`Name::is_valid_service_name`](crate::Name::is_valid_service_name).
    ///
    /// ```
    /// # use simple_dns::Label;
    /// assert!(Label::new_unchecked(&b"_http"[..]).is_valid_service_label());
    /// assert!(Label::new_unchecked(&b"_9p"[..]).is_valid_service_label());
    /// assert!(!Label::new_unchecked(&b"http"[..]).is_valid_service_label());
    /// assert!(!Label::new_unchecked(&b"_123"[..]).is_valid_service_label());
    /// ```
    pub fn is_valid_service_label(&self) -> bool {
        if self.data.is_empty() || self.data.len() > MAX_SERVICE_NAME_LENGTH {
            return false;
        }

        let Some((b'_', name)) = self.data.split_first() else {
            return false;
        };

        // RFC 6335 section 5.1: letters, digits, hyphens; at least one letter;
        // no leading, trailing or adjacent hyphens
        name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && name.iter().any(|c| c.is_ascii_alphabetic())
            && !name.starts_with(b"-")
            && !name.ends_with(b"-")
            && !name.windows(2).any(|w| w == b"--")
    }

    /// Returns `true` if the label can be used as a DNS-SD instance name or subtype
    /// (RFC 6763 sections 4.3 and 7.1).
    ///
    /// Any content is accepted, including dots, spaces and UTF-8, as long as the label has 1 to 63
    /// octets. The limit counts octets, not characters.
    ///
    /// ```
    /// # use simple_dns::Label;
    /// assert!(Label::new_unchecked(&b"My Printer. Floor 2"[..]).is_valid_instance_label());
    /// assert!(!Label::new_unchecked(&b""[..]).is_valid_instance_label());
    /// ```
    pub fn is_valid_instance_label(&self) -> bool {
        !(self.data.is_empty() || self.data.len() > MAX_LABEL_LENGTH)
    }
}

impl PartialEq for Label<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.data.eq_ignore_ascii_case(&other.data)
    }
}

impl Hash for Label<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.data.len());
        for &b in self.data.iter() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl PartialOrd for Label<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.data
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(other.data.iter().map(u8::to_ascii_lowercase))
    }
}

fn unescape_label<'a>(bytes: Cow<'a, [u8]>, mut position: usize) -> crate::Result<Label<'a>> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..position]);

    while position < bytes.len() {
        match bytes[position] {
            // Labels ending with \ are invalid
            b'\\' if position + 1 == bytes.len() => {
                return Err(crate::SimpleDnsError::InvalidServiceLabel);
            }

            b'\\' => {
                position += 1;
                if bytes[position].is_ascii_digit() {
                    // digit caracters must be a sequence of 3 \DDD

                    // not enough bytes, or next two bytes are not digits
                    if (bytes.len() - position) < 3
                        || !bytes[position + 1].is_ascii_digit()
                        || !bytes[position + 2].is_ascii_digit()
                    {
                        return Err(crate::SimpleDnsError::InvalidServiceLabel);
                    }

                    let mut digit = (bytes[position] - b'0') as u16 * 100;
                    digit += (bytes[position + 1] - b'0') as u16 * 10;
                    digit += (bytes[position + 2] - b'0') as u16;

                    if digit > 255 {
                        return Err(crate::SimpleDnsError::InvalidServiceLabel);
                    }

                    out.push(digit as u8);
                    position += 3;
                } else {
                    out.push(bytes[position]);
                    position += 1;
                }
            }
            c => {
                out.push(c);
                position += 1;
            }
        }
    }

    Ok(Label { data: out.into() })
}

impl Display for Label<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        use core::fmt::Write;

        let s = String::from_utf8_lossy(&self.data);
        for c in s.chars() {
            match c {
                '.' => {
                    f.write_char('\\')?;
                    f.write_char(c)?;
                }
                '\\' => {
                    f.write_str(r"\\")?;
                }
                _ => {
                    f.write_char(c)?;
                }
            }
        }

        Ok(())
    }
}

impl Debug for Label<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Label")
            .field("data", &self.to_string())
            .finish()
    }
}

impl AsRef<[u8]> for Label<'_> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Key for the name compression map.
///
/// Unlike [`Label`], which compares ASCII case-insensitively, this compares the raw bytes, so
/// names that differ only in case are never compressed into one and keep their original casing.
#[derive(Clone, Copy)]
pub(crate) struct ExactLabels<'a, 'b>(&'b [Label<'a>]);

impl<'a, 'b> ExactLabels<'a, 'b> {
    pub(crate) fn new(labels: &'b [Label<'a>]) -> Self {
        Self(labels)
    }
}

impl PartialEq for ExactLabels<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for ExactLabels<'_, '_> {}

impl PartialOrd for ExactLabels<'_, '_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExactLabels<'_, '_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0
            .iter()
            .map(|l| &l.data[..])
            .cmp(other.0.iter().map(|l| &l.data[..]))
    }
}

/// An iterator over the labels in a domain name
pub(crate) struct LabelsIter<'a> {
    bytes: &'a [u8],
    current: usize,
}

impl<'a> LabelsIter<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, current: 0 }
    }
}

impl<'a> Iterator for LabelsIter<'a> {
    type Item = Cow<'a, [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut i = self.current;
        // let mut has_escape = false;

        // Find the boundaries of the label
        while i < self.bytes.len() {
            match self.bytes[i] {
                b'\\' if i + 1 == self.bytes.len() => {
                    // This is an invalid label, ending with \
                    break;
                }
                b'\\' => {
                    //this label is escaped
                    // has_escape = true;
                    i += 2;
                }
                b'.' => {
                    let current = crate::lib::mem::replace(&mut self.current, i + 1);
                    if i - current == 0 {
                        // This is an empty label (or a sequence of .), just skip it
                        // has_escape = false;
                        i = self.current;
                        continue;
                    }

                    return Some(self.bytes[current..i].into());
                }
                _ => {
                    // all other characters, just advance
                    i += 1;
                }
            }
        }

        if self.current < self.bytes.len() {
            let current = crate::lib::mem::replace(&mut self.current, self.bytes.len());
            // Some(unescape_label(&self.bytes[current..], has_escape))
            Some(self.bytes[current..].into())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_label() {
        let input = b"invalid\xF0\x90\x80label";
        let label = Label::new_unchecked(input);

        assert_eq!(label.to_string(), "invalid�label");
    }

    #[test]
    fn labels_are_escaped() {
        let l = Label::new(b"escaped.label").expect("failed to create label");
        assert_eq!(r"escaped\.label", l.to_string());
    }

    fn label(s: &str) -> Label<'_> {
        Label::new_unchecked(s.as_bytes())
    }

    #[test]
    fn hostname_label_valid() {
        // RFC 952 / RFC 1123: letters, digits and hyphens, starting and ending with alphanumeric
        assert!(label("example").is_valid_hostname());
        assert!(label("a").is_valid_hostname());
        assert!(label("EXAMPLE").is_valid_hostname());
        assert!(label("a-b").is_valid_hostname());
        assert!(label("a--b").is_valid_hostname());
        assert!(label("1abc").is_valid_hostname());
        assert!(label("abc1").is_valid_hostname());
        assert!(label("123").is_valid_hostname());
        assert!(label(&"a".repeat(63)).is_valid_hostname());
    }

    #[test]
    fn hostname_label_invalid() {
        assert!(!label("").is_valid_hostname());
        assert!(!label(&"a".repeat(64)).is_valid_hostname());
        assert!(!label("-a").is_valid_hostname());
        assert!(!label("a-").is_valid_hostname());
        assert!(!label("-").is_valid_hostname());
        assert!(!label("_a").is_valid_hostname());
        assert!(!label("a_b").is_valid_hostname());
        assert!(!label("a.b").is_valid_hostname());
        assert!(!label("a b").is_valid_hostname());
        assert!(!label(r"a\b").is_valid_hostname());
        assert!(!label("caf\u{e9}").is_valid_hostname());
        assert!(!label("\u{1F600}").is_valid_hostname());
    }

    #[test]
    fn service_label_valid() {
        // RFC 6763 section 7 / RFC 6335 section 5.1: underscore + 1 to 15 chars
        assert!(label("_http").is_valid_service_label());
        assert!(label("_a").is_valid_service_label());
        assert!(label("_HTTP").is_valid_service_label());
        assert!(label("_ipp-tls").is_valid_service_label());
        assert!(label("_a-b-c").is_valid_service_label());
        // digits are allowed as long as there is at least one letter
        assert!(label("_9p").is_valid_service_label());
        assert!(label("_1a").is_valid_service_label());
        assert!(label("_a1").is_valid_service_label());
        // exactly 15 characters after the underscore
        assert!(label("_abcdefghijklmno").is_valid_service_label());
    }

    #[test]
    fn service_label_invalid() {
        assert!(!label("").is_valid_service_label());
        assert!(!label("_").is_valid_service_label());
        // missing mandatory underscore
        assert!(!label("http").is_valid_service_label());
        // 16 characters after the underscore
        assert!(!label("_abcdefghijklmnop").is_valid_service_label());
        // must contain at least one letter
        assert!(!label("_123").is_valid_service_label());
        assert!(!label("_1-2").is_valid_service_label());
        // must not begin or end with a hyphen
        assert!(!label("_-a").is_valid_service_label());
        assert!(!label("_a-").is_valid_service_label());
        // hyphens must not be adjacent
        assert!(!label("_a--b").is_valid_service_label());
        // only US-ASCII letters, digits and hyphens
        assert!(!label("_a_b").is_valid_service_label());
        assert!(!label("_a.b").is_valid_service_label());
        assert!(!label("_a b").is_valid_service_label());
        assert!(!label("_caf\u{e9}").is_valid_service_label());
        // the underscore is only allowed in the first position
        assert!(!label("__http").is_valid_service_label());
    }

    #[test]
    fn instance_label_valid() {
        // RFC 6763 section 4.3: any characters, including dots, spaces and UTF-8
        assert!(label("My Printer").is_valid_instance_label());
        assert!(label("a").is_valid_instance_label());
        assert!(label("Stuart's Test Server").is_valid_instance_label());
        assert!(label("My Printer. Floor 2").is_valid_instance_label());
        assert!(label(r"back\slash").is_valid_instance_label());
        assert!(label("-leading and trailing-").is_valid_instance_label());
        assert!(label("_underscore").is_valid_instance_label());
        assert!(label("caf\u{e9}").is_valid_instance_label());
        assert!(label("\u{1F5A8}").is_valid_instance_label());
        assert!(label(&"a".repeat(63)).is_valid_instance_label());
    }

    #[test]
    fn instance_label_invalid() {
        assert!(!label("").is_valid_instance_label());
        assert!(!label(&"a".repeat(64)).is_valid_instance_label());
    }

    #[test]
    fn instance_label_limit_counts_utf8_octets() {
        // 32 x 2-byte characters = 64 octets
        assert!(!label(&"\u{e9}".repeat(32)).is_valid_instance_label());
        // 31 x 2-byte characters + 1 ASCII = 63 octets
        assert!(label(&("\u{e9}".repeat(31) + "a")).is_valid_instance_label());
    }
}
