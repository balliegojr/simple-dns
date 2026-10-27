use crate::{
    bytes_buffer::BytesBuffer,
    lib::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        format, Hash, Hasher, Iter, Seek, TryFrom, Vec, Write,
    },
};

use super::{
    label::{ExactLabels, Label, LabelsIter},
    WireFormat, MAX_LABEL_LENGTH, MAX_NAME_LENGTH,
};

const POINTER_MASK: u8 = 0b1100_0000;
const POINTER_MASK_U16: u16 = 0b1100_0000_0000_0000;
const MAX_COMPRESSION_OFFSET: u64 = !POINTER_MASK_U16 as u64;

// NOTE: there are no extend labels implemented today
// const EXTENDED_LABEL: u8 = 0b0100_0000;
// const EXTENDED_LABEL_U16: u16 = 0b0100_0000_0000_0000;

/// A Name represents a domain-name, which consists of character strings separated by dots.  
/// Each section of a name is called label  
/// ex: `google.com` consists of two labels `google` and `com`
///
/// A name is at most 255 octets long in the wire format, and each label at most 63 octets.
/// [`Name::new`] checks these limits, but not the content of the labels. Use the `is_valid_*`
/// methods to check a name against the rules of a given role:
/// - [`Name::is_valid_hostname`]
/// - [`Name::is_valid_service_name`]
/// - [`Name::is_valid_instance_name`]
/// - [`Name::is_valid_sub_type_name`]
///
/// # Text format
///
/// [`Name::new`] reads the presentation format of RFC 1035 section 5.1 and RFC 4343
/// section 2.1:
/// - an unescaped `.` separates labels
/// - `\.` is a dot inside a label and `\\` is a backslash
/// - `\DDD`, three decimal digits, is the octet with that value, and `\X` for any other
///   non-digit X is the character X
/// - a trailing dot marks the name as absolute and does not add a label. A name made only of
///   dots is the root and has no labels
/// - empty labels, as in `a..b`, are skipped
///
/// [`Name::new_unchecked`] splits the text at unescaped dots in the same way, but it does not
/// interpret the escapes: the bytes of each label are kept as written, so `a\.b` becomes the
/// four byte label `a\.b`. To build a name from raw label content, use
/// [`Name::new_with_labels`].
///
/// [`Display`](core::fmt::Display) writes the same format, escaping `.` and `\` inside labels
/// (RFC 6763 section 4.3), so a name parsed back with [`Name::new`] is equal to the original.
///
/// The escapes exist only in text. In the wire format, labels are length-prefixed and hold
/// any octet.
///
/// ```
/// # use simple_dns::Name;
/// let name = Name::new(r"My\.Device._googlecast._tcp.local").unwrap();
/// assert_eq!(4, name.get_labels().len());
/// assert_eq!(b"My.Device", name.get_labels()[0].as_ref());
/// assert_eq!(r"My\.Device._googlecast._tcp.local", name.to_string());
/// ```
///
/// Microsoft implementation allows unicode characters in the name content.
/// To create a name with unicode characters, use [`Name::new_unchecked`] or
/// [`Name::new_with_labels`]
#[derive(Eq, Clone)]
pub struct Name<'a> {
    labels: Vec<Label<'a>>,
}

impl<'a> Name<'a> {
    /// Creates a new Name from text in the format described in the [type docs](Name#text-format).
    ///
    /// Returns an error if an escape sequence is malformed, if a label is longer than 63 octets
    /// after unescaping, or if the encoded name is longer than 255 octets.
    /// The content of the labels is not checked against a naming rule, use the `is_valid_*`
    /// methods for that.
    pub fn new(name: &'a str) -> crate::Result<Self> {
        let labels = LabelsIter::new(name.as_bytes())
            .map(Label::new)
            .collect::<Result<Vec<Label>, _>>()?;

        let name = Self { labels };

        if name.len() > MAX_NAME_LENGTH {
            Err(crate::SimpleDnsError::InvalidServiceName)
        } else {
            Ok(name)
        }
    }

    /// Create a new Name without checking for size limits or contents.
    ///
    /// The text is split at unescaped dots, but escape sequences are not interpreted: the bytes
    /// of each label are kept as written (see the [type docs](Name#text-format)). Use
    /// [`Name::new`] to unescape, or [`Name::new_with_labels`] to set the label content directly.
    pub fn new_unchecked(name: &'a str) -> Self {
        let labels = LabelsIter::new(name.as_bytes())
            .map(Label::new_unchecked)
            .collect();

        Self { labels }
    }

    /// Creates a new Name with given labels
    ///
    /// Allows construction of labels with `.` in them.
    pub fn new_with_labels(labels: &[Label<'a>]) -> Self {
        Self {
            labels: labels.to_vec(),
        }
    }

    /// Verify if name ends with .local.
    pub fn is_link_local(&self) -> bool {
        match self.iter().last() {
            Some(label) => b"local".eq_ignore_ascii_case(&label.data),
            None => false,
        }
    }

    /// Returns an Iter of this Name Labels
    pub fn iter(&'a self) -> Iter<'a, Label<'a>> {
        self.labels.iter()
    }

    /// Returns true if self is a subdomain of other
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        self.labels.len() > other.labels.len()
            && other
                .iter()
                .rev()
                .zip(self.iter().rev())
                .all(|(o, s)| *o == *s)
    }

    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> Name<'b> {
        Name {
            labels: self.labels.into_iter().map(|l| l.into_owned()).collect(),
        }
    }

    /// Returns the subdomain part of self, based on `domain`.
    /// If self is not a subdomain of `domain`, returns None
    ///
    /// Example:
    /// ```
    /// # use simple_dns::Name;
    /// let name = Name::new_unchecked("sub.domain.local");
    /// let domain = Name::new_unchecked("domain.local");
    ///
    /// assert!(domain.without(&name).is_none());
    ///
    /// let sub = name.without(&domain).unwrap();
    /// assert_eq!(sub.to_string(), "sub")
    /// ```
    pub fn without(&'_ self, domain: &Name) -> Option<Name<'_>> {
        if self.is_subdomain_of(domain) {
            let labels = self.labels[..self.labels.len() - domain.labels.len()].to_vec();

            Some(Name { labels })
        } else {
            None
        }
    }

    /// Get the labels that compose this name
    pub fn get_labels(&'_ self) -> &'_ [Label<'a>] {
        &self.labels[..]
    }

    fn plain_append<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        for label in self.iter() {
            out.write_all(&[label.len() as u8])?;
            out.write_all(&label.data)?;
        }

        out.write_all(&[0])?;
        Ok(())
    }

    fn compress_append<T: Write + Seek>(
        &'a self,
        out: &mut T,
        name_refs: &mut crate::lib::BTreeMap<crate::dns::label::ExactLabels<'a, '_>, u16>,
    ) -> crate::Result<()> {
        for (i, label) in self.iter().enumerate() {
            match name_refs.entry(ExactLabels::new(&self.labels[i..])) {
                crate::lib::BTreeEntry::Occupied(e) => {
                    let p = *e.get();
                    out.write_all(&(p | POINTER_MASK_U16).to_be_bytes())?;

                    return Ok(());
                }
                crate::lib::BTreeEntry::Vacant(e) => {
                    let pos = out.stream_position()?;
                    if pos <= MAX_COMPRESSION_OFFSET {
                        e.insert(pos as u16);
                    }
                    out.write_all(&[label.len() as u8])?;
                    out.write_all(&label.data)?;
                }
            }
        }

        out.write_all(&[0])?;
        Ok(())
    }

    /// Returns `true` if the name has at least one label and every label is a valid host name
    /// label, see [`Label::is_valid_hostname`].
    ///
    /// ```
    /// # use simple_dns::Name;
    /// assert!(Name::new_unchecked("my-host.example.com").is_valid_hostname());
    /// assert!(!Name::new_unchecked("_srv.example.com").is_valid_hostname());
    /// assert!(!Name::new_unchecked(".").is_valid_hostname());
    /// ```
    pub fn is_valid_hostname(&self) -> bool {
        !self.labels.is_empty() && self.labels.iter().all(|label| label.is_valid_hostname())
    }

    /// Returns `true` if the name is a DNS-SD subtype name:
    /// `<Subtype>._sub.<sn>._tcp|_udp.<domain>` (RFC 6763 section 7.1).
    ///
    /// The subtype can be any label (see [`Label::is_valid_instance_label`]) and does not need to
    /// start with an underscore. The rest of the name must be a valid service name, see
    /// [`Name::is_valid_service_name`].
    ///
    /// ```
    /// # use simple_dns::Name;
    /// assert!(Name::new_unchecked("_printer._sub._http._tcp.local").is_valid_sub_type_name());
    /// assert!(Name::new_unchecked("The Music Store._sub._http._tcp.local").is_valid_sub_type_name());
    /// assert!(!Name::new_unchecked("_printer._http._tcp.local").is_valid_sub_type_name());
    /// ```
    pub fn is_valid_sub_type_name(&self) -> bool {
        // <sub>._sub.<sn>._tcp.<servicedomain>.<parentdomain>.
        if self.labels.is_empty() {
            return false;
        }

        let mut labels = self.labels.iter();
        let (Some(subtype), Some(marker)) = (labels.next(), labels.next()) else {
            return false;
        };

        let sub = Label::new_unchecked(&b"_sub"[..]);
        subtype.is_valid_instance_label() && *marker == sub && Self::validate_service_name(labels)
    }

    /// Returns `true` if the name is a DNS-SD service instance name:
    /// `<Instance>.<sn>._tcp|_udp.<domain>` (RFC 6763 section 4.3).
    ///
    /// The instance can be any label (see [`Label::is_valid_instance_label`]), including one that
    /// contains dots. The rest of the name must be a valid service name, see
    /// [`Name::is_valid_service_name`].
    ///
    /// ```
    /// # use simple_dns::Name;
    /// assert!(Name::new_unchecked("My Printer._ipp._tcp.local").is_valid_instance_name());
    /// // the escaped dot keeps `My. Printer` as a single label
    /// assert!(Name::new(r"My\. Printer._ipp._tcp.local").unwrap().is_valid_instance_name());
    /// assert!(!Name::new_unchecked("My Printer._ipp._ftp.local").is_valid_instance_name());
    /// ```
    pub fn is_valid_instance_name(&self) -> bool {
        // <Instance>.<sn>._tcp.<servicedomain>.<parentdomain>.

        if self.labels.is_empty() {
            return false;
        }

        let mut labels = self.labels.iter();
        let Some(instance_name) = labels.next() else {
            return false;
        };

        instance_name.is_valid_instance_label() && Self::validate_service_name(labels)
    }

    /// Returns `true` if the name is a DNS-SD service name: `<sn>._tcp|_udp.<domain>`
    /// (RFC 6763 sections 4.1.2 and 7).
    ///
    /// - the first label must pass [`Label::is_valid_service_label`]
    /// - the second label must be `_tcp` or `_udp`, ignoring case
    /// - the remaining domain labels must pass [`Label::is_valid_hostname`]
    ///
    /// This is a syntax check. It does not check that the service is registered.
    ///
    /// ```
    /// # use simple_dns::Name;
    /// assert!(Name::new_unchecked("_http._tcp.local").is_valid_service_name());
    /// assert!(!Name::new_unchecked("http._tcp.local").is_valid_service_name());
    /// assert!(!Name::new_unchecked("_http._ftp.local").is_valid_service_name());
    /// ```
    pub fn is_valid_service_name(&self) -> bool {
        if self.labels.is_empty() {
            return false;
        }

        // <sn>._tcp . <servicedomain> . <parentdomain>.
        Self::validate_service_name(self.labels.iter())
    }

    fn validate_service_name(mut labels: Iter<'_, Label<'_>>) -> bool {
        let (Some(sn), Some(protocol)) = (labels.next(), labels.next()) else {
            return false;
        };

        let tcp = Label::new_unchecked(&b"_tcp"[..]);
        let udp = Label::new_unchecked(&b"_udp"[..]);

        sn.is_valid_service_label()
            && (*protocol == tcp || *protocol == udp)
            && labels.all(|l| l.is_valid_hostname())
    }

    /// Returns the bytes of each of the labels that compose this Name
    pub fn as_bytes(&self) -> impl Iterator<Item = &[u8]> {
        self.labels.iter().map(|label| label.as_ref())
    }
}

impl<'a> WireFormat<'a> for Name<'a> {
    const MINIMUM_LEN: usize = 1;

    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        // Parse labels will extract labels until it finds a 0 len label
        // or a pointer  to another label
        fn parse_labels<'a>(
            data: &mut BytesBuffer<'a>,
            name_len: &mut usize,
            labels: &mut Vec<Label<'a>>,
        ) -> crate::Result<Option<usize>> {
            loop {
                match data.get_u8()? {
                    0 => break Ok(None),
                    len if len & POINTER_MASK == POINTER_MASK => {
                        let mut pointer = len as u16;
                        pointer <<= 8;
                        pointer += data.get_u8()? as u16;
                        pointer &= !POINTER_MASK_U16;

                        break Ok(Some(pointer as usize));
                    }
                    len => {
                        *name_len += 1 + len as usize;

                        // Checking the full name len to avoid circular pointers
                        if *name_len >= MAX_NAME_LENGTH {
                            return Err(crate::SimpleDnsError::InvalidDnsPacket);
                        }

                        if len as usize > MAX_LABEL_LENGTH {
                            return Err(crate::SimpleDnsError::InvalidServiceLabel);
                        }

                        // Parsing allow invalid characters in the label.
                        // However, the length of the label must be validated (above)
                        labels.push(Label::new_unchecked(data.get_slice(len as usize)?));
                    }
                }
            }
        }

        let mut labels = Vec::new();
        let mut name_len = 0usize;

        let mut pointer = parse_labels(data, &mut name_len, &mut labels)?;

        let mut data = data.clone();
        while let Some(p) = pointer {
            // By creating a new buffer, it is possible to simplify the parse routine since
            // the original buffer position will remain intact when iterating throught the
            // pointers
            data = data.new_at(p)?;
            pointer = parse_labels(&mut data, &mut name_len, &mut labels)?;
        }

        Ok(Self { labels })
    }

    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        self.plain_append(out)
    }

    fn write_compressed_to<T: Write + Seek>(
        &'a self,
        out: &mut T,
        name_refs: &mut crate::lib::BTreeMap<crate::dns::label::ExactLabels<'a, '_>, u16>,
    ) -> crate::Result<()> {
        self.compress_append(out, name_refs)
    }

    fn len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + Self::MINIMUM_LEN
    }
}

impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Name::new(value)
    }
}

impl<'a> From<&'a [Label<'a>]> for Name<'a> {
    fn from(labels: &'a [Label<'a>]) -> Self {
        Name::new_with_labels(labels)
    }
}

impl<'a, const N: usize> From<[Label<'a>; N]> for Name<'a> {
    fn from(labels: [Label<'a>; N]) -> Self {
        Name::new_with_labels(&labels)
    }
}

impl Display for Name<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut labels = self.labels.iter();

        if let Some(label) = labels.next() {
            f.write_fmt(format_args!("{label}"))?;
        }

        for label in labels {
            f.write_fmt(format_args!(".{label}"))?;
        }

        Ok(())
    }
}

impl Debug for Name<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("Name")
            .field(&format!("{self}"))
            .field(&format!("{}", self.len()))
            .finish()
    }
}

impl PartialEq for Name<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.labels == other.labels
    }
}

impl Hash for Name<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.labels.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::Cursor;
    use crate::{lib::Vec, SimpleDnsError};

    #[test]
    fn construct_valid_names() {
        assert!(Name::new("some").is_ok());
        assert!(Name::new("some.local").is_ok());
        assert!(Name::new("some.local.").is_ok());
        assert!(Name::new("some-dash.local.").is_ok());
        assert!(Name::new("_sync_miss._tcp.local").is_ok());
        assert!(Name::new("1sync_miss._tcp.local").is_ok());

        assert_eq!(Name::new_unchecked("\u{1F600}.local.").labels.len(), 2);
    }

    #[test]
    fn is_link_local() {
        assert!(!Name::new("some.example.com").unwrap().is_link_local());
        assert!(Name::new("some.example.local.").unwrap().is_link_local());
    }

    #[test]
    fn parse_without_compression() {
        let mut data = BytesBuffer::new(
            b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\x01F\x03ISI\x04ARPA\x00\x04ARPA\x00",
        );
        data.advance(3).unwrap();
        let name = Name::parse(&mut data).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        let name = Name::parse(&mut data).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());
    }

    #[test]
    fn parse_with_compression() {
        let mut data = BytesBuffer::new(b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03\x07INVALID\xc0\x1b" );
        data.advance(3).unwrap();

        let name = Name::parse(&mut data).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        let name = Name::parse(&mut data).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());

        let name = Name::parse(&mut data).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", name.to_string());

        assert!(Name::parse(&mut data).is_err());
    }

    #[test]
    fn parse_handle_circular_pointers() {
        let mut data = BytesBuffer::new(&[249, 0, 37, 1, 1, 139, 192, 6, 1, 1, 1, 139, 192, 6]);
        data.advance(12).unwrap();

        assert_eq!(
            Name::parse(&mut data),
            Err(SimpleDnsError::InvalidDnsPacket)
        );
    }

    #[test]
    fn test_write() {
        let mut bytes = Vec::with_capacity(30);
        Name::new_unchecked("_srv._udp.local")
            .write_to(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);

        let mut bytes = Vec::with_capacity(30);
        Name::new_unchecked("_srv._udp.local2.")
            .write_to(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x06local2\x00", &bytes[..]);
    }

    #[test]
    fn root_name_should_generate_no_labels() {
        assert_eq!(Name::new_unchecked("").labels.len(), 0);
        assert_eq!(Name::new_unchecked(".").labels.len(), 0);
    }

    #[test]
    fn dot_sequence_should_generate_no_labels() {
        assert_eq!(Name::new_unchecked(".....").labels.len(), 0);
        assert_eq!(Name::new_unchecked("example.....com").labels.len(), 2);
    }

    #[test]
    fn root_name_should_write_zero() {
        let mut bytes = Vec::with_capacity(30);
        Name::new_unchecked(".").write_to(&mut bytes).unwrap();

        assert_eq!(b"\x00", &bytes[..]);
    }

    #[test]
    fn append_to_vec_with_compression() {
        let mut buf = Cursor::new(crate::lib::vec![0, 0, 0]);
        buf.set_position(3);

        let mut name_refs = Default::default();

        let f_isi_arpa = Name::new_unchecked("F.ISI.ARPA");
        f_isi_arpa
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        let foo_f_isi_arpa = Name::new_unchecked("FOO.F.ISI.ARPA");
        foo_f_isi_arpa
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");

        Name::new_unchecked("BAR.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");

        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        assert_eq!(data[..], buf.get_ref()[..]);
    }

    #[test]
    fn append_to_vec_with_compression_mult_names() {
        let mut buf = Cursor::new(Vec::new());
        let mut name_refs = Default::default();

        let isi_arpa = Name::new_unchecked("ISI.ARPA");
        isi_arpa
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add ISI.ARPA");

        let f_isi_arpa = Name::new_unchecked("F.ISI.ARPA");
        f_isi_arpa
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        let foo_f_isi_arpa = Name::new_unchecked("FOO.F.ISI.ARPA");
        foo_f_isi_arpa
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("BAR.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");

        let expected = b"\x03ISI\x04ARPA\x00\x01F\xc0\x00\x03FOO\xc0\x0a\x03BAR\xc0\x0a";
        assert_eq!(expected[..], buf.get_ref()[..]);

        let mut data = BytesBuffer::new(buf.get_ref());

        let first = Name::parse(&mut data).unwrap();
        assert_eq!("ISI.ARPA", first.to_string());
        let second = Name::parse(&mut data).unwrap();
        assert_eq!("F.ISI.ARPA", second.to_string());
        let third = Name::parse(&mut data).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", third.to_string());
        let fourth = Name::parse(&mut data).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", fourth.to_string());
    }

    #[test]
    fn names_differing_only_in_case_are_not_compressed_together() {
        let mut buf = Cursor::new(Vec::new());
        let mut name_refs = Default::default();

        let lower = Name::new_unchecked("foo.local");
        let upper = Name::new_unchecked("FOO.LOCAL");
        assert_eq!(lower, upper);

        lower
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add foo.local");
        upper
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.LOCAL");
        // an exact repeat is still compressed
        upper
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.LOCAL again");

        let expected = b"\x03foo\x05local\x00\x03FOO\x05LOCAL\x00\xc0\x0b";
        assert_eq!(expected[..], buf.get_ref()[..]);

        // casing survives a parse of the compressed bytes
        let mut data = BytesBuffer::new(buf.get_ref());
        let first = Name::parse(&mut data).unwrap();
        let second = Name::parse(&mut data).unwrap();
        assert_eq!(b"FOO", second.get_labels()[0].as_ref());
        assert_eq!(b"foo", first.get_labels()[0].as_ref());
    }

    #[test]
    fn ensure_different_domains_are_not_compressed() {
        let mut buf = Cursor::new(Vec::new());
        let mut name_refs = Default::default();

        let foo_bar_baz = Name::new_unchecked("FOO.BAR.BAZ");
        foo_bar_baz
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.BAR.BAZ");

        let foo_bar_buz = Name::new_unchecked("FOO.BAR.BUZ");
        foo_bar_buz
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.BAR.BUZ");

        Name::new_unchecked("FOO.BAR")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.BAR");

        let expected = b"\x03FOO\x03BAR\x03BAZ\x00\x03FOO\x03BAR\x03BUZ\x00\x03FOO\x03BAR\x00";
        assert_eq!(expected[..], buf.get_ref()[..]);
    }

    #[test]
    fn eq_other_name() -> Result<(), SimpleDnsError> {
        assert_eq!(Name::new("example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("some.example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.co")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.com.org")?, Name::new("example.com")?);

        let mut data =
            BytesBuffer::new(b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03");
        data.advance(3)?;
        assert_eq!(Name::new("F.ISI.ARPA")?, Name::parse(&mut data)?);
        assert_eq!(Name::new("FOO.F.ISI.ARPA")?, Name::parse(&mut data)?);
        Ok(())
    }

    #[test]
    fn len() -> crate::Result<()> {
        let mut bytes = Vec::new();
        let name_one = Name::new_unchecked("ex.com.");
        name_one.write_to(&mut bytes)?;

        assert_eq!(8, bytes.len());
        assert_eq!(bytes.len(), name_one.len());
        assert_eq!(8, Name::parse(&mut BytesBuffer::new(&bytes))?.len());

        Ok(())
    }

    #[test]
    fn len_compressed() -> crate::Result<()> {
        let name_one = Name::new_unchecked("ex.com.");
        let mut name_refs = Default::default();
        let mut bytes = Cursor::new(Vec::new());
        name_one.write_compressed_to(&mut bytes, &mut name_refs)?;
        name_one.write_compressed_to(&mut bytes, &mut name_refs)?;

        assert_eq!(10, bytes.get_ref().len());
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn hash() -> crate::Result<()> {
        fn get_hash(name: &Name) -> u64 {
            let mut hasher = std::hash::DefaultHasher::default();
            name.hash(&mut hasher);
            hasher.finish()
        }

        let mut data =
            BytesBuffer::new(b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03");
        data.advance(3)?;

        assert_eq!(
            get_hash(&Name::new("F.ISI.ARPA")?),
            get_hash(&Name::parse(&mut data)?)
        );

        assert_eq!(
            get_hash(&Name::new("FOO.F.ISI.ARPA")?),
            get_hash(&Name::parse(&mut data)?)
        );

        Ok(())
    }

    #[test]
    fn is_subdomain_of() {
        assert!(Name::new_unchecked("sub.example.com")
            .is_subdomain_of(&Name::new_unchecked("example.com")));

        assert!(!Name::new_unchecked("example.com")
            .is_subdomain_of(&Name::new_unchecked("example.com")));

        assert!(Name::new_unchecked("foo.sub.example.com")
            .is_subdomain_of(&Name::new_unchecked("example.com")));

        assert!(!Name::new_unchecked("example.com")
            .is_subdomain_of(&Name::new_unchecked("example.xom")));

        assert!(!Name::new_unchecked("domain.com")
            .is_subdomain_of(&Name::new_unchecked("other.domain")));

        assert!(!Name::new_unchecked("domain.com")
            .is_subdomain_of(&Name::new_unchecked("domain.com.br")));
    }

    #[test]
    fn subtract_domain() {
        let domain = Name::new_unchecked("_srv3._tcp.local");
        assert_eq!(
            Name::new_unchecked("a._srv3._tcp.local")
                .without(&domain)
                .unwrap()
                .to_string(),
            "a"
        );

        assert!(Name::new_unchecked("unrelated").without(&domain).is_none(),);

        assert_eq!(
            Name::new_unchecked("some.longer.domain._srv3._tcp.local")
                .without(&domain)
                .unwrap()
                .to_string(),
            "some.longer.domain"
        );
    }

    #[test]
    fn test_compress_append_near_boundary() -> crate::Result<()> {
        let mut buf = Cursor::new(Vec::new());
        let mut name_refs = Default::default();

        let before_boundary_pos = (MAX_COMPRESSION_OFFSET - 5) as usize;
        let padding = vec![0u8; before_boundary_pos];
        buf.write_all(&padding)?;

        let name1 = Name::new_unchecked("foo.example.com");
        let name2 = Name::new_unchecked("bar.test.net");

        // before the boundary
        let old_pos = buf.position();
        name1.write_compressed_to(&mut buf, &mut name_refs)?;
        assert_eq!(buf.position() - old_pos, name1.len() as u64);

        // after the boundary
        let old_pos = buf.position();
        name2.write_compressed_to(&mut buf, &mut name_refs)?;
        assert_eq!(buf.position() - old_pos, name2.len() as u64);

        // should be compressed
        let old_pos = buf.position();
        name1.write_compressed_to(&mut buf, &mut name_refs)?;
        assert_eq!(buf.position() - old_pos, 2);

        // should not be compressed
        let old_pos = buf.position();
        name2.write_compressed_to(&mut buf, &mut name_refs)?;
        assert_eq!(buf.position() - old_pos, name2.len() as u64);

        Ok(())
    }

    #[test]
    fn case_insensitive_label_and_name() {
        let lower = Name::new("_googlecast._tcp.local").unwrap();
        let upper = Name::new("_googlecast._TCP.LOCAL").unwrap();

        assert_eq!(lower, upper);
        assert!(Name::new("device._googlecast._TCP.LOCAL")
            .unwrap()
            .is_subdomain_of(&lower));

        let full = Name::new("device._googlecast._TCP.LOCAL").unwrap();
        let sub = full.without(&lower).unwrap();
        assert_eq!("device", sub.to_string());

        let mut map = std::collections::HashMap::new();
        map.insert(lower.clone(), 123);
        assert_eq!(Some(&123), map.get(&upper));

        let l1 = Label::new("Example".as_bytes()).unwrap();
        let l2 = Label::new("example".as_bytes()).unwrap();
        assert_eq!(l1, l2);
        assert_eq!(core::cmp::Ordering::Equal, l1.cmp(&l2));
    }

    #[test]
    fn escaped_dots_and_slashes() {
        let name = Name::new(r"My\.Device._googlecast._tcp.local").expect("failed to build name");
        assert_eq!(4, name.get_labels().len());
        assert_eq!(b"My.Device", name.get_labels()[0].as_ref());
        assert_eq!(r"My\.Device._googlecast._tcp.local", name.to_string());

        let name2 = Name::new(r"My\.Device._googlecast._tcp.local").expect("failed to build name");
        assert_eq!(4, name2.get_labels().len());
        assert_eq!(b"My.Device", name2.get_labels()[0].as_ref());
        assert_eq!(r"My\.Device._googlecast._tcp.local", name2.to_string());

        let formatted = name2.to_string();
        let roundtrip = Name::new(&formatted).expect("failed to build name");
        assert_eq!(name2, roundtrip);

        let name_slash = Name::new(r"My\\Device._tcp.local").expect("failed to build name");
        assert_eq!(3, name_slash.get_labels().len());
        assert_eq!(b"My\\Device", name_slash.get_labels()[0].as_ref());
        assert_eq!(r"My\\Device._tcp.local", name_slash.to_string());
    }

    #[test]
    fn escaped_dot_is_a_single_label_on_the_wire() {
        let name = Name::new(r"a\.b.local").expect("failed to build name");
        let mut bytes = Vec::new();
        name.write_to(&mut bytes).unwrap();

        // the dot is plain data on the wire, no escaping
        assert_eq!(b"\x03a.b\x05local\x00", &bytes[..]);

        let parsed = Name::parse(&mut BytesBuffer::new(&bytes)).unwrap();
        assert_eq!(name, parsed);
        assert_eq!(r"a\.b.local", parsed.to_string());
    }

    #[test]
    fn backslash_is_escaped_in_display() {
        let name = Name::new_with_labels(&[
            Label::new_unchecked(b"a\\b".as_slice()),
            Label::new_unchecked(b"local".as_slice()),
        ]);
        assert_eq!(r"a\\b.local", name.to_string());
    }

    #[test]
    fn escaped_backslash_followed_by_separator_dot() {
        // `\\` is a literal backslash, so the following `.` is a separator
        let name = Name::new(r"a\\.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a\\", name.get_labels()[0].as_ref());
        assert_eq!(b"local", name.get_labels()[1].as_ref());
    }

    #[test]
    fn escaped_dot_after_escaped_backslash() {
        // `\\\.` is a literal backslash followed by a literal dot
        let name = Name::new(r"a\\\.b.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a\\.b", name.get_labels()[0].as_ref());
    }

    #[test]
    fn dns_sd_instance_name_roundtrip() {
        // RFC 6763 section 4.3: dots inside the instance label are escaped
        let labels = [
            Label::new_unchecked(b"My Printer. Floor 2".as_slice()),
            Label::new_unchecked(b"_ipp".as_slice()),
            Label::new_unchecked(b"_tcp".as_slice()),
            Label::new_unchecked(b"local".as_slice()),
        ];
        let name = Name::new_with_labels(&labels);
        let text = name.to_string();
        assert_eq!(r"My Printer\. Floor 2._ipp._tcp.local", text);

        let parsed = Name::new(&text).unwrap();
        assert_eq!(name, parsed);
        assert_eq!(4, parsed.get_labels().len());
    }

    #[test]
    fn display_parse_roundtrip_with_special_bytes() {
        let name = Name::new_with_labels(&[
            Label::new_unchecked(b"a.b\\c.d".as_slice()),
            Label::new_unchecked(b"local".as_slice()),
        ]);
        let text = name.to_string();
        assert_eq!(r"a\.b\\c\.d.local", text);
        assert_eq!(name, Name::new(&text).unwrap());
    }

    #[test]
    fn decimal_escape_is_parsed_as_byte() {
        // RFC 1035 section 5.1: \DDD is the octet with that decimal value
        let name = Name::new(r"My\032Printer.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"My Printer", name.get_labels()[0].as_ref());

        let name = Name::new(r"a\046b.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a.b", name.get_labels()[0].as_ref());
    }

    #[test]
    fn escaped_non_special_char_is_the_char() {
        // RFC 1035 section 5.1: \X quotes X
        let name =
            Name::new(r"Stuart\'s\ Test\ Server._http._tcp.local").expect("failed to build name");
        assert_eq!(4, name.get_labels().len());
        assert_eq!(b"Stuart's Test Server", name.get_labels()[0].as_ref());
    }

    #[test]
    fn label_length_limit_counts_unescaped_octets() {
        // 63 octets once unescaped, even though the text form is longer
        let at_limit = format!("{}.local", r"a\.".repeat(31) + "a");
        let name = Name::new(&at_limit).unwrap();
        assert_eq!(63, name.get_labels()[0].len());

        // 64 octets once unescaped
        let over_limit = format!("{}.local", r"a\.".repeat(31) + "aa");
        assert!(Name::new(&over_limit).is_err());
    }

    #[test]
    fn malformed_decimal_escapes_are_rejected() {
        // RFC 4343 section 2.1: one or two digits are undefined
        assert!(Name::new(r"a\1.local").is_err());
        assert!(Name::new(r"a\12.local").is_err());
        // value does not fit in an octet
        assert!(Name::new(r"a\256b.local").is_err());
    }

    #[test]
    fn trailing_lone_backslash_is_rejected() {
        assert!(Name::new(r"local\").is_err());
        assert!(Name::new(r"a.local\").is_err());
    }

    #[test]
    fn decimal_escape_for_dot_is_data_not_separator() {
        // \046 is the octet 0x2E, but must not split the label
        let name = Name::new(r"a\046b.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a.b", name.get_labels()[0].as_ref());
        assert_eq!(r"a\.b.local", name.to_string());
    }

    #[test]
    fn decimal_escape_followed_by_digit() {
        // four digits: first three are the escape, the fourth is a literal digit
        let name = Name::new(r"a\0321b.local").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a 1b", name.get_labels()[0].as_ref());
    }

    #[test]
    fn decimal_escape_boundaries() {
        let name = Name::new(r"a\000\255z.local").expect("failed to build name");
        assert_eq!(b"a\x00\xffz", name.get_labels()[0].as_ref());

        let mut bytes = Vec::new();
        name.write_to(&mut bytes).unwrap();
        assert_eq!(b"\x04a\x00\xffz\x05local\x00", &bytes[..]);
    }

    #[test]
    fn rfc4343_examples() {
        let name =
            Name::new(r"Donald\032E\.\032Eastlake\0323rd.example.").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"Donald E. Eastlake 3rd", name.get_labels()[0].as_ref());

        let name = Name::new(r"a\000\\\255z.example.").expect("failed to build name");
        assert_eq!(2, name.get_labels().len());
        assert_eq!(b"a\x00\\\xffz", name.get_labels()[0].as_ref());
    }

    #[test]
    fn escaped_dot_before_trailing_dot_is_not_a_separator() {
        // the trailing unescaped dot only marks the name as absolute
        let name = Name::new(r"a\.").expect("failed to build name");
        assert_eq!(1, name.get_labels().len());
        assert_eq!(b"a.", name.get_labels()[0].as_ref());

        let absolute = Name::new(r"a\..").expect("failed to build name");
        assert_eq!(name, absolute);
    }

    #[test]
    fn root_name_with_escapes_elsewhere() {
        assert_eq!(0, Name::new_unchecked(".").get_labels().len());
        assert_eq!(1, Name::new_unchecked(r"\.").get_labels().len());
    }

    #[test]
    fn total_name_length_counts_unescaped_octets() {
        let label63 = r"a\.".repeat(31) + "a";
        let label60 = r"a\.".repeat(29) + "aa";

        // 3 * 64 + 61 + 1 = 254 octets
        let fits = format!("{label63}.{label63}.{label63}.{label60}");
        let name = Name::new(&fits).unwrap();
        assert_eq!(254, name.len());

        // 4 * 64 + 1 = 257 octets
        let too_long = format!("{label63}.{label63}.{label63}.{label63}");
        assert!(Name::new(&too_long).is_err());
    }

    #[test]
    fn hostname_valid() {
        assert!(Name::new_unchecked("example.com").is_valid_hostname());
        assert!(Name::new_unchecked("example.com.").is_valid_hostname());
        assert!(Name::new_unchecked("my-host.sub.example.com").is_valid_hostname());
        assert!(Name::new_unchecked("1host.local").is_valid_hostname());
        assert!(Name::new_unchecked("localhost").is_valid_hostname());
    }

    #[test]
    fn hostname_invalid() {
        assert!(!Name::new_unchecked("").is_valid_hostname());
        assert!(!Name::new_unchecked(".").is_valid_hostname());
        assert!(!Name::new_unchecked("-a.com").is_valid_hostname());
        assert!(!Name::new_unchecked("a-.com").is_valid_hostname());
        assert!(!Name::new_unchecked("_srv.local").is_valid_hostname());
        assert!(!Name::new_unchecked("a b.com").is_valid_hostname());
        assert!(!Name::new_unchecked("\u{1F600}.local").is_valid_hostname());
        // an escaped dot is data in the label, not a valid hostname character
        assert!(!Name::new_unchecked(r"a\.b.com").is_valid_hostname());
        // 64 octet label
        assert!(!Name::new_unchecked(&format!("{}.com", "a".repeat(64))).is_valid_hostname());
    }

    #[test]
    fn service_name_valid() {
        // RFC 6763 section 4.1.2: <sn>._tcp|_udp.<domain>
        assert!(Name::new_unchecked("_http._tcp.local").is_valid_service_name());
        assert!(Name::new_unchecked("_http._udp.local").is_valid_service_name());
        assert!(Name::new_unchecked("_http._tcp.local.").is_valid_service_name());
        assert!(Name::new_unchecked("_ipp-tls._tcp.example.com").is_valid_service_name());
        assert!(Name::new_unchecked("_9p._tcp.local").is_valid_service_name());
    }

    #[test]
    fn service_name_transport_is_case_insensitive() {
        // RFC 1035 section 2.3.3 / RFC 4343: comparison is case-insensitive
        assert!(Name::new_unchecked("_HTTP._TCP.local").is_valid_service_name());
        assert!(Name::new_unchecked("_http._Udp.local").is_valid_service_name());
    }

    #[test]
    fn service_name_invalid() {
        assert!(!Name::new_unchecked("").is_valid_service_name());
        // missing underscore on the service label
        assert!(!Name::new_unchecked("http._tcp.local").is_valid_service_name());
        // transport label must be _tcp or _udp
        assert!(!Name::new_unchecked("_http._ftp.local").is_valid_service_name());
        assert!(!Name::new_unchecked("_http.tcp.local").is_valid_service_name());
        assert!(!Name::new_unchecked("_http.local").is_valid_service_name());
        // the <Service> portion is a pair of labels
        assert!(!Name::new_unchecked("_http").is_valid_service_name());
        // service name syntax (RFC 6335)
        assert!(!Name::new_unchecked("_123._tcp.local").is_valid_service_name());
        assert!(!Name::new_unchecked("_a--b._tcp.local").is_valid_service_name());
        assert!(!Name::new_unchecked("_-a._tcp.local").is_valid_service_name());
        assert!(!Name::new_unchecked("_abcdefghijklmnop._tcp.local").is_valid_service_name());
        // invalid domain label
        assert!(!Name::new_unchecked("_http._tcp.-bad.local").is_valid_service_name());
    }

    #[test]
    fn instance_name_valid() {
        // RFC 6763 section 4.3: <Instance>.<sn>._tcp|_udp.<domain>
        assert!(Name::new_unchecked("printer._ipp._tcp.local").is_valid_instance_name());
        assert!(Name::new_unchecked("My Printer._ipp._tcp.local").is_valid_instance_name());
        assert!(Name::new_unchecked("My Printer._ipp._tcp.local.").is_valid_instance_name());
        assert!(
            Name::new_unchecked("Stuart's Test Server._http._tcp.local").is_valid_instance_name()
        );
        assert!(Name::new_unchecked("\u{1F5A8} Printer._ipp._udp.local").is_valid_instance_name());
        // dot inside the instance label
        assert!(Name::new_unchecked(r"My\. Printer._ipp._tcp.local").is_valid_instance_name());
        assert!(Name::new_with_labels(&[
            Label::new_unchecked(b"My. Printer".as_slice()),
            Label::new_unchecked(b"_ipp".as_slice()),
            Label::new_unchecked(b"_tcp".as_slice()),
            Label::new_unchecked(b"local".as_slice()),
        ])
        .is_valid_instance_name());
    }

    #[test]
    fn instance_name_escaped_dot_keeps_label_count() {
        let name = Name::new_unchecked(r"a\.b._ipp._tcp.local");
        assert_eq!(4, name.get_labels().len());
        assert!(name.is_valid_instance_name());

        // unescaped, the same text is five labels and the service pair is misplaced
        let name = Name::new_unchecked("a.b._ipp._tcp.local");
        assert_eq!(5, name.get_labels().len());
        assert!(!name.is_valid_instance_name());
    }

    #[test]
    fn instance_name_invalid() {
        assert!(!Name::new_unchecked("").is_valid_instance_name());
        // missing instance label: `_ipp` is taken as the instance, so the pair is wrong
        assert!(!Name::new_unchecked("_ipp._tcp.local").is_valid_instance_name());
        assert!(!Name::new_unchecked("My Printer._ipp._ftp.local").is_valid_instance_name());
        assert!(!Name::new_unchecked("My Printer.ipp._tcp.local").is_valid_instance_name());
        assert!(!Name::new_unchecked("My Printer._123._tcp.local").is_valid_instance_name());
        // the <Service> pair is required
        assert!(!Name::new_unchecked("My Printer").is_valid_instance_name());
        assert!(!Name::new_unchecked("My Printer._ipp").is_valid_instance_name());
        // instance label longer than 63 octets
        let long = format!("{}._ipp._tcp.local", "a".repeat(64));
        assert!(!Name::new_unchecked(&long).is_valid_instance_name());
    }

    #[test]
    fn sub_type_name_valid() {
        // RFC 6763 section 7.1: <Subtype>._sub.<Service>.<Domain>
        assert!(Name::new_unchecked("_printer._sub._http._tcp.local").is_valid_sub_type_name());
        assert!(Name::new_unchecked("_printer._sub._http._udp.local.").is_valid_sub_type_name());
    }

    #[test]
    fn sub_type_name_allows_arbitrary_label() {
        // subtype strings are not required to begin with an underscore and
        // may be constructed using arbitrary 8-bit data values
        assert!(Name::new_unchecked("printer._sub._http._tcp.local").is_valid_sub_type_name());
        assert!(
            Name::new_unchecked("The Music Store._sub._http._tcp.local").is_valid_sub_type_name()
        );
        assert!(Name::new_with_labels(&[
            Label::new_unchecked(b"a.b\xff".as_slice()),
            Label::new_unchecked(b"_sub".as_slice()),
            Label::new_unchecked(b"_http".as_slice()),
            Label::new_unchecked(b"_tcp".as_slice()),
            Label::new_unchecked(b"local".as_slice()),
        ])
        .is_valid_sub_type_name());
    }

    #[test]
    fn sub_type_name_invalid() {
        assert!(!Name::new_unchecked("").is_valid_sub_type_name());
        // `_sub` marker is required
        assert!(!Name::new_unchecked("_printer._http._tcp.local").is_valid_sub_type_name());
        assert!(!Name::new_unchecked("_printer._subx._http._tcp.local").is_valid_sub_type_name());
        // the service must still be valid
        assert!(!Name::new_unchecked("_printer._sub.http._tcp.local").is_valid_sub_type_name());
        assert!(!Name::new_unchecked("_printer._sub._http._ftp.local").is_valid_sub_type_name());
        assert!(!Name::new_unchecked("_printer._sub._123._tcp.local").is_valid_sub_type_name());
        // missing service pair
        assert!(!Name::new_unchecked("_printer._sub").is_valid_sub_type_name());
        assert!(!Name::new_unchecked("_printer").is_valid_sub_type_name());
    }
}
