macro_rules! rr_wrapper {
    (#[doc=$doc:expr] $t:ident: $w:ident = $c:literal) => {
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        #[doc = $doc]
        pub struct $t<'a>(pub $w<'a>);

        impl<'a> RR for $t<'a> {
            const TYPE_CODE: u16 = $c;
        }

        impl<'a> From<$w<'a>> for $t<'a> {
            fn from(value: $w<'a>) -> Self {
                $t(value)
            }
        }

        impl<'a> $t<'a> {
            /// Transforms the inner data into its owned type
            pub fn into_owned<'b>(self) -> $t<'b> {
                $t(self.0.into_owned())
            }
        }

        impl<'a> PacketPart<'a> for $t<'a> {
            fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
            where
                Self: Sized,
            {
                $w::parse(data, position).map(|n| $t(n))
            }

            fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
                self.0.write_to(out)
            }

            fn write_compressed_to<T: std::io::Write + std::io::Seek>(
                &'a self,
                out: &mut T,
                name_refs: &mut std::collections::HashMap<&'a [crate::dns::name::Label<'a>], usize>,
            ) -> crate::Result<()> {
                self.0.write_compressed_to(out, name_refs)
            }

            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<'a> std::ops::Deref for $t<'a> {
            type Target = $w<'a>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'a> std::ops::DerefMut for $t<'a> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

macro_rules! rdata_enum {
    ($($i:tt$(<$x:lifetime>)?,)+) => {
        /// Represents the RData of each [`TYPE`]
        #[derive(Debug, Eq, PartialEq, Hash, Clone)]
        #[allow(missing_docs)]
        pub enum RData<'a> {
            $(
                $i($i$(<$x>)?),
            )+

            NULL(u16, NULL<'a>),
        }

        impl<'a> PacketPart<'a> for RData<'a> {
            fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
            where
                Self: Sized,
            {
                if position + 10 > data.len() {
                    return Err(crate::SimpleDnsError::InsufficientData);
                }

                let rdatatype = u16::from_be_bytes(data[position..position + 2].try_into()?).into();
                let rdatalen = u16::from_be_bytes(data[position + 8..position + 10].try_into()?) as usize;

                if position + 10 + rdatalen > data.len() {
                    return Err(crate::SimpleDnsError::InsufficientData);
                }

                parse_rdata(&data[..position + 10 + rdatalen], position + 10, rdatatype)
            }

            fn write_to<T: std::io::Write>(
                &self,
                out: &mut T,
            ) -> crate::Result<()> {
                match &self {
                    $(
                        RData::$i(data) => data.write_to(out),
                    )+

                    RData::NULL(_, data) => data.write_to(out),
                }
            }

            fn write_compressed_to<T: std::io::Write + std::io::Seek>(
                &'a self,
                out: &mut T,
                name_refs: &mut  HashMap<&'a [crate::dns::name::Label<'a>], usize>,
            ) -> crate::Result<()> {
                match &self {
                    $(
                        RData::$i(data) => data.write_compressed_to(out, name_refs),
                    )+

                    RData::NULL(_, data) => data.write_compressed_to(out, name_refs),
                }
            }

            fn len(&self) -> usize {
                match &self {
                    $(
                        RData::$i(data) => data.len(),
                    )+

                    RData::NULL(_, data) => data.len(),
                }
            }
        }



        impl<'a> RData<'a> {
            /// Returns the [`TYPE`] of this RData
            pub fn type_code(&self) -> TYPE {
                match self {
                    $(
                        RData::$i(_) => TYPE::$i,
                    )+

                    RData::NULL(type_code, _) => TYPE::Unknown(*type_code),
                }
            }

            /// Transforms the inner data into its owned type
            pub fn into_owned<'b>(self) -> RData<'b> {
                match self {
                    $(
                        RData::$i(data) => RData::$i(data.into_owned()),
                    )+

                    RData::NULL(rdatatype, data) => RData::NULL(rdatatype, data.into_owned()),
                }
            }
        }

        fn parse_rdata(data: &[u8], position: usize, rdatatype: TYPE) -> crate::Result<RData> {
            let rdata = match rdatatype {
                $(
                    TYPE::$i => RData::$i($i::parse(data, position)?),
                )+

                TYPE::NULL => RData::NULL(rdatatype.into(), NULL::parse(data, position)?),
                TYPE::Unknown(rdatatype) => RData::NULL(rdatatype, NULL::parse(data, position)?),
            };

            Ok(rdata)
        }


        /// Possible TYPE values in DNS Resource Records
        /// Each value is described according to its own RFC
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        #[allow(missing_docs)]
        #[non_exhaustive]
        pub enum TYPE {
            $( $i,)+

            NULL,
            Unknown(u16)
        }


        impl From<TYPE> for u16 {
            fn from(value: TYPE) -> Self {
                match value {
                    $(
                        TYPE::$i => $i::TYPE_CODE,
                    )+

                    TYPE::NULL => NULL::TYPE_CODE,
                    TYPE::Unknown(x) => x,
                }
            }
        }

        impl From<u16> for TYPE {
            fn from(value: u16) -> Self {
                match value {
                    $(
                        $i::TYPE_CODE => TYPE::$i,
                    )+

                    NULL::TYPE_CODE => TYPE::NULL,
                    v => TYPE::Unknown(v),
                }
            }
        }
    }
}

pub(crate) use rdata_enum;
pub(crate) use rr_wrapper;
