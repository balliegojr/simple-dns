macro_rules! rr_wrapper {
    (#[doc=$doc:expr] $t:ident: $w:ident = $c:literal) => {
        #[derive(Debug, PartialEq, Eq, Hash, Clone)]
        #[doc = $doc]
        pub struct $t<'a>($w<'a>);

        impl<'a> RR for $t<'a> {
            const TYPE_CODE: u16 = $c;
        }

        impl<'a> From<$w<'a>> for $t<'a> {
            fn from(value: $w<'a>) -> Self {
                $t(value)
            }
        }

        impl<'a> $t<'a> {
            /// Transforms the inner data into it's owned type
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

            fn append_to_vec(
                &self,
                out: &mut Vec<u8>,
                name_refs: &mut Option<&mut std::collections::HashMap<u64, usize>>,
            ) -> crate::Result<()> {
                self.0.append_to_vec(out, name_refs)
            }

            fn len(&self) -> usize {
                self.0.len()
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
                    return Err(crate::SimpleDnsError::NoEnoughData);
                }

                let rdatatype = u16::from_be_bytes(data[position..position + 2].try_into()?).into();
                let rdatalen = u16::from_be_bytes(data[position + 8..position + 10].try_into()?) as usize;

                if position + 10 + rdatalen > data.len() {
                    return Err(crate::SimpleDnsError::NoEnoughData);
                }

                parse_rdata(&data[..position + 10 + rdatalen], position + 10, rdatatype)
            }

            fn append_to_vec(
                &self,
                out: &mut Vec<u8>,
                name_refs: &mut Option<&mut HashMap<u64, usize>>,
            ) -> crate::Result<()> {
                match &self {
                    $(
                        RData::$i(data) => data.append_to_vec(out, name_refs),
                    )+

                    RData::NULL(_, data) => data.append_to_vec(out, name_refs),
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

            /// Transforms the inner data into it's owned type
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
