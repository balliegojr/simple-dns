use std::collections::HashMap;

/// Represents anything that can be part of a dns packet (Question, Resource Record, RData)
pub(crate) trait PacketPart<'a> {
    /// Parse the contents of the data buffer begining in the given position
    /// It is necessary to pass the full buffer to this function, to be able to correctly implement name compression
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized;

    /// Append the bytes of this content to a given vector
    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()>;

    /// Returns the length in bytes of this content
    fn len(&self) -> usize;
}
