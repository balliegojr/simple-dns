use std::{
    collections::HashMap,
    io::{Seek, Write},
};

/// Represents anything that can be part of a dns packet (Question, Resource Record, RData)
pub(crate) trait PacketPart<'a> {
    /// Parse the contents of the data buffer begining in the given position
    /// It is necessary to pass the full buffer to this function, to be able to correctly implement name compression
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized;

    /// Write this part bytes to the writer
    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()>;

    fn write_compressed_to<T: Write + Seek>(
        &self,
        out: &mut T,
        _name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.write_to(out)
    }

    /// Returns the length in bytes of this content
    fn len(&self) -> usize;
}
