use crate::{
    lib::Vec,
    seek::{Seek, SeekFrom},
    write::Write,
};

pub struct Cursor {
    pos: u64,
    inner: Vec<u8>,
}

impl Cursor {
    pub fn new(inner: Vec<u8>) -> Self {
        Self { pos: 0, inner }
    }

    pub fn set_position(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }

    pub fn get_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Write for Cursor {
    fn write_all(&mut self, buf: &[u8]) -> crate::Result<()> {
        if buf.len() + self.pos as usize > self.inner.len() {
            self.inner.resize(self.pos as usize + buf.len(), 0);
        }

        slice_write_all(&mut self.pos, &mut self.inner, buf)
    }

    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

#[inline]
fn slice_write_all(pos_mut: &mut u64, slice: &mut [u8], buf: &[u8]) -> crate::Result<()> {
    let n = slice_write(pos_mut, slice, buf)?;
    if n < buf.len() {
        Err(crate::SimpleDnsError::FailedToWrite)
    } else {
        Ok(())
    }
}

#[inline]
fn slice_write(pos_mut: &mut u64, slice: &mut [u8], buf: &[u8]) -> crate::Result<usize> {
    let pos = core::cmp::min(*pos_mut, slice.len() as u64);
    (&mut slice[(pos as usize)..]).write_all(buf)?;
    *pos_mut += buf.len() as u64;
    Ok(buf.len())
}

impl Seek for Cursor {
    fn seek(&mut self, style: SeekFrom) -> crate::Result<u64> {
        let (base_pos, offset) = match style {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::End(n) => (self.inner.len() as u64, n),
            SeekFrom::Current(n) => (self.pos, n),
        };
        match base_pos.checked_add_signed(offset) {
            Some(n) => {
                self.pos = n;
                Ok(self.pos)
            }
            None => Err(crate::SimpleDnsError::FailedToWrite),
        }
    }
}
