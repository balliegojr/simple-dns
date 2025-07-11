pub trait Write {
    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()>;
    fn flush(&mut self) -> crate::Result<()>;
}

#[cfg(feature = "std")]
impl<T> Write for T
where
    T: std::io::Write,
{
    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
        self.write_all(bytes)
            .map_err(|_| crate::SimpleDnsError::FailedToWrite)
    }

    fn flush(&mut self) -> crate::Result<()> {
        self.flush()
            .map_err(|_| crate::SimpleDnsError::FailedToWrite)
    }
}

#[cfg(all(feature = "alloc", not(feature = "std")))]
impl Write for crate::lib::Vec<u8> {
    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(all(feature = "alloc", not(feature = "std")))]
impl Write for &mut [u8] {
    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
        if self.len() != bytes.len() {
            return Err(crate::SimpleDnsError::FailedToWrite);
        }

        self.copy_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}
