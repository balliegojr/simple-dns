pub(crate) trait Write {
    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()>;
}
