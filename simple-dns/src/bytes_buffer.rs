/// This buffer is used to read bytes from a slice in a safe way. It keeps track of the current
/// position and ensures that the buffer does not read past the end of the slice.
///
/// `get_*` functions return the value at the current position and advances the buffer position by the
/// size of the value read.
///
/// `peek_*` functions return the value at the specified offset without advancing the buffer position.
#[derive(Debug)]
pub struct BytesBuffer<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BytesBuffer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns `true` if there are more bytes remaining to read.
    pub fn has_remaining(&self) -> bool {
        self.offset < self.data.len()
    }

    /// advances the buffer position by `length` bytes if there are enough bytes remaining.
    pub fn advance(&mut self, length: usize) -> crate::Result<()> {
        self.bounds_check(length)?;
        self.offset += length;

        Ok(())
    }

    /// Returns a new buffer that with the offset set to the specified position.
    ///
    /// `postion` must be less than the current offset.
    pub fn previous_offset_ptr(&mut self, position: usize) -> crate::Result<Self> {
        if position >= self.offset {
            return Err(crate::SimpleDnsError::InvalidDnsPacket);
        }

        Ok(Self {
            data: self.data,
            offset: position,
        })
    }

    /// Returns a new buffer with the end of the buffer set to the current offset plus `length`.
    /// Used when parsing data where the length is not known inside the function receiving the
    /// buffer.
    pub fn limit_to(&mut self, length: usize) -> crate::Result<Self> {
        self.bounds_check(length)?;

        let data = &self.data[..self.offset + length];
        let offset = self.offset;
        self.offset += length;

        Ok(Self { data, offset })
    }

    /// Returns a slice of the remaining bytes in the buffer.
    pub fn get_remaining(&mut self) -> crate::Result<&'a [u8]> {
        let value = &self.data[self.offset..];
        self.offset = self.data.len();

        Ok(value)
    }

    /// Returns a slice of the next `length` bytes in the buffer.
    pub fn get_slice(&mut self, length: usize) -> crate::Result<&'a [u8]> {
        self.bounds_check(length)?;

        let value = &self.data[self.offset..self.offset + length];
        self.offset += length;

        Ok(value)
    }

    /// Returns the u32 value at the `offset` position without advancing the offset.
    pub fn peek_u32_in(&self, offset: usize) -> crate::Result<u32> {
        self.peek_array(offset).map(u32::from_be_bytes)
    }

    /// Returns the u16 value at the `offset` position without advancing the offset.
    pub fn peek_u16_in(&self, offset: usize) -> crate::Result<u16> {
        self.peek_array(offset).map(u16::from_be_bytes)
    }

    /// Returns the u128 value in the current position and advances the offset.
    pub fn get_u128(&mut self) -> crate::Result<u128> {
        self.get_array().map(u128::from_be_bytes)
    }

    /// Returns the i32 value in the current position and advances the offset.
    pub fn get_i32(&mut self) -> crate::Result<i32> {
        self.get_array().map(i32::from_be_bytes)
    }

    /// Returns the u32 value in the current position and advances the offset.
    pub fn get_u32(&mut self) -> crate::Result<u32> {
        self.get_array().map(u32::from_be_bytes)
    }

    /// Returns the u16 value in the current position and advances the offset.
    pub fn get_u16(&mut self) -> crate::Result<u16> {
        self.get_array().map(u16::from_be_bytes)
    }

    /// Returns the u8 value in the current position and advances the offset.
    pub fn get_u8(&mut self) -> crate::Result<u8> {
        self.bounds_check(1)?;

        let value = self.data[self.offset];
        self.offset += 1;

        Ok(value)
    }

    /// Peek an array of size N at the specified offset without advancing the offset.
    fn peek_array<const N: usize>(&self, offset: usize) -> crate::Result<[u8; N]> {
        self.bounds_check(N + offset)?;

        let offset = self.offset + offset;
        let value = self.data[offset..offset + N].try_into().unwrap();

        Ok(value)
    }

    /// Returns an array of size N in the current position and advances the offset.
    pub fn get_array<const N: usize>(&mut self) -> crate::Result<[u8; N]> {
        self.bounds_check(N)?;

        let value = self.data[self.offset..self.offset + N].try_into().unwrap();
        self.offset += N;

        Ok(value)
    }

    /// Checks if there are `length` bytes available to read from the current offset.
    fn bounds_check(&self, length: usize) -> crate::Result<()> {
        if (self.offset + length) <= self.data.len() {
            Ok(())
        } else {
            Err(crate::SimpleDnsError::InsufficientData)
        }
    }
}

impl<'a> From<&'a [u8]> for BytesBuffer<'a> {
    fn from(value: &'a [u8]) -> BytesBuffer<'a> {
        Self::new(value)
    }
}
