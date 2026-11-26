use std::io::{self, BufReader, Read, Seek};

pub fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Bound individual strings and text lines. A category or file can be many
// megabytes long and is always traversed without allocating its declared size.
pub const MAX_STRING: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub enum Value {
    Number(u64),
    Bytes { end: u64 },
}

pub struct Reader<R> {
    input: BufReader<R>,
    pub pos: u64,
}

impl<R: Read + Seek> Reader<R> {
    pub fn new(input: R) -> Self {
        Self {
            input: BufReader::new(input),
            pos: 0,
        }
    }

    pub fn seek(&mut self, pos: u64) -> io::Result<()> {
        // File length is limited to i64::MAX by the CLI.
        self.input.seek_relative(pos as i64 - self.pos as i64)?;
        self.pos = pos;
        Ok(())
    }

    pub fn bytes(&mut self, end: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        let len = end - self.pos;
        if len > MAX_STRING as u64 {
            return Err(invalid("geo string exceeds 1 MiB"));
        }
        buf.resize(len as usize, 0);
        self.input.read_exact(buf)?;
        self.pos = end;
        Ok(())
    }

    fn varint(&mut self, end: u64) -> io::Result<u64> {
        let mut result = 0;
        for shift in (0..=63).step_by(7) {
            if self.pos == end {
                return Err(invalid("truncated protobuf varint"));
            }
            let mut byte = [0];
            self.input.read_exact(&mut byte)?;
            self.pos += 1;
            let byte = byte[0];
            if shift == 63 && byte > 1 {
                return Err(invalid("protobuf varint exceeds u64"));
            }
            result |= u64::from(byte & 127) << shift;
            if byte < 128 {
                return Ok(result);
            }
        }
        Err(invalid("protobuf varint exceeds u64"))
    }

    pub fn walk(
        &mut self,
        end: u64,
        mut field: impl FnMut(&mut Self, u64, Value) -> io::Result<()>,
    ) -> io::Result<()> {
        while self.pos < end {
            let key = self.varint(end)?;
            let number = key >> 3;
            if !(1..=0x1fff_ffff).contains(&number) {
                return Err(invalid("invalid protobuf field number"));
            }
            let wire = key & 7;
            let len = match wire {
                0 => {
                    let value = self.varint(end)?;
                    field(self, number, Value::Number(value))?;
                    continue;
                }
                1 => 8,
                2 => self.varint(end)?,
                5 => 4,
                _ => return Err(invalid("unsupported protobuf wire type")),
            };
            if len > end - self.pos {
                return Err(invalid("protobuf field crosses message boundary"));
            }
            let field_end = self.pos + len;
            if wire == 2 {
                field(self, number, Value::Bytes { end: field_end })?;
            }
            if self.pos != field_end {
                self.seek(field_end)?;
            }
        }
        Ok(())
    }
}
