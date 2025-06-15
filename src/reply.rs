use bytes::Bytes;
use bytes::BytesMut;

#[derive(Clone)]
pub struct Reply {
    code: u16,
    ecode: Option<EnhancedCode>,
    text: Bytes,
}

impl Reply {
    pub fn new_checked(
        code: u16,
        ecode: Option<EnhancedCode>,
        text: impl Into<Bytes>,
    ) -> Option<Self> {
        assert!(
            (200..600).contains(&code),
            "code {code} not in range [200, 599]"
        );

        let text = text.into();
        for byte in &text {
            if !byte.is_ascii_graphic() && !b" \n\t".contains(byte) {
                return None;
            }
        }

        Some(Reply { code, ecode, text })
    }

    pub fn new_static(code: u16, ecode: Option<EnhancedCode>, text: &'static str) -> Self {
        Self::new_checked(code, ecode, text)
            .expect("reply text should contain \\t, \\n, space, and printable ASCII")
    }

    pub fn ok() -> Self {
        Self::new_static(250, None, "OK")
    }

    pub fn bad_sequence() -> Self {
        Self::new_static(503, None, "Bad sequence of commands")
    }

    pub fn no_mail_transaction() -> Self {
        Self::new_static(503, None, "No mail transaction in progress")
    }

    pub fn no_valid_recipients() -> Self {
        Self::new_static(554, None, "No valid recipients")
    }

    pub fn syntax_error() -> Self {
        Self::new_static(500, None, "Syntax error")
    }

    pub fn not_implemented() -> Self {
        Self::new_static(502, None, "Command not implemented")
    }

    pub fn data_ok() -> Self {
        Self::new_static(354, None, "OK, send data")
    }

    /// Used when we cannot read all mail data, such as with an
    /// oversized message.
    pub fn data_abort() -> Self {
        Self::new_static(450, None, "Data abort")
    }

    pub fn is_error(&self) -> bool {
        matches!(self.category(), Category::TempError | Category::PermError)
    }

    fn category(&self) -> Category {
        // Caveat: 552 on reply to RCPT is considered temporary.

        match self.code {
            200..=299 => Category::Success,
            300..=399 => Category::Intermediate,
            400..=499 => Category::TempError,
            500..=599 => Category::PermError,
            _ => unreachable!(),
        }
    }
}

pub(crate) trait ReplyDefault {
    fn with_default(self, default: Reply) -> Result<Reply, Reply>;
}

impl ReplyDefault for Option<Reply> {
    fn with_default(self, default: Reply) -> Result<Reply, Reply> {
        let expected_category = default.category();
        let reply = self.unwrap_or(default);
        let category = reply.category();

        if category == expected_category {
            Ok(reply)
        } else {
            Err(reply)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Category {
    Success,
    Intermediate,
    TempError,
    PermError,
}

impl Reply {
    pub(crate) fn write_to(&self, buf: &mut BytesMut) {
        let mut lines_iter = self.text.split(|&b| b == b'\n').peekable();

        while let Some(line) = lines_iter.next() {
            buf.extend_from_slice(itoa::Buffer::new().format(self.code).as_bytes());

            buf.extend_from_slice(lines_iter.peek().map_or(b" ", |_| b"-"));

            if let Some(EnhancedCode(a, b, c)) = self.ecode {
                buf.extend_from_slice(itoa::Buffer::new().format(a).as_bytes());
                buf.extend_from_slice(b".");
                buf.extend_from_slice(itoa::Buffer::new().format(b).as_bytes());
                buf.extend_from_slice(b".");
                buf.extend_from_slice(itoa::Buffer::new().format(c).as_bytes());
                buf.extend_from_slice(b" ");
            }

            buf.extend_from_slice(line);
            buf.extend_from_slice(b"\r");
        }
    }
}

#[derive(Clone, Copy)]
pub struct EnhancedCode(pub u8, pub u16, pub u16);
