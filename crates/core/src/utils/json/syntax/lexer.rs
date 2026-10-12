use crate::Utf16String;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Token {
    String,
    Value,
    Identifier { start: usize, end: usize },
    Punctuation(u8),
    End,
}

pub(super) struct Lexer<'a> {
    source: &'a [u16],
    offset: usize,
}

impl<'a> Lexer<'a> {
    pub(super) fn new(source: &'a [u16]) -> Self {
        Self { source, offset: 0 }
    }

    fn current(&self) -> Option<u16> {
        self.source.get(self.offset).copied()
    }

    pub(super) fn next(&mut self) -> Result<Token, Utf16String> {
        while matches!(self.current(), Some(9 | 10 | 13 | 32)) {
            self.offset += 1;
        }
        let Some(unit) = self.current() else {
            return Ok(Token::End);
        };
        match unit {
            34 => self.string(),
            39 => Err("Single quotes (') are not allowed in JSON".into()),
            45 | 48..=57 => self.number(),
            36 | 65..=90 | 95 | 97..=122 => {
                for literal in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
                    if self
                        .source
                        .get(self.offset..self.offset + literal.len())
                        .is_some_and(|candidate| {
                            candidate
                                .iter()
                                .copied()
                                .eq(literal.iter().copied().map(u16::from))
                        })
                    {
                        self.offset += literal.len();
                        return Ok(Token::Value);
                    }
                }
                let start = self.offset;
                while matches!(
                    self.current(),
                    Some(36 | 48..=57 | 65..=90 | 95 | 97..=122 | 0x200c | 0x200d)
                ) {
                    self.offset += 1;
                }
                Ok(Token::Identifier {
                    start,
                    end: self.offset,
                })
            }
            40 | 41 | 44 | 46 | 58 | 59 | 61 | 91 | 93 | 123 | 125 => {
                self.offset += 1;
                Ok(Token::Punctuation(unit as u8))
            }
            unit => Err(message("Unrecognized token '", &[unit], "'")),
        }
    }

    fn string(&mut self) -> Result<Token, Utf16String> {
        self.offset += 1;
        while let Some(unit) = self.current() {
            match unit {
                34 => {
                    self.offset += 1;
                    return Ok(Token::String);
                }
                0..=31 => break,
                92 => {
                    self.offset += 1;
                    match self.current() {
                        None => break,
                        Some(34 | 47 | 92 | 98 | 102 | 110 | 114 | 116) => self.offset += 1,
                        Some(117) => {
                            let Some(escape) = self.source.get(self.offset..self.offset + 5) else {
                                return Err("\\u must be followed by 4 hex digits".into());
                            };
                            if !escape
                                .iter()
                                .skip(1)
                                .all(|unit| matches!(unit, 48..=57 | 65..=70 | 97..=102))
                            {
                                return Err(message(
                                    "\"\\",
                                    escape,
                                    "\" is not a valid unicode escape",
                                ));
                            }
                            self.offset += 5;
                        }
                        Some(unit) => {
                            return Err(message("Invalid escape character ", &[unit], ""));
                        }
                    }
                }
                _ => self.offset += 1,
            }
        }
        Err("Unterminated string".into())
    }

    fn number(&mut self) -> Result<Token, Utf16String> {
        if self.current() == Some(45) {
            self.offset += 1;
        }
        match self.current() {
            Some(48) => self.offset += 1,
            Some(49..=57) => self.digits(),
            _ => return Err("Invalid number".into()),
        }
        if self.current() == Some(46) {
            self.offset += 1;
            if !matches!(self.current(), Some(48..=57)) {
                return Err("Invalid digits after decimal point".into());
            }
            self.digits();
        }
        if matches!(self.current(), Some(69 | 101)) {
            let exponent = self.offset;
            self.offset += 1;
            if matches!(self.current(), Some(43 | 45)) {
                self.offset += 1;
            }
            if !matches!(self.current(), Some(48..=57)) {
                // WTF::parseJSONDouble's fixed mode leaves an incomplete exponent for the next token.
                self.offset = exponent;
                return Ok(Token::Value);
            }
            self.digits();
        }
        Ok(Token::Value)
    }

    fn digits(&mut self) {
        while matches!(self.current(), Some(48..=57)) {
            self.offset += 1;
        }
    }
}

fn message(prefix: &str, units: &[u16], suffix: &str) -> Utf16String {
    Utf16String::from_units(
        prefix
            .encode_utf16()
            .chain(units.iter().copied())
            .chain(suffix.encode_utf16())
            .collect(),
    )
}
