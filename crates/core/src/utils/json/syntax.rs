//! Syntax diagnostics follow Bun 1.4.2's pinned JavaScriptCore LiteralParser.
//! WebKit 2e2aa2290fac856d6f451ceacb58f7f5b44dd057 reports lexer errors before grammar errors.

use crate::{AuthError, Utf16String};

mod lexer;
use lexer::{Lexer, Token};

#[cfg(test)]
mod native_contract;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
enum Container {
    Array,
    Object,
}

/// Classify failed decoding only. A valid source can still exceed the Rust value representation.
pub(super) fn error(source: &[u16]) -> Option<AuthError> {
    check(source).err().map(|message| {
        let mut units = "JSON Parse error: ".encode_utf16().collect::<Vec<_>>();
        units.extend_from_slice(message.as_utf16());
        AuthError::syntax_error(Utf16String::from_units(units).into())
    })
}

fn check(source: &[u16]) -> Result<(), Utf16String> {
    let mut lexer = Lexer::new(source);
    let mut token = lexer.next()?;
    let mut containers = Vec::new();
    loop {
        match token {
            Token::Punctuation(b'[') => {
                token = lexer.next()?;
                if token != Token::Punctuation(b']') {
                    containers.push(Container::Array);
                    continue;
                }
                token = lexer.next()?;
            }
            Token::Punctuation(b'{') => {
                token = lexer.next()?;
                if token == Token::String {
                    token = property_value(&mut lexer)?;
                    containers.push(Container::Object);
                    continue;
                }
                if token != Token::Punctuation(b'}') {
                    return Err("Expected '}'".into());
                }
                token = lexer.next()?;
            }
            Token::String | Token::Value => token = lexer.next()?,
            token => return Err(unexpected(token, source)),
        }
        loop {
            match containers.last() {
                Some(Container::Array) if token == Token::Punctuation(b',') => {
                    token = lexer.next()?;
                    if token == Token::Punctuation(b']') {
                        return Err("Unexpected comma at the end of array expression".into());
                    }
                    break;
                }
                Some(Container::Object) if token == Token::Punctuation(b',') => {
                    if lexer.next()? != Token::String {
                        return Err("Property name must be a string literal".into());
                    }
                    token = property_value(&mut lexer)?;
                    break;
                }
                Some(container) => {
                    let (closing, message) = match container {
                        Container::Array => (b']', "Expected ']'"),
                        Container::Object => (b'}', "Expected '}'"),
                    };
                    if token != Token::Punctuation(closing) {
                        return Err(message.into());
                    }
                    let _ = containers.pop();
                    token = lexer.next()?;
                }
                None => {
                    return if token == Token::End {
                        Ok(())
                    } else {
                        Err("Unable to parse JSON string".into())
                    };
                }
            }
        }
    }
}

fn property_value(lexer: &mut Lexer<'_>) -> Result<Token, Utf16String> {
    if lexer.next()? != Token::Punctuation(b':') {
        return Err("Expected ':' before value in object property definition".into());
    }
    lexer.next()
}

fn unexpected(token: Token, source: &[u16]) -> Utf16String {
    match token {
        Token::End => "Unexpected EOF".into(),
        Token::Identifier { start, end } => {
            let mut message = "Unexpected identifier \""
                .encode_utf16()
                .collect::<Vec<_>>();
            message.extend(source.iter().skip(start).take((end - start).min(200)));
            if end - start > 200 {
                message.extend("...".encode_utf16());
            }
            message.push(u16::from(b'"'));
            Utf16String::from_units(message)
        }
        Token::Punctuation(character) => {
            format!("Unexpected token '{}'", char::from(character)).into()
        }
        Token::String | Token::Value => "Could not parse value expression".into(),
    }
}
