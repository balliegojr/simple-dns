use std::path::Path;

use crate::rdata::RData;
use crate::{Name, ResourceRecord, SimpleDnsError, CLASS, TYPE};

use super::tokenizer::{Tokenizer, TokenizerEntry};
use super::ParseError;

type Result<T> = std::result::Result<T, ParseError>;

/// Parse a master file at `path` location
pub fn parse_file<'a>(
    path: impl AsRef<Path>,
    origin: Name,
) -> crate::Result<Vec<ResourceRecord<'a>>> {
    let unparsed_file = std::fs::read_to_string(path.as_ref())?;
    let include_path = path.as_ref().parent().or(Some("/".as_ref()));

    parse(&unparsed_file, origin, include_path)
        .map(|resources| resources.into_iter().map(|r| r.into_owned()).collect())
}

/// Parse the provided `content`
pub fn parse<'a>(
    content: &'a str,
    origin: Name<'a>,
    include_path: Option<&Path>,
) -> crate::Result<Vec<ResourceRecord<'a>>> {
    parse_content(content, origin, include_path, None, None)
}

/// Parse the provided `content`
fn parse_content<'a>(
    content: &'a str,
    origin: Name<'a>,
    include_path: Option<&Path>,
    mut default_class: Option<CLASS>,
    mut default_ttl: Option<u32>,
) -> crate::Result<Vec<ResourceRecord<'a>>> {
    let mut current_origin = origin;
    let mut resources = Vec::new();

    let mut tokens = Tokenizer::new(content).peekable();
    while let Some(token) = tokens.peek() {
        match token {
            TokenizerEntry::Token("$ORIGIN") => {
                current_origin = origin_entry(&mut tokens, &current_origin)?;
            }
            TokenizerEntry::Token("$INCLUDE") => {
                resources.extend(include_file(
                    &mut tokens,
                    current_origin.clone(),
                    include_path.ok_or(ParseError::MissingInformation("INCLUDE file path"))?,
                    default_class,
                    default_ttl,
                )?);
            }
            TokenizerEntry::Token("$TTL") => default_ttl = Some(ttl_entry(&mut tokens)?),
            TokenizerEntry::Token(_) => {
                resources.push(
                    resource_record(
                        &mut tokens,
                        &current_origin,
                        &default_ttl,
                        &mut default_class,
                    )?
                    .to_owned(),
                );
            }
            TokenizerEntry::EndOfEntry => {
                tokens.next();
            }
        }
    }

    Ok(resources)
}

fn domain<'a>(token: &'a str, origin: &Name<'a>) -> crate::Result<Name<'a>> {
    match token {
        "@" => Ok(origin.to_owned()),
        domain => Name::new(domain),
    }
}

fn origin_entry<'a>(
    mut tokens: impl Iterator<Item = TokenizerEntry<'a>>,
    origin: &Name<'a>,
) -> crate::Result<Name<'a>> {
    match tokens.nth(1) {
        Some(TokenizerEntry::Token(token)) => domain(token, origin),
        Some(TokenizerEntry::EndOfEntry) | None => Err(SimpleDnsError::InsufficientData),
    }
}

fn ttl_entry<'a>(mut tokens: impl Iterator<Item = TokenizerEntry<'a>>) -> Result<u32> {
    match tokens.nth(1) {
        Some(TokenizerEntry::Token(token)) => token
            .parse()
            .map_err(|_| ParseError::InvalidToken(token.to_string())),
        Some(TokenizerEntry::EndOfEntry) | None => Err(ParseError::UnexpectedEndOfInput),
    }
}

fn include_file<'a>(
    mut tokens: impl Iterator<Item = TokenizerEntry<'a>>,
    origin: Name,
    include_path: &Path,
    default_class: Option<CLASS>,
    default_ttl: Option<u32>,
) -> crate::Result<Vec<ResourceRecord<'a>>> {
    match tokens.nth(1) {
        Some(TokenizerEntry::Token(path)) => {
            let content = std::fs::read_to_string(include_path.join(path))?;
            parse_content(
                &content,
                origin,
                Some(include_path),
                default_class,
                default_ttl,
            )
            .map(|resources| resources.into_iter().map(|r| r.into_owned()).collect())
        }
        Some(TokenizerEntry::EndOfEntry) | None => Err(SimpleDnsError::InsufficientData),
    }
}

fn resource_record<'a>(
    tokens: impl Iterator<Item = TokenizerEntry<'a>>,
    origin: &Name<'a>,
    default_ttl: &Option<u32>,
    default_class: &mut Option<CLASS>,
) -> crate::Result<ResourceRecord<'a>> {
    let tokens: Vec<_> = tokens
        .map_while(|token| match token {
            TokenizerEntry::Token(token) => Some(token),
            TokenizerEntry::EndOfEntry => None,
        })
        .collect();

    let initial_guess = 4.min(tokens.len());
    for guess in (0..initial_guess).rev() {
        let rr_type: TYPE = match tokens[guess].parse() {
            Ok(rr_type) => rr_type,
            Err(_) => continue,
        };

        let rdata: RData =
            match RData::try_build_from_tokens(rr_type, &tokens[(guess + 1)..], origin) {
                Ok(rr_type) => rr_type,
                Err(_) => continue,
            };

        let mut maybe_class: Option<CLASS> = None;
        let mut maybe_ttl: Option<u32> = None;
        let mut maybe_name: Option<Name> = None;

        for guess in (0..guess).rev() {
            if let Ok(class) = tokens[guess].parse() {
                maybe_class = Some(class);
                if default_class.is_none() {
                    *default_class = Some(class)
                }

                continue;
            }

            if let Ok(ttl) = tokens[guess].parse() {
                maybe_ttl = Some(ttl);
                continue;
            }

            if let Ok(name) = domain(tokens[0], origin) {
                maybe_name = Some(name);
                continue;
            }
        }

        let class = maybe_class
            .or(*default_class)
            .ok_or(ParseError::MissingInformation("Class"))?;
        let ttl = maybe_ttl
            .or(*default_ttl)
            .ok_or(ParseError::MissingInformation("TTL"))?;
        let name = maybe_name.unwrap_or_else(|| origin.to_owned());

        return Ok(ResourceRecord::new(name, class, ttl, rdata));
    }

    Err(ParseError::UnexpectedEndOfInput)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_master_sample() -> crate::Result<()> {
        let resources = super::parse_file(
            "./samples/master_files/master.txt",
            Name::new_unchecked("domain.com"),
        )?;

        Ok(())
    }
    #[test]
    fn parse_a_rdata() -> crate::Result<()> {
        let mut rdata = parse(
            r#"100 IN A    0.0.0.0 "#,
            Name::new_unchecked("domain.com"),
            None,
        )?;

        assert_eq!(1, rdata.len());

        let rdata = rdata.pop().unwrap();
        assert_eq!(100, rdata.ttl);
        assert_eq!(CLASS::IN, rdata.class);

        assert!(matches!(
            rdata.rdata,
            RData::A(crate::rdata::A { address: 0 })
        ));

        Ok(())
    }

    #[test]
    fn parse_soa_rdata() -> crate::Result<()> {
        let mut rdata = parse(
            r#"@  100  IN  SOA     VENERA      Action\.domains (
                                     20     ; SERIAL
                                     7200   ; REFRESH
                                     600    ; RETRY
                                     3600000; EXPIRE
                                     60)    ; MINIMUM

            "#,
            Name::new_unchecked("domain.com"),
            None,
        )?;

        assert_eq!(1, rdata.len());

        let rdata = rdata.pop().unwrap();
        assert_eq!(100, rdata.ttl);
        assert_eq!(CLASS::IN, rdata.class);

        assert!(matches!(rdata.rdata, RData::SOA(..)));

        Ok(())
    }
}
