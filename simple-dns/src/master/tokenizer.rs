use std::iter::Peekable;
use std::str::CharIndices;

#[derive(Debug)]
pub struct Tokenizer<'a> {
    source: &'a str,
    inner: Peekable<CharIndices<'a>>,
    line_has_entry: bool,
    multiline: bool,
}

impl<'a> Tokenizer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            inner: source.char_indices().peekable(),
            // position: 0,
            line_has_entry: false,
            multiline: false,
        }
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = TokenizerEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(el) = self.inner.next() {
            match el {
                el if sp(&el) => {}
                el if comment(&el) => while self.inner.next_if(|el| !eol(el)).is_some() {},
                el if eol(&el) => {
                    while self.inner.next_if(eol).is_some() {}

                    if self.line_has_entry && !self.multiline {
                        self.line_has_entry = false;
                        return Some(TokenizerEntry::EndOfEntry);
                    }
                }

                el if ml_open(&el) => self.multiline = true,
                el if ml_close(&el) => self.multiline = false,

                (start, c) if quotes(&(start, c)) => {
                    self.line_has_entry = true;
                    let end = (&mut self.inner)
                        .scan(c, |prev, cur| {
                            if std::mem::replace(prev, cur.1) != '\\' && cur.1 == c {
                                None
                            } else {
                                Some(cur.0)
                            }
                        })
                        .last();

                    return match end {
                        Some(end) => self
                            .source
                            .get((start + 1)..=end)
                            .map(TokenizerEntry::Token),
                        None => self.source.get((start + 1)..).map(TokenizerEntry::Token),
                    };
                }

                (start, _c) => {
                    self.line_has_entry = true;
                    while self.inner.next_if(|el| !token_delim(el)).is_some() {}

                    return match self.inner.peek() {
                        Some((end, _c)) => self.source.get(start..*end).map(TokenizerEntry::Token),
                        None => self.source.get(start..).map(TokenizerEntry::Token),
                    };
                }
            }
        }

        if self.line_has_entry {
            self.line_has_entry = false;
            Some(TokenizerEntry::EndOfEntry)
        } else {
            None
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TokenizerEntry<'a> {
    Token(&'a str),
    EndOfEntry,
}

fn token_delim(el: &(usize, char)) -> bool {
    sp(el) || eol(el) || comment(el) || ml_close(el)
}

fn sp((_index, c): &(usize, char)) -> bool {
    *c == ' ' || *c == '\t'
}

fn eol((_index, c): &(usize, char)) -> bool {
    *c == '\r' || *c == '\n'
}

fn comment((_index, c): &(usize, char)) -> bool {
    *c == ';'
}

fn ml_open((_index, c): &(usize, char)) -> bool {
    *c == '('
}

fn ml_close((_index, c): &(usize, char)) -> bool {
    *c == ')'
}

fn quotes((_index, c): &(usize, char)) -> bool {
    *c == '"'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_line_token_iter() {
        let mut tokens_iter = Tokenizer::new("some token; with some comment");
        assert_eq!(Some(TokenizerEntry::Token("some")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::Token("token")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());
        assert!(tokens_iter.next().is_none());
    }

    #[test]
    fn test_quoted_token_iter() {
        let mut tokens_iter = Tokenizer::new(r#"unquoted "quoted \" token" unquoted"#);
        assert_eq!(Some(TokenizerEntry::Token("unquoted")), tokens_iter.next());
        assert_eq!(
            Some(TokenizerEntry::Token(r#"quoted \" token"#)),
            tokens_iter.next()
        );
        assert_eq!(Some(TokenizerEntry::Token("unquoted")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());
        assert!(tokens_iter.next().is_none());
    }

    #[test]
    fn test_multiple_lines_token_iter() {
        let mut tokens_iter = Tokenizer::new(
            r#"first line; with some comment
        second    line    ;another comment
     
        third line 
        "#,
        );

        assert_eq!(Some(TokenizerEntry::Token("first")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::Token("line")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());

        assert_eq!(Some(TokenizerEntry::Token("second")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::Token("line")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());

        assert_eq!(Some(TokenizerEntry::Token("third")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::Token("line")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());

        assert!(tokens_iter.next().is_none());
    }

    #[test]
    fn test_empty_lines() {
        let mut tokens_iter = Tokenizer::new(
            r#"     
     
     ; some comment

token"#,
        );

        assert_eq!(Some(TokenizerEntry::Token("token")), tokens_iter.next());
        assert_eq!(Some(TokenizerEntry::EndOfEntry), tokens_iter.next());
        assert!(tokens_iter.next().is_none());
    }

    #[test]
    fn test_multi_line_token_iter() {
        let mut tokens = Tokenizer::new(
            r#"token1 (

            token2

            token3)
    "#,
        );

        assert_eq!(Some(TokenizerEntry::Token("token1")), tokens.next());
        assert_eq!(Some(TokenizerEntry::Token("token2")), tokens.next());
        assert_eq!(Some(TokenizerEntry::Token("token3")), tokens.next());
    }
}
