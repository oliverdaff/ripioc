use crate::regex_builder::compile_re;

use std::boxed::Box;

use std::borrow::Cow;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

#[derive(Debug, PartialEq, Eq)]
pub enum HashIOC<'a> {
    MD5(&'a str),
    SHA1(&'a str),
    SHA256(&'a str),
    SHA512(&'a str),
    SSDEEP(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
pub struct HashIOCS<'a> {
    md5s: Vec<HashIOC<'a>>,
    sha1s: Vec<HashIOC<'a>>,
    sha256s: Vec<HashIOC<'a>>,
    sha512s: Vec<HashIOC<'a>>,
    ssdeeps: Vec<HashIOC<'a>>,
}

pub const MD5_PATTERN: &'static str = r#"\b[A-Fa-f0-9]{32}\b"#;

pub const SHA1_PATTERN: &'static str = r#"\b[A-Fa-f0-9]{40}\b"#;

pub const SHA256_PATTERN: &'static str = r#"\b[A-Fa-f0-9]{64}\b"#;

pub const SHA512_PATTERN: &'static str = r#"\b[A-Fa-f0-9]{128}\b"#;

pub const SSDEEP_PATTERN: &'static str = r#"\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}"#;

pub fn parse_md5(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref MD5_RE: Box<Regex> = compile_re(Cow::from(MD5_PATTERN));
    }
    return MD5_RE
        .find_iter(input)
        .map(|x| HashIOC::MD5(x.as_str()))
        .collect();
}

pub fn parse_sha1(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA1_RE: Box<Regex> = compile_re(Cow::from(SHA1_PATTERN));
    }
    return SHA1_RE
        .find_iter(input)
        .map(|x| HashIOC::SHA1(x.as_str()))
        .collect();
}

pub fn parse_sha256(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA256_RE: Box<Regex> = compile_re(Cow::from(SHA256_PATTERN));
    }
    SHA256_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SHA256)
        .collect()
}

pub fn parse_sha512(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA512_RE: Box<Regex> = compile_re(Cow::from(SHA512_PATTERN));
    }
    SHA512_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SHA512)
        .collect()
}

pub fn parse_ssdeep(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SSDEEP_RE: Box<Regex> = compile_re(Cow::from(SSDEEP_PATTERN));
    }
    SSDEEP_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SSDEEP)
        .collect()
}

pub fn parse_hash_iocs(input: &str) -> HashIOCS {
    lazy_static! {
        static ref HASH_PATTERNS: RegexSet  = RegexSetBuilder::new(
            vec![
            MD5_PATTERN,    //0
            SHA1_PATTERN,   //1
            SHA256_PATTERN, //2
            SHA512_PATTERN, //3
            SSDEEP_PATTERN  //4
            ]
        ).case_insensitive(true)
        .ignore_whitespace(true)
        .build().unwrap();
    }

    let matches = HASH_PATTERNS.matches(input);

    return HashIOCS {
        md5s: if matches.matched(0) {
            parse_md5(input)
        } else {
            vec![]
        },
        sha1s: if matches.matched(1) {
            parse_sha1(input)
        } else {
            vec![]
        },
        sha256s: if matches.matched(2) {
            parse_sha256(input)
        } else {
            vec![]
        },
        sha512s: if matches.matched(3) {
            parse_sha512(input)
        } else {
            vec![]
        },
        ssdeeps: if matches.matched(3) {
            parse_ssdeep(input)
        } else {
            vec![]
        },
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_md5() {
        assert_eq!(
            parse_md5("this ioc 08f2eb5f1bcbaf25ba97aef26593ed96"),
            vec![HashIOC::MD5("08f2eb5f1bcbaf25ba97aef26593ed96")]
        )
    }

    #[test]
    fn test_parse_sha1() {
        assert_eq!(
            parse_sha1("this is a ioc a6b2fa823815336bb7352b02a93c970df51f66e8"),
            vec![HashIOC::SHA1("a6b2fa823815336bb7352b02a93c970df51f66e8")]
        );
    }

    #[test]
    fn test_parse_sha256() {
        assert_eq!(
            parse_sha256(
                "this is a 05cc5051bfa5c2c356422f930e3f78dd63dd1252c98bf5e154c0e1a64a4b5532"
            ),
            vec![HashIOC::SHA256(
                "05cc5051bfa5c2c356422f930e3f78dd63dd1252c98bf5e154c0e1a64a4b5532"
            )]
        )
    }

    #[test]
    fn test_parse_sha512() {
        assert_eq!(
            parse_sha512(
                "
            this is a 5671025d77521321db8be6e150d66d67c79d2ce43b203207a03710fbff10e1\
            7800179803b4f974c75816a9dd8c3697a2f32fbb2d2b1cff2933f6a9e575061a32"
            ),
            vec![HashIOC::SHA512(
                "5671025d77521321db8be6e150d66d67c79d2ce43b203207a\
            03710fbff10e17800179803b4f974c75816a9dd8c3697a2f32fbb2d2b1cff2933f6a9e575061a32"
            )]
        )
    }

    #[test]
    fn test_parse_ssdeep() {
        assert_eq!(
            parse_ssdeep("
            this is a 96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO xxx"),
            vec![HashIOC::SSDEEP("96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO")]
        )
    }

    #[test]
    fn test_parse_hash_iocs() {
        assert_eq!(parse_hash_iocs("
        08f2eb5f1bcbaf25ba97aef26593ed96

        a6b2fa823815336bb7352b02a93c970df51f66e8
        05cc5051bfa5c2c356422f930e3f78dd63dd1252c98bf5e154c0e1a64a4b5532

        5671025d77521321db8be6e150d66d67c79d2ce43b203207a03710fbff10e1\
        7800179803b4f974c75816a9dd8c3697a2f32fbb2d2b1cff2933f6a9e575061a32 

        96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO
        "),
        HashIOCS{
            md5s : vec![HashIOC::MD5("08f2eb5f1bcbaf25ba97aef26593ed96")],
            sha1s : vec![HashIOC::SHA1("a6b2fa823815336bb7352b02a93c970df51f66e8")],
            sha256s : vec![HashIOC::SHA256("05cc5051bfa5c2c356422f930e3f78dd63dd1252c98bf5e154c0e1a64a4b5532")],
            sha512s : vec![HashIOC::SHA512("5671025d77521321db8be6e150d66d67c79d2ce43b203207a03710fbff10e1\
                        7800179803b4f974c75816a9dd8c3697a2f32fbb2d2b1cff2933f6a9e575061a32")],
            ssdeeps : vec![HashIOC::SSDEEP("96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO")]
        }
        )
    }
}
