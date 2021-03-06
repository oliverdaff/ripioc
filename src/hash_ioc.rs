//! Contains patterns to match hash indicators found in the input text.
//!
//! This module can be used to extract single hash patterns from
//! the text, using specific methods, ot to extract all hash patterns
//! using the `parse_hash_iocs` method.
//!
//! # Examples
//!
//! ## Extract all hash IOCs from the input text
//! ```
//! use ripioc::hash_ioc::parse_hash_iocs;
//!
//! let iocs = parse_hash_iocs("check for a6b2fa823815336bb7352b02a93c970df51f66e8");
//! ```
//!
//! ### Extract only the MD5 hash patterns
//! ```
//! use ripioc::hash_ioc::parse_md5;
//! let md5_iocs = parse_md5(
//!             "the sample contained\
//!             08f2eb5f1bcbaf25ba97aef26593ed96 ");
//! ```
//!
//! # Hash types extracted
//! *   MD5
//! *   SHA1
//! *   SHA256
//! *   SHA512
//! *   SSDEEP
#[cfg(feature = "serde_support")]
use serde::Serialize;

use crate::regex_builder::compile_re;

use std::boxed::Box;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

/// The types of hashes searched for in the input text.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub enum HashIOC<'a> {
    /// MD5 hash patterns.
    MD5(&'a str),
    /// SHA1 hash patterns.
    SHA1(&'a str),
    /// SHA256 hash patterns.
    SHA256(&'a str),
    /// SHA512 hash patterns.
    SHA512(&'a str),
    /// SSDEEP hash patterns.
    SSDEEP(&'a str),
}

///A set of hash patterns found in the input text.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct HashIOCS<'a> {
    pub md5s: Vec<HashIOC<'a>>,
    pub sha1s: Vec<HashIOC<'a>>,
    pub sha256s: Vec<HashIOC<'a>>,
    pub sha512s: Vec<HashIOC<'a>>,
    pub ssdeeps: Vec<HashIOC<'a>>,
}

const MD5_PATTERN: &str = r#"\b[A-Fa-f0-9]{32}\b"#;

const SHA1_PATTERN: &str = r#"\b[A-Fa-f0-9]{40}\b"#;

const SHA256_PATTERN: &str = r#"\b[A-Fa-f0-9]{64}\b"#;

const SHA512_PATTERN: &str = r#"\b[A-Fa-f0-9]{128}\b"#;

const SSDEEP_PATTERN: &str = r#"\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}"#;

///Parse all MD5 IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of MD5 IOCs found in the input text.
pub fn parse_md5(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref MD5_RE: Box<Regex> = compile_re(MD5_PATTERN);
    }
    MD5_RE
        .find_iter(input)
        .map(|x| HashIOC::MD5(x.as_str()))
        .collect()
}

///Parse all SHA1 IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of SHA1 IOCs found in the input text.
pub fn parse_sha1(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA1_RE: Box<Regex> = compile_re(SHA1_PATTERN);
    }
    SHA1_RE
        .find_iter(input)
        .map(|x| HashIOC::SHA1(x.as_str()))
        .collect()
}
///Parse all SHA256 IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of SHA256 IOCs found in the input text.
pub fn parse_sha256(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA256_RE: Box<Regex> = compile_re(SHA256_PATTERN);
    }
    SHA256_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SHA256)
        .collect()
}

///Parse all SHA512 IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of SHA512 IOCs found in the input text.
pub fn parse_sha512(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SHA512_RE: Box<Regex> = compile_re(SHA512_PATTERN);
    }
    SHA512_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SHA512)
        .collect()
}

///Parse all SSDEEP IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of SSDEEP IOCs found in the input text.
pub fn parse_ssdeep(input: &str) -> Vec<HashIOC> {
    lazy_static! {
        static ref SSDEEP_RE: Box<Regex> = compile_re(SSDEEP_PATTERN);
    }
    SSDEEP_RE
        .find_iter(input)
        .map(|x| x.as_str())
        .map(HashIOC::SSDEEP)
        .collect()
}

///Parse all hash IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A ['HashIOCS`](struct.HashIOCS.html) struct containing
/// all the hash IOCs found in the input text.
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

    HashIOCS {
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
        ssdeeps: if matches.matched(4) {
            parse_ssdeep(input)
        } else {
            vec![]
        },
    }
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
