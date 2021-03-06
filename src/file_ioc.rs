//! Contains patterns to match file indicators in text.
//!
//! This module can be used to extract single document types
//! from text, using specific methods, or extract all document
//! IOCs using `parse_file_iocs`.
//!
//! #Examples
//!
//!## Extract all document IOCs from the input text
//! ```
//! use ripioc::file_ioc::parse_file_iocs;
//!
//! let all_docs = parse_file_iocs("The exploit was via bad.doc and\
//!                     malicious.exe");
//!
//! ```
//!
//! ## Extract just doc files
//! ```
//! use ripioc::file_ioc::parse_doc;
//!
//! let docs = parse_doc("The exploit was delivered via test.doc");
//! ```
//!
//! # List of file types considered.
//!
//! *   Document type files.
//!     *   docx
//!     *   doc
//!     *   csv
//!     *   pdf
//!     *   xlsx
//!     *   xls
//!     *   rtf
//!     *   txt
//!     *   pptx
//!     *   ppt
//!     *   pages
//!     *   keynote
//!     *   numbers
//! *   Executable files
//!     *   exe
//!     *   dll
//!     *   jar
//! *   Flash files
//!     * flv
//!     * swf
//! *   Image files
//!     *   jpeg
//!     *   jpg
//!     *   gif
//!     *   png
//!     *   tiff
//!     *   bmp
//! *   Mac files
//!     *   plist
//!     *   app
//!     *   pkg
//! *   Web files
//!     *   html
//!     *   htm
//!     *   php
//!     *   jsp
//!     *   asp
//! *   Compressed files
//!     *   zip
//!     *   zipx
//!     *   7z
//!     *   rar
//!     *   tar
//!     *   gz
//!
#[cfg(feature = "serde_support")]
use serde::Serialize;

use crate::regex_builder::compile_re;

use std::boxed::Box;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

/// Different types of documents used as an IOC
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize))]
pub enum FileIOC<'a> {
    /// Document type files.
    /// Specifically
    /// *   docx
    /// *   doc
    /// *   csv
    /// *   pdf
    /// *   xlsx
    /// *   xls
    /// *   rtf
    /// *   txt
    /// *   pptx
    /// *   ppt
    /// *   pages
    /// *   keynote
    /// *   numbers
    DOC(&'a str),
    /// Executable files, specifically:
    /// *   exe
    /// *   dll
    /// *   jar
    EXE(&'a str),
    /// Flash files, specifically:
    /// * flv
    /// * swf
    FLASH(&'a str),
    /// Image files, specifically:
    /// *   jpeg
    /// *   jpg
    /// *   gif
    /// *   png
    /// *   tiff
    /// *   bmp
    IMG(&'a str),
    /// Mac files, specifically:
    /// *   plist
    /// *   app
    /// *   pkg
    MAC(&'a str),
    /// Web files, specifically:
    /// *   html
    /// *   htm
    /// *   php
    /// *   jsp
    /// *   asp
    WEB(&'a str),
    /// Compressed files, specifically:
    /// *   zip
    /// *   zipx
    /// *   7z
    /// *   rar
    /// *   tar
    /// *   gz
    ZIP(&'a str),
}

/// A collection of document IOC, partioned by document type
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct FileIOCS<'a> {
    /// Document iocs, found in the text
    pub docs: Vec<FileIOC<'a>>,
    /// Exe iocs, found in the text
    pub exes: Vec<FileIOC<'a>>,
    /// flash iocs, found in the text
    pub flashs: Vec<FileIOC<'a>>,
    /// img iocs, found in the text
    pub imgs: Vec<FileIOC<'a>>,
    /// mac iocs, found in the text
    pub macs: Vec<FileIOC<'a>>,
    /// web iocs, found in the text
    pub webs: Vec<FileIOC<'a>>,
    /// zip iocs, found in the text
    pub zips: Vec<FileIOC<'a>>,
}

const DOC_PATTERN: &str =
    r#"([\w\-]+)\.(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt|pages|keynote|numbers)"#;

const EXE_PATTERN: &str = r#"([\w]+)\.(exe|dll|jar)"#;

const FLASH_PATTERN: &str = r#"([\w\-]+)\.(flv|swf)"#;

const IMG_PATTERN: &str = r#"([\w\-]+)\.(jpeg|jpg|gif|png|tiff|bmp)"#;

const MAC_PATTERN: &str = r#"([%A-Za-z\.\-_/ ]+\.(plist|app|pkg))"#;

const WEB_PATTERN: &str = r#"(\w+\.(html|htm|php|jsp|asp))"#;

const ZIP_PATTERN: &str = r#"([\w\-]+\.(zip|zipx|7z|rar|tar|gz))"#;

///Parse all document IOCs found in the input text.
/// # Arguments
/// * input - input text to parse
/// # Return
/// A vector of document IOCs found in the input text.
pub fn parse_doc(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref DOC_RE: Box<Regex> = compile_re(DOC_PATTERN);
    }
    DOC_RE
        .find_iter(input)
        .map(|x| FileIOC::DOC(x.as_str()))
        .collect()
}

/// Parse all excutable file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of executable IOCs found in the input text.
pub fn parse_exe(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref EXE_RE: Box<Regex> = compile_re(EXE_PATTERN);
    }
    EXE_RE
        .find_iter(input)
        .map(|x| FileIOC::EXE(x.as_str()))
        .collect()
}

/// Parse all flash file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of flash IOCs found in the input text.
pub fn parse_flash(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref FLASH_RE: Box<Regex> = compile_re(FLASH_PATTERN);
    }
    FLASH_RE
        .find_iter(input)
        .map(|x| FileIOC::FLASH(x.as_str()))
        .collect()
}

/// Parse all image file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of image IOCs found in the input text.
pub fn parse_img(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref IMG_RE: Box<Regex> = compile_re(IMG_PATTERN);
    }
    IMG_RE
        .find_iter(input)
        .map(|x| FileIOC::IMG(x.as_str()))
        .collect()
}

/// Parse all mac file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of mac IOCs found in the input text.
pub fn parse_mac(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref MAC_RE: Box<Regex> = compile_re(MAC_PATTERN);
    }
    MAC_RE
        .find_iter(input)
        .map(|x| FileIOC::MAC(x.as_str()))
        .collect()
}

/// Parse all web file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of web IOCs found in the input text.
pub fn parse_web(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref WEB_RE: Box<Regex> = compile_re(WEB_PATTERN);
    }
    WEB_RE
        .find_iter(input)
        .map(|x| FileIOC::WEB(x.as_str()))
        .collect()
}

/// Parse all compressed file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of compressed IOCs found in the input text.
pub fn parse_zip(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref ZIP_RE: Box<Regex> = compile_re(ZIP_PATTERN);
    }
    ZIP_RE
        .find_iter(input)
        .map(|x| FileIOC::ZIP(x.as_str()))
        .collect()
}
/// Parse all file types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// A [`FileIOCS`](struct.FileIOCS.html) struct containing
/// all the file iocs found in the input text.
pub fn parse_file_iocs(input: &str) -> FileIOCS {
    lazy_static! {
        static ref FILE_PATTERNS: RegexSet = RegexSetBuilder::new(
            vec![
                DOC_PATTERN,             // 0
                EXE_PATTERN,             // 1
                FLASH_PATTERN,           // 2
                IMG_PATTERN,             // 3
                MAC_PATTERN,             // 4
                WEB_PATTERN,             // 5
                ZIP_PATTERN,             // 6
            ]
        ).case_insensitive(true)
        .ignore_whitespace(true)
        .build().unwrap();
    }
    let matches = FILE_PATTERNS.matches(input);

    FileIOCS {
        docs: if matches.matched(0) {
            parse_doc(input)
        } else {
            vec![]
        },
        exes: if matches.matched(1) {
            parse_exe(input)
        } else {
            vec![]
        },
        flashs: if matches.matched(2) {
            parse_flash(input)
        } else {
            vec![]
        },
        imgs: if matches.matched(3) {
            parse_img(input)
        } else {
            vec![]
        },
        macs: if matches.matched(4) {
            parse_mac(input)
        } else {
            vec![]
        },
        webs: if matches.matched(5) {
            parse_web(input)
        } else {
            vec![]
        },
        zips: if matches.matched(6) {
            parse_zip(input)
        } else {
            vec![]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_iocs() {
        assert_eq!(
            parse_file_iocs(
                "The report contains test.doc, test.exe
                test.flv, test.png, test.app, admin.jsp, payload.zip
                "
            ),
            FileIOCS {
                docs: vec![FileIOC::DOC("test.doc")],
                exes: vec![FileIOC::EXE("test.exe")],
                flashs: vec![FileIOC::FLASH("test.flv")],
                imgs: vec![FileIOC::IMG("test.png")],
                macs: vec![FileIOC::MAC("test.app")],
                webs: vec![FileIOC::WEB("admin.jsp")],
                zips: vec![FileIOC::ZIP("payload.zip")],
            }
        )
    }

    #[test]
    fn test_parse_doc() {
        assert_eq!(
            parse_doc("this ioc testing.doc"),
            vec![FileIOC::DOC("testing.doc")]
        )
    }

    #[test]
    fn test_parse_exe() {
        assert_eq!(
            parse_exe("this ioc testing.exe"),
            vec![FileIOC::EXE("testing.exe")]
        )
    }

    #[test]
    fn test_parse_flash() {
        assert_eq!(
            parse_flash("this ioc testing.flv"),
            vec![FileIOC::FLASH("testing.flv")]
        )
    }

    #[test]
    fn test_parse_img() {
        assert_eq!(
            parse_img("this ioc testing.png"),
            vec![FileIOC::IMG("testing.png")]
        )
    }

    #[test]
    fn test_parse_mac() {
        assert_eq!(
            parse_mac("this ioc testing.app"),
            vec![FileIOC::MAC("testing.app")]
        )
    }
    #[test]
    fn test_parse_web() {
        assert_eq!(
            parse_web("this ioc admin.jsp"),
            vec![FileIOC::WEB("admin.jsp")]
        )
    }

    #[test]
    fn test_parse_zip() {
        assert_eq!(
            parse_zip("this payload.zip"),
            vec![FileIOC::ZIP("payload.zip")]
        )
    }
}
