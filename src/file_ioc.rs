use crate::regex_builder::compile_re;

use std::boxed::Box;

use std::borrow::Cow;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

#[derive(Debug, PartialEq, Eq)]
pub enum FileIOC<'a>{
    DOC(&'a str),
    EXE(&'a str),
    FLASH(&'a str),
    IMG(&'a str),
    MAC(&'a str),
    WEB(&'a str),
    ZIP(&'a str)
}

#[derive(Debug, PartialEq, Eq)]
pub struct FileIOCS<'a>{
    docs: Vec<FileIOC<'a>>,
    exes: Vec<FileIOC<'a>>,
    flashs: Vec<FileIOC<'a>>,
    imgs: Vec<FileIOC<'a>>,
    macs: Vec<FileIOC<'a>>,
    webs: Vec<FileIOC<'a>>,
    zips: Vec<FileIOC<'a>>
}

pub const DOC_PATTERN: &'static str = r#"([\w\-]+)\.(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt|pages|keynote|numbers)"#;

pub const EXE_PATTERN: &'static str = r#"([\w]+)\.(exe|dll|jar)"#;

pub const FLASH_PATTERN: &'static str = r#"([\w\-]+)\.(flv|swf)"#;

pub const IMG_PATTERN: &'static str = r#"([\w\-]+)\.(jpeg|jpg|gif|png|tiff|bmp)"#;

pub const MAC_PATTERN: &'static str = r#"([\w\-]+)\.(jpeg|jpg|gif|png|tiff|bmp)"#;

pub const WEB_PATTERN: &'static str = r#"(\w+\.(html|htm|php|jsp|asp))"#;

pub const ZIP_PATTERN: &'static str = r#"([\w\-]+\\.(zip|zipx|7z|rar|tar|gz))"#;


pub fn parse_doc(input: &str) -> Vec<FileIOC> {
    lazy_static! {
        static ref DOC_RE: Box<Regex> = compile_re(Cow::from(DOC_PATTERN));
    }
    return DOC_RE.
    find_iter(input)
    .map(|x|FileIOC::DOC(x.as_str()))
    .collect()
}


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

    return FileIOCS{
        docs : if matches.matched(0) { parse_doc(input) } else { vec![]},
        exes : vec![],
        flashs: vec![],
        imgs: vec![],
        macs : vec![],
        webs : vec![],
        zips : vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_doc() {
        assert_eq!(
            parse_doc("this ioc testing.doc"),
            vec![FileIOC::DOC("testing.doc")]
        )
    }
}