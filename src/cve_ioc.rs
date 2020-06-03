//! Contains patterns to match CVE in text.
//!
//! This module can be used to extract just CVE patterns
//! from text.
//!
//! #Example
//! ```
//! use ripioc::cve_ioc::parse_cve;
//!
//! let cves = parse_cve("The exploit was assigned CVE-2014-0160");
//! ```
//!
use crate::regex_builder::compile_re;

use std::boxed::Box;

use std::borrow::Cow;

use regex::Regex;

/// Types of CVE found in the text, currently only one type is available.
#[derive(Debug, PartialEq, Eq)]
pub enum CVEIOC<'a> {
    /// A CVE found in the text.
    CVE(&'a str),
}

pub const CVE_PATTERN: &'static str = r#"(CVE-(19|20)\d{2}-\d{4,7})"#;

/// Returns all the CVEs found in the text.
///
/// # Arguments
///
/// *   A string slice to search
///
/// # Returns
/// Vector of [`CVIOC`](struct.CVEIOC.html) found in the input text.
///
pub fn parse_cve(input: &str) -> Vec<CVEIOC> {
    lazy_static! {
        static ref CVE_RE: Box<Regex> = compile_re(Cow::from(CVE_PATTERN));
    }
    return CVE_RE
        .find_iter(input)
        .map(|x| CVEIOC::CVE(x.as_str()))
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cve() {
        assert_eq!(
            parse_cve("this is a CVE-2020-2345"),
            vec![CVEIOC::CVE("CVE-2020-2345")]
        )
    }
}
