//! The ripioc module provides matches text against
//! regular expressions to for indicators or compromise (ioc).
//!
//! The library is a work in progress, expect breaking changes.
//!
//! Each module holds a regex for a type of IOC.
//!
//! *   Network
//! *   Hashes
//! *   Files
//! *   CVEs
//!
//! # Hello World
//! ```
//! use ripioc::parse_all_iocs;
//!
//! let iocs  = parse_all_iocs(
//!     "this is a description of sample that \
//!     connects to http://example.com\
//! ");
//!
//! ```
//!
#[macro_use]
extern crate lazy_static;
extern crate regex;

pub mod cve_ioc;
pub mod file_ioc;
pub mod hash_ioc;
pub mod network_ioc;

mod regex_builder;

use crate::file_ioc::parse_file_iocs;
use crate::file_ioc::FileIOCS;
use crate::hash_ioc::parse_hash_iocs;
use crate::hash_ioc::HashIOCS;
use crate::network_ioc::parse_network_iocs;
use crate::network_ioc::NetworkIOCS;

use crate::cve_ioc::parse_cve;
use crate::cve_ioc::CVEIOC;

#[derive(Debug, PartialEq, Eq)]
pub struct IOCS<'a> {
    /// A collection of IOCs found in the text.
    network_iocs: NetworkIOCS<'a>,
    hash_iocs: HashIOCS<'a>,
    file_iocs: FileIOCS<'a>,
    cve_iocs: Vec<CVEIOC<'a>>,
}

/// Matches all IOCs against the input and returns
/// the matches in a [`IOCS`](struct.IOCS.html).
///
/// # Arguments
///
/// * `input` - A string slice that contains the text to find IOCs in
///
/// ```
/// use ripioc::parse_all_iocs;
///
/// let iocs  = parse_all_iocs(
///     "this is a description of sample that \
///     connects to http://example.com\
/// ");
///
/// ```
pub fn parse_all_iocs(input: &str) -> IOCS {
    return IOCS {
        network_iocs: parse_network_iocs(input),
        hash_iocs: parse_hash_iocs(input),
        file_iocs: parse_file_iocs(input),
        cve_iocs: parse_cve(input),
    };
}
