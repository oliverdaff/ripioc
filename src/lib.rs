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

#[cfg(feature = "serde_support")]
extern crate serde;

pub mod cve_ioc;
pub mod file_ioc;
pub mod hash_ioc;
pub mod network_ioc;

mod regex_builder;

#[cfg(feature = "serde_support")]
use serde::Serialize;

use crate::file_ioc::parse_file_iocs;
use crate::file_ioc::FileIOCS;
use crate::hash_ioc::parse_hash_iocs;
use crate::hash_ioc::HashIOCS;
use crate::network_ioc::parse_network_iocs;
use crate::network_ioc::NetworkIOCS;

use crate::cve_ioc::parse_cve;
use crate::cve_ioc::CVEIOC;

/// A collection of IOCs found in the text.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize))]
pub struct IOCS<'a> {
    /// The network IOCs found in the text.
    pub network_iocs: NetworkIOCS<'a>,
    /// The HashIOCS found in the text.
    pub hash_iocs: HashIOCS<'a>,
    /// The FileIOCS found in the text.
    pub file_iocs: FileIOCS<'a>,
    /// The CVEIOCs found in the text.
    pub cve_iocs: Vec<CVEIOC<'a>>,
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
    IOCS {
        network_iocs: parse_network_iocs(input),
        hash_iocs: parse_hash_iocs(input),
        file_iocs: parse_file_iocs(input),
        cve_iocs: parse_cve(input),
    }
}
