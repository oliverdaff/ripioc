use regex::Regex;
use regex::RegexBuilder;

use std::boxed::Box;

pub fn compile_re(pattern: &str) -> Box<Regex> {
    let mut x = RegexBuilder::new(&pattern);
    x.case_insensitive(true);
    x.ignore_whitespace(true);
    return Box::new(x.build().unwrap());
}
