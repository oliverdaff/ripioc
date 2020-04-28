use regex::Regex;
use regex::RegexBuilder;

use std::borrow::Cow;
use std::boxed::Box;

pub fn compile_re<'a>(pattern: Cow<str>) -> Box<Regex> {
    let mut x = RegexBuilder::new(&pattern);
    x.case_insensitive(true);
    x.ignore_whitespace(true);
    return Box::new(x.build().unwrap());
}
