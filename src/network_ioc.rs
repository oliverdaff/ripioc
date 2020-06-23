//! Contains patterns to match network indicators in the input text.
//!
//! This module can be used to extract single network ioc types
//! from text, using specific methods, or extract all network
//! IOC types using `parse_network_iocs`.
//!
//! # Examples
//!
//! ## Extract all network IOCs from the input text.
//! ```
//! use ripioc::network_ioc::parse_network_iocs;
//!
//! let all_network_iocs = parse_network_iocs("The exploit used\
//!                     http://www.test.com as C2.");
//! ```
//!
//! ### Extract just the URL pattern
//! ```
//! use ripioc::network_ioc::parse_urls;
//!
//! let all_urls = parse_urls("Traffic was set to http://www.test.com ");
//! ```
#[cfg(feature = "serde_support")]
use serde::Serialize;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

use std::boxed::Box;

use crate::regex_builder::compile_re;

/// Different types of network types of IOC.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkIOC<'a> {
    /// URL type network ioc
    URL(&'a str),
    /// Domain type network ioc.
    DOMAIN(&'a str),
    /// Email type network ioc.
    EMAIL(&'a str),
    /// IPV4 type network ioc.
    IPV4(&'a str),
    /// IPv6 type network ioc.
    IPV6(&'a str),
    /// Hex encoded URL type network ioc.
    HexURL(&'a str),
}

/// A collection of network IOC, partioned network ioc type.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkIOCS<'a> {
    /// URL IOCs, found in the text.
    urls: Vec<NetworkIOC<'a>>,
    /// Domain IOCs, found in the text.
    domains: Vec<NetworkIOC<'a>>,
    /// Email IOCs, found in the text.
    emails: Vec<NetworkIOC<'a>>,
    /// IPV4 IOCs, found in the text.
    ipv4s: Vec<NetworkIOC<'a>>,
    /// IPv6 IOCs, found in the text.
    ipv6s: Vec<NetworkIOC<'a>>,
    /// HexURL IOCs, found in the text.
    hexurls: Vec<NetworkIOC<'a>>,
}

const URL_PATTERN: &str =
    r#"(\b((http|https|hxxp|hxxps|nntp|ntp|rdp|sftp|smtp|ssh|tor|webdav|xmpp)://[\S]{1,})\b)"#;
const DOMAIN_PATTERN: &str = r#"([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|
     agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|
     attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|
     best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|
     brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|
     capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|
     cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|
     college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|
     credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|
     delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|
     domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|
     er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|
     financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|
     frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|
     globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|
     hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|
     id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|
     iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|
     la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|
     lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|
     memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|
     mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|
     nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|
     photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|
     properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|
     rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|
     schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|
     solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|
     tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|
     toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|
     vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|
     whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw)\b)"#;

const EMAIL_PATTERN: &str = r#"[A-Za-z0-9_.]+@[0-9a-z.-]+"#;

const IPV4_PATTERN: &str =
    r#"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"#;

const IPV6_PATTERN: &str = r#"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
                             ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}
                             (:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:
                             ((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]
                                 |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]
                                     |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"#;

const HEX_URL_PATTERN: &str = r#"
                                            (
                                                [46][86]
                                                (?:[57]4)?
                                                [57]4[57]0
                                                (?:[57]3)?
                                                3a2f2f
                                                (?:2[356def]|3[0-9adf]|[46][0-9a-f]|[57][0-9af])+
                                            )
                                            (?:[046]0|2[0-2489a-c]|3[bce]|[57][b-e]|[8-f][0-9a-f]|0a|0d|09|[
                                                \x5b-\x5d\x7b\x7d\x0a\x0d\x20
                                            ]|$)
                                        "#;

/// Parse all network types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// A [`NetworkIOCs`](struct.NetworkIOCs.html) struct containing
/// all the network iocs found in the input text.
pub fn parse_network_iocs(input: &str) -> NetworkIOCS {
    lazy_static! {
        static ref NETWORK_IOCS_RE: RegexSet = RegexSetBuilder::new(
            vec![
                URL_PATTERN,       //0
                EMAIL_PATTERN,     //1
                DOMAIN_PATTERN,    //2
                IPV6_PATTERN,      //3
                IPV4_PATTERN,      //4
                HEX_URL_PATTERN    //5
        ]
        )
        .case_insensitive(true)
        .ignore_whitespace(true)
        .build().unwrap();
    }
    let matches = NETWORK_IOCS_RE.matches(input);
    NetworkIOCS {
        urls: if matches.matched(0) {
            parse_urls(input)
        } else {
            vec![]
        },
        emails: if matches.matched(1) {
            parse_emails(input)
        } else {
            vec![]
        },
        domains: if matches.matched(2) {
            parse_domains(input)
        } else {
            vec![]
        },
        ipv6s: if matches.matched(3) {
            parse_ipv6(input)
        } else {
            vec![]
        },
        ipv4s: if matches.matched(4) {
            parse_ipv4(input)
        } else {
            vec![]
        },
        hexurls: if matches.matched(5) {
            parse_hex_url(input)
        } else {
            vec![]
        },
    }
}

/// Parse all hex encoded URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of hex encoded URLs IOCs found in the input text.
pub fn parse_hex_url(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref HEX_URL_RE: Box<Regex> = compile_re(HEX_URL_PATTERN);
    }
    HEX_URL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::HexURL(x.as_str().trim_end()))
        .collect()
}

/// Parse all IPV6 types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of IPV6 IOCs found in the input text.
pub fn parse_ipv6(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref IPV6_RE: Box<Regex> = compile_re(IPV6_PATTERN);
    }
    IPV6_RE
        .find_iter(input)
        .map(|x| NetworkIOC::IPV6(x.as_str()))
        .collect()
}

/// Parse all IPV4 encoded URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of IPV4 IOCs found in the input text.
pub fn parse_ipv4(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref IPV4_RE: Box<Regex> = compile_re(IPV4_PATTERN);
    }
    IPV4_RE
        .find_iter(input)
        .map(|x| NetworkIOC::IPV4(x.as_str()))
        .collect()
}

/// Parse all URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of URLs IOCs found in the input text.
pub fn parse_urls(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref URL_RE: Box<Regex> = compile_re(URL_PATTERN);
    }
    URL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::URL(x.as_str()))
        .collect()
}

/// Parse all domains types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of domains IOCs found in the input text.
pub fn parse_domains(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref DOMAIN_RE: Box<Regex> = compile_re(DOMAIN_PATTERN);
    }
    DOMAIN_RE
        .find_iter(input)
        .map(|x| NetworkIOC::DOMAIN(x.as_str()))
        .collect()
}

/// Parse all email types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of email IOCs found in the input text.
pub fn parse_emails(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref EMAIL_RE: Box<Regex> = compile_re(EMAIL_PATTERN);
    }
    EMAIL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::EMAIL(x.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parase_ipv6() {
        assert_eq!(
            parse_ipv6("this has a ipv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            vec![NetworkIOC::IPV6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
        )
    }
    #[test]
    fn test_parse_domains() {
        assert_eq!(
            parse_domains("this has a www.test.com"),
            vec![NetworkIOC::DOMAIN("www.test.com")]
        );
    }

    #[test]
    fn test_parse_urls() {
        assert_eq!(
            parse_urls("this has a http://www.test.com"),
            vec![NetworkIOC::URL("http://www.test.com")]
        );
    }

    #[test]
    fn test_parse_emails() {
        assert_eq!(
            parse_emails("this has an email test@test.com"),
            vec![NetworkIOC::EMAIL("test@test.com")]
        );
    }

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(
            parse_ipv4("this has an ipv4 127.0.0.1"),
            vec![NetworkIOC::IPV4("127.0.0.1")]
        );
    }

    #[test]
    fn test_parse_hex_url() {
        assert_eq!(
            parse_hex_url("this has an hex encoded url 687474703A2F2F7777772E726970696F632E636F63"),
            vec![NetworkIOC::HexURL(
                "687474703A2F2F7777772E726970696F632E636F63"
            )]
        );
    }

    #[test]
    fn test_parse_network_iocs() {
        let results = parse_network_iocs(
            "
        127.0.0.1 www.test.com
        http://www.ripioc.com/url
        some_ioc@iocrip.com
        2001:0db8:85a3:0000:0000:8a2e:0370:7334
        687474703A2F2F7777772E726970696F632E636F63 some other text
        ",
        );
        assert_eq!(
            results,
            NetworkIOCS {
                urls: vec![NetworkIOC::URL("http://www.ripioc.com/url")],
                domains: vec![
                    NetworkIOC::DOMAIN("www.test.com"),
                    NetworkIOC::DOMAIN("www.ripioc.com"),
                    NetworkIOC::DOMAIN("iocrip.com")
                ],
                emails: vec![NetworkIOC::EMAIL("some_ioc@iocrip.com")],
                ipv4s: vec![NetworkIOC::IPV4("127.0.0.1")],
                ipv6s: vec![NetworkIOC::IPV6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")],
                hexurls: vec![NetworkIOC::HexURL(
                    "687474703A2F2F7777772E726970696F632E636F63"
                )]
            }
        )
    }
}
