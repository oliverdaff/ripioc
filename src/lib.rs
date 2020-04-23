#[macro_use] extern crate lazy_static;
extern crate regex;


pub mod network_ioc{
    use regex::Regex;
    use regex::RegexBuilder;
    use regex::RegexSet;
    use regex::RegexSetBuilder;

    #[derive(Debug, PartialEq, Eq)]
    pub enum NetworkIOC<'a> {
        URL(&'a str),
        DOMAIN(&'a str),
        EMAIL(&'a str),
        IPV4(&'a str),
        IPV6(&'a str),
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct NetworkIOCS<'a> {
        urls: Vec<NetworkIOC<'a>>,
        domains: Vec<NetworkIOC<'a>>,
        emails: Vec<NetworkIOC<'a>>,
        ipv4s: Vec<NetworkIOC<'a>>,
        ipv6s: Vec<NetworkIOC<'a>>
    }

    const URL_PATTERN: &str  = r"(\b((http|https|hxxp|hxxps|nntp|ntp|rdp|sftp|smtp|ssh|tor|webdav|xmpp)://[\S]{1,})\b)"; 
    const DOMAIN_PATTERN: &str = "([A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|\
        agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|\
        attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|\
        best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|\
        brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|\
        capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|\
        cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|\
        college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|\
        credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|\
        delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|\
        domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|\
        er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|\
        financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|\
        frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|\
        globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|\
        hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|\
        id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|\
        iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|\
        la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|\
        lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|\
        memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|\
        mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|\
        nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|\
        photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|\
        properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|\
        rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|\
        schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|\
        solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|\
        tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|\
        toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|\
        vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|\
        whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw)\\b)";

    const EMAIL_PATTERN : &str = r#"[A-Za-z0-9_.]+@[0-9a-z.-]+"#;

    const IPV4_PATTERN : &str = r#"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[?\.]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"#;

    const IPV6_PATTERN : &str = r#"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
                                ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}
                                (:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:
                                ((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]
                                    |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]
                                        |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"#;

    pub fn parse_network_iocs(input: &str) -> NetworkIOCS {

        lazy_static! {
            static ref NETWORK_IOCS_RE: RegexSet = RegexSetBuilder::new(
                vec![
                    URL_PATTERN,
                    EMAIL_PATTERN,
                    DOMAIN_PATTERN,
                    IPV6_PATTERN,
                    IPV4_PATTERN
            ]
            )
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        let matches = NETWORK_IOCS_RE.matches(input);
        return NetworkIOCS{
            urls: if matches.matched(0) { parse_urls(input) } else { vec![]},
            emails: if matches.matched(1) { parse_emails(input) } else { vec![]},
            domains: if matches.matched(2) { parse_domains(input) } else { vec![]},
            ipv6s: if matches.matched(3) { parse_ipv6(input)} else { vec![]},
            ipv4s: if matches.matched(4) { parse_ipv4(input)} else { vec![]},
        } 
    }

    pub fn parse_ipv6(input: &str) -> Vec<NetworkIOC> {
        lazy_static! {
            static ref IPV6_RE: Regex = RegexBuilder::new(IPV6_PATTERN)
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        return IPV6_RE.find_iter(input)
        .map(|x|x.as_str())
        .map(|x|NetworkIOC::IPV6(x))
        .collect();
    }


    pub fn parse_ipv4(input: &str) -> Vec<NetworkIOC> {
        lazy_static! {
            static ref IPV4_RE: Regex = RegexBuilder::new(IPV4_PATTERN)
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        return IPV4_RE.find_iter(input)
        .map(|x|x.as_str())
        .map(|x|NetworkIOC::IPV4(x))
        .collect();
    }

    pub fn parse_urls(input: &str) -> Vec<NetworkIOC> {
        lazy_static! {
            static ref URL_RE: Regex = RegexBuilder::new(URL_PATTERN)
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        return URL_RE.find_iter(input)
        .map(|x|NetworkIOC::URL(x.as_str()))
        .collect();
    }

    pub fn parse_domains(input: &str) -> Vec<NetworkIOC> {
        lazy_static! {
            static ref DOMAIN_RE: Regex = RegexBuilder::new(DOMAIN_PATTERN)
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        return DOMAIN_RE.find_iter(input)
        .map(|x|NetworkIOC::DOMAIN(x.as_str()))
        .collect();

    }

    pub fn parse_emails(input: &str) -> Vec<NetworkIOC> {
        lazy_static! {
            static ref EMAIL_RE: Regex = RegexBuilder::new(EMAIL_PATTERN)
            .case_insensitive(true)
            .ignore_whitespace(true)
            .build().unwrap();
        }
        return EMAIL_RE.find_iter(input)
        .map(|x|NetworkIOC::EMAIL(x.as_str())).collect();
    }


    #[cfg(test)]
    mod tests {
        use super::*;
    
        #[test]
        fn test_parase_ipv6(){
            assert_eq!(parse_ipv6("this has a ipv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334"), vec![NetworkIOC::IPV6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")])
        }
        #[test]
        fn test_parse_domains() {
            assert_eq!(parse_domains("this has a www.test.com"), vec![NetworkIOC::DOMAIN("www.test.com")]);
        }

        #[test]
        fn test_parse_urls() {
            assert_eq!(parse_urls("this has a http://www.test.com"), vec![NetworkIOC::URL("http://www.test.com")]);
        }

        #[test]
        fn test_parse_emails() {
            assert_eq!(parse_emails("this has an email test@test.com"), vec![NetworkIOC::EMAIL("test@test.com")]);
        }

        #[test]
        fn test_parse_ipv4() {
            assert_eq!(parse_ipv4("this has an ipv4 127.0.0.1"), vec![NetworkIOC::IPV4("127.0.0.1")]);
        }

        #[test]
        fn test_parse_network_iocs() {
            let results = parse_network_iocs("127.0.0.1 www.test.com");
            assert_eq!(results, NetworkIOCS{
                urls : vec![],
                domains: vec![NetworkIOC::DOMAIN("www.test.com")],
                emails: vec![],
                ipv4s: vec![NetworkIOC::IPV4("127.0.0.1")],
                ipv6s: vec![],
            })
        }
    }


}



