# RIP IOC

A simple rust library containing regex to match [indicators of compromise](https://taosecurity.blogspot.com/2018/11/the-origin-of-term-indicators-of.html "origin of term indicator") (IOC) found in text data.


## Motivation
Text content often contains indicators of compromise.  Sources include Twitter, web pages and pdf reports.  Often IOC extraction is done in slower languages, using Rust to provide this functionality enables large volumes of text to be processed quickly and with low overhead.

## Code Example
The main entry point to the library is `parse_all_iocs(input: &str) -> IOCS`.  This will return a IOCS object that contains each IOC found in the input text.

For example reading from `stdin`
```
extern crate ripioc;

use ripioc::parse_all_iocs;
use ripioc::IOCS;

fn main() {
    let mut input = String::new();
    match io::stdin().read_to_string(&mut input){
        Ok(_) => {
            let found_iocs = parse_all_iocs(&input);
            println!("{:?}", found_iocs);
        }
        Err(err) => println!("Error {}", err),
    }
}
```

## Installation
While this library is in initial state of development installation is done using cargo.

```
git checkout https://github.com/oliverdaff/ripioc
cargo test 
cargo install
```

The master branch can be referenced directly in the `Cargo.toml` files.

```
[dependencies.ripioc]
git = "ssh://git@github.com/oliverdaff/ripioc.git"
rev = "8cc750f"
```

Optionally a specific revision can be specified.
```
[dependencies.ripioc]
git = "ssh://git@github.com/oliverdaff/ripioc.git"
rev = "8cc750f"
```


## API Reference
The four different IOC groups are found their own modules.

* `ripico::file_ioc` contains parsers to extract file indicators and can be invoked with `ripioc::file_ioc::parse_file_iocs`. The files currently extracted grouped into:
    *   Doc files
    *   Exe files
    *   Flash files
    *   Image files
    *   Mac files
    *   Web files
    *   Zip files
* `ripico::hash` contains parsers to extract file indicators and can be invoked with `ripioc::hash_ioc::parse_hash_iocs`.  The hash signatures currently matched are:
    *   MD5 hashes
    *   SHA1 hashes
    * SH256 hashes
    * SHA512 hashes
    * SSDEEP hashes
* `ripico::network_ioc` contains parsers to extract network indicators and can be invoked with `ripioc::network_ioc::parse_network_iocs`.  The network IOCs currently matched are:
    * URLs
    * Domains
    * Emails
    * IPV4 addresses
    * IPV6 addresses
    * Hex encoded URLs.
*   `ripico::cve_ioc` contains a single CVE parser that can be invoked with `ripioc::cve_ioc::parse_cve`.

## Tests
The tests can be invoked with `cargo test`.

## Credits
This project was inspired by IOC parsers written in other languages:
*   [iocextract](https://github.com/InQuest/python-iocextract)
*   [Cacador](https://github.com/sroberts/cacador)
*   [ioc_parser](https://github.com/armbues/ioc_parser)
*   [jager](https://github.com/sroberts/jager)

## License
MIT © Oliver Daff