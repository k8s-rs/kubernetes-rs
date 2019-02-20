extern crate base64;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate har;
extern crate log;
extern crate pest;
#[macro_use]
extern crate pest_derive;
extern crate pretty_env_logger;
extern crate serde_json;
extern crate tokio;

use failure::Error;
use std::env;
use std::fs;
use std::result::Result;

use har::v1_3;
use pest::Parser;

#[derive(Parser)]
#[grammar_inline = r#"
level = { "I" | "E" | "W" }
digit = { '0'..'9' }
ws = _{ " "+ }
digits = { digit+ }
pid = @{ digits }
filename = { (ALPHABETIC | "_" | ".")+ }

code = @{ level ~ digit ~ digit ~ digit ~ digit }



time = @{ digits ~ ":" ~ digits ~ ":" ~ digits ~ "." ~ digits }
prelude = @{ code ~ ws ~ time ~ ws ~ pid ~ ws ~ filename ~ ":" ~ digits ~ "] " }
junk = { (!NEWLINE ~ ANY)* }
//response = { "Response Body: " ~ json }
method = @{ "POST" | "GET" | "PATCH" | "PUT" | "DELETE" }
url = { (!NEWLINE ~ ANY)+ }
request_line = { prelude ~ method ~ ws ~ url ~ NEWLINE}
field = { (ASCII_ALPHA | "-")+ }
value = { (!NEWLINE ~ ANY)+ }
header_line = _{ prelude ~ ws ~ field ~ ": " ~ value ~ NEWLINE }
header_lines = _{ (header_line)* }
request_headers = { prelude ~ "Request Headers:" ~ NEWLINE ~ header_lines }
response_status = { prelude ~ continued }
response_headers = { prelude ~ "Response Headers:" ~ NEWLINE ~ header_lines }
body = @{continued}
response_body = { prelude ~ "Response Body: " ~ body }
request = { request_line ~ request_headers ~ response_status ~ response_headers ~ response_body }
content = { junk }
continued = { junk ~ NEWLINE ~ (!prelude ~ junk ~ NEWLINE)* }
log_entry = { prelude ~ continued }
file = {
  SOI ~
  (request | log_entry | (ANY* ~ NEWLINE)) * ~
  EOI
  }
"#]

struct LogParser;

struct ParseHeaders<'a> {
    iter: pest::iterators::Pairs<'a, Rule>,
}

impl<'a> Iterator for ParseHeaders<'a> where {
    type Item = v1_3::Headers;

    fn next(&mut self) -> Option<v1_3::Headers> {
        let mut header = v1_3::Headers {
            name: "".to_string(),
            value: "".to_string(),
            comment: None,
        };
        for pair in &mut self.iter {
            match pair.as_rule() {
                Rule::prelude => {}
                Rule::field => header.name.push_str(pair.as_str()),
                Rule::value => {
                    header.value.push_str(pair.as_str());
                    return Some(header);
                }
                e => panic!("Unexpected req header pair {:?}", e),
            }
        }
        if header.name.len() != 0 {
            panic!("Half-parsed header {:?}", header.name)
        }
        None
    }
}

fn main_() -> Result<(), Error> {
    let creator = v1_3::Creator {
        name: "kubernetes-rs".to_string(),
        version: "0.2".to_string(),
        comment: None,
    };
    let entries: Vec<v1_3::Entries> = Vec::new();
    let _har = v1_3::Log {
        browser: None,
        comment: None,
        creator: creator,
        entries: entries,
        pages: None,
    };
    for arg in env::args().skip(1) {
        // TODO: support stdin
        let input = fs::read_to_string(arg)?;
        // the iterator must succeed given the definition of file - otherwise parse fails.
        let log = LogParser::parse(Rule::file, &input)?.next().unwrap();
        for record in log.into_inner() {
            match record.as_rule() {
                Rule::log_entry => {}
                Rule::request => {
                    // println!("YY{:?}", record);
                    let mut entry = v1_3::Entries {
                        pageref: None,
                        // TODO: put something in this; log misses date.
                        started_date_time: String::new(),
                        // TODO: comes from response time
                        time: 0,
                        request: v1_3::Request {
                            method: "unset".to_string(),
                            url: "unset".to_string(),
                            http_version: "unknown".to_string(),
                            cookies: Vec::new(),
                            headers: Vec::new(),
                            query_string: Vec::new(),
                            post_data: None,
                            headers_size: -1,
                            body_size: -1,
                            comment: None,
                            headers_compression: None,
                        },
                        response: v1_3::Response {
                            charles_status: None,
                            status: -1,
                            status_text: "".to_string(),
                            http_version: "unknown".to_string(),
                            cookies: Vec::new(),
                            headers: Vec::new(),
                            content: v1_3::Content {
                                size: -1,
                                compression: None,
                                mime_type: "".to_string(),
                                text: None,
                                encoding: None,
                                comment: None,
                            },
                            redirect_url: "".to_string(),
                            headers_size: -1,
                            body_size: -1,
                            comment: None,
                            headers_compression: None,
                        },
                        cache: v1_3::Cache {
                            before_request: None,
                            after_request: None,
                        },
                        timings: v1_3::Timings {
                            blocked: None,
                            dns: None,
                            connect: None,
                            send: -1,
                            wait: -1,
                            receive: -1,
                            ssl: None,
                            comment: None,
                        },
                        // TODO - infer from url?
                        server_ip_address: None,
                        connection: None,
                        comment: None,
                    };
                    for element in record.into_inner() {
                        match element.as_rule() {
                            Rule::request_line => {
                                for pair in element.into_inner() {
                                    match pair.as_rule() {
                                        Rule::method => {
                                            entry.request.method = pair.as_str().to_string()
                                        }
                                        Rule::url => entry.request.url = pair.as_str().to_string(),
                                        Rule::prelude => {}
                                        e => Err(format_err!("Unexpected req line pair {:?}", e))?,
                                    }
                                }
                            }
                            Rule::request_headers => {
                                for header in (ParseHeaders {
                                    iter: element.into_inner(),
                                }) {
                                    entry.request.headers.push(header)
                                }
                            }
                            // TODO: parse this with more detail
                            Rule::response_status => {
                                //println!("{:?}", element)
                            }
                            Rule::response_headers => {
                                for header in (ParseHeaders {
                                    iter: element.into_inner(),
                                }) {
                                    entry.response.headers.push(header)
                                }
                            }
                            Rule::response_body => {
                                for pair in element.into_inner() {
                                    match pair.as_rule() {
                                        Rule::prelude => {}
                                        Rule::body => {
                                            entry.response.content.text =
                                                Some(base64::encode(pair.as_str()));
                                            entry.response.content.encoding =
                                                Some("base64".to_string());
                                        }
                                        e => Err(format_err!(
                                            "Unexpected response body pair {:?}",
                                            e
                                        ))?,
                                    }
                                }
                            }
                            e => Err(format_err!("Unexpected parse rule 2 encountered {:?}", e))?,
                        }
                    }
                    println!("{}", serde_json::to_string(&entry)?);
                }
                Rule::EOI => (),
                e => Err(format_err!("Unexpected parse rule 1 encountered {:?}", e))?,
            }
        }
    }
    Ok(())
}

pub fn main_result<F>(main_: F)
where
    F: FnOnce() -> Result<(), Error>,
{
    pretty_env_logger::init();
    let status = match main_() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {}", e);
            for c in e.iter_chain().skip(1) {
                eprintln!(" Caused by {}", c);
            }
            eprintln!("{}", e.backtrace());
            1
        }
    };
    ::std::process::exit(status);
}

/// Collects all the given inputs as kubectl -v8 web transactions and outputs
/// as one har.
/// `kubectl version -v8 2> version.log && log2har version.log > version.har`
fn main() {
    main_result(main_)
}
