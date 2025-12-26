#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! regex = "1"
//! reqwest = { version = "0.12", features = ["blocking", "rustls-tls"] }
//! ```
use anyhow::{Context, Ok, Result};
use regex::Regex;
use std::collections::BTreeSet;
// FindSecBugs can scan CWE-113, CWE-117, CWE-22, CWE-326, CWE-327, CWE-329, CWE-502, CWE-643, CWE-78, CWE-79, CWE-918, CWE-943, CWE-95
fn main() -> Result<()> {
    let cwe_list = vec![
        "CWE-22", "CWE-78", "CWE-79", "CWE-95", "CWE-113", "CWE-117", "CWE-326", "CWE-327", "CWE-329", "CWE-347", "CWE-377", "CWE-502", "CWE-643", "CWE-760", "CWE-918", "CWE-943", "CWE-1333"
    ];
    const URL: &str = "https://find-sec-bugs.github.io/bugs.htm";
    let resp = reqwest::blocking::get(URL).with_context(|| format!("GET {}", URL))?;
    let status = resp.status();
    let html = resp.text().context("read response body")?;
    anyhow::ensure!(status.is_success(), "HTTP {} when fetching {}", status, URL);
    let re = Regex::new(r"CWE-(\d+)")?;
    let mut set = BTreeSet::new();

    for cap in re.captures_iter(&html) {
        set.insert(format!("CWE-{}", &cap[1]));
    }
    let mut first = true;
    for cwe in set {
        if cwe_list.contains(&cwe.as_str()) {
            if first {
                print!("{cwe}");
                first = false;
                continue;
            }
            print!(", {cwe}");
        }
    }
    println!();
    Ok(())
}