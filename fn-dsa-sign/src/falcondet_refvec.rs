//! Checks the FLR backend against vectors dumped from algorand/falcon built
//! with FALCON_FPEMU = 1.

extern crate std;

use super::flr::FLR;
use std::collections::HashMap;
use std::format;
use std::println;
use std::string::{String, ToString};
use std::vec::Vec;

fn flr_of(bits: u64) -> FLR {
    FLR::decode(&bits.to_le_bytes()).expect("decode")
}

fn bits_of(x: FLR) -> u64 {
    u64::from_le_bytes(x.encode())
}

fn hexv(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect("hex")
}

#[test]
fn flr_matches_falcon_fpr() {
    let path = format!("{}/tests-data/fpr_vectors.txt", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("vectors");
    let mut bad: HashMap<&str, usize> = HashMap::new();
    let mut tot: HashMap<&str, usize> = HashMap::new();
    let mut first: HashMap<&str, String> = HashMap::new();

    let mut note = |op: &'static str, ok: bool, detail: String| {
        *tot.entry(op).or_default() += 1;
        if !ok {
            *bad.entry(op).or_default() += 1;
            first.entry(op).or_insert(detail);
        }
    };

    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() || f[0].starts_with('#') {
            continue;
        }
        match f[0] {
            "u1" => {
                let x = flr_of(hexv(f[1]));
                note("neg", bits_of(-x) == hexv(f[3]), f[1].into());
                note("half", bits_of(x.half()) == hexv(f[5]), f[1].into());
                note("double", bits_of(x.double()) == hexv(f[7]), f[1].into());
                note("square", bits_of(x.square()) == hexv(f[9]), f[1].into());
            }
            "u2" => {
                // rint/floor/trunc are documented only for values in
                // -(2^63-1)..+(2^63-1). Screen on the input's exponent: the
                // corpus ranges far wider, and out-of-domain inputs are not a
                // meaningful comparison (the C reference returns garbage there
                // rather than erroring).
                let bits = hexv(f[1]);
                let exp = ((bits >> 52) & 0x7FF) as i32;
                if bits == 0 || exp < 1023 + 50 {
                    let x = flr_of(bits);
                    note("rint", x.rint() == f[3].parse::<i64>().unwrap(), f[1].into());
                    note("floor", x.floor() == f[5].parse::<i64>().unwrap(), f[1].into());
                    note("trunc", x.trunc() == f[7].parse::<i64>().unwrap(), f[1].into());
                }
            }
            "u3" => {
                let x = flr_of(hexv(f[1]));
                note("sqrt", bits_of(x.sqrt()) == hexv(f[3]), f[1].into());
            }
            "b" => {
                let (a, b) = (flr_of(hexv(f[1])), flr_of(hexv(f[2])));
                note("add", bits_of(a + b) == hexv(f[4]), format!("{},{}", f[1], f[2]));
                note("sub", bits_of(a - b) == hexv(f[6]), format!("{},{}", f[1], f[2]));
                note("mul", bits_of(a * b) == hexv(f[8]), format!("{},{}", f[1], f[2]));
            }
            "d" => {
                let (a, b) = (flr_of(hexv(f[1])), flr_of(hexv(f[2])));
                note("div", bits_of(a / b) == hexv(f[4]), format!("{},{}", f[1], f[2]));
            }
            "e" => {
                let (x, ccs) = (flr_of(hexv(f[1])), flr_of(hexv(f[2])));
                note("expm_p63", x.expm_p63(ccs) == hexv(f[4]), format!("{},{}", f[1], f[2]));
            }
            _ => {}
        }
    }

    let mut failed = false;
    for op in ["neg", "half", "double", "square", "rint", "floor", "trunc",
               "sqrt", "add", "sub", "mul", "div", "expm_p63"] {
        let t = tot.get(op).copied().unwrap_or(0);
        if t == 0 {
            continue;
        }
        let b = bad.get(op).copied().unwrap_or(0);
        println!("{:<10} {:<7} {}/{} mismatched  {}", op,
                 if b == 0 { "MATCH" } else { "DIFFER" }, b, t,
                 first.get(op).cloned().unwrap_or_default());
        if b != 0 {
            failed = true;
        }
    }
    assert!(!failed, "FLR backend does not match round-3 Falcon");
}
