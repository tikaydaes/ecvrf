use ecvrf::{derive_public_key, prove, verify};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: cli prove <sk_hex> <alpha_hex> | verify <pk_hex> <pi_hex> <alpha_hex> | derive-pk <sk_hex>"
        );
        process::exit(2);
    }

    match args[1].as_str() {
        "prove" => {
            if args.len() < 4 {
                process::exit(2);
            }
            let sk = hex::decode(&args[2]).unwrap_or_else(|_| process::exit(2));
            let alpha = hex::decode(&args[3]).unwrap_or_else(|_| process::exit(2));
            match prove(&sk, &alpha) {
                Ok(pi) => println!("{}", hex::encode(pi)),
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(1);
                }
            }
        }
        "verify" => {
            if args.len() < 5 {
                process::exit(2);
            }
            let pk = hex::decode(&args[2]).unwrap_or_else(|_| process::exit(2));
            let pi = hex::decode(&args[3]).unwrap_or_else(|_| process::exit(2));
            let alpha = hex::decode(&args[4]).unwrap_or_else(|_| process::exit(2));
            match verify(&pk, &pi, &alpha) {
                Ok(beta) => println!("{}", hex::encode(beta)),
                Err(_) => process::exit(1),
            }
        }
        "derive-pk" => {
            if args.len() < 3 {
                process::exit(2);
            }
            let sk = hex::decode(&args[2]).unwrap_or_else(|_| process::exit(2));
            match derive_public_key(&sk) {
                Ok(pk) => println!("{}", hex::encode(pk)),
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            process::exit(2);
        }
    }
}
