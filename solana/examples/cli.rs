use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cli verify <pk_hex> <pi_hex> <alpha_hex>");
        process::exit(2);
    }

    match args[1].as_str() {
        "verify" => {
            if args.len() < 5 {
                process::exit(2);
            }
            let pk = hex::decode(&args[2]).unwrap_or_else(|_| process::exit(2));
            let pi = hex::decode(&args[3]).unwrap_or_else(|_| process::exit(2));
            let alpha = hex::decode(&args[4]).unwrap_or_else(|_| process::exit(2));
            match ecvrf_solana::verify(&pk, &pi, &alpha) {
                Ok(beta) => println!("{}", hex::encode(beta)),
                Err(_) => process::exit(1),
            }
        }
        other => {
            eprintln!("unknown command: {other} (solana is verify-only)");
            process::exit(2);
        }
    }
}
