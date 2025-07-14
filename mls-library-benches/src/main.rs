use std::{
    io::{Write, stdout},
    time::Instant,
};

use clap::Parser;
use mls_library_benches::{BenchSetup, BenchmarkCase as _, PlaintextGenerator, mls_rs::MlsRs, openmls::OpenMls};

#[derive(Debug, clap::Parser)]
struct Args {
    /// How many messages to generate
    #[arg(short = 'm', long, default_value_t = 1000)]
    n_messages: usize,
    /// How many senders to send the messages from
    #[arg(short = 's', long, default_value_t = 100)]
    n_senders: usize,
    /// When set, run a single benchmark instance using OpenMLS
    #[arg(long)]
    openmls: bool,
    /// When set, run a single benchmark instance using mls-rs
    #[arg(long, alias = "mlsrs")]
    mls_rs: bool,
}

fn timed<Thunk, Out>(msg: String, thunk: Thunk) -> Out
where
    Thunk: FnOnce() -> Out,
{
    print!("{msg}... ");
    stdout().flush().expect("can flush stdout");
    let start = Instant::now();
    let out = thunk();
    let duration = Instant::now().duration_since(start).as_secs_f64();
    let duration = (duration * 1000.0).round() / 1000.0;
    println!("OK ({duration}s)");
    out
}

fn run_bench<Bench: BenchSetup + Default>(args: &Args, plaintext_generator: &PlaintextGenerator) {
    let mut bench = Bench::default();

    let (case, hash) = timed(format!("setting up {} case", Bench::ident()), || {
        bench.setup(plaintext_generator, args.n_senders, args.n_messages)
    });

    let decrypted_hash = timed(
        format!("decrypting {} messages ({})", args.n_messages, Bench::ident()),
        || case.decrypt_all(),
    );

    assert_eq!(
        hash,
        decrypted_hash,
        "{} failed to correctly decrypt its encrypted messages",
        Bench::ident()
    );
    println!("{} decrypted all messages successfully", Bench::ident());
}

fn main() {
    let args = Args::parse();
    let plaintext_generator = PlaintextGenerator::default();
    if args.openmls {
        run_bench::<OpenMls>(&args, &plaintext_generator);
    }
    if args.mls_rs {
        run_bench::<MlsRs>(&args, &plaintext_generator);
    }
    if !(args.openmls || args.mls_rs) {
        println!("no library selected; try `--mls-rs` or `--openmls`");
    }
}
