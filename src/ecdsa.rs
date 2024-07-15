use ed25519_dalek as dalek;
use ed25519_dalek::Signer as _;
use rand::rngs::OsRng;
use super::stats::{calculate_mean, calculate_median};
use std::time::Instant;


pub fn benchmark_ecdsa_signs(nodes: usize) -> (f64, f64, f64) {
    // for normal sign-verify
    let mut csprng = OsRng;
    
    let mut keypairs: Vec<_> = Vec::new();
    let msg = "hello, this is benchmark".as_bytes();
    let mut signs = Vec::new();

    for _ in 0..nodes {
        let keypair = dalek::Keypair::generate(&mut csprng);
        let public = keypair.public;
        let secret = keypair;
        keypairs.push((public, secret));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating single sign
    let mut time_to_create_normal_sign = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        let sign = keypairs[i].1.sign(msg);

        let end_time = Instant::now();

        signs.push(sign);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_normal_sign.push(elapsed_time.as_secs_f64());
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single sign
    let mut time_to_verify_normal_sign = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();

        keypairs[i].0.verify_strict(msg, &signs[i]).unwrap();

        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_normal_sign.push(elapsed_time.as_secs_f64());
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for f+1 sign
    let mut time_to_verify_fplus1_independent_signs = 0.0;
    let n = (nodes - 1) / 3 + 1;

    let start_time = Instant::now();

    for i in 0..n {
        keypairs[i].1.verify_strict(msg, &signs[i]).unwrap();
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_fplus1_independent_signs = elapsed_time.as_secs_f64();


    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign
    let mut time_to_verify_all_independent_signs = 0.0;

    let start_time = Instant::now();

    for i in 0..nodes {
        keypairs[i].1.verify_strict(msg,&signs[i]).unwrap();
    }

    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////


    let mean_single_sign_creation = calculate_mean(&time_to_create_normal_sign) * 1000.0;
    let median_single_sign_creation =
        calculate_median(&mut time_to_create_normal_sign) * 1000.0;
    let mean_single_sign_verify = calculate_mean(&time_to_verify_normal_sign) * 1000.0;
    let median_single_sign_verify =
        calculate_median(&mut time_to_verify_normal_sign) * 1000.0;
    let fplusq_sign_verify = time_to_verify_fplus1_independent_signs * 1000.0;
    let n_sign_verify = time_to_verify_all_independent_signs * 1000.0;


    //OUTPUT
    println!("for sign in g1 : ");
    println!(
        "mean time to create single bls sign: {:.4} ms",
        mean_single_sign_creation
    );
    println!(
        "median time to create single bls sign: {:.4} ms",
        median_single_sign_creation
    );
    println!(
        "mean time to verify single bls sign: {:.4} ms",
        mean_single_sign_verify
    );
    println!(
        "meadian time to verify single bls sign: {:.4} ms",
        median_single_sign_verify
    );
    println!(
        "time takes to verify f+1 signs: {:.4} ms",
        fplusq_sign_verify
    );
    println!(
        "time takes to verify n signs: {:.4} ms",
        n_sign_verify
    );
    println!("");


    (
        mean_single_sign_creation,
        mean_single_sign_verify,
        n_sign_verify,
    )
}
