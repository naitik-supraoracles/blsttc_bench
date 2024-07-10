use super::stats::{calculate_mean, calculate_median};
use blsttc::group::ff::Field;
use blsttc::group::prime::PrimeCurveAffine;
use blsttc::nizk_dleq::{prove_gen, verify_proof, DLEqInstance, DLEqWitness, ZkProofDLEq};
use blsttc::rand::thread_rng as blsttc_thread_rng;
use blsttc::{
    hash_g1, Fr, G1Affine, G1Projective, G2Affine, G2Projective, PublicKeyG2, PublicKeyShareG1,
    PublicKeyShareG2, SecretKeySet, SecretKeyShare, SignatureG1, SignatureShareG1,
};
use std::time::Instant;

pub fn benchmark_nizk_multisig_bls(nodes: usize) -> (f64, f64, f64, f64, f64, f64) {
    let mut keypairs: Vec<(PublicKeyShareG1, PublicKeyShareG2, SecretKeyShare)> = Vec::new();
    let msg = "hello, this is benchmark".as_bytes();
    let mut signs_g1 = Vec::new();

    let mut nizks = Vec::new();

    let threshold = 2; // some random value less than total nodes
    let mut rng = blsttc::rand::rngs::OsRng;
    // Generate a set of secret key shares
    let sk_set = SecretKeySet::random(threshold, &mut rng);
    // Get the corresponding public key set
    let pk_set_g1 = sk_set.public_keys();
    let pk_set_g2 = sk_set.public_keys_g2();

    for node in 0..nodes {
        let sk_share = sk_set.secret_key_share(node);
        let pk_share_g1 = pk_set_g1.public_key_share(node);
        let pk_share_g2 = pk_set_g2.public_key_share(node);

        keypairs.push((pk_share_g1, pk_share_g2, sk_share));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating sign share in g1 with nizk
    let mut time_to_create_sign_share_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();
        let sign = keypairs[i].2.sign_g1(msg);

        //calc nizk
        let pk = keypairs[i].0;
        let mut rng = blsttc_thread_rng();
        let r: Fr = Fr::random(&mut rng);
        let g = G1Affine::generator();
        let h = hash_g1(msg);
        let g_x = pk.0 .0;
        let h_x = sign.0 .0;
        let instance = DLEqInstance { g, h, g_x, h_x };
        let witness = DLEqWitness {
            scalar_x: keypairs[i].2 .0 .0,
            scalar_r: r,
        };
        let nizk = prove_gen(&instance, &witness);
        let end_time = Instant::now();
        signs_g1.push(sign);
        nizks.push(nizk);

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_create_sign_share_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying single g1 sign share with nizk
    let mut time_to_verify_single_sign_share_g1 = Vec::new();
    for i in 0..nodes {
        let start_time = Instant::now();
        let sig = &signs_g1[i];
        let key = keypairs[i].0;
        let g = G1Affine::generator();
        let g_x = key.0 .0;
        let h_x = sig.0 .0;
        let nizk = &nizks[i];
        let h = hash_g1(msg);
        let instance = DLEqInstance { g, h, g_x, h_x };
        verify_proof(&instance, &nizk).unwrap();
        let end_time = Instant::now();

        // Calculate elapsed time
        let elapsed_time = end_time.duration_since(start_time);
        time_to_verify_single_sign_share_g1.push(elapsed_time.as_secs_f64());
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for all sign share in g1 with nizk
    let mut time_to_verify_all_independent_signs_g1 = 0.0;

    let start_time = Instant::now();
    for i in 0..nodes {
        let sig = &signs_g1[i];
        let key = keypairs[i].0;
        let g = G1Affine::generator();
        let g_x = key.0 .0;
        let h_x = sig.0 .0;
        let nizk = &nizks[i];
        let h = hash_g1(msg);
        let instance = DLEqInstance { g, h, g_x, h_x };
        verify_proof(&instance, &nizk).unwrap();
    }
    let end_time = Instant::now();

    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_all_independent_signs_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating aggregated sign g1
    let mut time_to_create_aggregated_sign_g1 = 0.0;

    let start_time = Instant::now();
    let mut agg_sign_g1 = signs_g1[0].clone();
    for i in 1..signs_g1.len() {
        let new_agg_sign_g1 = aggregate_sign_g1(&agg_sign_g1, &signs_g1[i]);
        agg_sign_g1 = new_agg_sign_g1;
    }
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_create_aggregated_sign_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for creating aggregated pubkey g2
    let mut time_to_create_aggregated_pubkey_g2 = 0.0;

    let start_time = Instant::now();
    let mut agg_pubkey_g2 = keypairs[0].1.clone();
    for i in 1..keypairs.len() {
        let new_agg_pubkey_g2 = aggregate_pubkey_g2(&agg_pubkey_g2, &keypairs[i].1);
        agg_pubkey_g2 = new_agg_pubkey_g2;
    }
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_create_aggregated_pubkey_g2 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    //for verifying aggregated sign g1
    let mut time_to_verify_aggregated_sign_g1 = 0.0;

    let start_time = Instant::now();
    agg_pubkey_g2.verify(&agg_sign_g1, msg);
    let end_time = Instant::now();

    // Calculate elapsed time
    let elapsed_time = end_time.duration_since(start_time);
    time_to_verify_aggregated_sign_g1 = elapsed_time.as_secs_f64();

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    let mean_single_sign_creation_g1 = calculate_mean(&time_to_create_sign_share_g1) * 1000.0;
    let median_single_sign_creation_g1 =
        calculate_median(&mut time_to_create_sign_share_g1) * 1000.0;
    let mean_single_sign_verify_g1 = calculate_mean(&time_to_verify_single_sign_share_g1) * 1000.0;
    let median_single_sign_verify_g1 =
        calculate_median(&mut time_to_verify_single_sign_share_g1) * 1000.0;
    let n_sign_verify_g1 = time_to_verify_all_independent_signs_g1 * 1000.0;
    let creation_agg_pubkey_g2 = time_to_create_aggregated_pubkey_g2 * 1000.0;
    let creation_agg_sign_g1 = time_to_create_aggregated_sign_g1 * 1000.0;
    let verify_agg_sign_g1 = time_to_verify_aggregated_sign_g1 * 1000.0;

    //OUTPUT
    println!("for signshare in g1 : ");
    println!(
        "mean time to create single  bls sign share in g1 (with nizk): {:.4} ms",
        mean_single_sign_creation_g1
    );
    println!(
        "median time to create single bls sign share in g1 (with nizk): {:.4} ms",
        median_single_sign_creation_g1
    );
    println!(
        "mean time to verify single bls sign share in g1 (with nizk): {:.4} ms",
        mean_single_sign_verify_g1
    );
    println!(
        "meadian time to verify single bls sign share in g1 (with nizk): {:.4} ms",
        median_single_sign_verify_g1
    );
    println!(
        "time takes to verify n independent signs share in g1 (with nizk): {:.4} ms",
        n_sign_verify_g1
    );
    println!(
        "time takes to create aggregated pubkey in g2: {:.4} ms",
        creation_agg_pubkey_g2
    );
    println!(
        "time takes to create aggregated sign in g1: {:.4} ms",
        creation_agg_sign_g1
    );
    println!(
        "time takes to verify aggregated sign in g1: {:.4} ms",
        verify_agg_sign_g1
    );
    println!("");

    (
        mean_single_sign_creation_g1,
        mean_single_sign_verify_g1,
        n_sign_verify_g1,
        creation_agg_pubkey_g2,
        creation_agg_sign_g1,
        verify_agg_sign_g1,
    )
}

pub fn aggregate_sign_g1(
    agg_sig: &SignatureShareG1,
    new_sign: &SignatureShareG1,
) -> SignatureShareG1 {
    let agg_sign = G1Affine::from(agg_sig.0 .0 + G1Projective::from(new_sign.0 .0));
    let sign = SignatureShareG1(SignatureG1(agg_sign));
    sign
}

pub fn aggregate_pubkey_g2(
    agg_key: &PublicKeyShareG2,
    new_key: &PublicKeyShareG2,
) -> PublicKeyShareG2 {
    let agg_key = G2Affine::from(agg_key.0 .0 + G2Projective::from(new_key.0 .0));
    let key = PublicKeyShareG2(PublicKeyG2(agg_key));
    key
}
