use blsttc_benchmark::{
    multisig_bls::benchmark_multisig_bls, multisig_bls_nizk::benchmark_nizk_multisig_bls,
    simple_bls::benchmark_normal_bls, threshold_bls::benchmark_threshold_bls,
};
use csv::Writer;
use std::fs::File;

fn main() {
    //array for nodes for benchmark
    let nodes_info = [10, 20, 50, 100, 150, 200, 250, 500, 1000];

    //file to store bls simple sig results
    let bls_simple_file = File::create("simple.csv").unwrap();

    //file to store bls threshold sig results
    let bls_threshold_file = File::create("threshold.csv").unwrap();

    //file to store bls multisig aggregation results
    let bls_multisig_file = File::create("multisig_aggregation.csv").unwrap();

    //file to store bls multisig aggregation results (nizk)
    let bls_nizk_multisig_file = File::create("multisig_aggregation_with_nizk.csv").unwrap();

    //dedicated writer to each file
    let mut wtr1 = Writer::from_writer(bls_simple_file);
    let mut wtr2 = Writer::from_writer(bls_threshold_file);
    let mut wtr3 = Writer::from_writer(bls_multisig_file);
    let mut wtr4 = Writer::from_writer(bls_nizk_multisig_file);

    //setting coloumn name
    wtr1.write_record(&[
        "nodes",
        "creation_single_sign_g1",
        "creation_single_sign_g2",
        "verify_single_sign_g1",
        "verify_single_sign_g2",
        "verify_n_signs_g1",
        "verify_n_signs_g2",
    ])
    .unwrap();
    wtr2.write_record(&[
        "nodes",
        "creation_single_sign_share_g1",
        "creation_single_sign_share_g2",
        "verify_single_sign_share_g1",
        "verify_single_sign_share_g2",
        "verify_n_signshares_g1",
        "verify_n_signshares_g2",
        "creation_threshold_sig_g1",
        "creation_threshold_sig_g2",
        "verify_threshold_sig_g1",
        "verify_threshold_sig_g2",
    ])
    .unwrap();
    wtr3.write_record(&[
        "nodes",
        "creation_single_sign_share_g1",
        "creation_single_sign_share_g2",
        "verify_single_sign_share_g1",
        "verify_single_sign_share_g2",
        "verify_n_signshares_g1",
        "verify_n_signshares_g2",
        "creation_agg_pubkey_g1",
        "creation_agg_pubkey_g2",
        "creation_agg_sign_g1",
        "creation_agg_sign_g2",
        "verify_agg_sig_g1",
        "verify_agg_sig_g2",
    ])
    .unwrap();
    wtr4.write_record(&[
        "nodes",
        "creation_single_sign_share_g1",
        "verify_single_sign_share_g1",
        "verify_n_signshares_g1",
        "creation_agg_pubkey_g2",
        "creation_agg_sign_g1",
        "verify_agg_sig_g1",
    ])
    .unwrap();

    //bls simple signs
    for nodes in nodes_info {
        println!("\n ####### nodes : {} ####### \n", nodes);

        println!("\n ####### simple bls ####### \n");
        let (
            mean_single_sign_creation_g1,
            mean_single_sign_creation_g2,
            mean_single_sign_verify_g1,
            mean_single_sign_verify_g2,
            n_sign_verify_g1,
            n_sign_verify_g2,
        ) = benchmark_normal_bls(nodes);
        wtr1.write_record(&[
            &format!("{}", nodes),
            &format!("{:.4}", mean_single_sign_creation_g1),
            &format!("{:.4}", mean_single_sign_creation_g2),
            &format!("{:.4}", mean_single_sign_verify_g1),
            &format!("{:.4}", mean_single_sign_verify_g2),
            &format!("{:.4}", n_sign_verify_g1),
            &format!("{:.4}", n_sign_verify_g2),
        ])
        .unwrap()
    }

    //bls threshold signs
    for nodes in nodes_info {
        println!("\n ####### nodes : {} #######", nodes);

        println!("\n ####### threshold bls ####### \n");
        let (
            mean_single_sign_creation_g1,
            mean_single_sign_creation_g2,
            mean_single_sign_verify_g1,
            mean_single_sign_verify_g2,
            n_sign_verify_g1,
            n_sign_verify_g2,
            creation_threshold_sign_g1,
            creation_threshold_sign_g2,
            verify_threshold_sign_g1,
            verify_threshold_sign_g2,
        ) = benchmark_threshold_bls(nodes);
        wtr2.write_record(&[
            &format!("{}", nodes),
            &format!("{:.4}", mean_single_sign_creation_g1),
            &format!("{:.4}", mean_single_sign_creation_g2),
            &format!("{:.4}", mean_single_sign_verify_g1),
            &format!("{:.4}", mean_single_sign_verify_g2),
            &format!("{:.4}", n_sign_verify_g1),
            &format!("{:.4}", n_sign_verify_g2),
            &format!("{:.4}", creation_threshold_sign_g1),
            &format!("{:.4}", creation_threshold_sign_g2),
            &format!("{:.4}", verify_threshold_sign_g1),
            &format!("{:.4}", verify_threshold_sign_g2),
        ])
        .unwrap()
    }

    //bls multisig aggregation
    for nodes in nodes_info {
        println!("\n ####### nodes : {} ####### \n", nodes);

        println!("\n ####### multisig aggregation bls ####### \n");
        let (
            mean_single_sign_creation_g1,
            mean_single_sign_creation_g2,
            mean_single_sign_verify_g1,
            mean_single_sign_verify_g2,
            n_sign_verify_g1,
            n_sign_verify_g2,
            creation_agg_pubkey_g1,
            creation_agg_pubkey_g2,
            creation_agg_sign_g1,
            creation_agg_sign_g2,
            verify_agg_sign_g1,
            verify_agg_sign_g2,
        ) = benchmark_multisig_bls(nodes);
        wtr3.write_record(&[
            &format!("{}", nodes),
            &format!("{:.4}", mean_single_sign_creation_g1),
            &format!("{:.4}", mean_single_sign_creation_g2),
            &format!("{:.4}", mean_single_sign_verify_g1),
            &format!("{:.4}", mean_single_sign_verify_g2),
            &format!("{:.4}", n_sign_verify_g1),
            &format!("{:.4}", n_sign_verify_g2),
            &format!("{:.4}", creation_agg_pubkey_g1),
            &format!("{:.4}", creation_agg_pubkey_g2),
            &format!("{:.4}", creation_agg_sign_g1),
            &format!("{:.4}", creation_agg_sign_g2),
            &format!("{:.4}", verify_agg_sign_g1),
            &format!("{:.4}", verify_agg_sign_g2),
        ])
        .unwrap();
    }

    for nodes in nodes_info {
        println!("\n ####### nodes : {} ####### \n", nodes);

        println!("\n ####### multisig aggregation bls (with nizk) ####### \n");
        let (
            mean_single_sign_creation_g1,
            mean_single_sign_verify_g1,
            n_sign_verify_g1,
            creation_agg_pubkey_g2,
            creation_agg_sign_g1,
            verify_agg_sign_g1,
        ) = benchmark_nizk_multisig_bls(nodes);
        wtr4.write_record(&[
            &format!("{}", nodes),
            &format!("{:.4}", mean_single_sign_creation_g1),
            &format!("{:.4}", mean_single_sign_verify_g1),
            &format!("{:.4}", n_sign_verify_g1),
            &format!("{:.4}", creation_agg_pubkey_g2),
            &format!("{:.4}", creation_agg_sign_g1),
            &format!("{:.4}", verify_agg_sign_g1),
        ])
        .unwrap();
    }
}
