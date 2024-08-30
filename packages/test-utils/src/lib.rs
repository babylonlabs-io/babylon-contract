use babylon_bitcoin::{deserialize, BlockHash, BlockHeader};
use babylon_proto::babylon::btclightclient::v1::{BtcHeaderInfo, QueryMainChainResponse};
use babylon_proto::babylon::btcstaking::v1::{BtcDelegation, Params as BtcStakingParams};
use babylon_proto::babylon::zoneconcierge::v1::BtcTimestamp;
use cargo_metadata::MetadataCommand;
use prost::bytes::Bytes;
use prost::Message;
use serde::{Deserialize, Serialize};

use babylon_proto::babylon::finality::v1::{MsgAddFinalitySig, MsgCommitPubRandList};
use std::collections::HashMap;
use std::path::PathBuf;
use std::{env, fs};

const BTC_LC_MAIN: &str = "btc_light_client.dat";
const BTC_LC_FORK: &str = "btc_light_client_fork.dat";
const BTC_LC_FORK_MSG: &str = "btc_light_client_fork_msg.json";

const BTC_TIMESTAMP: &str = "btc_timestamp.dat";
const BTC_TIMESTAMP_HEADER0: &str = "btc_timestamp_header0.dat";
const BTC_TIMESTAMP_HEADER1: &str = "btc_timestamp_header1.dat";

const PARAMS_DATA: &str = "btcstaking_params.dat";
const BTC_DELEGATION_DATA: &str = "btc_delegation.dat";
const COMMIT_PUB_RAND_DATA: &str = "commit_pub_rand_msg.dat";
const PUB_RAND_VALUE: &str = "pub_rand_value.dat";
const ADD_FINALITY_SIG_DATA: &str = "add_finality_sig_{}_msg.dat";

const EOTS_DATA: &str = "eots_testdata.json";

fn find_workspace_root() -> PathBuf {
    // Get the current working directory
    let cwd = env::current_dir().unwrap();

    // Use cargo_metadata to find the root manifest for the workspace
    let mut metadata_cmd = MetadataCommand::new();
    let metadata = metadata_cmd.current_dir(cwd).no_deps().exec().unwrap();
    metadata.workspace_root.into_std_path_buf()
}

fn find_testdata_path() -> PathBuf {
    find_workspace_root()
        .join("packages")
        .join("test-utils")
        .join("testdata")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EotsTestData {
    pub sk: String,
    pub pk: String,
    pub sr: String,
    pub pr: String,
    pub msg1: String,
    pub msg2: String,
    pub sig1: String,
    pub sig2: String,
}

pub fn get_eots_testdata() -> EotsTestData {
    let file_path = find_testdata_path().join(EOTS_DATA);
    let testdata_bytes: &[u8] = &fs::read(file_path).unwrap();
    let testdata: EotsTestData = serde_json::from_slice(testdata_bytes).unwrap();

    testdata
}

pub fn get_btc_lc_mainchain_resp() -> QueryMainChainResponse {
    let file_path = find_testdata_path().join(BTC_LC_MAIN);

    let testdata: &[u8] = &fs::read(file_path).unwrap();
    QueryMainChainResponse::decode(testdata).unwrap()
}

pub fn get_btc_lc_headers() -> Vec<BtcHeaderInfo> {
    let resp = get_btc_lc_mainchain_resp();
    resp.headers
        .iter()
        .map(|h| BtcHeaderInfo {
            header: Bytes::from(hex::decode(&h.header_hex).unwrap()),
            // FIXME: Use BlockHash / Hash helper / encapsulation to reverse the hash under the hood
            hash: Bytes::from(
                hex::decode(&h.hash_hex)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>(),
            ),
            height: h.height,
            work: { Bytes::from(h.work.clone()) },
        })
        .collect()
}

pub fn get_btc_lc_fork_headers() -> Vec<BtcHeaderInfo> {
    let file_path = find_testdata_path().join(BTC_LC_FORK);
    let testdata: &[u8] = &fs::read(file_path).unwrap();
    let resp = QueryMainChainResponse::decode(testdata).unwrap();
    resp.headers
        .iter()
        .map(|h| BtcHeaderInfo {
            header: Bytes::from(hex::decode(&h.header_hex).unwrap()),
            // FIXME: Use BlockHash / Hash helper / encapsulation to reverse the hash under the hood
            hash: Bytes::from(
                hex::decode(&h.hash_hex)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>(),
            ),
            height: h.height,
            work: { Bytes::from(h.work.clone()) },
        })
        .collect()
}

pub fn get_btc_lc_fork_msg() -> Vec<u8> {
    let file_path = find_testdata_path().join(BTC_LC_FORK_MSG);
    let testdata: &[u8] = &fs::read(file_path).unwrap();
    testdata.to_vec()
}

pub fn get_btc_timestamp_and_headers() -> (BtcTimestamp, HashMap<BlockHash, BlockHeader>) {
    let mut header_map: HashMap<BlockHash, BlockHeader> = HashMap::new();

    let header0_path = find_testdata_path().join(BTC_TIMESTAMP_HEADER0);
    let header0_bytes: &[u8] = &fs::read(header0_path).unwrap();
    let header0: BlockHeader = deserialize(header0_bytes).unwrap();
    header_map.insert(header0.block_hash(), header0);

    let header1_path = find_testdata_path().join(BTC_TIMESTAMP_HEADER1);
    let header1_bytes: &[u8] = &fs::read(header1_path).unwrap();
    let header1: BlockHeader = deserialize(header1_bytes).unwrap();
    header_map.insert(header1.block_hash(), header1);

    let ts_path = find_testdata_path().join(BTC_TIMESTAMP);
    let testdata: &[u8] = &fs::read(ts_path).unwrap();
    let btc_ts = BtcTimestamp::decode(testdata).unwrap();

    (btc_ts, header_map)
}

pub fn get_params() -> BtcStakingParams {
    let params_path = find_testdata_path().join(PARAMS_DATA);
    let params_data: &[u8] = &fs::read(params_path).unwrap();
    BtcStakingParams::decode(params_data).unwrap()
}

pub fn get_btc_delegation() -> BtcDelegation {
    let btc_del_path = find_testdata_path().join(BTC_DELEGATION_DATA);
    let btc_del_data: &[u8] = &fs::read(btc_del_path).unwrap();
    BtcDelegation::decode(btc_del_data).unwrap()
}

pub fn get_pub_rand_commit() -> MsgCommitPubRandList {
    let pub_rand_commit_path = find_testdata_path().join(COMMIT_PUB_RAND_DATA);
    let pub_rand_commit_data: &[u8] = &fs::read(pub_rand_commit_path).unwrap();

    MsgCommitPubRandList::decode(pub_rand_commit_data).unwrap()
}

/// Get public randomness value (at index 1)
//  TODO: Support indexed public randomness values
pub fn get_pub_rand_value() -> Vec<u8> {
    let pub_rand_value_path = find_testdata_path().join(PUB_RAND_VALUE);
    let pub_rand_value_data: Vec<u8> = fs::read(pub_rand_value_path).unwrap();

    pub_rand_value_data
}

pub fn get_add_finality_sig() -> MsgAddFinalitySig {
    let add_finality_sig_path = find_testdata_path().join(ADD_FINALITY_SIG_DATA.replace("{}", "1"));
    let add_finality_sig_data: &[u8] = &fs::read(add_finality_sig_path).unwrap();

    MsgAddFinalitySig::decode(add_finality_sig_data).unwrap()
}

pub fn get_add_finality_sig_2() -> MsgAddFinalitySig {
    let add_finality_sig_path = find_testdata_path().join(ADD_FINALITY_SIG_DATA.replace("{}", "2"));
    let add_finality_sig_data: &[u8] = &fs::read(add_finality_sig_path).unwrap();

    MsgAddFinalitySig::decode(add_finality_sig_data).unwrap()
}
