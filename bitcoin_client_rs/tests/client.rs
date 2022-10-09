mod utils;
use std::str::FromStr;

use bitcoin::{hashes::hex::ToHex, util::bip32::DerivationPath};
use ledger_bitcoin_client::{async_client, client, wallet};

fn test_cases(path: &str) -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string(path).expect("Unable to read file");
    serde_json::from_str(&data).expect("Wrong tests data")
}

#[tokio::test]
async fn test_get_extended_pubkey() {
    for case in test_cases("./tests/data/get_extended_pubkey.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let derivation_path: DerivationPath = case
            .get("derivation_path")
            .map(|v| v.as_str().unwrap())
            .map(|s| DerivationPath::from_str(&s).unwrap())
            .unwrap();

        let display: bool = case
            .get("display")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let xpk_str: String = case
            .get("result")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let transport = utils::TransportReplayer::new(utils::RecordStore::new(&exchanges));
        let key = client::BitcoinClient::new(transport.clone())
            .get_extended_pubkey(&derivation_path, display)
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);

        let key = async_client::BitcoinClient::new(transport.clone())
            .get_extended_pubkey(&derivation_path, display)
            .await
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);
    }
}

#[tokio::test]
async fn test_register_wallet() {
    for case in test_cases("./tests/data/register_wallet.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let name: String = case
            .get("name")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let policy: String = case
            .get("policy")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys_str: Vec<String> = case
            .get("keys")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys: Vec<wallet::WalletPubKey> = keys_str
            .iter()
            .map(|s| wallet::WalletPubKey::from_str(s).unwrap())
            .collect();

        let hmac_result: String = case
            .get("hmac")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let version: usize = case
            .get("version")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let version = if version == 1 {
            wallet::Version::V1
        } else {
            wallet::Version::V2
        };

        let wallet = wallet::WalletPolicy::new(name, version, policy, keys);

        let transport = utils::TransportReplayer::new(utils::RecordStore::new(&exchanges));
        let (_id, hmac) = client::BitcoinClient::new(transport.clone())
            .register_wallet(&wallet)
            .unwrap();

        assert_eq!(hmac.to_hex(), hmac_result);

        let (_id, hmac) = async_client::BitcoinClient::new(transport.clone())
            .register_wallet(&wallet)
            .await
            .unwrap();

        assert_eq!(hmac.to_hex(), hmac_result);
    }
}
