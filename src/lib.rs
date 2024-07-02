pub mod crypto;
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use crypto::crypto::CertConfig;
    use std::{env, str::FromStr};
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::panic;
    use tokio::runtime::Runtime;
    use openssl::x509::{X509VerifyResult, X509};
    #[tokio::test]
    async fn test_token_generator() {
        let key = "randomkey".to_string();
        let crypto_op = crypto::crypto::CryptoOp::default();
        let payload = serde_json::json!(
            {
                "username":"user"
            });
        let payload = serde_json::to_string(&payload).expect("json error");
        println!("trimmed payload is: {payload}");
        let token_string = crypto_op.generate_token(&key, payload.clone()).await.expect("token generation error");
        println!("Token string is: {token_string}");
        let decoded_payload = crypto_op.verify_token(&key,token_string).await.expect("token verification error");
        assert_eq!(payload, decoded_payload);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_bad_token() {
        let key = "randomkey".to_string();
        let crypto_op = crypto::crypto::CryptoOp::default();
        let payload = serde_json::json!(
            {
                "username":"user"
            });
        let payload = serde_json::to_string(&payload).expect("json error");
        println!("trimmed payload is: {payload}");
        let token_string = crypto_op.generate_token(&key, payload.clone()).await.expect("token generation error");
        println!("Token string is: {token_string}");
        let tampered_token = token_string+"a";
        let decoded_payload = crypto_op.verify_token(&key,tampered_token).await.expect("token verification error");
        assert_eq!(payload, decoded_payload);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_bad_key() {
        let key = "randomkey".to_string();
        let crypto_op = crypto::crypto::CryptoOp::default();
        let payload = serde_json::json!(
            {
                "username":"user"
            });
        let payload = serde_json::to_string(&payload).expect("json error");
        println!("trimmed payload is: {payload}");
        let token_string = crypto_op.generate_token(&key, payload.clone()).await.expect("token generation error");
        println!("Token string is: {token_string}");
        let mut tampered_key = String::from_str(&key).unwrap();
        tampered_key.push_str("a");
        let decoded_payload = crypto_op.verify_token(&tampered_key,token_string).await.expect("token verification error");
        assert_eq!(payload, decoded_payload);
    }

    #[tokio::test]
    async fn test_hash_generator() {
        let expected=String::from("uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek");
        let crypto_op = crypto::crypto::CryptoOp::default();
        let payload = String::from("hello world");
        let hash_string = crypto_op.generate_hash(payload).await.expect("hash generation error");
        println!("Hash string is: {hash_string}");
        assert_eq!(expected,hash_string);
    }

    #[tokio::test]
    async fn test_x509() {
        let save_path=String::from("/home/rillo/workspace/personal/rust/cert-generator-app/libraries/crypto-lib/scripts/");
        dotenvy::from_path(".env").expect("dot env error");
        let ca_path = env::var("ROOT_CA_PATH").expect("env variable error");
        let key_path = env::var("SERVER_KEY_PATH").expect("env variable error");
        let host_url = env::var("HOST_CN").expect("env variable error");
        let mut ca_file = File::open(ca_path).expect("read failure");
        let mut ca_buf = Vec::new();
        ca_file.read_to_end(&mut ca_buf).expect("read error");
        let mut key_file = File::open(key_path).expect("read failure");
        let mut key_buf = Vec::new();
        key_file.read_to_end(&mut key_buf).expect("read error");
        let new_config = CertConfig::new(host_url, ca_buf.clone(), key_buf);   


        let crypto_op = crypto::crypto::CryptoOp::default();
        let client_credential = crypto_op.generate_rsa_x509(&new_config).await.expect("x509 error");
        let client_cert_string = String::from_utf8_lossy(client_credential.get_cert());
        let client_key_string = String::from_utf8_lossy(client_credential.get_key());
        println!("client cert is: {:?}",client_cert_string);
        println!("client key is: {:?}",client_key_string);
        let client_cert_path = std::path::Path::new(&save_path).join("client.cert");
        let client_cert_key = std::path::Path::new(&save_path).join("client.key");
        std::fs::write(client_cert_path,client_credential.get_cert()).expect("file IO error");
        std::fs::write(client_cert_key,client_credential.get_key()).expect("file IO error");
        // Verify that this cert was issued by this ca
        let ca_cert = X509::from_pem(&ca_buf).expect("ca conversion error");
        let client_buf = client_credential.get_cert();
        let client_cert = X509::from_pem(&client_buf).expect("cclient cert conversion error");
        match ca_cert.issued(&client_cert) {
            X509VerifyResult::OK => println!("Certificate verified!"),
            ver_err => {
                panic!("Failed to verify certificate: {}", ver_err);
            }
        };
    }
}
