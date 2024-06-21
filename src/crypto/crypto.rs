use openssl::hash::{MessageDigest,Hasher};
use openssl::sign::Signer;
use serde_json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::{pkey::PKey,rsa::Rsa,nid::Nid};
use openssl::ec::{EcGroup, EcKey};
use openssl::x509::{self, X509Name, X509Req, X509};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};

#[derive(Debug,Default)]
pub struct CryptoOp;

#[derive(Debug,Default)]
pub struct CertConfig{
    pub(crate) cn:String,
    pub(crate) root_ca: Vec<u8>,
    pub(crate) server_key: Vec<u8>
}

#[derive(Debug,Default)]
pub struct ClientCredential{
    client_key:Vec<u8>,
    client_cert:Vec<u8>
}

impl ClientCredential{
    pub fn new(client_key:Vec<u8>,client_cert:Vec<u8>)->Self{
        ClientCredential{
            client_key,
            client_cert
        }
    }
    pub fn get_key(&self)->&[u8]{
        &self.client_key
    }

    pub fn get_cert(&self)->&[u8]{
        &self.client_cert
    }
}

impl CertConfig {
    pub fn new(cn:String,root_ca: Vec<u8>,server_key: Vec<u8>)->Self{
        CertConfig{
            cn,
            root_ca,
            server_key
        }
    }
}

impl CryptoOp{
    pub async fn generate_token(&self,key_string:&str,payload:String)->Result<String, Box<dyn std::error::Error>>
    {
        let key = key_string.as_bytes();
        let json_header=String::from(
        r#"
                {
                "alg": "HS256",
                "typ": "JWT"
                }
        
        "#);
        let json_header: serde_json::Value = serde_json::from_str(&json_header).expect("json error");
        let json_header = serde_json::to_string(&json_header).expect("json error");
        println!("trimmed json_header is: {json_header}");
        let json_header_encoded = URL_SAFE_NO_PAD.encode(json_header.as_bytes());
        let payload_encoded = URL_SAFE_NO_PAD.encode(payload);
        println!("encoded payload is: {payload_encoded}");
        let pkey = openssl::pkey::PKey::hmac(key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        let full_payload= format!("{json_header_encoded}.{payload_encoded}");
        signer.update(full_payload.as_bytes())?;
        let signature = signer.sign_to_vec()?;
        println!("Signature byte: {:?}", signature);
        let signature_string = URL_SAFE_NO_PAD.encode(signature);
        println!("Signature string: {:?}", signature_string);
        let token = format!("{full_payload}.{signature_string}");
        Ok(token)

    }

    pub async fn generate_hash(&self,input:String)->Result<String, Box<dyn std::error::Error>>
    {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
    
        // Update the hasher with the input string bytes
        hasher.update(input.as_bytes())?;
        let hash_result = hasher.finish()?;
        println!("hash result is: {:?}",hash_result);
        let hash_encode=URL_SAFE_NO_PAD.encode(hash_result);
        Ok(hash_encode)
    }

    fn generate_private_key(&self)->Result<PKey<openssl::pkey::Private>,Box<dyn std::error::Error>>{
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa.clone())?;
        Ok(pkey)
    }

    fn generate_csr(&self,pkey:PKey<openssl::pkey::Private>)->Result<X509Req,Box<dyn std::error::Error>>{
        // Create the X509 name for the client
        let mut name = x509::X509NameBuilder::new()?;
        name.append_entry_by_text("C", "NG")?;
        name.append_entry_by_text("O", "BTGKS")?;
        name.append_entry_by_text("CN", "client")?;
        let name = name.build();

        // Build the CSR
        let mut req = x509::X509ReqBuilder::new()?;
        req.set_version(2)?;
        req.set_subject_name(&name)?;
        req.set_pubkey(&pkey)?;
        req.sign(&pkey, MessageDigest::sha256())?;
        let csr = req.build();
        Ok(csr)
    }

    pub async fn generate_rsa_x509(&self,config:&CertConfig)->Result<ClientCredential, Box<dyn std::error::Error>>{
        let pkey = self.generate_private_key()?;
        let x509_req = self.generate_csr(pkey.clone())?;

        // Load CA certificate and private key
        let ca_cert = X509::from_pem(&config.root_ca)?;
        let ca_key = PKey::private_key_from_pem(&config.server_key)?;

        // Sign CSR with CA key to create certificate
        let mut x509 = X509::builder()?;
        x509.set_version(2)?;
        x509.set_subject_name(x509_req.subject_name())?;
        x509.set_issuer_name(ca_cert.subject_name())?;
        //let pkey = x509_req.public_key()?;
        x509.set_pubkey(&pkey)?;

        // Set the validity period of the certificate (days)
        let valid_days = 358000;
        x509.set_not_before(&Asn1Time::days_from_now(0).unwrap())?;
        x509.set_not_after(&Asn1Time::days_from_now(valid_days).unwrap())?;
        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        x509
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        x509.sign(&ca_key, openssl::hash::MessageDigest::sha256())?;
        let x509 = x509.build();
        let priv_key = pkey.private_key_to_pem_pkcs8()?;
        let cert = x509.to_pem()?;
        let credential = ClientCredential::new(priv_key, cert);
        Ok(credential)
    }

    pub async fn generate_ecdsa_key_pair(&self,config:&CertConfig)->Result<ClientCredential, Box<dyn std::error::Error>>{
        // let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        // let ec_key = EcKey::generate(&group)?;
        // let pkey = PKey::from_ec_key(ec_key.clone())?;
        // // Create X509 Name
        // let mut x509_name = X509Name::builder()?;
        // x509_name.append_entry_by_text("CN", &config.cn)?;
        // let x509_name = x509_name.build();

        // // Create CSR
        // let mut x509_req = X509Req::builder()?;
        // x509_req.set_subject_name(&x509_name)?;
        // x509_req.set_pubkey(&pkey)?;
        // x509_req.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        // let x509_req = x509_req.build();

        // // Load CA certificate and private key
        // let ca_cert = X509::from_pem(&config.root_ca)?;
        // let ca_key = PKey::private_key_from_pem(&config.server_key)?;

        // // Sign CSR with CA key to create certificate
        // let mut x509 = X509::builder()?;
        // x509.set_subject_name(x509_req.subject_name())?;
        // x509.set_issuer_name(ca_cert.subject_name())?;
        // let pkey = x509_req.public_key()?;
        // x509.set_pubkey(&pkey)?;

        // // Set the validity period of the certificate (days)
        // let valid_days = 358000;
        // x509.set_not_before(&Asn1Time::days_from_now(0).unwrap())?;
        // x509.set_not_after(&Asn1Time::days_from_now(valid_days).unwrap())?;
        // let mut serial = BigNum::new().unwrap();
        // serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        // x509
        //     .set_serial_number(&serial.to_asn1_integer().unwrap())
        //     .unwrap();

        // x509.sign(&ca_key, openssl::hash::MessageDigest::sha256())?;
        // let x509 = x509.build();
        // let priv_key = ec_key.private_key_to_pem()?;
        // let cert = x509.to_pem()?;
        // let credential = ClientCredential::new(priv_key, cert);
        // Ok(credential)
        todo!()
    }
}
