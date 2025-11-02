use log::{info, error};
use rcgen::{
    BasicConstraints,
    Certificate,
    CertificateParams,
    DistinguishedName,
    DnType,
    DnValue,
    IsCa,
    KeyIdMethod,
    KeyPair,
    KeyUsagePurpose,
    PKCS_ECDSA_P384_SHA384,
    SanType,
};
use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use time::{Duration, OffsetDateTime};

use crate::utils::fs::{get_app_dir, read_file, write_file};

// Reference: https://github.com/rustls/rcgen/issues/111
pub fn create_root_ca() {
    info!("Creating the root CA certificates...");

    let mut params = CertificateParams::default();

    params.alg = &PKCS_ECDSA_P384_SHA384;
    params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
    params.key_identifier_method = KeyIdMethod::Sha384;

    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::PrintableString("Root CA ECC".to_string()),
    );
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 10);

    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    
    let cert = Certificate::from_params(params).unwrap();

    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();

    let root_cert_path = "server/root_cert.pem";
    let root_cert_path_abs = format!("{}/{}", get_app_dir(), root_cert_path.to_string());
    let root_key_path = "server/root_key.pem";
    let root_key_path_abs = format!("{}/{}", get_app_dir(), root_key_path.to_string());
    
    match write_file(root_cert_path.to_string(), cert_pem.as_bytes()) {
        Ok(_) => {
            info!("{} created successfully.", root_cert_path_abs);
        }
        Err(e) => {
            error!("Could not create root_cert.pem: {}", e);
        }
    }

    match write_file(root_key_path.to_string(), key_pem.as_bytes()) {
        Ok(_) => {
            info!("{} created successfully.", root_key_path_abs);
        }
        Err(e) => {
            error!("Could not create root_cert.pem: {}", e);
        }
    }
}

pub fn read_root_ca() -> Result<Certificate, Error> {
    let cert_vec = read_file("server/root_cert.pem".to_string()).unwrap();
    let cert = String::from_utf8(cert_vec).unwrap();

    let key_vec = read_file("server/root_key.pem".to_string()).unwrap();
    let key = String::from_utf8(key_vec).unwrap();

    let key_pair = KeyPair::from_pem(key.as_str()).unwrap();

    let params = CertificateParams::from_ca_cert_pem(cert.as_str(), key_pair).unwrap();

    let ca_cert = Certificate::from_params(params).unwrap();

    Ok(ca_cert)
}

pub fn create_server_certs(listener_name: String, hosts: Vec<String>, ip: String) {
    let mut params = CertificateParams::default();

    params.alg = &PKCS_ECDSA_P384_SHA384;
    params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
    params.key_identifier_method = KeyIdMethod::Sha384;

    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::PrintableString("a.local".to_string()),
    );
    params.distinguished_name = dn;

    let dns_names: Vec<_> = hosts.iter().map(|n| SanType::DnsName(n.to_string())).collect();
    let addr: Ipv4Addr = ip.parse().unwrap();

    params.subject_alt_names = [vec![
        // SanType::DnsName("localhost".to_string()),
        SanType::IpAddress(IpAddr::V4(addr)),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1,))),
    ], dns_names].concat();

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 1);

    let cert = Certificate::from_params(params).unwrap();

    let root_ca = read_root_ca().unwrap();
    let cert_signed_pem = cert.serialize_pem_with_signer(&root_ca).unwrap();

    // Write to the files
    let cert_path = format!("server/listeners/{}/certs/cert.pem", listener_name.to_string());
    let cert_path_abs = format!("{}/{}", get_app_dir(), cert_path.to_string());
    let key_path = format!("server/listeners/{}/certs/key.pem", listener_name.to_string());
    let key_path_abs = format!("{}/{}", get_app_dir(), key_path.to_string());

    match write_file(
        cert_path.to_string(),
        cert_signed_pem.as_bytes()
    ) {
        Ok(_) => {
            info!("{} created successfully.", cert_path_abs.to_string());
        },
        Err(e) => {
            error!("Could not create cert.pem: {}", e);
        },
    }

    match write_file(
        key_path.to_string(),
        cert.serialize_private_key_pem().as_bytes()
    ) {
        Ok(_) => {
            info!("{} created successfully.", key_path_abs.to_string());
        },
        Err(e) => {
            error!("Could not create key.pem: {}", e);
        }
    }
}

// Create the client certificates.
// The certificates don't need to be saved as files.
// Instead of that, send the bytes data when generating the implant.
pub fn create_client_certs() -> (String, String) {
    let mut params = CertificateParams::default();

    params.alg = &PKCS_ECDSA_P384_SHA384;
    params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
    params.key_identifier_method = KeyIdMethod::Sha384;

    let dn = DistinguishedName::new();
    params.distinguished_name = dn;

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(364 * 1);

    let cert = Certificate::from_params(params).unwrap();

    let root_ca = read_root_ca().unwrap();
    let cert_signed_pem = cert.serialize_pem_with_signer(&root_ca).unwrap();

    let _cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();

    (cert_signed_pem, key_pem)
}

// pub fn read_server_certs(name: String) -> Result<(String, String), Error> {
//     let cert_path = format!("server/listeners/{}/certs/cert.pem", name.to_string());
//     let key_path = format!("server/listeners/{}/certs/key.pem", name.to_string());

//     let cert = match read_file(cert_path) {
//         Ok(b) => String::from_utf8(b).unwrap(),
//         Err(e) => {
//             return Err(Error::new(ErrorKind::Other, format!("{}", e)));
//         }
//     };

//     let key = match read_file(key_path) {
//         Ok(b) => String::from_utf8(b).unwrap(),
//         Err(e) => {
//             return Err(Error::new(ErrorKind::Other, format!("{}", e)));
//         }
//     };

//     Ok((cert, key))
// }