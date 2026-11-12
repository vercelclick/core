use crate::config::CONFIG_DIR;
use click_core::{InternalError, StatusCode, caller};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use time::{Duration, OffsetDateTime};

fn generate_certificates(cert_path: &PathBuf, key_path: &PathBuf) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(365);
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string().try_into().unwrap()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost".to_string());
    dn.push(DnType::OrganizationName, "Vercel Click");
    dn.push(DnType::OrganizationalUnitName, "Click Vault");

    params.distinguished_name = dn;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let mut cert_file = File::create(cert_path)
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error creating certificate pem file {}",
                    cert_path.display()
                ),
                err,
            )
        })
        .unwrap();
    cert_file.write_all(cert.pem().as_bytes()).unwrap();

    let mut key_file = File::create(key_path)
        .map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error creating certificate key file {}", key_path.display()),
                err,
            )
        })
        .unwrap();
    key_file
        .write_all(key_pair.serialize_pem().as_bytes())
        .unwrap();
}

pub fn get_certificates() -> (PathBuf, PathBuf) {
    let cert_path = CONFIG_DIR.join("cert.pem");
    let key_path = CONFIG_DIR.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        eprintln!("Generating local TLS certificates for secure communication...");
        generate_certificates(&cert_path, &key_path);
        eprintln!("Certificates generated successfully!");

        #[cfg(target_os = "macos")]
        {
            eprintln!("-------- FOR MACOS USERS --------");
            eprintln!(
                "Safari may reject connections using local certificates, use a different browser or run:"
            );
            eprintln!("\tclick install-certificates");
        }
    }

    (cert_path, key_path)
}

#[cfg(target_os = "macos")]
pub fn install_macos_certificates() {
    let (cert_path, _) = get_certificates();
    let cert_path = format!("{}", cert_path.display());

    let args = vec![
        "security",
        "add-trusted-cert",
        "-d",
        "-r",
        "trustRoot",
        "-k",
        "/Library/Keychains/System.keychain",
        &cert_path,
    ];

    let command = format!("sudo {}", args.join(" "));
    let error_message = format!(
        "Error executing command. You can run the command below directly:\n\t{}\nIf the issue persists, please raise a support ticker with support@secretpass.cloud",
        command
    );
    eprintln!("Requesting elevation to add certificate to macOS keychain...");
    let status = Command::new("sudo")
        .args(args)
        .status()
        .expect(&error_message);

    if status.success() {
        eprintln!("✅ Certificate successfully added and trusted by macOs/Safari!");
        eprintln!("Please restart Safari for the certificate to take effect.");
    } else {
        eprintln!("❌ Failed to add certificate, safari may reject connections to click cli");
        eprintln!("Try adding the certificate by running:");
        eprintln!("\t{}", command);
        eprintln!(
            "If the issue persists, please raise a support ticker with support@secretpass.cloud"
        );
    }
}
