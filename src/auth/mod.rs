use chrono::{DateTime, Utc};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req, X509};
use std::fmt::Display;
use uuid::Uuid;

#[derive(Debug)]
pub enum CAError {
    CertificateExpired,
}

impl Display for CAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for CAError {}

pub struct CertificateAuthority {
    private_key: PKey<Private>,
    public_key: PKey<Public>,
    cert: X509,
}

impl CertificateAuthority {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(ca) = Self::get() {
            return Ok(ca);
        };
        let rsa = Rsa::generate_with_e(4096, &BigNum::from_u32(65537u32).unwrap())?;
        let private_key = PKey::from_rsa(rsa.clone())?;
        let public_key = PKey::public_key_from_pem(&rsa.public_key_to_pem()?)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", "US")?;
        name_builder.append_entry_by_text("ST", "California")?;
        name_builder.append_entry_by_text("L", "Los Angeles")?;
        name_builder.append_entry_by_text("O", "Stevedore")?;
        name_builder.append_entry_by_text("CN", "Stevedore")?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&public_key)?;

        let serial_number = {
            let mut bn = BigNum::new()?;
            bn.rand(159, MsbOption::MAYBE_ZERO, false)?;
            bn.to_asn1_integer()?
        };
        builder.set_serial_number(&serial_number)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.sign(&private_key, MessageDigest::sha256())?;

        let cert = builder.build();

        let ca = CertificateAuthority {
            public_key: public_key.clone(),
            private_key: private_key.clone(),
            cert: cert.clone(),
        };

        let private_key = private_key.clone().private_key_to_pem_pkcs8()?;
        std::fs::write("ca_pkey.pem", &private_key)?;

        let public_key = public_key.public_key_to_pem()?;
        std::fs::write("ca_key.pem", &public_key)?;

        let cert = cert.to_pem()?;
        std::fs::write("ca_cert.prm", &cert)?;

        Ok(ca)
    }

    pub fn get() -> Result<Self, Box<dyn std::error::Error>> {
        let public_key = PKey::public_key_from_pem(std::fs::read("ca_key.pem")?.as_slice())?;
        let private_key = PKey::private_key_from_pem(std::fs::read("ca_pkey.pem")?.as_slice())?;
        let cert = X509::from_pem(std::fs::read("ca_cert.pem")?.as_slice())?;
        if Self::is_valid(&cert)? {
            Ok(CertificateAuthority {
                public_key,
                private_key,
                cert,
            })
        } else {
            Err(Box::new(CAError::CertificateExpired))
        }
    }

    fn is_valid(cert: &X509) -> Result<bool, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let not_before = DateTime::parse_from_rfc3339(&cert.not_before().to_string())?;
        let not_after = DateTime::parse_from_rfc3339(&cert.not_after().to_string())?;

        Ok(now >= not_before && now <= not_after)
    }

    pub fn sign(&self, id: Uuid) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let rsa = Rsa::generate_with_e(4096, &BigNum::from_u32(65537u32).unwrap())?;
        let private_key = PKey::from_rsa(rsa.clone())?;
        let public_key = PKey::public_key_from_pem(&rsa.public_key_to_pem()?)?;

        let mut csr_builder = X509Req::builder()?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", "US")?;
        name_builder.append_entry_by_text("ST", "California")?;
        name_builder.append_entry_by_text("L", "Los Angeles")?;
        name_builder.append_entry_by_text("O", "Stevedore")?;
        name_builder.append_entry_by_text("CN", "Stevedore")?;
        // name_builder.append_entry_by_text("SAN", &id.to_string())?;
        name_builder.append_entry_by_nid(Nid::SUBJECT_ALT_NAME, &id.to_string())?;
        let name = name_builder.build();

        csr_builder.set_subject_name(&name)?;
        csr_builder.set_pubkey(&public_key)?;
        let csr = csr_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(csr.subject_name())?;
        builder.set_issuer_name(self.cert.subject_name())?;
        builder.set_pubkey(&public_key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.sign(&self.private_key, MessageDigest::sha256())?;
        Ok((
            builder.build().to_pem()?,
            private_key.private_key_to_pem_pkcs8()?,
        ))
    }

    pub fn cert(&self) -> X509 {
        self.cert.clone()
    }

    pub fn public_key(&self) -> PKey<Public> {
        self.public_key.clone()
    }
}
