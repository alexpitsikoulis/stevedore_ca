use core::cmp::Ordering;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509};
use std::fmt::Display;

#[derive(Debug)]
pub enum CAError {
    _CertificateExpired,
}

impl Display for CAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CAError {}

pub struct CertificateAuthority {
    private_key: PKey<Private>,
    _public_key: PKey<Public>,
    cert: X509,
}

impl CertificateAuthority {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let rsa = Rsa::generate(4096)?;
        let private_key = PKey::from_rsa(rsa.clone())?;
        let public_key = PKey::from_rsa(Rsa::from_public_components(
            rsa.n().to_owned()?,
            rsa.e().to_owned()?,
        )?)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "US")?;
        name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, "California")?;
        name_builder.append_entry_by_nid(Nid::LOCALITYNAME, "Los Angeles")?;
        name_builder.append_entry_by_nid(Nid::ORG, "Stevedore")?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, "StevedoreCA")?;
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

        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;

        builder.sign(&private_key, MessageDigest::sha256())?;

        let cert = builder.build();

        let ca = CertificateAuthority {
            private_key: private_key.clone(),
            _public_key: public_key.clone(),
            cert: cert.clone(),
        };

        Ok(ca)
    }

    pub fn is_expired(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let now = Asn1Time::days_from_now(0)?;
        Ok(now.compare(self.cert().not_before())? != Ordering::Greater
            || now.compare(self.cert().not_after())? != Ordering::Less)
    }

    pub fn cert(&self) -> X509 {
        self.cert.clone()
    }

    pub fn private_key(&self) -> PKey<Private> {
        self.private_key.clone()
    }
}
