use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509Req, X509,
    },
};
use std::sync::{Arc, Mutex};

pub mod certificate_authority {
    tonic::include_proto!("certificate_authority");
}

use certificate_authority::certificate_authority_server::CertificateAuthority;
pub use certificate_authority::certificate_authority_server::CertificateAuthorityServer;

use certificate_authority::{
    SignCertificateRequest, SignCertificateResponse, VerifyCertificateRequest,
    VerifyCertificateResponse,
};
use tonic::{Request, Response, Status};

use self::certificate_authority::{GetRootCertificateRequest, GetRootCertificateResponse};

pub struct CertificateAuthorityHanlder {
    ca: Arc<Mutex<crate::auth::CertificateAuthority>>,
}

impl CertificateAuthorityHanlder {
    pub fn new(ca: crate::auth::CertificateAuthority) -> Self {
        CertificateAuthorityHanlder {
            ca: Arc::new(Mutex::new(ca)),
        }
    }
}

#[tonic::async_trait]
impl CertificateAuthority for CertificateAuthorityHanlder {
    async fn get_root_certificate(
        &self,
        request: Request<GetRootCertificateRequest>,
    ) -> Result<Response<GetRootCertificateResponse>, Status> {
        let mut ca = match self.ca.lock() {
            Ok(ca) => ca,
            Err(e) => {
                return Err(Status::internal(format!(
                    "failed to lock ca mutex: {:?}",
                    e
                )))
            }
        };

        if ca
            .is_expired()
            .map_err(|e| Status::internal(format!("failed to check cert expiration: {:?}", e)))?
        {
            *ca = crate::auth::CertificateAuthority::new()
                .map_err(|e| Status::internal(format!("failed to generate CA: {:?}", e)))?;
        };

        let ca_cert_pem = ca.cert().to_pem().map_err(|e| {
            Status::internal(format!(
                "failed to convert root ca certificate to pem: {:?}",
                e
            ))
        })?;
        let mut certificate: Option<Vec<u8>> = Some(ca_cert_pem.clone());

        if let Some(provided_cert) = request.into_inner().certificate {
            if provided_cert == ca_cert_pem {
                certificate = None;
            }
        }

        Ok(Response::new(GetRootCertificateResponse { certificate }))
    }

    async fn sign_certificate(
        &self,
        request: Request<SignCertificateRequest>,
    ) -> Result<Response<SignCertificateResponse>, Status> {
        let csr = X509Req::from_pem(&request.into_inner().csr)
            .map_err(|e| Status::internal(format!("failed to parse CSR from pem: {:?}", e)))?;

        let ca = self.ca.lock().unwrap();

        let certificate = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut cert_builder = X509::builder()?;
            cert_builder.set_subject_name(csr.subject_name())?;
            cert_builder.set_issuer_name(ca.cert().subject_name())?;
            cert_builder.set_version(2)?;

            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(365)?;
            cert_builder.set_not_before(&not_before)?;
            cert_builder.set_not_after(&not_after)?;

            cert_builder.append_extension(
                SubjectAlternativeName::new()
                    .dns("localhost")
                    .dns("127.0.0.1")
                    .dns("127.0.1.1")
                    .build(&cert_builder.x509v3_context(Some(&ca.cert()), None))?,
            )?;
            cert_builder.append_extension(BasicConstraints::new().build()?)?;
            cert_builder.append_extension(
                KeyUsage::new()
                    .critical()
                    .non_repudiation()
                    .digital_signature()
                    .key_encipherment()
                    .build()?,
            )?;
            cert_builder.append_extension(
                SubjectKeyIdentifier::new()
                    .build(&cert_builder.x509v3_context(Some(&ca.cert()), None))?,
            )?;
            cert_builder.append_extension(
                AuthorityKeyIdentifier::new()
                    .keyid(false)
                    .issuer(false)
                    .build(&cert_builder.x509v3_context(Some(&ca.cert()), None))?,
            )?;

            cert_builder.set_pubkey(csr.public_key()?.as_ref())?;
            cert_builder.sign(&ca.private_key(), MessageDigest::sha256())?;
            Ok(cert_builder.build().to_pem()?)
        }()
        .map_err(|e| Status::internal(format!("failed to build certificate: {:?}", e)))?;

        Ok(Response::new(SignCertificateResponse { certificate }))
    }

    async fn verify_certificate(
        &self,
        request: Request<VerifyCertificateRequest>,
    ) -> Result<Response<VerifyCertificateResponse>, Status> {
        let cert = X509::from_pem(&request.into_inner().certificate)
            .map_err(|e| Status::internal(format!("failed to parse certificate: {:?}", e)))?;
        let ca = self.ca.lock().unwrap();

        match cert.verify(&ca.private_key()) {
            Ok(_) => {
                for entry in cert.subject_name().entries_by_nid(Nid::SUBJECT_ALT_NAME) {
                    if let Ok(id) = entry.data().as_utf8() {
                        return Ok(Response::new(VerifyCertificateResponse {
                            id: id.to_string(),
                        }));
                    };
                }
                Err(Status::unauthenticated("client certificate is missing id"))
            }
            Err(e) => Err(Status::unauthenticated(format!(
                "client certificate is not valid for this service: {:?}",
                e
            ))),
        }
    }
}
