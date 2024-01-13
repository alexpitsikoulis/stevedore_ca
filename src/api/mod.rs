use std::str::FromStr;

use openssl::{
    x509::X509,
    nid::Nid,
};

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
use uuid::Uuid;

pub struct CertificateAuthorityHanlder {
    ca: crate::auth::CertificateAuthority,
}

#[tonic::async_trait]
impl CertificateAuthority for CertificateAuthorityHanlder {
    async fn sign_certificate(
        &self,
        request: Request<SignCertificateRequest>,
    ) -> Result<Response<SignCertificateResponse>, Status> {
        let id = Uuid::from_str(&request.into_inner().id).map_err(|e| {
            Status::invalid_argument(format!(
                "invalid client id provided, please provide valid UUID: {:?}",
                e
            ))
        })?;

        let (certificate, _) = self.ca.sign(id).map_err(|e| {
            Status::internal(format!(
                "failed to sign certificate for client '{}': {:?}",
                id, e
            ))
        })?;
        Ok(Response::new(SignCertificateResponse{certificate}))
    }

    async fn verify_certificate(
        &self,
        request: Request<VerifyCertificateRequest>,
    ) -> Result<Response<VerifyCertificateResponse>, Status> {
        let cert = X509::from_pem(&request.into_inner().certificate).map_err(|e| Status::internal(format!("failed to parse certificate: {:?}", e)))?;
        let ca_public_key = self.ca.public_key();

        match cert.verify(&ca_public_key) {
            Ok(_) => {
                for entry in cert.subject_name().entries_by_nid(Nid::SUBJECT_ALT_NAME) {
                    if let Ok(id) = entry.data().as_utf8() {
                        return Ok(Response::new(VerifyCertificateResponse{id: id.to_string()}))
                    };
                }
                Err(Status::unauthenticated("client certificate is missing id"))

            },
            Err(e) => Err(Status::unauthenticated(format!("client certificate is not valid for this service: {:?}", e))),
        }
    }
}
