use api::{CertificateAuthorityHanlder, CertificateAuthorityServer};
use auth::CertificateAuthority;
use tonic::transport::Server;

mod api;
mod auth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertificateAuthority::new()?;
    let addr = "127.0.0.1:50052".parse()?;
    let ca_handler = CertificateAuthorityHanlder::new(ca);

    Server::builder()
        .add_service(CertificateAuthorityServer::new(ca_handler))
        .serve(addr)
        .await?;

    Ok(())
}
