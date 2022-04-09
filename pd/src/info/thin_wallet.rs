use penumbra_proto::{
    self as proto,
    chain::NoteSource,
    crypto::NoteCommitment,
    thin_wallet::{thin_wallet_server::ThinWallet, ValidatorStatusRequest},
};

use tonic::Status;
use tracing::instrument;

// We need to use the tracing-futures version of Instrument,
// because we want to instrument a Stream, and the Stream trait
// isn't in std, and the tracing::Instrument trait only works with
// (stable) std types.
//use tracing_futures::Instrument;

use crate::components::{app::View as _, shielded_pool::View as _, staking::View as _};
use crate::WriteOverlayExt;

use super::RpcOverlay;

#[tonic::async_trait]
impl<T: 'static + WriteOverlayExt> ThinWallet for RpcOverlay<T> {
    #[instrument(skip(self, request))]
    async fn transaction_by_note(
        &self,
        request: tonic::Request<NoteCommitment>,
    ) -> Result<tonic::Response<NoteSource>, Status> {
        let cm = request
            .into_inner()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid commitment"))?;
        let source = self
            .0
            .note_source(&cm)
            .await
            .map_err(|_| Status::unavailable("database error"))?
            .ok_or_else(|| Status::not_found("note commitment not found"))?;
        tracing::debug!(?cm, ?source);

        Ok(tonic::Response::new(source.into()))
    }

    #[instrument(skip(self, request))]
    async fn validator_status(
        &self,
        request: tonic::Request<ValidatorStatusRequest>,
    ) -> Result<tonic::Response<proto::stake::ValidatorStatus>, Status> {
        self.0.check_chain_id(&request.get_ref().chain_id).await?;

        let id = request
            .into_inner()
            .identity_key
            .ok_or_else(|| Status::invalid_argument("missing identity key"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid identity key"))?;

        let status = self
            .0
            .validator_status(&id)
            .await
            .map_err(|_| Status::unavailable("database error"))?
            .ok_or_else(|| Status::not_found("validator not found"))?;

        Ok(tonic::Response::new(status.into()))
    }

    #[instrument(skip(self, request))]
    async fn next_validator_rate(
        &self,
        request: tonic::Request<proto::stake::IdentityKey>,
    ) -> Result<tonic::Response<proto::stake::RateData>, Status> {
        let identity_key = request
            .into_inner()
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("invalid identity key"))?;

        let rate_data = self
            .0
            .next_validator_rate(&identity_key)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?
            .unwrap();

        Ok(tonic::Response::new(rate_data.into()))
    }
}