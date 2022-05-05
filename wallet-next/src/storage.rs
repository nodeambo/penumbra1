use penumbra_chain::params::ChainParams;
use penumbra_crypto::{
    merkle::{NoteCommitmentTree, Tree},
    note::Commitment,
    FieldExt,
};
use penumbra_proto::{crypto::FullViewingKey, Message, Protobuf};
use sqlx::{query, Executor, Pool, Sqlite};

use crate::sync::ScanResult;

#[derive(Clone)]
pub struct Storage {
    pool: Pool<Sqlite>,
}

impl Storage {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn migrate(self: &Storage) -> anyhow::Result<()> {
        sqlx::migrate!().run(&self.pool).await.map_err(Into::into)
    }

    /// The last block height we've scanned to, if any.
    pub async fn last_sync_height(&self) -> anyhow::Result<Option<u64>> {
        let result = sqlx::query!(
            r#"
            SELECT height
            FROM sync_height
            ORDER BY height DESC
            LIMIT 1
        "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(result[0].height.map(|h| h as u64))
    }

    pub async fn chain_params(&self) -> anyhow::Result<ChainParams> {
        let result = query!(
            r#"
            SELECT bytes
            FROM chain_params
            LIMIT 1
        "#
        )
        .fetch_all(&self.pool)
        .await?;

        ChainParams::decode(result[0].bytes.as_ref().unwrap().as_slice())
    }

    pub async fn full_viewing_key(&self) -> anyhow::Result<FullViewingKey> {
        let result = query!(
            r#"
            SELECT bytes
            FROM full_viewing_key
            LIMIT 1
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(FullViewingKey::decode(
            result[0].bytes.as_ref().unwrap().as_slice(),
        )?)
    }

    pub async fn note_commitment_tree(&self) -> anyhow::Result<NoteCommitmentTree> {
        let result = query!(
            r#"
            SELECT bytes
            FROM note_commitment_tree
            LIMIT 1
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        //let nct_data = bincode::serialize(&result)?;

        Ok(bincode::deserialize(
            result[0].bytes.as_ref().unwrap().as_slice(),
        )?)
    }

    pub async fn record_block(
        &self,
        scan_result: ScanResult,
        nct: &mut NoteCommitmentTree,
    ) -> anyhow::Result<Self> {
        // Insert all new note records
        for note_record in scan_result.new_notes {
            let query = format!(
                r#"INSERT INTO notes (
                        note_commitment,
                        height_spent,
                        height_created,
                        diversifier,
                        amount,
                        asset_id,
                        transmission_key,
                        blinding_factor,
                        diversifier_index,
                        nullifier)
                    VALUES ({:?},NULL,{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?})"#,
                note_record.note_commitment.0.to_bytes(),
                //height_spent is NULL
                scan_result.height,
                note_record.note.diversifier().0,
                note_record.note.amount(),
                note_record.note.asset_id().to_bytes(),
                note_record.note.transmission_key().0,
                note_record.note.note_blinding().to_bytes(),
                note_record.diversifier_index.0,
                note_record.nullifier.to_bytes()
            );

            let _result = &self.pool.execute(&*query).await?;
        }

        // Update any rows of the table with matching nullifiers to have height_spent
        for nullifier in scan_result.spent_nullifiers {
            let height_spent = format!("{:?}", &scan_result.height);
            let nullifier = format!("{:?}", &nullifier.to_bytes());

            let result = query!(
                r#"UPDATE notes 
                SET height_spent = ?
                WHERE nullifier = ?
                RETURNING note_commitment"#,
                height_spent,
                nullifier
            )
            .fetch_all(&self.pool)
            .await?;

            //Forget spent note commitments from the NCT

            nct.remove_witness(&Commitment::try_from(result[0].note_commitment.as_slice())?);
        }

        // Update NCT table with current NCT state

        let query = format!(
            "UPDATE note_commitment_tree
            SET bytes = {:?}",
            bincode::serialize(nct)
        );

        let _result = &self.pool.execute(&*query).await?;

        Ok(self.to_owned())
    }
}
