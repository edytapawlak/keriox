use keri::{database::lmdb::LmdbEventDatabase, error::Error, keri::Keri, signer::CryptoBox};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs::{create_dir_all, File};
use tempfile::Builder;

#[derive(Debug, Serialize, Deserialize)]
struct TestData {
    setup: Setup,
    input: Vec<String>,
    output: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Setup {
    prefix: String,
    secret_current: String,
    secret_nxt: String,
    icp_event: String,
}

fn setup_eve(setup: Setup, db: LmdbEventDatabase) -> Result<Keri<LmdbEventDatabase>, Error> {
    let key_manager = CryptoBox::derive_from_seed(&setup.secret_current, &setup.secret_nxt)?;
    let eve = Keri::new(db, key_manager, setup.prefix.parse()?)?;
    eve.process_events(setup.icp_event.as_bytes())?;
    Ok(eve)
}

#[test]
fn test_direct_mode_bob() -> Result<(), Error> {
    let file = File::open("./tests/test_vectors/bob_test.yaml").unwrap();
    let test_data: TestData = serde_yaml::from_reader(&file).unwrap();

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    create_dir_all(root.path()).unwrap();
    let eve_db = LmdbEventDatabase::new(root.path()).unwrap();

    let eve = setup_eve(test_data.setup, eve_db)?;

    for (event, expected) in test_data
        .input
        .into_iter()
        .zip(test_data.output.into_iter())
    {
        let response = eve.process_events(event.as_bytes())?;
        assert_eq!(response, expected);
    }

    Ok(())
}

#[test]
fn test_direct_mode_sam() -> Result<(), Error> {
    let file = File::open("./tests/test_vectors/sam_test.yaml").unwrap();

    let test_data: TestData = serde_yaml::from_reader(&file).unwrap();

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    create_dir_all(root.path()).unwrap();
    let eve_db = LmdbEventDatabase::new(root.path()).unwrap();

    let eve = setup_eve(test_data.setup, eve_db)?;

    for (event, expected) in test_data
        .input
        .into_iter()
        .zip(test_data.output.into_iter())
    {
        let response = eve.process_events(event.as_bytes())?;
        assert_eq!(response, expected);
    }

    Ok(())
}
