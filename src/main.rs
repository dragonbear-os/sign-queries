use data_encoding::HEXLOWER;
use ring::hmac::{Tag, HMAC_SHA256};
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::BufWriter,
    path::Path,
    sync::mpsc::channel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use threadpool::ThreadPool;
use walkdir::WalkDir;

const SIGNING_KEY: &str = "SIGNING_KEY";
const OUTPUT_FILE: &str = "signatures.json";
const GRAPHQL_SUFFIX: &str = ".graphql.ts";
const CONCRETE_REQUEST: &str = "ConcreteRequest";

#[derive(Debug)]
enum Error {
    MissingDirectory,
    MissingSigningKey,
    IoError(std::io::Error),
    ParamSerialization,
    SignatureFileCreation,
    SignatureSerialization,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Params {
    #[serde(rename = "cacheID")]
    cache_id: String,
    id: Option<String>,
    metadata: Value,
    name: String,
    #[serde(rename = "operationKind")]
    operation_kind: String,
    text: String,
}

fn compute_digest<P: AsRef<Path>>(filepath: P, key: ring::hmac::Key) -> Result<Option<(Tag, String)>, Error> {
    let contents = std::fs::read_to_string(filepath)?;

    let digest = match find_params(&contents) {
        Some(raw_params) => {
            let params: Params = serde_json::from_str(&raw_params).map_err(|_| Error::ParamSerialization)?;
            let tag = ring::hmac::sign(&key, (&params.text).as_bytes());
            Some((tag, params.name))
        }
        None => None
    };

    Ok(digest)
}

fn is_graphql<P: AsRef<Path>>(filepath: P) -> bool {
    filepath
        .as_ref()
        .file_name()
        .map(|s| s.to_string_lossy().ends_with(GRAPHQL_SUFFIX))
        .unwrap_or(false)
}

fn find_params(contents: &String) -> Option<String> {
    let concrete = contents.find(CONCRETE_REQUEST)?;
    let rest = &contents[concrete..];
    let mut found_params = None;
    let mut params = Vec::new();
    for line in rest.lines() {
        if let Some(end) = found_params.as_ref() {
            params.push(line);
            if line.starts_with(end) {
                break;
            }
        }
        if line.trim().starts_with("\"params\": {") {
            let mut ws_count = 0;
            for c in line.chars() {
                if c.is_whitespace() {
                    ws_count += 1;
                } else {
                    break;
                }
            }
            // This makes a string that has the same leading whitespace as "params": {
            // but with a single } which is what we will be looking for as the closing brace
            // for the params object.
            found_params = Some(format!("{0: >1$}", '}', ws_count+1));
            // We insert a single opening brace which strips the "params": part
            params.push("{");
            continue;
        }
    }
    Some(params.join(""))
}

fn main() -> Result<(), Error> {
    let pool = ThreadPool::new(num_cpus::get());
    let (tx, rx) = channel();

    let dir = env::args().nth(1).ok_or(Error::MissingDirectory)?;
    println!("Doing {}", dir);

    let signing_key_arg = env::args().nth(2).ok_or(Error::MissingSigningKey);
    let signing_key = std::env::var(SIGNING_KEY).or(signing_key_arg)?;

    let key = ring::hmac::Key::new(HMAC_SHA256, signing_key.as_bytes());

    for entry in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.path().is_dir() && is_graphql(e.path())) {
            let path = entry.path().to_owned();
            let tx = tx.clone();
            let key = key.clone();
            pool.execute(move || {
                let digest = compute_digest(path, key);
                tx.send(digest).expect("Could not send data!");
            });
        }

    drop(tx);

    let mut signatures = BTreeMap::new();
    for t in rx.iter() {
        if let Some((sha, name)) = t? {
            let hash = HEXLOWER.encode(sha.as_ref());
            signatures.insert(name, hash);
        }
    }

    let f = File::create(OUTPUT_FILE).map_err(|_| Error::SignatureFileCreation)?;
    let writer = BufWriter::new(f);

    // The JS version uses tabs for pretty printing JSON for some reason
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(writer, formatter);
    signatures.serialize(&mut ser).map_err(|_| Error::SignatureSerialization)?;
    Ok(())
}
