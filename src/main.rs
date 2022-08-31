use data_encoding::HEXLOWER;
use ring::hmac::{Tag, HMAC_SHA256};
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::BufWriter,
    path::Path,
    sync::Arc,
    sync::mpsc::channel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use swc_common::{self, SourceMap};
use swc_ecma_visit::{noop_visit_type, Visit, VisitWith};
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax, TsConfig};
use threadpool::ThreadPool;
use walkdir::WalkDir;

const SIGNING_KEY: &str = "SIGNING_KEY";
const OUTPUT_FILE: &str = "signatures.json";
const GRAPHQL_SUFFIX: &str = ".graphql.ts";
const CONCRETE_REQUEST: &str = "ConcreteRequest";

#[derive(Debug, Clone, Copy)]
enum Strategy {
    Manual,
    Swc,
}

impl From<String> for Strategy {
    fn from(s: String) -> Self {
        match &*s {
            "swc" | "SWC" | "Swc" => Self::Swc,
            _ => Self::Manual,
        }
    }
}

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

#[derive(Debug, Deserialize, Serialize, Default)]
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

fn compute_digest<P: AsRef<Path>>(filepath: P, key: ring::hmac::Key, strategy: Strategy) -> Result<Option<(Tag, String)>, Error> {
    let params = match strategy {
        Strategy::Swc => get_params_swc(filepath),
        Strategy::Manual => get_params(filepath),
    };
    let digest = match params? {
        Some(params) => {
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

fn get_params<P: AsRef<Path>>(filepath: P) -> Result<Option<Params>, Error> {
    let contents = std::fs::read_to_string(filepath)?;

    let params = match find_params(&contents) {
        Some(raw_params) => {
            let params: Params = serde_json::from_str(&raw_params).map_err(|_| Error::ParamSerialization)?;
            Some(params)
        }
        None => None
    };
    Ok(params)
}

#[derive(Default)]
struct MyCollector {
    params: bool,
    name: String,
    text: String,
    done: i32,
}
impl Visit for MyCollector {
    noop_visit_type!();

    fn visit_key_value_prop(&mut self, n: &swc_ecma_ast::KeyValueProp) {
        if self.done == 2 {
            return
        }
        match &n.key {
            swc_ecma_ast::PropName::Str(s) => {
                if self.params {
                    if s.raw.as_deref() == Some("\"name\"") {
                        match &*n.value {
                            swc_ecma_ast::Expr::Lit(swc_ecma_ast::Lit::Str(ss)) => {
                                //self.name = ss.value.as_deref().unwrap().trim_matches('"').to_owned();
                                self.name = ss.value.to_string();
                                self.done += 1;
                            }
                            _ => {}
                        }
                    }
                    if s.raw.as_deref() == Some("\"text\"") {
                        match &*n.value {
                            swc_ecma_ast::Expr::Lit(swc_ecma_ast::Lit::Str(ss)) => {
                                self.text = ss.value.to_string();
                                self.done += 1;
                            }
                            _ => {}
                        }
                    }
                } else if s.raw.as_deref() == Some("\"params\"") {
                    self.params = true;
                }
            }
            _ => println!("Unknown key {:?}", n.key),
        }
        n.visit_children_with(self);
    }
}

fn get_params_swc<P: AsRef<Path>>(filepath: P) -> Result<Option<Params>, Error> {
    let cm: Arc<SourceMap> = Default::default();
    let fm = cm.load_file(filepath.as_ref()).unwrap();
    let lexer = Lexer::new(
        Syntax::Typescript(TsConfig {
            no_early_errors: true,
            tsx: false,
            ..Default::default()
        }),
        Default::default(),
        StringInput::from(&*fm),
        None,
    );

    let mut parser = Parser::new_from(lexer);
    let module = parser.parse_typescript_module().unwrap();
    let mut visitor = MyCollector::default();
    module.visit_with(&mut visitor);
    if !visitor.params || visitor.done < 2 {
        return Ok(None);
    }
    Ok(Some(Params {
        name: visitor.name,
        text: visitor.text,
        ..Default::default()
    }
    ))
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

    let output_file = env::args().nth(3).unwrap_or(OUTPUT_FILE.to_string());
    let strategy: Strategy = env::args().nth(4).unwrap_or("swc".to_string()).into();

    for entry in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.path().is_dir() && is_graphql(e.path())) {
            let path = entry.path().to_owned();
            let tx = tx.clone();
            let key = key.clone();
            pool.execute(move || {
                let digest = compute_digest(path, key, strategy);
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


    let f = File::create(output_file).map_err(|_| Error::SignatureFileCreation)?;
    let writer = BufWriter::new(f);

    // The JS version uses tabs for pretty printing JSON for some reason
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(writer, formatter);
    signatures.serialize(&mut ser).map_err(|_| Error::SignatureSerialization)?;
    Ok(())
}
