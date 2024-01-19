use std::{
    env,
    fs::{remove_dir_all, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use cargo_metadata::{Metadata, MetadataCommand};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use toml::Table;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    /// Name of the person to greet
    #[command(subcommand)]
    command: Commands,

    /// Configuration file to read. Defaults to .hax.toml
    #[arg(short, long)]
    config: Option<String>,

    /// Path to the manifest (Cargo.toml) to read, including the file name.
    #[arg(short, long)]
    manifest_path: Option<String>,

    /// The package to analyse.
    /// By default, everything from the used Cargo.toml is included.
    #[arg(short, long)]
    package: Option<String>,
}

impl Args {
    /// Get the [`Config`].
    fn config(&self) -> Config {
        let config_file = self.config.clone().unwrap_or(".hax.toml".to_string());
        read_config(&config_file)
    }

    /// Get the Cargo manifest
    fn cargo_metadata(&self) -> Metadata {
        MetadataCommand::new()
            .manifest_path(&self.cargo_manifest_path())
            .exec()
            .unwrap()
    }

    /// Get the Cargo manifest path
    fn cargo_manifest_path(&self) -> PathBuf {
        self.manifest_path
            .clone()
            .map(|p| Path::new(&p).to_owned())
            .unwrap_or(
                env::current_dir()
                    .unwrap()
                    .join("Cargo.toml")
                    .as_path()
                    .to_owned(),
            )
    }

    /// Get the directory of the package, specified in the arguments.
    /// If no package is specified, use the path of the Cargo.toml.
    fn target_directory(&self) -> PathBuf {
        let manifest = self.cargo_metadata();
        let target_dir = Path::new(&self.cargo_manifest_path())
            .parent()
            .unwrap()
            .to_owned();
        let target_dir = if let Some(package) = &self.package {
            manifest
                .packages
                .into_iter()
                .find(|p| &p.name == package)
                .and_then(|p| {
                    Some(
                        p.manifest_path
                            .parent()
                            .as_ref()
                            .unwrap()
                            .as_std_path()
                            .to_owned(),
                    )
                })
                .unwrap_or(target_dir)
        } else {
            target_dir
        };
        target_dir
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Hax extract
    Extract {
        /// The target to extract from the .hax.toml config
        target: Option<String>,
    },
    /// Verify the extracted code
    Verify {
        /// The backend to use for the verification. Currently only F* (fstar) is supported.
        backend: String,
        /// The target to extract from the .hax.toml config
        target: Option<String>,
    },
    /// Clean the target. Removes all proof related files
    Clean,
}

/// The config format
#[derive(Debug, Clone, Deserialize)]
struct Config {
    target: Vec<Target>,
}

impl Config {
    /// Get the target with the given `name`, or the first target we can find.
    fn target(&self, name: &str) -> Target {
        self.target
            .iter()
            .find(|c| &c.name == name)
            .unwrap()
            .clone()
        // .unwrap_or(default_target)
    }
}

/// A target
#[derive(Debug, Clone, Deserialize)]
struct Target {
    /// Name of the target library or binary.
    name: String,

    /// A hax include string to pass on the command line.
    include: Option<String>,

    /// F* version, or command to use for verification
    fstar: Option<Table>,

    /// Karamel version or command to use for C extraction
    krml: Option<Table>,

    /// Eurydice version or command to use for C extraction
    eurydice: Option<Table>,
}

/// Read the config file.
fn read_config(config_file: &str) -> Config {
    let mut file = match File::open(config_file) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {config_file}."),
    };
    let mut config = String::new();
    file.read_to_string(&mut config)
        .expect("Error reading file {config_file}");
    match toml::from_str(&config) {
        Ok(r) => r,
        Err(e) => {
            println!("{:?}", e);
            panic!("Error reading file {config_file}.")
        }
    }
}

/// Run extract command.
fn extract(args: &Args, target_name: &Option<String>) {
    let config = args.config();

    // Get the target to extract, if none is given, we take the first one we find.
    let default_target = config.target[0].clone();
    let target = if let Some(target) = &target_name {
        config
            .target
            .into_iter()
            .find(|c| &c.name == target)
            .unwrap_or(default_target)
    } else {
        default_target
    };

    let mut hax_cmd = vec!["hax"];
    if let Some(package_name) = &args.package {
        // This has to be the first cargo arg. It has the `-C`.
        hax_cmd.extend_from_slice(&["-C", "-p", package_name]);
        // Close cargo args
        // XXX: move behind others if needed
        hax_cmd.push(";");
    }
    hax_cmd.push("into");
    if let Some(s) = &target.include {
        hax_cmd.extend_from_slice(&["-i", s]);
    };
    hax_cmd.push("fstar");

    let status = Command::new("cargo")
        .args(hax_cmd)
        .status()
        .expect("failed to run cargo hax");
    assert!(status.success());
}

/// Remove the proof directory and clean up.
fn clean(args: &Args) {
    let target_dir = args.target_directory();
    let proof_dir = proof_dir(target_dir);
    let _ = remove_dir_all(proof_dir);
}

/// Proof directory in the crate root.
fn proof_dir(target_dir: PathBuf) -> PathBuf {
    let proof_dir = target_dir.join("proofs");
    proof_dir
}

/// Run verification
/// FIXME
fn verify(args: &Args, backend: &String, target: &Option<String>) {
    let config = args.config();
    let target = config.target("test-crate");
    let fstar_binary = target
        .fstar
        .map(|m| m.get("path").unwrap().as_str().unwrap().to_owned())
        .unwrap_or("fstar.exe".to_owned());

    let proofs_dir = proof_dir(args.target_directory())
        .join("fstar")
        .join("extraction");

    let path_env = env::var("PATH").unwrap();
    let envs = vec![("PATH", path_env + ";fstar_binary")];

    let status = Command::new("make")
        .current_dir(proofs_dir)
        .envs(envs)
        .status()
        .expect("failed to run make");
    assert!(status.success());
}

fn main() {
    // Get the command line arguments
    let args = Args::parse();

    // Run the command
    match &args.command {
        Commands::Extract { target } => extract(&args, target),
        Commands::Clean => clean(&args),
        Commands::Verify { backend, target } => verify(&args, backend, target),
    }
}
