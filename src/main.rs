#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(unused)]

#![deny(unsafe_code)]

use std::env::{var, args_os};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use serde::Deserialize;


/// Name of the PAM config file specified in `/etc/pam.d`.
static PAM_NAME: &str = "minisudo";

/// Path to the configuration file.
static CONFIG_PATH: &str = "/etc/minisudo-rules.toml";


fn main() {

    // Look up current user
    let user = users::get_user_by_uid(users::get_current_uid()).expect("No current user");
    let username = user.name().to_str().expect("Non-UTF8 username");

    // Load rules from the config file
    let config = Config::load_from_file();

    // Put together the command to run
    let args = args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("Usage: minisudo <COMMAND>");
        exit(2);
    }

    // Look up the full path of the program in the first argument.
    // We need this to check against the path given in the rules file,
    // and also because exec requires the full path, not just the name.
    let binary = match which(&args[0]) {
        Some(b) => {
            b
        }
        None => {
            eprintln!("minisudo: No such command {:?}", &args[0]);
            exit(1);
        }
    };

    // Make sure the rules say it’s OK for this user to run this program
    if ! config.test(username, &binary) {
        eprintln!("minisudo: User {} is not allowed to run {}.", username, binary.display());
        eprintln!("This incident will be reported.");  // not really
        exit(1);
    }

    // Have the user enter a password
    let message = format!("Password for {:?}: ", user.name());
    let password = rpassword::read_password_from_tty(Some(&message)).expect("No password");

    // Authenticate them using PAM
    let mut authenticator = pam::Authenticator::with_password(PAM_NAME).expect("No authenticator");
    authenticator.get_handler().set_credentials(username, password);
    if let Err(e) = authenticator.authenticate() {
        eprintln!("minisudo: Authentication failed: {}", e);
        exit(1);
    }

    // Run the command, stopping the current process if the new one
    // starts successfully, and continuing if there’s an error.
    authenticator.open_session().expect("No session");
    let error = Command::new(binary)
        .args(&args[1..])
        .exec();

    // If you get here the command didn’t work, so print the error.
    eprintln!("minisudo: Error running program: {}", error);
    exit(1);
}


/// Finds the binary with the given name that gets run, by searching the
/// `PATH` environment variable, returning None if no binary is found.
fn which(binary_basename: &OsStr) -> Option<PathBuf> {
    for pathlet in var("PATH").expect("no $PATH").split(':') {
        let mut potential_path = PathBuf::from(pathlet);
        potential_path.push(binary_basename);

        if potential_path.exists() {
            return Some(potential_path);
        }
    }

    None
}


/// The root type for the config file.
#[derive(PartialEq, Debug, Deserialize)]
struct Config {
    rule: Vec<Rule>,
}

/// One of the rules specified in the config file.
#[derive(PartialEq, Debug, Deserialize)]
struct Rule {
    user: String,
    program: String,
}

impl Config {

    /// Load all the rules from the config file.
    pub fn load_from_file() -> Self {
        let file = fs::read_to_string(CONFIG_PATH).expect("No rules");
        toml::from_str(&file).expect("Bad parse")
    }

    /// Tests whether the given user and program
    pub fn test(&self, user: &str, program: &Path) -> bool {
        self.rule.iter()
            .any(|r| r.user == user && (r.program == "*" || &*r.program == program.as_os_str()))
    }
}
