#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(unused)]

#![deny(unsafe_code)]

use std::env::{args_os, current_dir, var};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use serde::Deserialize;
use users::User;


/// Name of the PAM config file specified in `/etc/pam.d`.
static PAM_NAME: &str = "minisudo";

/// Path to the configuration file.
static CONFIG_PATH: &str = "/etc/minisudo-rules.toml";


fn main() {

    // Load rules from the config file
    let config = Config::load_from_file();

    // Put together the command to run
    let args = args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("Usage: minisudo <COMMAND>");
        exit(2);
    }

    // Look up the full path of the program in the first argument.
    // We need this to check against the path given in the config file,
    // and also because exec requires the full path, not just the name.
    let binary = lookup_binary(&args[0]);

    // Make sure the rules say it’s OK for this user to run this program
    let user = current_user().expect("No current user");
    let username = user.name().to_str().expect("Non-UTF8 username");
    if ! config.test(&user, &binary) {
        eprintln!("minisudo: User {:?} is not allowed to run {}.", username, binary.display());
        eprintln!("This incident will be reported.");  // not really
        exit(1);
    }

    // Have the user enter a password
    let message = format!("Password for {}: ", username);
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


/// Looks up the current user by their ID.
fn current_user() -> Option<User> {
    users::get_user_by_uid(users::get_current_uid())
}


/// Turns the binary the user is trying to run, which could be a
/// basename like `ls`, an absolute path such as `/usr/bin/ls`, or a
/// relative path such as `./ls`, into an absolute path.
fn lookup_binary(binary_basename: &OsStr) -> PathBuf {
    let input_path = PathBuf::from(binary_basename);

    // If the path is absolute, we already have the full path.
    if input_path.is_absolute() {
        return input_path;
    }

    // If the path is relative and has more than one component, then
    // create the full path relative to where we are now.
    if input_path.components().count() > 1 {
        let mut path = current_dir().expect("No current directory");
        path.push(input_path);
        return path;
    }

    // Otherwise, search through every directory in the `PATH`
    // environment variable to find the absolute path of the binary.
    // This variable is user-controlled, so be very careful about which
    // files are deemed acceptable.
    for pathlet in var("PATH").expect("no $PATH").split(':') {
        let mut potential_path = PathBuf::from(pathlet);
        potential_path.push(binary_basename);

        if potential_path.exists()
        && potential_path.metadata().map_or(false, |m| m.permissions().mode() & 0o111 != 0)
        {
            return potential_path;
        }
    }

    // If the code above can’t find one, then there is no such program.
    eprintln!("minisudo: No such command {}", input_path.display());
    exit(1);
}


/// The root type for the config file.
#[derive(PartialEq, Debug, Deserialize)]
struct Config {
    #[serde(rename = "rule")]
    rules: Vec<Rule>,
}

/// One of the rules specified in the config file.
#[derive(PartialEq, Debug, Deserialize)]
struct Rule {
    #[serde(flatten)]
    matcher: Matcher,
    program: String,
}

/// The specification for which user or group this rule applies to.
#[derive(PartialEq, Debug, Deserialize)]
#[serde(untagged)]
enum Matcher {
    UserByName { user: String },
    GroupByName { group: String },
}

impl Config {

    /// Load all the rules from the config file.
    fn load_from_file() -> Self {
        let file = fs::read_to_string(CONFIG_PATH).expect("No rules");
        toml::from_str(&file).expect("Bad parse")
    }

    /// Tests whether the rule lets the user run the program.
    fn test(&self, user: &User, program: &Path) -> bool {
        self.rules.iter()
            .any(|r| r.matcher.test(user) && (r.program == "*" || &*r.program == program.as_os_str()))
    }
}

impl Matcher {

    /// Tests whether this matcher is for the given user.
    fn test(&self, user: &User) -> bool {
        match self {
            Self::UserByName { user: username } => {
                user.name() == &**username
            }
            Self::GroupByName { group: groupname } => {
                user.groups().iter().flatten().any(|g| g.name() == &**groupname)
            }
        }
    }
}
