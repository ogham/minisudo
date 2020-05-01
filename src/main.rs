use std::env::args_os;
use std::fs;
use std::os::unix::process::CommandExt;
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

    // Look up the full path of the program in the first argument
    let binary = match which::which(&args[0]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("No such command {:?}: {}", &args[0], e);
            exit(1);
        },
    };

    // Make sure the rules say it’s OK for this user to run this program
    if ! config.test(username, binary.to_str().unwrap()) {
        eprintln!("User {} is not allowed to run {}", username, binary.display());
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
        eprintln!("Authentication failed: {}", e);
        exit(1);
    }

    // Run the command, stopping the current process if the new one
    // starts successfully, and continuing if there’s an error.
    authenticator.open_session().expect("No session");
    let error = Command::new(binary)
        .args(&args[1..])
        .exec();

    // If you get here the command didn’t work, so print the error.
    eprintln!("Error running program: {}", error);
    exit(1);
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
    pub fn test(&self, user: &str, program: &str) -> bool {
        self.rule.iter()
            .any(|r| r.user == user && (r.program == "*" || r.program == program))
    }
}
