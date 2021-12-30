extern crate failure;
extern crate uuid;
extern crate widestring;
extern crate winapi;
extern crate winreg;
extern crate clap;
extern crate sysinfo;

mod reg_watch;
mod auto_steam;

use clap::{App, Arg, crate_version, crate_name, crate_description, ArgMatches};
use crate::auto_steam::auto_steam::{MyRegTraits, MyRegVars};

fn get_args() -> ArgMatches {
    return App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(Arg::new("user")
            .required(true)
            .forbid_empty_values(true)
            .short('u')
            .long("user")
            .value_name("USERNAME")
            .help("Steam username")
            .takes_value(true))
        .arg(Arg::new("pass")
            .required(true)
            .forbid_empty_values(true)
            .short('p')
            .long("pass")
            .value_name("PASSWORD")
            .help("Steam password")
            .takes_value(true))
        .get_matches();
}

fn main() {
    let auto_steam = MyRegVars::new();
    let args = get_args();
    let user = args.value_of("user").unwrap().to_string();
    let pass = args.value_of("pass").unwrap().to_string();
    let appid = auto_steam.list_installed_and_choose();

    // I could shut down asynchronously, make choice and then await the async shutdown
    auto_steam.shutdown_steam_if_running();

    // todo: check if login successful, by registry attribute of CurrentUserID or something
    let mut main_child = auto_steam.start_steam_login(&user, &pass, &appid);

    if auto_steam.wait_for_game_start(&appid) {
        auto_steam.wait_for_game_exit(&appid);
        auto_steam.shut_down_steam()
            .wait()
            .expect("failed to wait on child");
        main_child.wait().expect("failed to wait on child");
        auto_steam.start_steam();
    } else {
        println!("wait_for_game_start was false");
        main_child.wait().expect("failed to wait on child");
    }
}