pub mod auto_steam {
    use std::io;
    use std::io::Write;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;
    use same_file::is_same_file;
    use sysinfo::{ProcessExt, System, SystemExt};
    use winapi::um::winreg::HKEY_CURRENT_USER;
    use winreg::RegKey;
    use crate::auto_steam::auto_steam::private_auto_steam::MyPrivateRegTraits;
    use crate::reg_watch;
    use crate::reg_watch::WatchResponse;

    pub struct MyRegVars {
        base_steam_reg: RegKey,
        apps_reg_key: RegKey,
        active_process_reg_key: RegKey,
        steam_path: String,
    }

    fn watch_reg(reg_key: &RegKey, timeout: u32) -> WatchResponse {
        let watch_timeout = match timeout {
            0 => { reg_watch::Timeout::Infinite }
            _ => { reg_watch::Timeout::Milli(timeout) }
        };
        return reg_watch::watch(
            &reg_key,
            reg_watch::filter::REG_NOTIFY_CHANGE_LAST_SET,
            false,
            watch_timeout,
        ).unwrap();
    }

    fn get_steam_path(base_steam_reg: &RegKey) -> String {
        let exe: String = base_steam_reg.get_value("SteamExe").unwrap();
        return exe;
    }

    pub mod private_auto_steam {
        use std::process::Command;
        use winreg::RegKey;

        pub(super) trait MyPrivateRegTraits {
            fn get_running_appid(&self) -> u32;
            fn get_steam_pid(&self) -> usize;
            fn get_app_running_value(&self, app_reg: &RegKey) -> u32;
            fn get_app_updating_value(&self, app_reg: &RegKey) -> u32;
            fn get_app_installed_value(&self, app_reg: &RegKey) -> u32;
            fn get_app_name_value(&self, app_reg: &RegKey) -> u32;
            fn create_new_command(&self) -> Command;
            fn handle_a_game_is_already_running(&self);
        }
    }

    impl private_auto_steam::MyPrivateRegTraits for MyRegVars {
        fn get_running_appid(&self) -> u32 {
            let running: u32 = self.base_steam_reg.get_value("RunningAppID").unwrap();
            return running;
        }

        fn get_steam_pid(&self) -> usize {
            let pid: u32 = self.active_process_reg_key.get_value("pid").unwrap();
            return pid as usize;
        }

        fn get_app_running_value(&self, app_reg: &RegKey) -> u32 {
            let running: u32 = app_reg.get_value("Running").unwrap();
            return running;
        }

        fn get_app_updating_value(&self, app_reg: &RegKey) -> u32 {
            let updating: u32 = app_reg.get_value("Updating").unwrap();
            return updating;
        }

        fn get_app_installed_value(&self, app_reg: &RegKey) -> u32 {
            let installed: u32 = app_reg.get_value("Installed").unwrap();
            return installed;
        }

        fn get_app_name_value(&self, app_reg: &RegKey) -> u32 {
            let name: u32 = app_reg.get_value("Name").unwrap();
            return name;
        }

        fn create_new_command(&self) -> Command {
            let mut command = Command::new(&self.steam_path);
            command.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            return command;
        }

        fn handle_a_game_is_already_running(&self) {
            if self.get_running_appid() == 0 { return; }

            println!("A Steam app is already running, please close it . . .");

            loop {
                watch_reg(&self.base_steam_reg, 100);
                if self.get_running_appid() == 0 {
                    println!("Steam app closed . . .");
                    return;
                }
            }
        }
    }

    pub trait MyRegTraits {
        fn wait_for_game_start(&self, app_id: &str) -> bool;
        fn wait_for_game_exit(&self, app_id: &str) -> ();
        fn list_installed_and_choose(&self) -> String;
        fn shut_down_steam(&self) -> Child;
        fn shutdown_steam_if_running(&self);
        fn start_steam_login(&self, user: &str, pass: &str, appid: &str) -> Child;
        fn start_steam(&self) -> Child;
        fn new() -> MyRegVars;
    }

    impl MyRegTraits for MyRegVars {
        fn wait_for_game_start(&self, appid: &str) -> bool {
            let app_reg_key = self.apps_reg_key
                .open_subkey(appid)
                .unwrap();

            if self.get_app_running_value(&app_reg_key) == 1 { return true; }

            let mut now = Instant::now();
            loop {
                watch_reg(&app_reg_key, 3000);
                if self.get_app_running_value(&app_reg_key) == 1 { return true; }
                if self.get_app_updating_value(&app_reg_key) == 1 {
                    now = Instant::now();
                    continue;
                }
                if now.elapsed().as_secs() > 60 { return false; }
            }
        }

        fn wait_for_game_exit(&self, appid: &str) -> () {
            let app_reg_key = self.apps_reg_key
                .open_subkey(appid)
                .unwrap();

            if self.get_app_running_value(&app_reg_key) == 0 { return; }

            loop {
                watch_reg(&app_reg_key, 0);
                if self.get_app_running_value(&app_reg_key) == 0 { return; }
            }
        }

        fn list_installed_and_choose(&self) -> String {
            let mut apps: Vec<[String; 2]> = Vec::new();
            for app in self.apps_reg_key.enum_keys() {
                let id = app.unwrap();
                let app_reg_key = self.apps_reg_key.open_subkey(&id).unwrap();
                let get_name = app_reg_key.get_value("Name");
                if get_name.is_err() || self.get_app_installed_value(&app_reg_key) == 0 {
                    continue;
                }
                let name = get_name.unwrap();
                apps.push([name, id]);
            }

            println!("Choose from one of the following installed games:");
            for (i, x) in apps.iter().enumerate() {
                println!("{}. {}", i + 1, x[0]);
            }

            let choice: usize;
            loop {
                let mut buffer = String::new();
                let stdin = io::stdin();
                print!("choice: ");
                io::stdout().flush().expect("stdout flush error");
                stdin.read_line(&mut buffer).unwrap();
                match buffer.trim().parse::<usize>() {
                    Ok(parsed_value) => {
                        if parsed_value > 0 && parsed_value <= apps.len() {
                            choice = parsed_value - 1;
                            break;
                        }
                        println!("Index out of bounds");
                    }
                    Err(_e) => {
                        println!("Bad input");
                    }
                }
            }

            return apps[choice][1].to_owned();
        }

        fn shut_down_steam(&self) -> Child {
            return self.create_new_command()
                .arg("-shutdown")
                .spawn()
                .expect("Something went wrong when shutting down steam.exe");
        }

        fn shutdown_steam_if_running(&self) {
            let steam_pid: usize = self.get_steam_pid();
            let mut s = System::new();
            let mut not_shut_down_yet = true;
            loop {
                s.refresh_process(steam_pid);
                if let Some(process) = s.process(steam_pid) {
                    if !is_same_file(process.exe(), &self.steam_path).unwrap_or(false) {
                        return;
                    }
                    self.handle_a_game_is_already_running();
                    if not_shut_down_yet {
                        self.shut_down_steam().wait().expect("failed to wait on child");
                        not_shut_down_yet = false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                return;
            }
        }

        fn start_steam_login(&self, user: &str, pass: &str, appid: &str) -> Child {
            return self.create_new_command()
                .args([
                    "-silent",
                    "-login",
                    user,
                    pass,
                    "-applaunch",
                    appid
                ])
                .spawn()
                .expect("Something went wrong when starting steam.exe");
        }

        fn start_steam(&self) -> Child {
            return self.create_new_command()
                .spawn()
                .expect("Something went wrong when starting steam.exe");
        }

        fn new() -> MyRegVars {
            let hklm: RegKey = RegKey::predef(HKEY_CURRENT_USER);
            let base_steam_reg: RegKey = hklm
                .open_subkey("Software\\Valve\\Steam").unwrap();
            let apps_reg_key: RegKey = base_steam_reg.open_subkey("Apps").unwrap();
            let active_process_reg_key: RegKey = base_steam_reg
                .open_subkey("ActiveProcess").unwrap();
            let steam_path = get_steam_path(&base_steam_reg);
            return MyRegVars {
                base_steam_reg,
                apps_reg_key,
                active_process_reg_key,
                steam_path,
            };
        }
    }
}
