use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/cscpassist/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/cscpassist/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAC4jAAAuIwF4pT92AAAAB3RJTUUH6AcSCAgjGl7aiQAAJ1lJREFUeNrtnXl0ZFd95z/3vVf7oipJpV2t3tR7u3G7bePYBuN4GQIEApmEwwyZJGCHECYLmcmZcEJIyELInDOZhMWGAQIJhOQYsgxMgvECXmK7bRy37e62u1u9qLXvVSXVXu/d+eMtKm2lqlKp1O3426dsSVX17vL73t/93d/93d8VVIG3H/8UgACageuAW4FjwG4gBgQAbdnXJFCsppzXODTMPtwICsA0cAF4FngUOG79TX73xt+u+EEVVcQSvAL0A+8B3gEcAMIN7brXsRYWgNPAPwLfAs4DRiVEKEsAS/AA24B7gPcDfVvd2tdRFheBvwS+DIwClCPCmgSwhK8Bbwc+ARxh46rrdTQGEnNq+D3gIUBfiwSrCtQSfgD4DeC/AU1b3aLXURNmgE8Bnwcyq5FgBQEs4YeBPwB+GXBtdStex4aQA/4M+EMgtZwESwhQMvL/CPgIoG517esFsby1cq0PWW9LXksoAJ/GJEGulAROky3hq8BvAb/PVTryhTCFJ6VE1w0KRZ1isUihqFs/6+i6gW4YGIaBlKAoAiEEqqqgqSouTcXl0nC7NFyaiqqq1meuamJkMKfz+yhZKgpYYu2/A/gaEN3q2paDlBIhTO7aQikUdbK5PKl0loVUhlQ6RyabI18omkI3DKSUDjnWghAWGRSBqqq43Rpej5uAz0Mw4CPo9+LzunG5NBQhuMr4MA68F3gMzNVBqdOmG/gdrlDhlwpdEQLdkGRzeRLzaeKJBRLzKdLZPIVC0RG0qGDNIoRYQgjzuxLDWCRVIpkGYZarqSper4tw0E8kHCQSDuD3eVBVZdW6XmHoAH4X+FlMpxGiZPR/HPjkVtdwOUo7U0pJJptnLrHA1GyCRDJNNpfHkHLJ9L5Znb+UKObU4XZphII+WqNhWqJhAn4PqqJcyZrBAD4K/Dksum13Az+31TUrhS14RQgKuk4imWJ8Ks7MXJJMdqnQlQaNtlJimVOPJJcvkJ0tMD2bxON2EW0K0h6L0hIJ4XZrGyht06AAHwC+DQzbNXwXJgm2HLbghRDkC0WmZ5OMTswQT6Qo6HrDhV4Ojh3CIhnGpuaYnIkTCvjpbIvSHovg83q2uqrLcQjTwXe/hjnnv2Ora1Qq+EKhyMR0nOHxGZLzKXTDHO1XgtDXQikZDEOSmE+RmE8xPDZNV0cLnW3N+LzuJW3dyuoCPwV8Q8N08R7eqpqUCl43DKZnEgyOTBFPLGBYc+6VLPjVUGqzLKSznL0wwujELL1drXS2NeN2aUvavkW4FjikYW7pRraiBqUdkJhPcWloksmZOLpuLOnIqxVLiJDK8OrAMBNTcXb0ttPSHDaXkVtHghbgFg24ngZv8kirQFvdD49NMzgyRTaXX9JxrxWUEmE2Pk9yIU1Xews7etsc+2ALiKAAN2qYe/wNw5JRn0wxcGmM6bnkVqvDhsBuX7Goc3lkknhigV3bO2lraXL8EQ3ug/0a0Nao0uwGGobByMQsFwbHyGRfm6O+HGxhJxfSvPzqJfq629je04bLpTWaBJ0aEGxESXbD8vkC5y+PMzw6jW4Y/64EX4pSbXDh8jjzqQx7d3YT8HsbWY2QBrgb1eBUOsur54eZmkks6YR6Qm7ybk2962xrg8npONlsnn27e2iOhJy2bPIA0RrmqoonU7xybojEfMppeD1RKnhFUdZ9/ort4fWeb0hnQ6ne9V8+Jezd1UNHLNoQu6AhBJiZS3L63BCpdNZpcD1hC6UpFKCzvZmg34uirEMAy/dQYQEUdYP5VIaxyVmS8+m6C8Z+Viab5/TZyxSLOt0dLZtOgk0nwNRsgtNnh8hkc5uq8ttaI+zf3YvfZ81o68wE1U4UAog1h+mIRXl1YIiJ6fimCMZ2gb96fhjDkPR2tW4qCZSNP2JtTM8mOX328qYJ34bP62HPji78XjeGYe35U/5VLSRgSInf62b3ji7HrbsZEEJQLOqcvTDC0Oi0I/zNsG82jQBziQVOn7tMJpvfVOFLCdGmIAG/13QwbWJZwgoACfq9RJqCmxodJISgqOucvTjCyPiM87d6o64EsBk6v5Dm9LnLpDObO/LNTgG/z93Q5aQQgoDPU1HAyUbLsTXBxNTcppRRNwLYaiqTzfPKwDDzC5lNF4pNOEVRGurLFlaZZh02uSzHJhhhLrGwpN31QF0IYAu/WNQ5d3GE2fj85vbKvzOYAyvHqwPDjlatFwnqQgC7QpeGJxmbnHP+9lqGYdj+gMaVmZhPcfbCCMWiXjcS1G0KmJxJMDg88e9iU8eEbGjcn92nE9NxBkcm69bPGyKAzcB0JsfApVEKFjM3HXLzXb7rQzj1sF+bXmKJpp2ZM6fZjZa7IUeQvbN34fI48wuZTe+A0gYLRYBiLssMAUVTGouf28Q6CAFSSIRmeROlBKMxe/p2DMXApVGCAS9ej3tD5W7YEzgxFWdsctap3GbCiRRu9qC2eBEuU4FNuYvMZyaxo/LkJqjnpU8U5Jp0PHsiVkQoGKkC+kQGI9cYLRhPphgcmWLPjq4NlVcTAUqXfBeHJtD1xm3rKk1uXH1BRMlBjBwGOT3XkPIduEBxLZ6eU0IuhFulcDGJ1NcekaUqu9Y+s6eCkbFpYs1hmiOhmrVATQSwKzA0OkVyIV3Xfl0TVr8pIZcp/JKjPwKx9ZkLpFU3j4pMr54Rxxa+W7jQ0dFl7QPH9g9cHJogHPSjabWd462aADbTkgvpTXVRrmwxptFVlHYPLNYJubmT/lpVsutgBzmu028uobHP3ctOVydJI82J3Hlm9XknPrIWzMzNMzEdp7ujpSYtUDUBhBAYUjI0Ok0uX2j4ks+Yy2FE3SiBlYeXS2PzxRoSWcs+qNSadgI8S59inRLSZ3PIrL7qsz3CxTHvHva4e1GFQowIETXAk5lTTBbjUIPwbCP88ugUrc1hPO7qD3RXRQCbYYlEionpeNWFbRRCCIxskcL5JErYDZpAGpKf7n8jd28/gmKJXkGgiVWCQqSkIA0M5LJUAZKCoa+rRASgKSoKgn+5fIJvnT9urkYMiZHRMZJ5pLFUkFJKPIqLG7376Xd3A2BgIBC0qGFu8R3iifTLTOmJmkgAkJxPMzEVZ1t3rOrvVkUAe/QPj0+TLxS35MCGEAIjp2NMmctOQ0qu39/L+ztvBmk0phKKQmIswTeHH1khsOXCdwsXN3j3OcKXSEc7SaBFDXGL/xD/mjnJZLF6EjgG4fgM7bFI1VqgYkeQrSHn59NMzSQ2xeayHSq6YSVwkMaqqrk0msdM7KCCNNAb9MIwMDCWGKHLI4xM4Wtc791Dv2ul8J3PAa1qmFt9h+nQola8QvUGTXIh7cRaVuMcqpgAdtvGJufIF4p1nfullOjSQCJp8vjpb+7kQGsPPaEW3Kq2boO2egHAipnGFv5e9rp7rTgCuaZdYiBpVkPc7DtIqxqu2qC1tcDY5KyzT1ApqpoC0pkckzPxuvadlBJDSnZF23nf/lu5a8cRekMtuFUXz40N8CsPfYmRhZk1O2+rUDR0VjP/bWv/Ou+eioQPpgaRQLMa5qi3nx+mX6Qgqx9k8WSaeDJFrDlsHp+v4PsVEUBKUATO2fx6QUpT2b1157X88Zvex6HYNlOdAkPz09x34kFGF2bLdp5Ektcbn4k2U8yvyEJiC/+Ydw/73dsqEv7ytrSqTfgVD4kq22RHEE1Mz9ESDVVMnoqmACGgqBtMTMcrZlYlMKTkLdsO8vk77+GaWJ+p6qVkIhXnNx/9Gt+7eMJpnN3BSzZerOVXItcgZ5QFiVmmZGn2Ek2oHPX21yZ8aX42aaTIGrUNMoHpF6hmkFZsAyykMyTn03VTxIaUxPxhPn7TT7Mt3ErR0BEIZrIL/I/Hv8E/nHsWhWWGFaAqi1W2VefowpxpnDUIumEwtjDnTNVSShShcMSziwPuvpqErwjBgpHhhewAOVm7f8VOoWMmrVj/8xUTYGZunnyhfqrWkAZ37TjCjV39jkt0IZ/hY49/g6+fehxYuqTSDYODrb385vXvwOdyL+4KAgNzY6QK2brVbT2kCjkuJiYd8Upgm9bGIc92K3NYLcLP8lTmFKPFmZrrZTqGJNOzCXQpKwpWqYgAum4wG5+vW9StlBKXonJH3zV4VFeJShdEPAG8mmvJUkg3DPqbO/nMHR/gI0ffSl84VpI8QuHs3BiDiemG+CUUIRian+ZCfAJFKI4At7nacAnNUeWV9oMQgoSe5snMy1wuTFrdUHs7hDCNwWyF00BFBMhkc2aQZx070qd52B6OOQ2WUhJ0efj9W36WP73t52j3Rxx/QH+0k/vuvIdbe/bT5PGzLdzqEEQAk+kEjw2dMqeETQzMsIX7r8OvMpFe9IVIKSnIWrSjIGVkeSLzMkOFaacvNopcPk9yIV0fDSCE6Wqsp/oHK+eesriDZXsZ3arGvUfu4Mtv/TCHYr3sjLTz2Ts/wG3bDmJIA0UouBXN0Q9CCIqGzrfPPsNMdn7Tkjfa2i+eS/Hts8dNm8Vy/kjgYmGcjFF5wKZhSJqDAd5141G6W6MYdbJhhJVDMZ5YqMgGWHcZKCXE51MYhlz3vF01yOkFpjNLo4dLj0DdveMIPaFmFvJZbujsd1R+ppBnKpNcoo1UofDs2ADfGXienz90G9LQ6x6tKaREVVS+e/55nho5gypKjVGY0Of4t9w5bvDuQxNq2Z05KSWRgJ+fuekGrt3ex87OGB968Is8Nz6AyvoHW9etK5CYT1Ms6utuE6+rAYpF3Yrxr2t/kinmOTs3urLy1ogyDIMDLb3c2NVv7uBJiSoUzsfHGZgbRykVgBBkiwX+/Pn/x0B8HEVR6joVSClRFIVzc2P8r+e+Q6a49LSTTdwz+SFO5M47Ru1yl66dwdTt0njPG49xpG8bujR4Q9sO7r/7Xm7sNA3ietQ9nc2RzRfW/dy6BMjlC2Sy9Y220aXB4Vgfb+49sKRznA41exWJ6SW019u6NHjgzNNML9MAYE4pL08N8gdPfYtkLuMYaBuFvcSby6b4xJN/x4tTg6sam/YUdjJ3kZdzFzGkYS1TpfMcIQRpmeXJzEnOZIed9wyp84a2HXzx7g9xc/c+s80brHuhUCSdzq47cNU999zxe2u9KTBjz0bGZ+sS8CgxN3oOx/q4/657Odaxm6GZGTwuDU1dXW3af1OFwvcvvcgnn3qAdCG/Qgj2907PDFMwdH6sey9ua4VRa71t4c/nM/zuk3/L10+vXJ4ur4MhJVN6HE2oxNTIkkxgOaPAM9lXeCU7xNOjZ+kNt3KotRcQGNKgIxjlpq49nJoZ4lJiakOBIlJCKOinual8ApjyBBAwNZOsS0YP2+d/JNbHfXfdyxu79vDMuQG+/sRTzGeybI/FcK+Sr0JVVAwk37/0Ih999KtcTk4vcQatJoAfjZ8nnktzfccugm6fM4VUWn+HdIrKZDrBx5/4Jl9+6dGKvKBmHQwm9DmLBE1oQiVj5Hkue4bzhTGEgIV8lqdHz7C9qY39LT0gTN9IW6CJm7v3cWZ2lPPxiZpIYE5J4PO6iVkJqGoiAMDYxCzxZGpDBqC923dt+w6+cPcvcUNnP0+fO8e3jj9HPJVhLpVif08XzcEA6WLe2iOQpAo5Ts8M89nn/5lPPvUAg2WEX9p4XRr8aOI8p6YvsyvaQVew2UngvJ5xZgre/OzxsXN89Adf5Vtnnlni9q1EADYJsjJPWuY4kTvPpeLiwRlFCJK5DE+NnmFXtIO9zd0WCSSt/hC39OznQnzCsZOqJYEEXJpGZ1vUOce4GsquAgxDksltbPPHFv6xjl3cd9e9HG3fyfFzA3zrmeeYz2QJ+Ty889hRdsZiPDc2wB8+/W0AXIrGZDrBQHycqXQCEOsKv1QAUkr++cILvDQ1yPsPvpn3HbiV/mgHLkWzNAIlvgTzMgghFApGkTOz4/zN6Sf4q1OPMTI/i1JNNpGSOhSlzuncoKOZlo9mVVEYmZ/lVx/+CqpQeNuuoxiYjq/tTTE+d+cH8fzAxd+fPV59oAim/VYsGma8RG0EMMjnCzWvAGzhX9+xm/vvvpc3tO3g6XPn+PYzP2I+kyXo9fDuG45x895+Tkxe4lce/jI/GhsoCbQwPX2CdQQgl/8qFzt4YZY/Of4P/M0rT/KWbQe5fdthDrb2EvOH8WlmkodMMc9UOsmp6SF+cPkkj14+yeXklPOMWmGvBJx0uKt8RlUUhudn+NVHvoIiBG/dea1Dgu5QM3/x47+IR3Xxt688WbU9UyzqFIpFPJ61o4TE249/ak1zM5sr8NyLZ0mls9WrIGvOP9axa4nw7ZFvC/+WfXs4OTXEvQ/ez/Gxc6ii/Dq4IifLkhNCEgXFWlEYuFWNqCdIiy9I0G0mlVjIZ5nNLDCXWyCvF03SWWrc6ShERa7mWu0kc9S3cd9d93Dn9muclYCqKExn5vnYY9/ga6ceq5gEUko0VeW6a3YTLWMIltUAuq47eXurgT3yj7bv5L67TOE/O3B+xci/Zd8eTk4P8aHvf4FnxwbKCt9+pktREW4VvArCo4KmYLoEzNHmU1y8v+MmujwRJJLZ/AIPT58krecsH72p/otI5jC3kYVXEAkHiYogdvy5R3HxlpaDRF0BAMZzCb458SxZvWAzC3SJLBrIvIHM6ehFHWkY65J4NaiKwqXEJL/y0Jf43J0fNElgEaPFG+LTt70ft+riSy89Yi4xK3i+IaUVIbT2zmB5Ali++EoEbveJ/fuxjl18/s57ONq+g2fPX+CBZ54lmckQ8Hh41/XXLQr/wS/wzOhZZ9StJfgmj5839Rzgth2H+D/Jpxg04ivUs0QS0Pz8wpEf5w2hPkAymUswcybNRC5OpWkkJBBx+fno3nfQ62sFBCfmB/nOi2cpFtNLNnuklKBLXAXBu33XcGFslGfHB0gXclUTQVUULsQnVpDAkAYRT4A/ftP7cKkq95/4fkVJNqVFgHIobwPo5b1S9nuqouDzefB6XOiGQW+glc++5YMc69zN8xcu8sDTz5JIZ/B73Lzr+qPcum8vL04O8uGHvsjx0YE1ha9LA4/q4if6ruGXr72LW3v2k6LAN068AKn4qpIz7/sxkIaOgcQjNEKql7Eq5k9DGvgUD17hwrDiFAw7R+CyKDAhBFIDr8fLPdfcyb4b23ho8CW++OLDPDH8CnmjuMRtXA0J7r/rXm7vO+SQIOT28clb3osmVD77wr+sSwI7wLYmAggo65Gy/94cCdHXHSPSFMSlqeb6U3XzSOokYwMJnj5+nng6jc/t5p3HjvKm/ft4cerSou97FeHb9sP2pjZ+68Z38t59N9Pk8ZvJFPPZqrxkAdXDTn8bZ1NjFX9HAtt8LYQ1XyWHfszDoVJSMIo0eQP89N6buL3vMN985Un+7LnvcjExWdVKwiHBw1/i83few1u2HXRIEHR5+cTN/xEh4LP/9j1nU2ot2Iks1kJZapYVvhB0d7Rw5MAOOtqieNwuFEVBVRVyssATs6/ylclHGXHN4Hd7eOexa3nzgf0VC//Huvfyjbf/KvceuYOg20vR0CsKl5ZIitKwZ3tUoXBzdC8B1VMRcaSUuBWNm6N7rV3Hyshmu62RZsBoxOPnl6+9m2/+5K9z27aDzmqgUqiKwrnZMT70/S/y8KWXHAIZ0iDg8vCJm3+GX7vubWiKWva56+0y1rzGiYYD7NnZjcftWpIuxXyZp3N0l0GyO8Ut1+/mLQcP8FKFwv/xvsN85a0f5o1dexwtVLEXDzPMGkzL3UByKNTLHa2HnTLW/K7lgLoluo8bmnZbJ4gqnDYs4pn9IJx6H+vYzVfe+mHe1X+D44iqFKqicH5unA8/9CUeWkICiV/z8LGb3s3P7LsJoxy51imuLAHMTl8pJEUR9HbF8HoWfe25fIHhsRmGRqcXcwNKKLiKTATjvDB5sazwwTrl07mbv7jjF9kd7bRCrzfugnYJlZ/tvIm7YtegCdXZcSt92Tt4N0f38V+634SvNFKpooKWHuiw66wbOtvCrfzv23+B/7DjDVVv9JTaBI8MvrxkiRr2+HnPnpvwqGXW+ev03Zo2gMROurzyPY/bTbQpYIVFmyngT54ZZHrWvPihJRrimv07zGlBwuNTp/nLM49wYvxSGeEbdAWjfPrN/4l9zd3rzm2Vwh4xYc3HB3tvZ0+gi4enX+ZyZpqsUQBMld/piXJbywHuaDlMSPPWLfrZvgupO9TCn972nxmen+HlqcuoNawOPvLQl/nMHR/gju2HEZZheSkx6QyUtcovh7KrAFVRVnV+eNwaLmvjxoxBSznCB5iNLxBPpuiIRQBBspjh0sLUmoaQudev8l+v+wlu7dm/oXPza3WCYR3SvKv1Gm6K9DOSnWUqnzRP5biC9HhbiLr8TkrY+pdvxjf8zk3v4YPfu59UoTrnmmrFI9zz4H38xrG3c2vPfl6cGuQvnv9nJ1JqNSjqRgigKiiqYt49XQJ7NWT+snhWrzSVuqII50P2Bsta0KXBj3Xv5ecP3WY9f3OSMJvVlQQ1L/uD3eyn23nfsBR4NZs+y59fblRLq51v23UdP7XnBr528odoorqkDrbb+Ld++HXCHh+pQtbxXK5Vp9Kwu9VQ1gawb9Nejlw+T86KNpFApClIRyyCaq0COtuiRMJBhySFQtH5/IqOkRKv5uaD19xBm7+p7qNvLRjIJS+n02oMfVURuMTa40lYbfVpbn7pyJ20ByJLXNaVQhEKhjSIZ82LNJUyPgYhhBkSVqaYdTWAS1uNAEWmZxMEretNXJrK/v5tdHe0AIKmkJmyxDYY5xIp50awFYKQBkdifdy940jFLs4rEaaFX37JZW9VX9u+g7u2H+GvTz2GUqUWsJ9TCVRFweVSyy4ElPUe4PG4lviRF/MDTbOQyjjMdmkqrdEwrdGQI3w7kdTl0SkMY/VoHxD8xK6jxPzhukTz1nq8uh4lV1KqlBKP6uKn+m/Ar1Xmm6gVmqY4ttpaWHcZ6PO4V7rChHn/zysDQ8ynso6hWJqLX1EE2VyeM+dHiFtJjldDk8fPm3sPOse8qsFqdwBIaa/HNzFF/SrlVgrbID3WsYsdkbaapoFK4XZpq2rwUpSlhxDg93mcUV6ag0diHhc7ceo8PV0xWqMh3G4XAsgXi8QTKS6PTpFIrn1HkCElveFW+qMdVhDlGh3uRNEozpwnzTdWEYw0N32EQJGrrDhq6EhRsnSVmCHiqz1TsTxhQpZfSUgkbf4mron1cXJ6iNrye5WHlOD1uMsGg8B65wKkSQBVVVZsC9tTwUI6y5nzw1x0abjdGgIzfVkuX1j3giWJZEdTG1FPYE3B2EevckaRs6kxXkwOEhIqO91NqCzfDQSXovLE7GkGUxNLlLJkMQlFtRAIxvNJOjQ/UcW9YldRAm5F5bGZ02SKWY6E+2hxBcuSwK1q7GvpRmGTMowKCFRwd1JZAkjM61hcmoaurzTiSo9G5/KFFZb+utuVQFcwikvV1njfSklXzPLXI4/z+OwrpPUcIaERckfWfO4TM6frbgUIoFMLlP3Mv86+wtNzZ9gX6OJD2+5kh7+trGHbHWxGXceXXwvsQRMMeMvGAkAFewFut4bPV/5+HNsPsPxVSac2efxrRtrYZ/2+M/k8D069SEbPO38r9xJWprB6viotV0rJyfkh/nbsKXJG+WPeIbdv0w60appqXqOzDrfWPRqmqSqhgJ/Z+MKmmFVe1eVE6iyHAGYKKZ6cfdU5cu1WNDyK6ftecfKm7rWTKzrQlNeyMwmYZM3LInmjiILCqwujTOWT9Hhb1px2NEXdtNQ3Po/buZi6HNYlgBAQCfsZGt2kq8vKPE8gmCssEC+mnMDQnf522q1wr1UTPtaJBg4l5co3Sulqm8WKVddT80NIJFkjz0Ixuwa1NxdSQjjkX3cFABUeDg0F/bhd2prevM1EQerOUkkAHtWNS1G3ZKVfDgLwqm4UIdDlYlxCo2E73yLhAIoi1p0CKooH8Hs9BAO+Lel0ZZmSvFL9hDUtLzepPW6XRiQcqF+KGFVVaI4EHX9A47EsMfRVgErCyF2KWvcpVWKqf59v/fkfqogIao6EKppTNhtbf1VMZRAI1HXG92bcoSyA1mgYrcIDLRUTIBTwEQr6699T1TSwjs+wtZndaVBfctmey0bD43HREg1V3FcVZwrVNJVYS5OZLKpBW7arwdggDQQQL2Z4JT3OSC6BRNLhDnMo0Emz5q/rBNPoPpJAc1MIv89b8XeqShUbaw4zOOxec2v3SobtHRvKzfGdmVOM5RMOmV5KjXIqPcY7Ww7T5W5cTEK926cqCu2xCKoiKm5DVToq4PfS2lyfbdtGQwhB2ijw0NwZRvJxwMwtpArTsz+ci/No/Bw5o/ZE2FvdL+Ggz7w/iMq1TxXp4k1GdbZFrQMgW93c6iAQjOUSDOfjKzKQ2mHsg9lZJgvzNS/N7NzHjcaibJpxu6q7BKaKdPFmt0TCQYdldap9ReVuFAKY13NlnTN5qbNg7TdcbQj4vbS3Rqr+XlVTgHnkWKGnsxVNrVMmrnUEXI+0aWCq54DqXrGFXAqXUPApri1X5VW1y5JBd3szXq+76u9XRQA7hVtLJERLdGO2gF1xbb2lUp0Go0TS6Q7T4Q6tWElIaQaGdnsitLtDV42zyUYo6KOzvbmm71a9UJVSoqoK27pjuDdiC1ijel1/eR1lEVQ93B7ZQ7MWQJfmlTSGFSTS7gpxe1O/qQGuEvvGnvvNU1rVj34wl4EVHYC1Yavj5qYQ7bEow2PTNfkF7F2y6XSy7AFGnfokTsQqb7cvxntjRzmRGmYyvwACut1NvCHYQ8wVrFtC7Epg1MFobI4E6YxFa/6+BhSBqq6asnectve0MRufJ52pLZGkAE5MXiKeSxPx+FktlLOuGT+tmIJuTxNdniYK1pEql6I2dNtWSgkKzGUX0A295mdomsr23nZcLq1m51xNvkq7oGDAR193W8UJkpdDFQovTl6yjj8rmy4E27q39Y1LUXFZJ2caKXwzwbXBM6PnTBJWKbdFw6+F1mjYbFuNWmvDzurujhZiLU01fVcIQaqQ44+e+Xuen7jgOGVKYawZ+lE7tnKRp1hZTx+59BL/eO5ZJwtatQiH/GzvrX3wOfXZSGNsNbS7rxOft7ZDDqqicHLqMr/4L5/j7159imQuY+6kCQXhjM6rwyhbDkUIhGJ6G+2UsTOZeb568gd85OEvM56OVx0TaB/CKe3zhl8fb8MuOBzys3t7B6fPDdV0lbxJgiHu+d59HG3fybXtO2gPmClWZ1igoNQ2T24lssU8n3vhe4SlD0VRyOsFxlNxTk5d5uT0EDm9UFXuIFicPrZ1tzlad6MG64YIUIrOthbmFzJcGp6siZWqopAp5nl8+DSPD592Imxbm8McO9yPqjZ+a7Va2C0WQpArFvjqyz8knlxYcqhEsQJFqt0qtrVrrKWJ7T2Lqv+KIIC9KtjZ12ldLpmobWkohHNk2s5DtDzzxpWM0mygxaKBoRtm5G+dlpXhoJ+9O7s3ZPUvR12Glc1Gt0tj764emkKBujwTzNtKM5mc4zG+Gvz0QpiXbNZr21xKidfrZt/uHivWv37b1XXTqzYJAn4v+/t7nYpuFLl8gXOXxlhImdfC2VeqKlfYSxWK5V2UTM8muXB5YtUT0dXCHlj7dvbQHAk5fV0v1M0GKK1YJBzgQH8vJ89cJpPN1Vxhm1ST03FS6SzNkRBjgVnaPU2oqxypVOzMJJsIQ8o1c+/N5hcYSkwzM5ckl6/98kcb9iprz85uOtpMb19VbtsKUFcClKIlGubAnl5On728mDWsBtgkSKWzLKSzXGaKtd02jZoeyqRks+yAughfVenf0WUl3ticQ6SbalrHmps4uKcPv29jiRDss4aK3blr/qNBr9X/KVZSrXqN/P6dXWzritXN4l8Nm6YBbLQ2hzm0t49Xzg0xn8oAG70Z88o3AjcCe87v39lNT0fLpgofNlkD2GiOhDi8fzvRSNBp5OtYCjtE3ed1c2DPNno7Wzdd+NAgAoC5hr1m3w4625o37L9+rcHui3DIz+F92+mwtncbEX5vxwM0pJE+r5uDe7bh93kYHJm0LjN4bav0SvpFCEFbSxN7dnYT8C/G9DeibzQgA9QWTlIF7FGvaSq7t3cSCvg4d2mUVDrbsMZeSbBHvUvT6OuJ0dfThkurn4evQmQ0YAqobT+3SpTOaR1tUYIBLwODY0xOx0syjr/2iWALvynkZ9f2LmLN4YbM96tgRgPOALsbVWJpA4MBH4f39jESCXFpaIJ0Jrelx842G4ujXqWro4XtPe34rEjeLWr3eQ14FnjbVnWIqqps64rR3BTk0vAk41Nzzj03rxUilGZLa44E2dHbQUs0tGTUb1Fbn9eAJ4A5oPbIwhqxXBsc6N9Ge2uEwZFJZuMLGIax4nNXE0pXOqGgj96uGJ2xKC7r9M4Wa7sU8LgGnABeBt601Z2lKIJYSxPRpiCTMwmGx6aJJ1Pm5UhcPUQoFXzQ76Wro4WutsWDG1s86m2cBZ7TMEf//2WLCVCac1DTVLram4m1hJmeTTIyPks8sUBB15cEXVxJKL06T1UEoYCPzrZm2mORFdm6rpC6fw8YtV3B/wR8iAYag2uhlAguTaOrrZm2libiyRTjU3Fm5pJksnnnLt7S7zQay51ZbpdGtClIRyxKi5U69wrFOPAALO4FDAB/BXxyq2tmwxaqYRmKLdEwzZEQmWye2fg8U7NJEvMpcrnCEjKUfrfeKBW4HbDkcmmEAj5aomFizWGCAa9z+/gVjAeAl8DaP3378U8B9AD/ABzb6tqthuXJqnXDIJPNk5hPM5dYIDmfJpPNUSjqll+9/LnT1VPXr1G29R8hzIRZHreLUMBHtClIpClI0O81L2ZYpa5XIM4BPwm8+t0bf3vJbuAw8IfAV4HIVtdyOUo71JDmhVYBv5dgwEtXezOFQpFMLk8qlWU+nSGdzpHJ5skXzCvUdWPxpjBYeZZ/uQZRFGFduKDhcbvw+zwEA15CAR9+nxeP24WqrJ7i/goWfhb4NPDqinZbWkADPgZ8nAZsFW8G7OTIUkqKuk6xqJMvFCkUdAqFIgXrQmzDIYQdb2CSSlMVNE3D7VLNfPtWzn2l5AKtK1y9rwUJfA7470D2uzf+ttlfpZ+wSBAC/idw7/L3r2YsSfErl/xvaSNLPnOVCnot/D2moT9lCx+WbQdbb8xjaoEvYR4cfU3AvNNn8cYzufy9VT7zGsI/Ab+Gue+zBKuOcEsThIHfBH7d+vl1XH3IY67uPo659KN09EMZFW+RwIVpMX4cOLLVrXkdVWEQcyr/KpBaLngbZed4iwQA2zBtgvdbP7+OKxczmMv5z2C6+OVawocKjTyLCAqwB3g3plY4gGkwvo6tRxa4ADwI/B3wb0ChnOBtVGXlW0QQQAtwHfBm4HpMYsQAX4WPKrLSzlJpYIziVYByZ0CymHs4g8ALwGPA05i+HKMSwdv4/xqejk2f+cn1AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDI0LTA3LTE4VDAwOjEwOjAzKzA4OjAw22THBwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyNC0wNy0xOFQwMDowODozNSswODowMJU/0lYAAAAASUVORK5CYII=".into()
    }
}
