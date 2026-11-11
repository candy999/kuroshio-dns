//! Windows 服務（規格 07 第 1 節）：`kuroshio service install|uninstall|start|stop|status`
//!
//! 服務管理員呼叫 `kuroshio service-run -c <設定檔>`，跟 cmd 執行走同一個 `serve()`；
//! 服務「停止」與 Ctrl+C 一樣正常收尾（寫出快照）。日誌寫在設定檔旁的 kuroshio.log。

use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(not(windows))]
pub fn dispatch(_config: PathBuf) -> Result<()> {
    anyhow::bail!("只有 Windows 有服務模式；OpenWrt 用 /etc/init.d/kuroshio")
}

#[cfg(not(windows))]
pub fn control(_action: &str, _config: &Path) -> Result<()> {
    anyhow::bail!("只有 Windows 有服務模式；OpenWrt 用 /etc/init.d/kuroshio")
}

#[cfg(windows)]
pub use imp::{control, dispatch};

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::ffi::{OsStr, OsString};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const NAME: &str = "kuroshio";
    static CONFIG: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(config: PathBuf) -> Result<()> {
        let _ = CONFIG.set(config);
        service_dispatcher::start(NAME, ffi_service_main).context("只能由 Windows 服務管理員啟動（請用 kuroshio service start）")?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run() {
            let log = log_path(CONFIG.get().map(PathBuf::as_path).unwrap_or(Path::new(".")));
            let _ = std::fs::write(log.with_extension("error.log"), format!("{e:#}\n"));
        }
    }

    fn log_path(config: &Path) -> PathBuf {
        config.parent().unwrap_or(Path::new(".")).join("kuroshio.log")
    }

    fn status(state: ServiceState, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(if state == ServiceState::StopPending { 20 } else { 0 }),
            process_id: None,
        }
    }

    fn run() -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = Mutex::new(Some(tx));
        let handler = move |ev| match ev {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(t) = tx.lock().unwrap().take() {
                    let _ = t.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let h = service_control_handler::register(NAME, handler)?;
        h.set_service_status(status(ServiceState::Running, 0))?;
        let config = CONFIG.get().cloned().unwrap_or_else(|| PathBuf::from("config.json"));
        let threads = crate::thread_count(&config, false);
        let rt = crate::build_runtime(1)?;
        let r = rt.block_on(crate::serve(config.clone(), false, threads, Some(log_path(&config)), async {
            let _ = rx.await;
        }));
        h.set_service_status(status(ServiceState::Stopped, if r.is_ok() { 0 } else { 1 }))?;
        r
    }

    pub fn control(action: &str, config: &Path) -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .context("無法連到服務管理員（需要以系統管理員身分執行）")?;
        match action {
            "install" => {
                let exe = std::env::current_exe()?;
                let config = std::fs::canonicalize(config).unwrap_or_else(|_| config.to_path_buf());
                if let Some(dir) = config.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                if !config.exists() {
                    std::fs::write(&config, "{}\n")?;
                }
                let info = ServiceInfo {
                    name: OsString::from(NAME),
                    display_name: OsString::from("黑潮 DNS（Kuroshio DNS）"),
                    service_type: ServiceType::OWN_PROCESS,
                    start_type: ServiceStartType::AutoStart,
                    error_control: ServiceErrorControl::Normal,
                    executable_path: exe,
                    launch_arguments: vec![OsString::from("service-run"), OsString::from("-c"), config.clone().into_os_string()],
                    dependencies: vec![],
                    account_name: None,
                    account_password: None,
                };
                let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
                svc.set_description("把連線帶回台灣節點的 DNS 伺服器：區網 DNS、DoH / DoT / DoQ / DoH3、廣告過濾、CDN 台灣節點")?;
                // 當掉自動重啟（規格 09）：DNS 停了等於斷網，每次都 1 秒後立刻重啟、不放棄
                // （次數超過動作數時服務管理員重複最後一個動作）；程式自己以錯誤結束也算失敗
                svc.update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
                    reboot_msg: None,
                    command: None,
                    actions: Some(vec![
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: Duration::from_secs(1)
                        };
                        3
                    ]),
                })?;
                svc.set_failure_actions_on_non_crash_failures(true)?;
                println!("已安裝服務 {NAME}（開機自動啟動），設定檔：{}", config.display());
                println!("啟動：kuroshio service start；日誌：{}", log_path(&config).display());
            }
            "uninstall" => {
                let svc = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
                if svc.query_status()?.current_state != ServiceState::Stopped {
                    let _ = svc.stop();
                    std::thread::sleep(Duration::from_secs(3));
                }
                svc.delete()?;
                println!("已移除服務 {NAME}（設定與資料保留）");
            }
            "start" => {
                mgr.open_service(NAME, ServiceAccess::START)?.start(&[] as &[&OsStr])?;
                println!("已啟動");
            }
            "stop" => {
                mgr.open_service(NAME, ServiceAccess::STOP)?.stop()?;
                println!("已送出停止（會先寫出快照）");
            }
            "status" => {
                let s = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS)?.query_status()?;
                println!("{:?}", s.current_state);
            }
            other => bail!("不認識的動作 {other}（install / uninstall / start / stop / status）"),
        }
        Ok(())
    }
}
