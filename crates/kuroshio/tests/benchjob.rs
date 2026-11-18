//! 每日評測的子程序（隱藏指令 __job-dns-benchmark）：實際執行 kuroshio 執行檔

use std::io::Write;
use std::process::{Command, Stdio};

fn run(input: &str) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!("kuroshio-benchchild-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_kuroshio"))
        .args(["__job-dns-benchmark", "--state"])
        .arg(&dir)
        .arg("--base")
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // 標準輸入要開著（關掉 = 主程式不見了，子程序會自己結束）
    let mut stdin = c.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    drop(stdin);
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}

#[test]
fn child_command_reports_errors_on_stderr_and_exit_code() {
    // 設定格式錯誤：結束碼 2
    let (code, _, err) = run("not json\n");
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("ERROR"), "{err}");
    // 沒有任何候選（清單目錄是空的）：評測失敗，結束碼 1，最後一行進度是 null
    let dir = std::env::temp_dir().join(format!("kuroshio-benchchild-lists-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = serde_json::json!({
        "system": { "persistDir": dir.join("state").to_string_lossy() },
        "benchmark": { "dir": dir.to_string_lossy() },
        "upstream": { "pinned": [] }
    });
    let (code, out, err) = run(&format!("{cfg}\n"));
    assert_eq!(code, 1, "out={out} err={err}");
    assert!(err.contains("ERROR"), "評測失敗的原因寫在標準錯誤：{err}");
    assert!(
        err.lines()
            .any(|l| l.trim_start().starts_with("INFO") || l.trim_start().starts_with("ERROR")),
        "{err}"
    );
    assert!(out.trim_end().ends_with("{\"progress\":null}"), "{out}");
}
