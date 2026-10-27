use std::process::Command;

use chrono::Datelike;

fn main() {
    // A set APP_VERSION wins: the Docker build context has no `.git`.
    println!("cargo:rerun-if-env-changed=APP_VERSION");
    if let Some(version) = std::env::var("APP_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        println!("cargo:rustc-env=APP_VERSION={}", version.trim());
        return;
    }

    let count = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or_else(|| "0".to_string());

    let year = chrono::Utc::now().year();

    println!("cargo:rustc-env=APP_VERSION={year}.{count}");
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(git_root) = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
    {
        if git_root.status.success() {
            if let Ok(s) = String::from_utf8(git_root.stdout) {
                let dir = std::path::PathBuf::from(s.trim());
                let head = dir.join("HEAD");
                let refs = dir.join("refs/heads");
                if head.exists() {
                    println!("cargo:rerun-if-changed={}", head.display());
                }
                if refs.exists() {
                    println!("cargo:rerun-if-changed={}", refs.display());
                }
            }
        }
    }
}
