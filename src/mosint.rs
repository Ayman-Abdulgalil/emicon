use std::process::Command;
use std::path::Path;
use std::fs;
use chrono::Utc;
use crate::shared::Ecerr;
use crate::shared::env_var_expand;

/// Runs a full `mosint` enumeration for the given email address and returns
/// the results as a JSON string.
///
/// # Details
/// - Assumes the `mosint` binary exists at:
///   - **Linux:** `/usr/bin/mosint`
///   - **Windows:** `C:\Program Files\mosint`
///
/// - Results are stored temporarily in:
///   - **Linux:** `/tmp/emicon/{email}-{UTC-timestamp}.json`
///   - **Windows:** `C:\Windows\Temp\emicon\{email}-{UTC-timestamp}.json`
///
/// - The temporary folder will be created if it does not exist.
/// - Returns the JSON content as a string on success.
/// - Returns [`Ecerr`] on failure (invalid syntax, missing mosint binary, or execution errors).
pub fn mosint(email: &str) -> Result<String, Ecerr> {
    // Generate unique timestamped output filename
    let now = Utc::now().format("%Y-%m-%d-%H-%M-%S");
    let binary_path: String;
    let config_path: String;
    let result_path: String;

    #[cfg(target_os = "linux")]
    {
        binary_path = "/usr/bin/mosint".to_string();
        config_path = env_var_expand("$HOME/.mosint.conf");
        result_path = format!("/tmp/emicon/{email}-{now}.json");
    }

    #[cfg(target_os = "windows")]
    {
        binary_path = "C:\\Program Files\\mosint".to_string();
        config_path = env_var_expand("%APPDATA%\\Emicon\\.mosint.json");
        result_path = format!("C:\\Windows\\Temp\\emicon\\{email}-{now}.json");
    }

    // Ensure parent directory exists
    if let Some(parent) = Path::new(&result_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let command = format!("{binary_path} -c {config_path} -o {result_path} {email}");

    // Run mosint inside shell to expand environment variables.
    let result = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|_| Ecerr::MosintExecutionFailed)?;

    if result.status.success() {
        // Read output JSON file back into a string
        let data = fs::read_to_string(&result_path)
            .map_err(|e| Ecerr::MosintFileReadError(e))?;
        
        // Validate it's valid JSON
        serde_json::from_str::<serde_json::Value>(&data)
            .map_err(|e| Ecerr::MosintParseError(e))?;

        Ok(data) // Return raw JSON string
    } else {
        let stdout_msg = String::from_utf8_lossy(&result.stdout);
        let stderr_msg = String::from_utf8_lossy(&result.stderr);

        if stdout_msg.contains("Email syntax is not valid") 
            || stderr_msg.contains("Email syntax is not valid") {
            return Err(Ecerr::MosintInvalidSyntax);
        }

        // Catch-all error for other execution failures
        Err(Ecerr::MosintExecutionFailed)
    }
}
