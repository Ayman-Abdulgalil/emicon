use std::io;
use std::fmt;
use std::env;
use serde_json;



/// Application-wide error type to capture different operational errors.
#[derive(Debug)]
pub enum Ecerr {
    // NoInternet,
    MosintInvalidSyntax,
    MosintExecutionFailed,
    MosintFileReadError(io::Error),
    MosintParseError(serde_json::Error),
    Io(io::Error),
}

impl fmt::Display for Ecerr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Ecerr::NoInternet => write!(f, "No internet connection"),
            Ecerr::MosintInvalidSyntax => write!(f, "Invalid email syntax for Mosint"),
            Ecerr::MosintExecutionFailed => write!(f, "Mosint process failed"),
            Ecerr::MosintFileReadError(e) => write!(f, "Failed to read Mosint output: {}", e),
            Ecerr::MosintParseError(e) => write!(f, "Failed to parse Mosint JSON: {}", e),
            Ecerr::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for Ecerr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Ecerr::MosintFileReadError(e) => Some(e),
            Ecerr::MosintParseError(e) => Some(e),
            Ecerr::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Ecerr {
    fn from(error: io::Error) -> Self {
        Ecerr::Io(error)
    }
}

impl From<serde_json::Error> for Ecerr {
    fn from(error: serde_json::Error) -> Self {
        Ecerr::MosintParseError(error)
    }
}



#[cfg(target_os = "linux")] 
/// Expand environment variables in a string, in Unix and Windows.
pub fn env_var_expand(input: &str) -> String {
    let mut output = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(&next) = chars.peek() {
                if next == '{' {
                    // Parse ${VAR}
                    chars.next(); // consume '{'
                    let mut var_name = String::new();
                    while let Some(&ch) = chars.peek() {
                        if ch == '}' {
                            chars.next(); // consume '}'
                            break;
                        }
                        var_name.push(ch);
                        chars.next();
                    }
                    if let Ok(val) = env::var(&var_name) {
                        output.push_str(&val);
                    } else {
                        // If not found, keep original syntax
                        output.push_str(&format!("${{{}}}", var_name));
                    }
                } else {
                    // Parse $VAR
                    let mut var_name = String::new();

                    // According to POSIX, variable names are [A-Za-z0-9_] starting with letter or _
                    while let Some(&ch) = chars.peek() {
                        if ch.is_alphanumeric() || ch == '_' {
                            var_name.push(ch);
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if !var_name.is_empty() {
                        if let Ok(val) = env::var(&var_name) {
                            output.push_str(&val);
                        } else {
                            output.push('$');
                            output.push_str(&var_name);
                        }
                    } else {
                        // No valid var name, just output '$'
                        output.push('$');
                    }
                }
            } else {
                // '$' at end of string, just output it
                output.push('$');
            }
        } else {
            output.push(c);
        }
    }

    output
}

#[cfg(target_os = "windows")]
/// Expand environment variables in a string, in Unix and Windows.
pub fn env_var_expand(input: &str) -> String {
    let mut output = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let mut var_name = String::new();
            while let Some(&next_char) = chars.peek() {
                if next_char == '%' {
                    chars.next(); // consume the closing '%'
                    break;
                } else {
                    var_name.push(next_char);
                    chars.next();
                }
            }
            if let Ok(val) = env::var(&var_name) {
                output.push_str(&val);
            } else {
                // If env var not found, keep it as-is with percent signs
                output.push('%');
                output.push_str(&var_name);
                output.push('%');
            }
        } else {
            output.push(c);
        }
    }
    output
}

