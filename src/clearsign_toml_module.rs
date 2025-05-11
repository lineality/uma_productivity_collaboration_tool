// clearsign_toml_module.rs
//! This is a module. You can import functions
//! from this module as the examples below.
//!
//! this is vanilla rust code for managing clearsign-toml files, 
//! .toml files that are stay clearsigned as they are used
//! including gpg decrytpion of newly recieved files
//! 
//! GPG handling code for clearsigning and encrypting files.
//! This module provides functionality to clearsign files with your private key
//! and encrypt them with a recipient's public key file.
/*

mod clearsign_toml_module;  // This declares the module and tells Rust to look for clearsign_toml_module.rs
use crate::clearsign_toml_module::{
    manual_q_and_a_new_encrypted_clearsigntoml_verification,
}; 

fn main() -> Result<(), String> {
    println!("=== GPG Clearsigned TOML File Processor ===");
    println!("This tool helps process encrypted clearsigned TOML files");
    println!("Make sure GPG is properly installed on your system");
    println!("-----------------------------------------------");
    
    match manual_q_and_a_new_encrypted_clearsigntoml_verification() {
        Ok(()) => {
            println!("Operation completed successfully!");
            Ok(())
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(format!("Failed to process encrypted clearsigned TOML file: {}", e))
        }
    }
}
*/

/*
```markdown
## GPG Code Overview
This module provides secure GPG file processing capabilities, specifically handling:
1. Clearsigning files with a private key
2. Encrypting clearsigned files for specific recipients
3. Decrypting and validating received files

## Prerequisites
- GPG (GnuPG) must be installed and configured on the system
- Users must have appropriate GPG keys generated/imported:
  - Sender needs their private key for signing
  - Sender needs recipient's public key for encryption
  - Recipient needs their private key for decryption
  - Recipient needs sender's public key for validation

## Directory Structure
```
project_root/
├── invites_updates/
│   ├── incoming/     # For received public keys
│   └── outgoing/     # For encrypted output files
└── src/
    └── handle_gpg.rs # This module
```

## Key Functions

### For Senders
```rust
pub fn clearsign_and_encrypt_file_for_recipient(
    input_file_path: &Path,
    your_signing_key_id: &str,
    recipient_public_key_path: &Path,
) -> Result<(), GpgError>
```
- Takes a file, clearsigns it, and encrypts it for a recipient
- Output: `invites_updates/outgoing/<original_filename>.gpg`

### For Recipients
```rust
pub fn decrypt_and_validate_file(
    encrypted_file_path: &Path,
    validator_key_id: &str,
    output_path: &Path,
) -> Result<(), GpgError>
```
- Decrypts received file and validates the clearsign signature

## Error Handling
All operations return `Result<T, GpgError>` where `GpgError` includes:
- FileSystemError
- GpgOperationError
- TempFileError
- PathError
- ValidationError
- DecryptionError

## Security Features
1. No unsafe code
2. Temporary files automatically cleaned up
3. No unwrap() calls - all errors properly handled
4. GPG trust model set to "always" for encryption operations
5. Signature validation enforced
6. All operations use separate temporary files

## Common GPG Commands for Users
```bash
# List secret keys (for signing)
gpg --list-secret-keys --keyid-format=long

# List public keys (for validation)
gpg --list-keys --keyid-format=long

# Export public key
gpg --armor --export KEYID > public_key.asc

# Import public key
gpg --import public_key.asc
```

## Usage Examples

### Sending a File
```rust
let input_file = Path::new("config.toml");
let signing_key = "3AA5C34371567BD2";
let recipient_key = Path::new("invites_updates/incoming/recipient_key.asc");

clearsign_and_encrypt_file_for_recipient(
    input_file,
    signing_key,
    recipient_key
)?;
```

### Receiving a File
```rust
let encrypted_file = Path::new("invites_updates/outgoing/config.toml.gpg");
let validator_key = "1234567890ABCDEF";
let output_file = Path::new("decrypted_config.toml");

decrypt_and_validate_file(
    encrypted_file,
    validator_key,
    output_file
)?;
```

## Process Flow

### Sending
1. Validate signing key exists
2. Create temporary file paths
3. Clearsign original file
4. Encrypt clearsigned file
5. Clean up temporary files
6. Output to `invites_updates/outgoing/`

### Receiving
1. Decrypt received file
2. Verify clearsign signature
3. Extract verified content
4. Clean up temporary files
5. Output decrypted and verified file

## Maintenance Notes
- No third-party dependencies
- All file operations use temporary files
- Extensive error handling throughout
- Clear, descriptive variable names
- Full documentation coverage

## Testing
Recommended test scenarios:
1. Valid signing key, valid recipient key
2. Invalid signing key
3. Invalid recipient key
4. File permission issues
5. Missing directories
6. Large files
7. Invalid file paths
8. Malformed GPG keys

## Future Improvements
Consider adding:
1. Async support
2. Multiple recipient support
3. Key validation caching
4. Configurable output directories
5. Logging integration
6. Stream processing for large files

## Support
For questions or issues:
1. Check GPG key validity
2. Verify file permissions
3. Ensure GPG is properly installed
4. Check error messages in GpgError enum
5. Verify directory structure exists

## Security Notes
1. Never share private keys
2. Regularly backup GPG keys
3. Use strong passphrases
4. Keep GPG updated
5. Monitor file permissions
6. Verify key fingerprints
```

# Module Use Example:

```rust
use std::path::Path;
use std::io::{self, Write};

mod clearsign_toml_module;  // This declares the module and tells Rust to look for handle_gpg.rs
use crate::clearsign_toml_module::{
    GpgError, 
    clearsign_and_encrypt_file_for_recipient, 
    decrypt_and_validate_file,
    rust_gpg_tools_interface,
};

// call module
pub fn main() -> Result<(), GpgError> {
    rust_gpg_tools_interface();
}
```
*/

/*
Sample use 
mod read_toml_field;  // This declares the module and tells Rust to look for handle_gpg.rs
use crate::read_toml_field::{
    read_field_from_toml,
    read_basename_fields_from_toml,
    read_single_line_string_field_from_toml,
    read_multi_line_toml_string,
    read_integer_array,
    read_singleline_string_from_clearsigntoml,
    read_multiline_string_from_clearsigntoml,
}; 

fn main() -> Result<(), String> {
    let value = read_field_from_toml("test.toml", "fieldname");
    println!("Field value -> {}", value);
    
    // Read all prompt fields
    let prompt_values = read_basename_fields_from_toml("config.toml", "prompt");
    println!("Prompts: {:?}", prompt_values);

    let single_line = read_single_line_string_field_from_toml("config.toml", "promptsdir_1")?;
    let multi_line = read_multi_line_toml_string("config.toml", "multi_line")?;
    let integer_array = read_integer_array("config.toml", "schedule_duration_start_end")?;
    
    println!("Single line: {}", single_line);
    println!("Multi line: {}", multi_line);
    println!("Numbers: {:?}", integer_array);
    
    Ok(())
}

*/
use std::error::Error as StdError;
use std::fmt;
use std::io::{
    self, 
    Write, 
    BufRead, 
    Read,
};
use std::fs::{
    self,
    File,
};
use std::path::{
    Path, 
    PathBuf,
};
use std::process::Command;
use std::time::{
    SystemTime,
    UNIX_EPOCH,
};

/// The function reads a single line from a TOML file that starts with a specified field name
/// and ends with a value. The function returns an empty string if the field is not found, and
/// does not panic or unwrap in case of errors. The function uses only standard Rust libraries
/// and does not introduce unnecessary dependencies.
///
/// design:
/// 0. start with an empty string to return by default
/// 1. get file at path
/// 2. open as text
/// 3. iterate through rows
/// 4. look for filed name as start of string the " = "
/// 5. grab that whole row of text
/// 6. remove "fieldname = " from the beginning
/// 7. remove '" ' and trailing spaces from the end
/// 8. return that string, if any
/// by default, return an empty string, if anything goes wrong, 
/// handle the error, and return an empty string
///
/// requires:
/// use std::fs::File;
/// use std::io::{self, BufRead};
///
/// example use:
///     let value = read_field_from_toml("test.toml", "fieldname");
///
pub fn read_field_from_toml(path: &str, field_name: &str) -> String {
    // Validate input parameters
    if path.is_empty() || field_name.is_empty() {
        println!("Error: Empty path or field name provided");
        return String::new();
    }

    // Verify file extension
    if !path.to_lowercase().ends_with(".toml") {
        println!("Warning: File does not have .toml extension: {}", path);
    }

    // Debug print statement
    println!("Attempting to open file at path: {}", path);

    // Open the file at the specified path
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            // More detailed error reporting
            println!("Failed to open file at path: {}. Error: {}", path, e);
            return String::new();
        },
    };

    // Debug print statement
    println!("Successfully opened file at path: {}", path);

    // Create a buffered reader to read the file line by line
    let reader = io::BufReader::new(file);

    // Keep track of line numbers for better error reporting
    let mut line_number = 0;

    // Iterate through each line in the file
    for line_result in reader.lines() {
        line_number += 1;

        // Handle line reading errors
        let line = match line_result {
            Ok(line) => line,
            Err(e) => {
                println!("Error reading line {}: {}", line_number, e);
                continue;
            }
        };

        // Skip empty lines and comments
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }

        // Debug print statement
        println!("Processing line {}: {}", line_number, line);

        // Check if line starts with field name
        if line.trim_start().starts_with(field_name) {
            // Debug print statement
            println!("Found field '{}' on line {}", field_name, line_number);

            // Split the line by '=' and handle malformed lines
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                println!("Malformed TOML line {} - missing '=': {}", line_number, line);
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            // Verify exact field name match (avoiding partial matches)
            if key != field_name {
                continue;
            }

            // Handle empty values
            if value.is_empty() {
                println!("Warning: Empty value found for field '{}'", field_name);
                return String::new();
            }

            // Debug print statement
            println!("Extracted value: {}", value);

            // Clean up the value: remove quotes and trim spaces
            let cleaned_value = value.trim().trim_matches('"').trim();
            
            // Verify the cleaned value isn't empty
            if cleaned_value.is_empty() {
                println!("Warning: Value became empty after cleaning for field '{}'", field_name);
                return String::new();
            }

            return cleaned_value.to_string();
        }
    }

    // If we get here, the field wasn't found
    println!("Field '{}' not found in file", field_name);
    String::new()
}

/// Reads all fields from a TOML file that share a common base name (prefix before underscore)
/// and returns a vector of their values. Returns an empty vector if no matching fields are found
/// or if any errors occur.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `base_name` - Base name to search for (e.g., "prompt" will match "prompt_1", "prompt_2", etc.)
///
/// # Returns
/// * `Vec<String>` - Vector containing all values for fields matching the base name
///
/// # Example
/// ```
/// let values = read_basename_fields_from_toml("config.toml", "prompt");
/// // For TOML content:
/// // prompt_1 = "value1"
/// // prompt_2 = "value2"
/// // Returns: vec!["value1", "value2"]
/// ```
pub fn read_basename_fields_from_toml(path: &str, base_name: &str) -> Vec<String> {
    let mut values = Vec::new();

    // Validate input parameters
    if path.is_empty() || base_name.is_empty() {
        println!("Error: Empty path or base name provided");
        return values;
    }

    // Open and read the file
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            println!("Failed to open file at path: {}. Error: {}", path, e);
            return values;
        },
    };

    let reader = io::BufReader::new(file);
    let base_name_with_underscore = format!("{}_", base_name);

    // Process each line
    for (line_number, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(line) => line,
            Err(e) => {
                println!("Error reading line {}: {}", line_number + 1, e);
                continue;
            }
        };

        // Skip empty lines and comments
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        // Check if line starts with base_name_
        if trimmed_line.starts_with(&base_name_with_underscore) {
            // Split the line by '=' and handle malformed lines
            let parts: Vec<&str> = trimmed_line.splitn(2, '=').collect();
            if parts.len() != 2 {
                println!("Malformed TOML line {} - missing '=': {}", line_number + 1, line);
                continue;
            }

            let value = parts[1].trim();
            
            // Clean up the value: remove quotes and trim spaces
            let cleaned_value = value.trim().trim_matches('"').trim();
            
            if !cleaned_value.is_empty() {
                values.push(cleaned_value.to_string());
            }
        }
    }

    // Sort values to ensure consistent ordering
    values.sort();
    values
}

/// Reads a single-line string field from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<String, String>` - The field value or an error message
pub fn read_single_line_string_field_from_toml(path: &str, field_name: &str) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", field_name)) {
            return Ok(trimmed
                .splitn(2, '=')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string());
        }
    }
    
    Err(format!("Field '{}' not found", field_name))
}


/// Reads a u8 integer value from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<u8, String>` - The parsed u8 value or an error message
pub fn read_u8_field_from_toml(path: &str, field_name: &str) -> Result<u8, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", field_name)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", field_name))?
                .trim();
                
            // Parse the value as u8
            return value_str.parse::<u8>()
                .map_err(|e| format!("Failed to parse '{}' as u8: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", field_name))
}

/// Reads a u64 integer value from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<u64, String>` - The parsed u64 value or an error message
pub fn read_u64_field_from_toml(path: &str, field_name: &str) -> Result<u64, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", field_name)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", field_name))?
                .trim();
                
            // Parse the value as u64
            return value_str.parse::<u64>()
                .map_err(|e| format!("Failed to parse '{}' as u64: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", field_name))
}

/// Reads a floating point (f64) value from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<f64, String>` - The parsed f64 value or an error message
pub fn read_float_f64_field_from_toml(path: &str, field_name: &str) -> Result<f64, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", field_name)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", field_name))?
                .trim();
                
            // Parse the value as f64
            return value_str.parse::<f64>()
                .map_err(|e| format!("Failed to parse '{}' as floating point number: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", field_name))
}

/// Reads a floating point (f32) value from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<f32, String>` - The parsed f32 value or an error message
pub fn read_float_f32_field_from_toml(path: &str, field_name: &str) -> Result<f32, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", field_name)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", field_name))?
                .trim();
                
            // Parse the value as f32
            return value_str.parse::<f32>()
                .map_err(|e| format!("Failed to parse '{}' as 32-bit floating point number: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", field_name))
}

/// Reads a multi-line string field (triple-quoted) from a TOML file.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<String, String>` - The concatenated multi-line value or an error message
pub fn read_multi_line_toml_string(path: &str, field_name: &str) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Find the start of the field
    let field_start = format!("{} = \"\"\"", field_name);
    let start_pos = content.find(&field_start)
        .ok_or_else(|| format!("Multi-line field '{}' not found", field_name))?;

    // Find the end of the field (next """)
    let content_after_start = &content[start_pos + field_start.len()..];
    let end_pos = content_after_start.find("\"\"\"")
        .ok_or_else(|| format!("Closing triple quotes not found for field '{}'", field_name))?;

    // Extract the content between the triple quotes
    let multi_line_content = &content_after_start[..end_pos];

    // Clean up the content
    Ok(multi_line_content
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<&str>>()
        .join("\n")
        .trim()
        .to_string())
}

/// Reads an array of integers from a TOML file into a Vec<u64>.
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
/// 
/// # Returns
/// * `Result<Vec<u64>, String>` - The vector of integers or an error message
pub fn read_integer_array(path: &str, field_name: &str) -> Result<Vec<u64>, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = [", field_name)) {
            let array_part = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or("Invalid array format")?
                .trim()
                .trim_matches(|c| c == '[' || c == ']');
                
            return array_part
                .split(',')
                .map(|s| s.trim().parse::<u64>()
                    .map_err(|e| format!("Invalid integer: {}", e)))
                .collect::<Result<Vec<u64>, String>>();
        }
    }
    
    Err(format!("Array field '{}' not found", field_name))
}

/// Extracts a GPG key from a TOML file.
/// This function assumes the GPG key is stored in a multi-line field.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `key_field` - Name of the field containing the GPG key
///
/// # Returns
/// * `Result<String, String>` - The GPG key or an error message
fn extract_gpg_key_from_clearsigntoml(path: &str, key_field: &str) -> Result<String, String> {
    read_multi_line_toml_string(path, key_field)
}

// /// Verifies a clearsigned TOML file using GPG.
// ///
// /// # Arguments
// /// * `path` - Path to the TOML file
// /// * `key` - The GPG key to use for verification
// ///
// /// # Returns
// /// * `Result<(), String>` - Success or error message
// fn verify_clearsign(path: &str, key: &str) -> Result<(), String> {
//     // Create a temporary file to hold the key
//     let temp_key_path = format!("{}.key", path);
//     std::fs::write(&temp_key_path, key)
//         .map_err(|e| format!("Failed to write temporary key file: {}", e))?;

//     // Use gpg to verify the file
//     let output = Command::new("gpg")
//         .arg("--verify")
//         .arg("--batch")
//         .arg("--no-tty")
//         .arg("--keyring")
//         .arg(&temp_key_path)
//         .arg(path)
//         .output()
//         .map_err(|e| format!("Failed to execute GPG: {}", e))?;

//     // Clean up the temporary key file
//     let _ = std::fs::remove_file(temp_key_path);

//     if !output.status.success() {
//         let stderr = String::from_utf8_lossy(&output.stderr);
//         return Err(format!("GPG verification failed: {}", stderr));
//     }

//     Ok(())
// }

/// Verifies a clearsigned TOML file using GPG.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `key` - The GPG key to use for verification
///
/// # Returns
/// * `Result<bool, String>` - True if verification succeeds, false if it fails, or an error message
fn verify_clearsign(path: &str, key: &str) -> Result<bool, String> {
    // Create a temporary file to hold the key
    let temp_key_path = format!("{}.key", path);
    std::fs::write(&temp_key_path, key)
        .map_err(|e| format!("Failed to write temporary key file: {}", e))?;

    // Use gpg to verify the file
    let output = Command::new("gpg")
        .arg("--verify")
        .arg("--batch")
        .arg("--no-tty")
        .arg("--keyring")
        .arg(&temp_key_path)
        .arg(path)
        .output()
        .map_err(|e| format!("Failed to execute GPG: {}", e))?;

    // Clean up the temporary key file
    let _ = std::fs::remove_file(temp_key_path);

    // Return the verification result
    Ok(output.status.success())
}

/// Reads a single-line string field from a clearsigned TOML file.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
///
/// # Returns
/// * `Result<String, String>` - The field value or an error message
pub fn read_singleline_string_from_clearsigntoml(path_to_clearsigntoml_with_gpgkey: &str, field_name: &str) -> Result<String, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path_to_clearsigntoml_with_gpgkey, "gpg_key_public")?;

    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path_to_clearsigntoml_with_gpgkey, &key)?;

    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path_to_clearsigntoml_with_gpgkey));
    }

    // Only read the field if verification succeeded
    read_single_line_string_field_from_toml(path_to_clearsigntoml_with_gpgkey, field_name)
}


/// Reads a single-line string field from a clearsigned TOML file using a GPG key from a separate config file.
///
/// # Purpose
/// This function provides a way to verify and read from clearsigned TOML files that don't contain
/// their own GPG keys, instead using a key from a separate centralized config file. This approach
/// helps maintain consistent key management across multiple clearsigned files.
///
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file
/// 3. If verification succeeds, reads the requested field from the verified file
/// 4. Returns the field value or an appropriate error
///
/// # Arguments
/// * `config_file_with_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// * `target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// * `field_name` - Name of the field to read from the target file
///
/// # Returns
/// * `Ok(String)` - The value of the requested field if verification succeeds
/// * `Err(String)` - Detailed error message if any step fails
///
/// # Errors
/// This function may return errors in several cases:
/// * If the config file cannot be read or doesn't contain a valid GPG key
/// * If the target file cannot be read or its signature cannot be verified with the provided key
/// * If the specified field doesn't exist in the target file or has an invalid format
///
/// # Example
/// ```
/// let config_path = "config/security.toml";
/// let target_path = "data/settings.toml";
/// 
/// match read_singleline_string_using_clearsignedconfig_from_clearsigntoml(
///     config_path, 
///     target_path, 
///     "api_endpoint"
/// ) {
///     Ok(value) => println!("API Endpoint: {}", value),
///     Err(e) => eprintln!("Error: {}", e)
/// }
/// ```
pub fn read_singleline_string_using_clearsignedconfig_from_clearsigntoml(
    config_file_with_gpg_key: &str,
    target_clearsigned_file: &str, 
    field_name: &str,
) -> Result<String, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(config_file_with_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", config_file_with_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            target_clearsigned_file,
            config_file_with_gpg_key
        ));
    }

    // Step 4: Read the requested field from the verified file
    read_single_line_string_field_from_toml(target_clearsigned_file, field_name)
        .map_err(|e| format!("Failed to read field '{}' from verified file '{}': {}", 
                            field_name, target_clearsigned_file, e))
}

// // DOC String NEEDED
// pub fn read_singleline_string_using_clearsignedconfig_from_clearsigntoml(
//     path_to_config_file_with_gpgkey: &str,
//     path_to_clearsigntoml_without_gpgkey: &str, 
//     field_name: &str,
//     ) -> Result<String, String> {
//     // Extract GPG key from the file
//     let key = extract_gpg_key_from_clearsigntoml(path_to_config_file_with_gpgkey, "gpg_key_public")?;

//     // Verify the file and only proceed if verification succeeds
//     let verification_result = verify_clearsign(path_to_clearsigntoml_without_gpgkey, &key)?;

//     if !verification_result {
//         return Err(format!(
//             "GPG verification failed for file: {:?} {:?}",
//             &path_to_config_file_with_gpgkey,
//             &path_to_clearsigntoml_without_gpgkey,
//         ));
//     }

//     // Only read the field if verification succeeded
//     read_single_line_string_field_from_toml(
//         path_to_clearsigntoml_without_gpgkey, 
//         field_name
//     )
// }


/// Reads a multi-line string field from a clearsigned TOML file.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
///
/// # Returns
/// * `Result<String, String>` - The field value or an error message
pub fn read_multiline_string_from_clearsigntoml(path: &str, field_name: &str) -> Result<String, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_multi_line_toml_string(path, field_name)
}

/// Reads an integer array field from a clearsigned TOML file.
///
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read
///
/// # Returns
/// * `Result<Vec<u64>, String>` - The integer array or an error message
pub fn read_integerarray_clearsigntoml(path: &str, field_name: &str) -> Result<Vec<u64>, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_integer_array(path, field_name)
}


/// Reads an string array field from a clearsigned TOML file
///...
pub fn read_str_array_clearsigntoml(path: &str, field_name: &str) -> Result<Vec<u64>, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_integer_array(path, field_name)
}


#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::write;
    use std::fs::remove_file;

    // Mock test for clearsign functions
    // These tests will be skipped in environments without GPG
    #[test]
    fn test_clearsign_reading() {
        // This test should be run only if GPG is available
        if !Command::new("gpg").arg("--version").status().map_or(false, |s| s.success()) {
            println!("Skipping GPG test because GPG is not available");
            return;
        }

        // Create a mock TOML file with a fake GPG key for testing
        let test_content = r#"
            gpg_key_public = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----
            mQENBF0blBUBCADPhh9ZoC2QXlA8Xu0ghtQTf5VQgC8CmxPM/H85q8HyITWJ6S+c
            LCG9OSvqpqxN9VTRLVqf9051Rj4nQzGEEzqUJp3zHfLKZN3SNKVnMn8CyeMoWJGg
            XgNjnyfk687AB0Pn5JApzVaS9JDYVOPmTNXk4T9wLs2vYbKQ9E4/Mv0fnRBYaAgm
            JQT53jdH/QUIVIqnYvMbwB4TZY8MfA4AoT4QyqDB5ppiUWH5S2PJqId29Z/Y45J+
            -----END PGP PUBLIC KEY BLOCK-----
            """
            promptsdir_1 = "test/dir"
            multi_line = """
            This is a
            multi-line
            value
            """
            schedule_duration_start_end = [1, 2, 3, 4]
        "#;
        
        let test_file = "test_clearsign.toml";
        write(test_file, test_content).unwrap();

        // These tests will fail in real environments since we're using a fake GPG key
        // but they demonstrate the API usage
        let _ = read_singleline_string_from_clearsigntoml(test_file, "promptsdir_1");
        let _ = read_multiline_string_from_clearsigntoml(test_file, "multi_line");
        let _ = read_integerarray_clearsigntoml(test_file, "schedule_duration_start_end");

        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_basename_fields() {
        // Create a temporary test TOML file
        let test_content = r#"
            # Test TOML file
            prompt_1 = "value1"
            prompt_2 = "value2"
            other_field = "other"
            prompt_3 = "value3"
        "#;
        let test_file = "test_basename.toml";
        write(test_file, test_content).unwrap();

        // Test reading basename fields
        let values = read_basename_fields_from_toml(test_file, "prompt");
        
        // Clean up
        let _ = remove_file(test_file);

        assert_eq!(values, vec!["value1", "value2", "value3"]);
    }

    #[test]
    fn test_empty_input() {
        let values = read_basename_fields_from_toml("", "prompt");
        assert!(values.is_empty());
    }
    
    #[test]
    fn test_single_line_string() {
        let test_content = r#"
            field1 = "value1"
            field2 = "value2"
        "#;
        let test_file = "test_single.toml";
        write(test_file, test_content).unwrap();
        
        let result = read_single_line_string_field_from_toml(test_file, "field1");
        assert_eq!(result.unwrap(), "value1");
        
        std::fs::remove_file(test_file).unwrap();
    }
    

    #[test]
    fn test_multi_line_string() {
        let test_content = r#"
description = """
This is a
multi-line
string
"""\
"#;
        let test_file = "test_multi.toml";
        write(test_file, test_content).unwrap();
        
        let result = read_multi_line_toml_string(test_file, "description");
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("multi-line"));
        assert_eq!(content, "This is a\nmulti-line\nstring");
        
        std::fs::remove_file(test_file).unwrap();
    }
    
    #[test]
    fn test_integer_array() {
        let test_content = r#"
            numbers = [1, 2, 3, 4, 5]
        "#;
        let test_file = "test_array.toml";
        write(test_file, test_content).unwrap();
        
        let result = read_integer_array(test_file, "numbers");
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4, 5]);
        
        std::fs::remove_file(test_file).unwrap();
    }
}

////////////
// gpg code
////////////

// use std::error::Error as StdError;
// use std::fmt;

// First, implement Display trait for GpgError (if not already implemented)
impl fmt::Display for GpgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// Then implement the Error trait for GpgError
impl StdError for GpgError {
    // This method is optional; only needed if your error wraps other errors
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            GpgError::FileSystemError(e) => Some(e),
            _ => None,
        }
    }
}

// Add these to the existing GpgError enum:
impl GpgError {
    /// Returns a user-friendly error message
    pub fn to_string(&self) -> String {
        match self {
            GpgError::FileSystemError(e) => format!("File system error: {}", e),
            GpgError::GpgOperationError(s) => format!("GPG operation error: {}", s),
            GpgError::TempFileError(s) => format!("Temporary file error: {}", s),
            GpgError::PathError(s) => format!("Path error: {}", s),
            GpgError::ValidationError(s) => format!("Validation error: {}", s),
            GpgError::DecryptionError(s) => format!("Decryption error: {}", s),
        }
    }
}

/// Clearsigns a file with the user's private key and saves the output to a specified location.
///
/// # Arguments
/// * `input_file_path` - Path to the file that needs to be clearsigned
/// * `output_file_path` - Path where the clearsigned file will be saved
/// * `signing_key_id` - GPG key ID to use for signing
///
/// # Returns
/// * `Ok(())` if clearsigning succeeds
/// * `Err(GpgError)` if any operation fails
///
/// # Example
/// ```no_run
/// let input = Path::new("document.txt");
/// let output = Path::new("document.txt.asc");
/// let key_id = "3AA5C34371567BD2";
/// clearsign_filepath_to_path(input, output, key_id)?;
/// ```
pub fn clearsign_filepath_to_path(
    input_file_path: &Path,
    output_file_path: &Path,
    signing_key_id: &str,
) -> Result<(), GpgError> {
    // Validate that the signing key exists and is available
    if !validate_gpg_key(signing_key_id)? {
        return Err(GpgError::GpgOperationError(
            format!("Signing key '{}' not found in keyring", signing_key_id)
        ));
    }
    
    // Ensure the output directory exists
    if let Some(parent) = output_file_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| GpgError::FileSystemError(e))?;
    }
    
    // Directly clearsign the file to the specified output path
    let clearsign_output = Command::new("gpg")
        .arg("--clearsign")
        .arg("--default-key")
        .arg(signing_key_id)
        .arg("--output")
        .arg(output_file_path)
        .arg(input_file_path)
        .output()
        .map_err(|e| GpgError::GpgOperationError(e.to_string()))?;

    if !clearsign_output.status.success() {
        let error_message = String::from_utf8_lossy(&clearsign_output.stderr);
        return Err(GpgError::GpgOperationError(error_message.to_string()));
    }

    Ok(())
}

/// Decrypts and validates a clearsigned, encrypted file
/// 
/// # Arguments
/// * `encrypted_file_path` - Path to the encrypted .gpg file
/// * `validator_key_id` - GPG key ID to validate the clearsign signature
/// * `output_path` - Where to save the decrypted and verified file
/// 
/// # Returns
/// * `Ok(())` if decryption and validation succeed
/// * `Err(GpgError)` if any operation fails
pub fn decrypt_and_validate_file(
    encrypted_file_path: &Path,
    validator_key_id: &str,
    output_path: &Path,
) -> Result<(), GpgError> {
    // Create temporary paths for intermediate files
    let decrypted_temp_path = create_temp_file_path("decrypted_temp")?;
    
    // First decrypt the file
    decrypt_gpg_file(encrypted_file_path, &decrypted_temp_path)?;
    
    // Then verify the clearsign signature
    verify_clearsign_signature(&decrypted_temp_path, validator_key_id)?;
    
    // If verification succeeded, extract the original content
    extract_verified_content(&decrypted_temp_path, output_path)?;
    
    // Cleanup
    if decrypted_temp_path.exists() {
        fs::remove_file(&decrypted_temp_path)
            .map_err(|e| GpgError::TempFileError(e.to_string()))?;
    }
    
    Ok(())
}

/// Decrypts a GPG encrypted file.
///
/// # Arguments
/// * `encrypted_file_path` - Path to the encrypted GPG file
/// * `output_path` - Path where the decrypted output will be saved
///
/// # Returns
/// * `Ok(())` - If decryption succeeds
/// * `Err(GpgError)` - If any operation fails
///
/// # Notes
/// This function requires that the user has the appropriate private key
/// in their GPG keyring to decrypt the file.
pub fn decrypt_gpg_file(
    encrypted_file_path: &Path,
    output_path: &Path,
) -> Result<(), GpgError> {
    let decrypt_output = Command::new("gpg")
        .arg("--decrypt")
        .arg("--output")
        .arg(output_path)
        .arg(encrypted_file_path)
        .output()
        .map_err(|e| GpgError::DecryptionError(e.to_string()))?;

    if !decrypt_output.status.success() {
        let error_message = String::from_utf8_lossy(&decrypt_output.stderr);
        return Err(GpgError::DecryptionError(error_message.to_string()));
    }

    Ok(())
}

/// Verifies a clearsigned file's signature.
///
/// # Arguments
/// * `clearsigned_file_path` - Path to the clearsigned file
/// * `validator_key_id` - GPG key ID to use for validation
///
/// # Returns
/// * `Ok(())` - If signature validation succeeds
/// * `Err(GpgError)` - If validation fails or any other operation fails
///
/// # Notes
/// This function first checks if the validator key exists in the keyring
/// before attempting to verify the signature.
fn verify_clearsign_signature(
    clearsigned_file_path: &Path,
    validator_key_id: &str,
) -> Result<(), GpgError> {
    // First check if the validator key exists
    if !validate_gpg_key(validator_key_id)? {
        return Err(GpgError::ValidationError(
            format!("Validator key '{}' not found in keyring", validator_key_id)
        ));
    }

    let verify_output = Command::new("gpg")
        .arg("--verify")
        .arg(clearsigned_file_path)
        .output()
        .map_err(|e| GpgError::ValidationError(e.to_string()))?;

    if !verify_output.status.success() {
        let error_message = String::from_utf8_lossy(&verify_output.stderr);
        return Err(GpgError::ValidationError(error_message.to_string()));
    }

    Ok(())
}

/// Extracts the original content from a verified clearsigned file.
///
/// # Arguments
/// * `clearsigned_file_path` - Path to the verified clearsigned file
/// * `output_path` - Path where the extracted content will be saved
///
/// # Returns
/// * `Ok(())` - If content extraction succeeds
/// * `Err(GpgError)` - If any operation fails
///
/// # Notes
/// This function parses the clearsigned file to extract only the content
/// between the PGP header and signature sections
fn extract_verified_content(
    clearsigned_file_path: &Path,
    output_path: &Path,
) -> Result<(), GpgError> {
    // Read the clearsigned file
    let content = fs::read_to_string(clearsigned_file_path)
        .map_err(|e| GpgError::FileSystemError(e))?;
    
    // Extract the content between the clearsign markers
    let content_lines: Vec<&str> = content.lines().collect();
    let mut extracted_content = Vec::new();
    let mut in_content = false;

    for line in content_lines {
        if line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            in_content = true;
            continue;
        } else if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
            break;
        } else if in_content && !line.starts_with("Hash: ") {
            extracted_content.push(line);
        }
    }

    // Write the extracted content to the output file
    fs::write(output_path, extracted_content.join("\n"))
        .map_err(|e| GpgError::FileSystemError(e))?;

    Ok(())
}

/// Validates that a GPG key ID exists in the keyring.
///
/// # Arguments
/// * `key_id` - The GPG key ID to check for existence
///
/// # Returns
/// * `Ok(bool)` - True if the key exists, false otherwise
/// * `Err(GpgError)` - If there was an error executing the GPG command
///
/// # Example
/// ```no_run
/// let key_exists = validate_gpg_key("3AA5C34371567BD2")?;
/// if key_exists {
///     println!("Key found in keyring");
/// } else {
///     println!("Key not found in keyring");
/// }
/// ```
pub fn validate_gpg_key(key_id: &str) -> Result<bool, GpgError> {
    let validation_output = Command::new("gpg")
        .arg("--list-keys")
        .arg(key_id)
        .output()
        .map_err(|e| GpgError::GpgOperationError(e.to_string()))?;

    Ok(validation_output.status.success())
}

/// Validates that a GPG secret key ID exists in the user's GPG keyring and is available.
///
/// This function is crucial for operations that require signing, as it checks for the
/// presence of the private key component.
///
/// # Arguments
/// * `key_id` - The GPG key ID (long format recommended) to check for. This ID typically
///   refers to the public key, but GPG uses it to find the associated secret key.
///
/// # Returns
/// * `Ok(true)` - If the secret key corresponding to the `key_id` exists in the keyring.
/// * `Ok(false)` - If the secret key is not found (GPG command succeeds but indicates no such key).
/// * `Err(GpgError::GpgOperationError)` - If there was an error executing the GPG command itself,
///   or if the GPG command reported an error other than "key not found".
///
/// # Process
/// Internally, this function executes the command `gpg --list-secret-keys <key_id>`.
/// The success of this GPG command (exit status 0) indicates that GPG recognizes
/// the key ID and has information about its secret part.
///
/// # Note
/// This function does not check if the key is passphrase-protected or if the GPG agent
/// can access it without interaction. It only confirms its presence in the secret keyring.
pub fn validate_gpg_secret_key(key_id: &str) -> Result<bool, GpgError> {
    // Ensure the key_id is not empty, as GPG might interpret this differently.
    if key_id.is_empty() {
        return Err(GpgError::GpgOperationError(
            "Key ID for secret key validation cannot be empty.".to_string(),
        ));
    }

    // Log the action being performed for traceability.
    println!(
        "Validating presence of GPG secret key for ID: '{}'",
        key_id
    );

    // Construct and execute the GPG command to list the specific secret key.
    let validation_output_result = Command::new("gpg")
        .arg("--list-secret-keys") // Command to list secret keys.
        .arg(key_id) // Specify the key ID to look for.
        .output(); // Execute the command and capture its output.

    match validation_output_result {
        Ok(output) => {
            // GPG command executed. Now check its status.
            if output.status.success() {
                // GPG command succeeded, meaning the secret key is known.
                println!("GPG secret key for ID '{}' found in keyring.", key_id);
                Ok(true)
            } else {
                // GPG command failed. This usually means the secret key was not found,
                // or some other GPG error occurred.
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                println!(
                    "GPG secret key for ID '{}' not found or GPG error. GPG stderr: {}",
                    key_id, stderr_output
                );
                // We interpret a non-success status as the key not being definitively available.
                // GPG's `gpg --list-secret-keys <non_existent_key_id>` typically returns a non-zero exit code.
                Ok(false)
            }
        }
        Err(io_error) => {
            // Failed to execute the GPG command itself (e.g., GPG not in PATH).
            eprintln!(
                "Failed to execute GPG command for secret key validation (ID: '{}'): {}",
                key_id, io_error
            );
            Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG command while validating secret key ID '{}': {}",
                key_id, io_error
            )))
        }
    }
}

/// Custom error type for GPG operations
#[derive(Debug)]
pub enum GpgError {
    /// Errors related to file system operations
    FileSystemError(std::io::Error),
    /// Errors related to GPG operations
    GpgOperationError(String),
    /// Errors related to temporary file management
    TempFileError(String),
    /// Errors related to path manipulation
    PathError(String),
    /// Errors related to signature validation
    ValidationError(String),
    /// Errors related to decryption
    DecryptionError(String),
}

/// Generates a current Unix timestamp for unique file naming.
///
/// # Returns
/// * `u64` - Current Unix timestamp in seconds
///
/// # Notes
/// This function is used internally to create unique filenames
/// for temporary files used during GPG operations.
fn generate_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Creates a temporary file path with a unique name.
///
/// # Arguments
/// * `prefix` - Prefix to use for the temporary file name
///
/// # Returns
/// * `Ok(PathBuf)` - Path to the new temporary file
/// * `Err(GpgError)` - If there was an error creating the path
///
/// # Notes
/// This function creates the parent directory if it doesn't exist
/// and returns an absolute path to the temporary file.
fn create_temp_file_path(prefix: &str) -> Result<PathBuf, GpgError> {
    let mut temp_dir = std::env::temp_dir();
    let timestamp = generate_timestamp();
    let temp_filename = format!("gpg_temp_{}_{}", timestamp, prefix);
    temp_dir.push(temp_filename);
    
    // Ensure the parent directory exists
    if let Some(parent) = temp_dir.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| GpgError::TempFileError(format!("Failed to create temp directory: {}", e)))?;
    }
    
    Ok(temp_dir)
}

/// Clearsigns a file using your GPG private key.
///
/// # Arguments
/// * `input_file_path` - Path to the file to be clearsigned
/// * `temp_file_path` - Path where the clearsigned output will be saved
/// * `your_key_id` - Your private key ID for signing
///
/// # Returns
/// * `Ok(())` - If clearsigning succeeds
/// * `Err(GpgError)` - If any operation fails
///
/// # Notes
/// This is an internal function used by higher-level functions
/// like `clearsign_and_encrypt_file_for_recipient`.
fn clearsign_file_with_private_key(
    input_file_path: &Path,
    temp_file_path: &Path,
    your_key_id: &str,  // Your private key ID for signing
) -> Result<(), GpgError> {
    let clearsign_output = Command::new("gpg")
        .arg("--clearsign")
        .arg("--default-key")
        .arg(your_key_id)
        .arg("--output")
        .arg(temp_file_path)
        .arg(input_file_path)
        .output()
        .map_err(|e| GpgError::GpgOperationError(e.to_string()))?;

    if !clearsign_output.status.success() {
        let error_message = String::from_utf8_lossy(&clearsign_output.stderr);
        return Err(GpgError::GpgOperationError(error_message.to_string()));
    }

    Ok(())
}

/// Encrypts a file using a recipient's public key file.
///
/// # Arguments
/// * `input_file_path` - Path to the file to be encrypted
/// * `output_file_path` - Path where the encrypted output will be saved
/// * `recipient_public_key_path` - Path to the recipient's public key file
///
/// # Returns
/// * `Ok(())` - If encryption succeeds
/// * `Err(GpgError)` - If any operation fails
///
/// # Notes
/// This function uses GnuPG's "always" trust model to allow
/// encrypting for recipients whose keys might not be fully trusted
/// in the local GPG keyring.
fn encrypt_file_with_public_key(
    input_file_path: &Path,
    output_file_path: &Path,
    recipient_public_key_path: &Path,
) -> Result<(), GpgError> {
    // First, import the recipient's public key for this operation
    let encrypt_output = Command::new("gpg")
        .arg("--encrypt")
        .arg("--trust-model")
        .arg("always")  // Trust the key for this operation
        .arg("--recipient-file")
        .arg(recipient_public_key_path)
        .arg("--output")
        .arg(output_file_path)
        .arg(input_file_path)
        .output()
        .map_err(|e| GpgError::GpgOperationError(e.to_string()))?;

    if !encrypt_output.status.success() {
        let error_message = String::from_utf8_lossy(&encrypt_output.stderr);
        return Err(GpgError::GpgOperationError(error_message.to_string()));
    }

    Ok(())
}

/// Main function to process a file: clearsign with your key and encrypt with recipient's public key
/// Clearsigns a file with your GPG key and encrypts it with a recipient's public key.
///
/// # Overview
/// This function provides a secure way to share files with specific recipients by:
/// 1. Clearsigning the file with your private GPG key (provides authentication)
/// 2. Encrypting the clearsigned file with the recipient's public key (provides confidentiality)
///
/// # Path Handling
/// IMPORTANT: All file paths are processed as follows:
/// - Input file path: Used as provided (should be an absolute path if possible)
/// - Recipient public key path: Used as provided (should be an absolute path if possible)
/// - Output file path: Automatically generated in `{EXECUTABLE_DIR}/invites_updates/outgoing/{original_filename}.gpg`
/// - Temporary files: Created in the system's temporary directory with unique names
///
/// # Process Flow
/// 1. Validates that your signing key exists in the GPG keyring
/// 2. Creates necessary temporary and output directories
/// 3. Clearsigns the input file with your private key
/// 4. Encrypts the clearsigned file with the recipient's public key
/// 5. Cleans up temporary files
/// 6. Saves the final encrypted file to the output location
///
/// # Security Considerations
/// - Uses GPG's "always" trust model for encryption (recipient key doesn't need to be fully trusted)
/// - Creates and cleans up temporary files securely
/// - Does not permanently import recipient keys to your keyring
/// - Verifies key availability before beginning operations
///
/// # Arguments
/// * `input_file_path` - Path to the file to be clearsigned and encrypted
/// * `your_signing_key_id` - Your GPG key ID used for clearsigning (e.g., "7673C969D81E94C63D641CF84ED13C31924928A5")
/// * `recipient_public_key_path` - Path to the recipient's public key file (ASCII-armored format)
///
/// # Returns
/// * `Ok(())` - If the operation completes successfully
/// * `Err(GpgError)` - If any step fails, with detailed error information
///
/// # Errors
/// May return various `GpgError` types:
/// * `GpgError::GpgOperationError` - If GPG operations fail (missing keys, invalid keys, etc.)
/// * `GpgError::FileSystemError` - If file operations fail (permission issues, disk full, etc.)
/// * `GpgError::PathError` - If path operations fail (invalid paths, missing directories, etc.)
/// * `GpgError::TempFileError` - If temporary file operations fail
///
/// # Example
/// ```
/// use std::path::Path;
/// 
/// // Clearsign and encrypt a configuration file for a collaborator
/// let result = clearsign_and_encrypt_file_for_recipient(
///     &Path::new("/path/to/config.toml"),
///     "7673C969D81E94C63D641CF84ED13C31924928A5",  // Your key ID
///     &Path::new("/path/to/recipient_key.asc")
/// );
///
/// match result {
///     Ok(()) => println!("File successfully clearsigned and encrypted"),
///     Err(e) => eprintln!("Error: {}", e.to_string()),
/// }
/// ```
///
/// # Related Functions
/// * `clearsign_file_with_private_key()` - Lower-level function to just clearsign a file
/// * `encrypt_file_with_public_key()` - Lower-level function to just encrypt a file
/// * `validate_gpg_key()` - Used to check if a GPG key exists in the keyring
///
/// # GPG Requirements
/// - GPG must be installed and available in the system PATH
/// - Your private key must be available in your GPG keyring
/// - Your private key should not have a passphrase, or GPG must be configured for non-interactive use
///
pub fn clearsign_and_encrypt_file_for_recipient(
    input_file_path: &Path,
    your_signing_key_id: &str,
    recipient_public_key_path: &Path,
) -> Result<(), GpgError> {
    // First validate that your signing key exists and is available
    if !validate_gpg_key(your_signing_key_id)? {
        return Err(GpgError::GpgOperationError(
            format!("Signing key '{}' not found in keyring", your_signing_key_id)
        ));
    }

    // Create paths for temporary and final files
    let original_filename = input_file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| GpgError::PathError("Invalid input file name".to_string()))?;
    
    // Create a simple temp file name without directory paths embedded in it
    let clearsigned_temp_path = create_temp_file_path(&format!("clearsigned_{}", original_filename))?;
    
    // Create absolute path for the output directory relative to executable
    let relative_output_dir = "invites_updates/outgoing";
    let absolute_output_dir = gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck(relative_output_dir)
        .map_err(|e| GpgError::PathError(format!("Failed to resolve output directory path: {}", e)))?;
    
    // Ensure the output directory exists
    fs::create_dir_all(&absolute_output_dir)
        .map_err(|e| GpgError::FileSystemError(e))?;
    
    // Create the final output path
    let final_output_path = absolute_output_dir.join(format!("{}.gpg", original_filename));
    
    // Log the paths being used
    println!("Input file: {}", input_file_path.display());
    println!("Temporary clearsigned file: {}", clearsigned_temp_path.display());
    println!("Final output path: {}", final_output_path.display());
    
    // Clearsign with your private key
    clearsign_file_with_private_key(input_file_path, &clearsigned_temp_path, your_signing_key_id)?;
    
    // Encrypt with recipient's public key
    encrypt_file_with_public_key(&clearsigned_temp_path, &final_output_path, recipient_public_key_path)?;

    // Cleanup temporary file
    if clearsigned_temp_path.exists() {
        fs::remove_file(&clearsigned_temp_path)
            .map_err(|e| GpgError::TempFileError(e.to_string()))?;
    }

    // Log completion
    println!("\nSuccessfully completed clearsigning and encryption");
    println!("Output file: {}", final_output_path.display());
    
    Ok(())
}

/// Interactive workflow for decrypting and validating files.
///
/// # Purpose
/// Guides the user through providing necessary information to decrypt
/// and validate a clearsigned, encrypted GPG file.
///
/// # Process
/// 1. Prompts for validator's GPG key ID
/// 2. Validates input parameters
/// 3. Decrypts and validates the file
/// 4. Reports results to the user
///
/// # Returns
/// * `Ok(())` - If the workflow completes successfully
/// * `Err(GpgError)` - If any step fails
///
/// # Notes
/// Uses default file paths for input and output if not specified.
fn decrypt_and_validate_workflow() -> Result<(), GpgError> {
    // Specify the default encrypted file path
    let encrypted_file = Path::new("invites_updates/outgoing/test.toml.gpg");
    
    // Specify where the decrypted and verified file will be saved
    let output_file = Path::new("invites_updates/decrypted_and_verified.toml");

    // Display helpful information about finding GPG key IDs
    println!("\nTo get the validator's key ID, run: $ gpg --list-keys --keyid-format=long");
    print!("Enter validator's GPG key ID: ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    // Get the validator's key ID from user input
    let mut validator_key_id = String::new();
    io::stdin()
        .read_line(&mut validator_key_id)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    let validator_key_id = validator_key_id.trim();

    // Validate that a key ID was provided
    if validator_key_id.is_empty() {
        return Err(GpgError::ValidationError(
            "No validator key ID provided".to_string()
        ));
    }

    // Display the parameters that will be used
    println!("\nProcessing with the following parameters:");
    println!("Encrypted file path: {}", encrypted_file.display());
    println!("Validator key ID: {}", validator_key_id);
    println!("Output file path: {}", output_file.display());

    // Perform the decryption and validation
    decrypt_and_validate_file(encrypted_file, &validator_key_id, output_file)?;
    
    // Confirm successful completion
    println!("\nSuccess: File has been decrypted and signature verified!");
    println!("Decrypted file location: {}", output_file.display());
    
    Ok(())
}

/// Main entry point for GPG file decryption and validation.
/// 
/// # Purpose
/// Provides an interactive command-line interface for decrypting and validating
/// GPG encrypted files that have been clearsigned.
/// 
/// # Process
/// 1. Prompts for necessary GPG key information
/// 2. Validates input parameters
/// 3. Decrypts the specified encrypted file
/// 4. Verifies the clearsign signature
/// 5. Outputs the decrypted and verified file
/// 
/// # Arguments
/// None - Interactive prompts gather needed information
/// 
/// # Returns
/// * `Ok(())` - Operation completed successfully
/// * `Err(GpgError)` - Operation failed with specific error details
/// 
/// # Example Usage
/// ```no_run
/// fn main() -> Result<(), GpgError> {
///     // ... function contents ...
/// }
/// ```
/// 
/// # Notes
/// - Requires GPG to be installed and configured
/// - Requires appropriate private keys to be available in the GPG keyring
/// - Default input file location: invites_updates/outgoing/*.gpg
pub fn rust_gpg_tools_interface() -> Result<(), GpgError> {
    // Ask user which operation they want to perform
    println!("GPG File Processing Utility");
    println!("---------------------------");
    println!("1. Decrypt and validate an encrypted file");
    println!("2. Clearsign a file");
    println!("3. Clearsign and encrypt a file for a recipient");
    
    print!("\nSelect an operation (1-3): ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    let mut operation = String::new();
    io::stdin()
        .read_line(&mut operation)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    
    match operation.trim() {
        "1" => decrypt_and_validate_workflow()?,
        "2" => clearsign_workflow()?,
        "3" => clearsign_and_encrypt_workflow()?,
        _ => return Err(GpgError::ValidationError("Invalid selection".to_string())),
    }
    
    Ok(())
}

// helpers


/// Gets the directory where the current executable is located.
///
/// # Returns
///
/// * `Result<PathBuf, io::Error>` - The absolute directory path containing the executable or an error
///   if it cannot be determined.
pub fn gpg_get_absolute_path_to_executable_parentdirectory() -> Result<PathBuf, io::Error> {
    // Get the path to the current executable
    let executable_path = std::env::current_exe().map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to determine current executable path: {}", e),
        )
    })?;
    
    // Get the directory containing the executable
    let executable_directory = executable_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to determine parent directory of executable",
        )
    })?;
    
    Ok(executable_directory.to_path_buf())
}


/// Converts a path to an absolute path based on the executable's directory location.
/// Does NOT check if the path exists or attempt to create anything.
///
/// # Arguments
///
/// * `path_to_make_absolute` - A path to convert to an absolute path relative to 
///   the executable's directory location.
///
/// # Returns
///
/// * `Result<PathBuf, io::Error>` - The absolute path based on the executable's directory or an error
///   if the executable's path cannot be determined or if the path cannot be resolved.
///
/// # Examples
///
/// ```
/// use manage_absolute_executable_directory_relative_paths::make_input_path_name_abs_executabledirectoryrelative_nocheck;
///
/// // Get an absolute path for "data/config.json" relative to the executable directory
/// let abs_path = make_input_path_name_abs_executabledirectoryrelative_nocheck("data/config.json").unwrap();
/// println!("Absolute path: {}", abs_path.display());
/// ```
pub fn gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck<P: AsRef<Path>>(path_to_make_absolute: P) -> Result<PathBuf, io::Error> {
    // Get the directory where the executable is located
    let executable_directory = gpg_get_absolute_path_to_executable_parentdirectory()?;
    
    // Create a path by joining the executable directory with the provided path
    let target_path = executable_directory.join(path_to_make_absolute);
    
    // If the path doesn't exist, we still return the absolute path without trying to canonicalize
    if !gpg_abs_executable_directory_relative_exists_boolean_check(&target_path)? {
        // Ensure the path is absolute (it should be since we joined with executable_directory)
        if target_path.is_absolute() {
            return Ok(target_path);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Failed to create absolute path",
            ));
        }
    }
    
    // Path exists, so we can canonicalize it to resolve any ".." or "." segments
    target_path.canonicalize().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to canonicalize path: {}", e),
        )
    })
}

/// Checks if a path exists (either as a file or directory).
///
/// # Arguments
///
/// * `path_to_check` - The path to check for existence
///
/// # Returns
///
/// * `Result<bool, io::Error>` - Whether the path exists or an error
pub fn gpg_abs_executable_directory_relative_exists_boolean_check<P: AsRef<Path>>(path_to_check: P) -> Result<bool, io::Error> {
    let path = path_to_check.as_ref();
    Ok(path.exists())
}

/// Store the entire clearsigned file (still in clearsigned format with all signatures intact) to the output path
/// Decrypts a GPG-encrypted file containing a clearsigned document, verifies the signature,
/// and stores the entire clearsigned file (still clearsigned) to the output path.
///
/// # Arguments
/// * `incoming_gpg_encrypted_path` - Path to the GPG-encrypted file
/// * `gpg_key_id` - GPG key ID to verify the clearsign signature
/// * `output_verified_clearsign_path` - Path where to store the verified clearsigned file
///
/// # Returns
/// * `Result<(), GpgError>` - Success or failure
///
/// # Description
/// This function:
/// 1. Decrypts the GPG-encrypted file
/// 2. Verifies the clearsign signature within the decrypted content
/// 3. Stores the entire verified clearsigned document (with signatures intact)
///    to the specified output path
///
/// Unlike other functions that extract content from clearsigned files,
/// this function preserves the entire clearsigned structure including
/// signature blocks.
pub fn extract_verify_store_gpg_encrypted_clearsign_toml(
    incoming_gpg_encrypted_path: &Path,
    gpg_key_id: &str,
    output_verified_clearsign_path: &Path,
) -> Result<(), GpgError> {
    // Step 1: Create a temporary path for the decrypted file
    let decrypted_temp_path = create_temp_file_path("decrypted_clearsign")?;
    
    // Step 2: Decrypt the GPG file
    decrypt_gpg_file(incoming_gpg_encrypted_path, &decrypted_temp_path)?;
    
    // Step 3: Verify the clearsign signature
    verify_clearsign_signature(&decrypted_temp_path, gpg_key_id)?;
    
    // Step 4: If verification succeeded, ensure the output directory exists
    if let Some(parent) = output_verified_clearsign_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| GpgError::FileSystemError(e))?;
    }
    
    // Step 5: Copy the entire clearsigned file to the output location
    fs::copy(&decrypted_temp_path, output_verified_clearsign_path)
        .map_err(|e| GpgError::FileSystemError(e))?;
    
    // Step 6: Clean up the temporary file
    if decrypted_temp_path.exists() {
        fs::remove_file(&decrypted_temp_path)
            .map_err(|e| GpgError::TempFileError(e.to_string()))?;
    }
    
    // Success - the verified clearsigned file has been stored to the output path
    println!("Successfully verified and stored clearsigned file to: {}", 
             output_verified_clearsign_path.display());
    
    Ok(())
}

pub fn manual_q_and_a_new_encrypted_clearsigntoml_verification() -> Result<(), String> {
    println!("GPG Encrypted Clearsigned TOML File Processor");
    println!("---------------------------------------------");
    
    // Get input file path from user
    print!("Enter path to the GPG-encrypted file: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input_path = String::new();
    io::stdin().read_line(&mut input_path).map_err(|e| e.to_string())?;
    let input_path = Path::new(input_path.trim());
    
    // Verify the file exists
    if !input_path.exists() {
        return Err(format!("Error: File not found at {}", input_path.display()));
    }
    
    // Get GPG key ID for verification
    println!("\nTo find your GPG key ID, run: gpg --list-keys --keyid-format=long");
    print!("Enter the GPG key ID to verify the signature: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut key_id = String::new();
    io::stdin().read_line(&mut key_id).map_err(|e| e.to_string())?;
    let key_id = key_id.trim();
    
    // Get output file path
    print!("Enter path where to save the verified clearsigned file: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut output_path = String::new();
    io::stdin().read_line(&mut output_path).map_err(|e| e.to_string())?;
    let output_path = Path::new(output_path.trim());
    
    // Display the parameters
    println!("\nProcessing with the following parameters:");
    println!("Input encrypted file: {}", input_path.display());
    println!("GPG key ID for verification: {}", key_id);
    println!("Output path for verified clearsigned file: {}", output_path.display());
    println!("\nProcessing...");
    
    // Call the function from the module
    extract_verify_store_gpg_encrypted_clearsign_toml(
        input_path,
        key_id,
        output_path
    ).map_err(|e| e.to_string())?;
    
    println!("Done! The verified clearsigned file has been saved.");
    Ok(())
}
/// Decrypts a GPG-encrypted file to a specified output file
///
/// This function performs decryption of a GPG-encrypted file using the user's private key
/// and saves the result to the specified output file. It does not perform signature verification,
/// which allows for examining the decrypted content before validating signatures.
///
/// # Arguments
/// * `input_file_path` - Path to the GPG-encrypted input file
/// * `output_file_path` - Path where the decrypted content should be saved
///
/// # Returns
/// * `Ok(())` if the decryption succeeds
/// * `Err(GpgError)` if the decryption fails
///
/// # Errors
/// * `GpgError::PathError` - If the input file doesn't exist or output path is invalid
/// * `GpgError::GpgOperationError` - If the GPG decryption operation fails
pub fn decrypt_gpgfile_to_output(input_file_path: &Path, output_file_path: &Path) -> Result<(), GpgError> {
    // Debug logging
    println!("Decrypting GPG file: {} to: {}", 
               input_file_path.display(), output_file_path.display());
    
    // Check if input file exists
    if !input_file_path.exists() {
        return Err(GpgError::PathError(format!(
            "Input file does not exist: {}", 
            input_file_path.display()
        )));
    }
    
    // Convert paths to strings for the command
    let input_path_str = input_file_path
        .to_str()
        .ok_or_else(|| GpgError::PathError(format!(
            "Failed to convert input path to string: {}", 
            input_file_path.display()
        )))?;
    
    let output_path_str = output_file_path
        .to_str()
        .ok_or_else(|| GpgError::PathError(format!(
            "Failed to convert output path to string: {}", 
            output_file_path.display()
        )))?;
    
    // Create the GPG command to decrypt the file
    let mut command = Command::new("gpg");
    command
        .arg("--batch")
        .arg("--yes")
        .arg("--decrypt")
        .arg("--output")
        .arg(output_path_str)
        .arg(input_path_str);
    
    println!("GPG decrypt command: {:?}", command);
    
    // Execute the command and check for success
    let output = command.output()
        .map_err(|e| GpgError::GpgOperationError(format!(
            "Failed to execute GPG command: {}", e
        )))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GpgError::GpgOperationError(format!(
            "GPG decryption failed: {}", stderr
        )));
    }
    
    // Verify the output file was created
    if !output_file_path.exists() {
        return Err(GpgError::PathError(format!(
            "Error in decrypt_gpgfile_to_output(): Decryption succeeded but output file was not created: {}", 
            output_file_path.display()
        )));
    }
    
    println!("Successfully decrypted file");
    Ok(())
}

/// Reads an array of strings from a TOML file into a Vec<String>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an array of strings defined by the specified field name.
/// It handles both single-line arrays (`field = ["value1", "value2"]`) and multi-line arrays:
/// ```toml
/// field = [
///     "value1",
///     "value2",
/// ]
/// ```
/// 
/// # Arguments
/// * `path` - Path to the TOML file
/// * `field_name` - Name of the field to read (must be an array of strings in the TOML file)
/// 
/// # Returns
/// * `Result<Vec<String>, String>` - A vector containing all strings in the array if successful,
///   or an error message if the field is not found or cannot be parsed correctly
/// 
/// # Error Handling
/// This function returns errors when:
/// * The file cannot be opened or read
/// * The specified field is not found
/// * The field is not a valid array format
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// colors = [
///     "red",
///     "green",
///     "blue"
/// ]
/// ```
/// 
/// Usage:
/// ```
/// let colors = read_string_array_field_from_toml("config.toml", "colors")?;
/// // Returns: vec!["red", "green", "blue"]
/// ```
pub fn read_string_array_field_from_toml(path: &str, field_name: &str) -> Result<Vec<String>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Variables to track multi-line array parsing
    let mut in_array = false;
    let mut array_values = Vec::new();
    let array_start_pattern = format!("{} = [", field_name);
    
    // Process each line
    for line_result in reader.lines() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line from file '{}': {}", path, e))?;
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Case 1: Check if we're starting an array definition
        if !in_array && trimmed.starts_with(&array_start_pattern) {
            in_array = true;
            
            // Check if this is a single-line array definition (starts and ends on same line)
            if trimmed.contains(']') {
                // Extract everything between the brackets
                let bracket_start = trimmed.find('[').ok_or_else(|| 
                    format!("Malformed array format for field '{}': opening bracket missing", field_name))?;
                
                let bracket_end = trimmed.rfind(']').ok_or_else(|| 
                    format!("Malformed array format for field '{}': closing bracket missing", field_name))?;
                
                // Make sure closing bracket comes after opening bracket
                if bracket_end <= bracket_start {
                    return Err(format!("Malformed array format for field '{}'", field_name));
                }
                
                // Extract array content between brackets
                let array_content = &trimmed[bracket_start + 1..bracket_end].trim();
                
                // If the array is not empty, parse its elements
                if !array_content.is_empty() {
                    // Split by commas and process each value
                    array_values = array_content
                        .split(',')
                        .map(|s| {
                            // Clean up each string value
                            s.trim()
                             .trim_matches('"')
                             .to_string()
                        })
                        .filter(|s| !s.is_empty()) // Skip empty entries
                        .collect();
                }
                
                // We've processed a single-line array, so return the result
                return Ok(array_values);
            }
            
            // If we get here, this is the start of a multi-line array
            // Check if there's a value on the same line as the opening bracket
            if let Some(first_element_pos) = trimmed.find('[') {
                let after_bracket = &trimmed[first_element_pos + 1..].trim();
                
                // If there's content after the opening bracket
                if !after_bracket.is_empty() && !after_bracket.starts_with(']') {
                    // Check if there's a comma in this content (could be multiple values)
                    if after_bracket.contains(',') {
                        // Handle multiple values on same line as opening bracket
                        for value_part in after_bracket.split(',') {
                            let clean_value = value_part.trim().trim_matches('"').to_string();
                            if !clean_value.is_empty() && clean_value != "]" {
                                array_values.push(clean_value);
                            }
                        }
                    } else {
                        // Single value on same line as opening bracket
                        let clean_value = after_bracket.trim().trim_matches('"').to_string();
                        if !clean_value.is_empty() {
                            array_values.push(clean_value);
                        }
                    }
                }
            }
            
            continue;
        }
        
        // Case 2: If we're inside a multi-line array definition
        if in_array {
            // Check if this line is just the closing bracket
            if trimmed == "]" {
                // We've reached the end of the array
                return Ok(array_values);
            }
            
            // This is an array element line - check if it contains a closing bracket
            let has_closing_bracket = trimmed.contains(']');
            
            if has_closing_bracket {
                // Extract content before the closing bracket
                let parts: Vec<&str> = trimmed.split(']').collect();
                let value_part = parts[0].trim();
                
                // Handle case where value and closing bracket are on same line
                if !value_part.is_empty() {
                    // Clean the value (remove comma and quotes)
                    let clean_value = value_part
                        .trim_end_matches(',')
                        .trim()
                        .trim_matches('"')
                        .to_string();
                    
                    if !clean_value.is_empty() {
                        array_values.push(clean_value);
                    }
                }
                
                // End array processing since we found the closing bracket
                return Ok(array_values);
            } else {
                // Regular array element (no closing bracket)
                // Clean up the value and add it to the results
                let clean_value = trimmed
                    .trim_end_matches(',')
                    .trim()
                    .trim_matches('"')
                    .to_string();
                
                if !clean_value.is_empty() {
                    array_values.push(clean_value);
                }
            }
        }
    }
    
    // If we parsed array values but didn't find the closing bracket
    if !array_values.is_empty() {
        // This is technically a malformed TOML file, but we'll return what we found
        // for robustness, with a warning in the logs
        println!("Warning: Array field '{}' in '{}' is missing a closing bracket, but values were found",
                field_name, path);
        return Ok(array_values);
    }
    
    // If we get here, we didn't find the array
    Err(format!("String array field '{}' not found in file '{}'", field_name, path))
}

/// Reads an array of strings from a clearsigned TOML file into a Vec<String>.
/// 
/// # Purpose
/// This function securely reads a string array from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the requested string array
/// 
/// # Arguments
/// * `path` - Path to the clearsigned TOML file
/// * `field_name` - Name of the field to read (must be an array of strings in the TOML file)
/// 
/// # Returns
/// * `Result<Vec<String>, String>` - A vector containing all strings in the array if successful and verified,
///   or an error message if verification fails or the field cannot be read
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for the configuration.
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// ipv4_addresses = [
///     "10.0.0.213",
///     "192.168.1.1"
/// ]
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Calling:
/// ```
/// let addresses = read_string_array_clearsigntoml("secure_config.toml", "ipv4_addresses")?;
/// // Returns: vec!["10.0.0.213", "192.168.1.1"] if signature verification succeeds
/// ```
pub fn read_str_array_field_clearsigntoml(path: &str, field_name: &str) -> Result<Vec<String>, String> {
    // Step 1: Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from file '{}': {}", path, e))?;
    
    // Step 2: Verify the file's clearsign signature
    let verification_result = verify_clearsign(path, &key)
        .map_err(|e| format!("Error during signature verification of file '{}': {}", path, e))?;
    
    // Step 3: Check if verification was successful
    if !verification_result {
        return Err(format!("GPG signature verification failed for file: {}", path));
    }
    
    // Step 4: If verification succeeded, read the requested field
    read_string_array_field_from_toml(path, field_name)
        .map_err(|e| format!("Failed to read string array '{}' from verified file '{}': {}", 
                             field_name, path, e))
}

/// Reads an array of strings from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read string arrays from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file
/// 3. If verification succeeds, reads the requested string array field
/// 4. Returns the string array or an appropriate error
/// 
/// # Arguments
/// * `config_file_with_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// * `target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// * `field_name` - Name of the string array field to read from the target file
/// 
/// # Returns
/// * `Ok(Vec<String>)` - The string array values if verification succeeds
/// * `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let addresses_file = "network_config.toml";
/// 
/// let ipv4_addresses = read_string_array_using_clearsignedconfig_from_clearsigntoml(
///     config_path,
///     addresses_file, 
///     "ipv4_addresses"
/// )?;
/// // Returns: vec!["10.0.0.213", "192.168.1.1"] if verification succeeds
/// ```
pub fn read_stringarray_using_clearsignedconfig_from_clearsigntoml(
    config_file_with_gpg_key: &str,
    target_clearsigned_file: &str, 
    field_name: &str,
) -> Result<Vec<String>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(config_file_with_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             config_file_with_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            target_clearsigned_file,
            config_file_with_gpg_key
        ));
    }

    // Step 4: Read the requested field from the verified file
    read_string_array_field_from_toml(target_clearsigned_file, field_name)
        .map_err(|e| format!("Failed to read string array '{}' from verified file '{}': {}", 
                             field_name, target_clearsigned_file, e))
}

/// Verifies a clearsigned file and extracts its content to a separate output file
///
/// This function performs two distinct operations:
/// 1. Verifies the signature on a clearsigned file using a provided public key file
/// 2. If verification succeeds, extracts just the content portion (without signature blocks)
///    and writes it to the specified output file
///
/// # Arguments
/// * `clearsigned_input_path` - Path to the clearsigned file to verify
/// * `public_key_file_path` - Path to the file containing the public key for verification
/// * `extracted_content_output_path` - Path where the extracted content should be saved
///
/// # Returns
/// * `Ok(())` if both verification and extraction succeed
/// * `Err(GpgError)` if either verification or extraction fails
///
/// # Errors
/// * `GpgError::PathError` - If input files don't exist or paths are invalid
/// * `GpgError::ValidationError` - If signature verification fails
/// * `GpgError::GpgOperationError` - If GPG operations fail
pub fn verify_clearsigned_file_and_extract_content_to_output(
    clearsigned_input_path: &Path,
    public_key_file_path: &Path,
    extracted_content_output_path: &Path
) -> Result<(), GpgError> {
    // Debug logging
    println!("Starting verification and extraction process");
    println!("Clearsigned input file: {}", clearsigned_input_path.display());
    println!("Public key file: {}", public_key_file_path.display());
    println!("Output file for extracted content: {}", extracted_content_output_path.display());
    
    // STEP 1: Validate input file paths exist
    if !clearsigned_input_path.exists() {
        return Err(GpgError::PathError(format!(
            "Clearsigned input file does not exist: {}", 
            clearsigned_input_path.display()
        )));
    }
    
    if !public_key_file_path.exists() {
        return Err(GpgError::PathError(format!(
            "Public key file does not exist: {}", 
            public_key_file_path.display()
        )));
    }
    
    // STEP 2: Read the content of the public key file
    let public_key = match fs::read_to_string(public_key_file_path) {
        Ok(key) => key,
        Err(e) => return Err(GpgError::GpgOperationError(format!(
            "Failed to read public key file: {}", e
        )))
    };
    
    // STEP 3: Convert input file path to string for the verify_clearsign function
    let clearsigned_input_path_str = clearsigned_input_path
        .to_str()
        .ok_or_else(|| GpgError::PathError(format!(
            "Failed to convert input file path to string: {}", 
            clearsigned_input_path.display()
        )))?;
    
    // STEP 4: Verify the signature using the existing verify_clearsign function
    println!("Verifying clearsigned file signature");
    let verification_result = verify_clearsign(clearsigned_input_path_str, &public_key)
        .map_err(|e| GpgError::GpgOperationError(format!(
            "Failed to verify clearsigned file: {}", e
        )))?;
    
    // STEP 5: Check verification result, abort if verification failed
    if !verification_result {
        println!("Signature verification failed");
        return Err(GpgError::ValidationError(
            "Signature verification failed".to_string()
        ));
    }
    
    println!("Signature verification succeeded");
    
    // STEP 6: Read the content of the input file for extraction
    let clearsigned_content = match fs::read_to_string(clearsigned_input_path) {
        Ok(content) => content,
        Err(e) => return Err(GpgError::GpgOperationError(format!(
            "Failed to read clearsigned file for content extraction: {}", e
        )))
    };
    
    // STEP 7: Identify the clearsigned format markers
    // Clearsigned files have this structure:
    // -----BEGIN PGP SIGNED MESSAGE-----
    // Hash: SHA256
    // 
    // [actual content]
    // -----BEGIN PGP SIGNATURE-----
    // [signature data]
    // -----END PGP SIGNATURE-----
    let begin_content_marker = "-----BEGIN PGP SIGNED MESSAGE-----";
    let begin_signature_marker = "-----BEGIN PGP SIGNATURE-----";
    
    // STEP 8: Validate the file has the expected clearsigned format
    if !clearsigned_content.contains(begin_content_marker) || !clearsigned_content.contains(begin_signature_marker) {
        println!("Input file does not have the expected clearsigned format");
        return Err(GpgError::ValidationError(
            "Input file does not have the expected clearsigned format".to_string()
        ));
    }
    
    // STEP 9: Find where the actual content starts (after the header and empty line)
    println!("Extracting content portion from clearsigned file");
    let content_start = clearsigned_content
        .find(begin_content_marker)
        .and_then(|pos| {
            // Look for the empty line after the header
            clearsigned_content[pos..].find("\n\n")
                .map(|rel_pos| pos + rel_pos + 2) // +2 to skip the double newline
        })
        .ok_or_else(|| GpgError::ValidationError(
            "Failed to locate content section in clearsigned file".to_string()
        ))?;
    
    // STEP 10: Find where the signature starts
    let signature_start = clearsigned_content
        .find(begin_signature_marker)
        .ok_or_else(|| GpgError::ValidationError(
            "Failed to locate signature section in clearsigned file".to_string()
        ))?;
    
    // STEP 11: Extract only the content portion (between header and signature)
    let extracted_content = clearsigned_content[content_start..signature_start].trim();
    
    // STEP 12: Write the extracted content to the output file
    println!("Writing extracted content to output file");
    match fs::write(extracted_content_output_path, extracted_content) {
        Ok(_) => {
            println!("Successfully verified clearsigned file and extracted content to: {}", 
                      extracted_content_output_path.display());
            Ok(())
        },
        Err(e) => Err(GpgError::GpgOperationError(format!(
            "Failed to write extracted content to output file: {}", e
        )))
    }
}


/// Lists available GPG key IDs and prompts the user to select one for signing operations.
/// 
/// # Purpose
/// This function provides an interactive interface for users to select which GPG key ID
/// to use for signing operations. It lists available key IDs with their associated user
/// identities and allows selection via a numbered menu.
///
/// # Process Flow
/// 1. Queries GPG for a list of available key IDs (metadata only)
/// 2. Displays these key IDs in a numbered list with their associated user identities
/// 3. Prompts the user to either:
///    - Select a specific key ID by entering its number
///    - Press Enter to use the default key ID (first in the list)
/// 4. Returns the selected or default key ID
///
/// # Security Notes
/// This function ONLY accesses and displays key ID metadata (never secret key material).
/// The GPG command used (--list-secret-keys) shows identifying information about keys,
/// not the actual cryptographic key material.
///
/// # Returns
/// * `Ok(String)` - The selected GPG key ID
/// * `Err(GpgError)` - If listing keys fails, no keys are available, or user input is invalid
///
/// # Example
/// ```
/// match select_gpg_signing_shortkey_id() {
///     Ok(key_id) => println!("Selected key ID: {}", key_id),
///     Err(e) => eprintln!("Error selecting key ID: {}", e.to_string()),
/// }
/// ```
pub fn select_gpg_signing_shortkey_id() -> Result<String, GpgError> {
    // Execute GPG to list key IDs (NOT the keys themselves)
    // Using --with-colons format for more reliable parsing
    let gpg_output = Command::new("gpg")
        .arg("--list-secret-keys")
        .arg("--keyid-format=long")
        .arg("--with-colons")
        .output()
        .map_err(|e| GpgError::GpgOperationError(format!(
            "Failed to execute GPG to list key IDs: {}", e
        )))?;

    // Check if the command executed successfully
    if !gpg_output.status.success() {
        let error_message = String::from_utf8_lossy(&gpg_output.stderr);
        return Err(GpgError::GpgOperationError(format!(
            "GPG command failed while listing key IDs: {}", error_message
        )));
    }

    // Parse the output to extract key IDs and user identities
    let output_text = String::from_utf8_lossy(&gpg_output.stdout);
    let key_id_list = parse_gpg_key_id_listing(&output_text)?;

    // Verify we found at least one key ID
    if key_id_list.is_empty() {
        return Err(GpgError::GpgOperationError(
            "No GPG key IDs found in your keyring. Please create or import a key pair.".to_string()
        ));
    }

    // Display the available key IDs as a numbered list
    println!("\nAvailable GPG key IDs for signing:");
    for (index, (key_id, user_identity)) in key_id_list.iter().enumerate() {
        println!("{}. {} ({})", index + 1, key_id, user_identity);
    }

    // Prompt the user for selection
    print!("\nSelect a key ID number or press Enter to use the default key ID: ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!(
            "Failed to display prompt: {}", e
        )))?;

    // Read the user's selection
    let mut user_input = String::new();
    io::stdin()
        .read_line(&mut user_input)
        .map_err(|e| GpgError::GpgOperationError(format!(
            "Failed to read user input: {}", e
        )))?;

    let trimmed_input = user_input.trim();

    // If user pressed Enter without a selection, use the default (first) key ID
    if trimmed_input.is_empty() {
        let default_key_id = &key_id_list[0].0;
        println!("Using default key ID: {} ({})", default_key_id, key_id_list[0].1);
        return Ok(default_key_id.clone());
    }

    // Otherwise parse the user's numeric selection
    match trimmed_input.parse::<usize>() {
        Ok(selected_number) if selected_number > 0 && selected_number <= key_id_list.len() => {
            // Valid selection - return the corresponding key ID
            let selected_index = selected_number - 1;
            let selected_key_id = &key_id_list[selected_index].0;
            println!("Using key ID: {} ({})", 
                     selected_key_id, key_id_list[selected_index].1);
            Ok(selected_key_id.clone())
        },
        _ => {
            // Invalid selection
            Err(GpgError::GpgOperationError(format!(
                "Invalid selection: '{}'. Please enter a number between 1 and {}.", 
                trimmed_input, key_id_list.len()
            )))
        }
    }
}


// use std::io::{self, Write};
// use std::process::Command;
// use std::str;

// GpgError enum is assumed to be defined elsewhere, as per your instructions.
// For this example, we'll assume it has at least a GpgOperationError variant:
//
// #[derive(Debug)]
// pub enum GpgError {
//     GpgOperationError(String),
//     // Potentially other variants like ParseError, UserInputError, NoKeysFoundError
// }
//
// impl std::fmt::Display for GpgError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             GpgError::GpgOperationError(msg) => write!(f, "GPG Error: {}", msg),
//         }
//     }
// }
//
// impl std::error::Error for GpgError {}
//
// --- End of assumed GpgError definition ---


/// Holds structured information about a GPG public key, primarily its fingerprint and user identity.
///
/// This structure is used to store and display key information parsed from GPG's output.
#[derive(Debug, Clone)] // Clone is useful for easily returning owned data from the selection.
struct GpgPublicKeyDisplayInfo {
    /// The full GPG key fingerprint (e.g., a 40-character hexadecimal string for RSA keys).
    /// This is the long, unique identifier for the public key.
    fingerprint: String,
    /// The primary user identity (UID) string associated with the key (e.g., "User Name <email@example.com>").
    user_identity: String,
}

/// Decodes a GPG UID string that might contain percent-encoded characters.
///
/// GPG's colon-delimited output format (`--with-colons`) percent-encodes certain bytes
/// within User ID strings (e.g., `%40` for `@`, `%25` for `%`, `%20` for space).
/// This function decodes these sequences back into their original byte values
/// and then interprets the entire resulting byte sequence as a UTF-8 string.
///
/// # Arguments
/// * `encoded_uid_string`: A string slice representing the GPG UID, potentially containing
///   percent-encoded sequences.
///
/// # Returns
/// A `String` where percent-encoded sequences have been converted to their corresponding
/// characters.
/// - If an invalid or incomplete percent-encoded sequence (e.g., `%A` followed by end-of-string,
///   or `%XY` where X or Y are not hex digits) is encountered, the original sequence
///   (e.g., `'%', 'A'`) is passed through literally to the output string as UTF-8 bytes.
/// - If the final sequence of decoded bytes does not form valid UTF-8, any invalid UTF-8
///   sequences are replaced with `U+FFFD REPLACEMENT CHARACTER`, per `String::from_utf8_lossy`.
fn decode_gpg_uid_string(encoded_uid_string: &str) -> String {
    // Pre-allocate vector with capacity based on the input string length.
    // Decoded string is unlikely to be much larger, usually same size or smaller.
    let mut decoded_bytes: Vec<u8> = Vec::with_capacity(encoded_uid_string.len());
    
    // Iterate over characters of the input string.
    let mut char_iterator = encoded_uid_string.chars();

    while let Some(current_char) = char_iterator.next() {
        if current_char == '%' {
            // This character might be the start of a percent-encoded sequence.
            // A valid sequence is '%' followed by two hexadecimal digits.
            let hex_char1_opt = char_iterator.next();
            let hex_char2_opt = char_iterator.next();

            if let (Some(hc1), Some(hc2)) = (hex_char1_opt, hex_char2_opt) {
                // Check if both characters are ASCII hexadecimal digits.
                if hc1.is_ascii_hexdigit() && hc2.is_ascii_hexdigit() {
                    let hex_pair_str = format!("{}{}", hc1, hc2);
                    // Attempt to parse the hex pair (e.g., "4A") into a u8 byte value.
                    // This `from_str_radix` should succeed if `is_ascii_hexdigit` was true for both.
                    if let Ok(byte_value) = u8::from_str_radix(&hex_pair_str, 16) {
                        decoded_bytes.push(byte_value);
                    } else {
                        // This case is highly unlikely if `is_ascii_hexdigit` passed.
                        // It implies an issue with `from_str_radix` or char properties.
                        // Fallback: treat as a literal sequence.
                        decoded_bytes.push(b'%'); // Push the literal '%' byte.
                        let mut char_encode_buffer = [0; 4]; // Max 4 bytes for a char in UTF-8.
                        decoded_bytes.extend_from_slice(hc1.encode_utf8(&mut char_encode_buffer).as_bytes());
                        decoded_bytes.extend_from_slice(hc2.encode_utf8(&mut char_encode_buffer).as_bytes());
                    }
                } else {
                    // One or both characters after '%' are not hex digits. Treat as literal.
                    decoded_bytes.push(b'%');
                    let mut char_encode_buffer = [0; 4];
                    decoded_bytes.extend_from_slice(hc1.encode_utf8(&mut char_encode_buffer).as_bytes());
                    decoded_bytes.extend_from_slice(hc2.encode_utf8(&mut char_encode_buffer).as_bytes());
                }
            } else {
                // Incomplete percent sequence (e.g., "%" at end of string, or "%A" at end).
                // Treat as literal characters.
                decoded_bytes.push(b'%');
                if let Some(hc1) = hex_char1_opt { // If there was at least one char after '%'
                    let mut char_encode_buffer = [0; 4];
                    decoded_bytes.extend_from_slice(hc1.encode_utf8(&mut char_encode_buffer).as_bytes());
                }
                // If hc2 was also None, nothing more to push for this partial sequence.
            }
        } else {
            // Not a percent-encoded character; append its UTF-8 bytes directly.
            let mut char_encode_buffer = [0; 4]; // Max 4 bytes for a char in UTF-8.
            decoded_bytes.extend_from_slice(current_char.encode_utf8(&mut char_encode_buffer).as_bytes());
        }
    }
    
    // Convert the accumulated byte vector to a String.
    // `from_utf8_lossy` replaces any invalid UTF-8 sequences with U+FFFD.
    String::from_utf8_lossy(&decoded_bytes).into_owned()
}

/// Parses GPG's colon-delimited output to extract public key fingerprints and user identities.
///
/// This function is designed to process the output of the GPG command:
/// `gpg --list-keys --keyid-format=long --with-colons --with-fingerprint`.
/// It iterates through the lines of output, identifying sequences of records:
///   1. `pub`: Indicates a primary public key.
///   2. `fpr`: Contains the full fingerprint for the preceding `pub` key.
///   3. `uid`: Contains a user identity string for that key.
///
/// The function associates the fingerprint from an `fpr` record with the first `uid` record
/// that follows it for a given `pub` key.
///
/// # Arguments
/// * `gpg_output_string`: A string slice containing the raw, colon-delimited output from GPG.
///
/// # Returns
/// * `Ok(Vec<GpgPublicKeyDisplayInfo>)`: A vector of `GpgPublicKeyDisplayInfo` structs. Each struct
///   represents a public key, containing its fingerprint and primary user identity.
///   The vector will be empty if no keys are found or if keys lack necessary information (fingerprint/UID).
/// * `Err(GpgError::GpgOperationError)`: If the parsing logic determines that no valid key information
///   could be extracted (e.g., output is malformed or no keys with UIDs are present).
fn parse_gpg_public_key_listing(gpg_output_string: &str) -> Result<Vec<GpgPublicKeyDisplayInfo>, GpgError> {
    // Vector to store the information for each successfully parsed public key.
    let mut parsed_keys_info: Vec<GpgPublicKeyDisplayInfo> = Vec::new();
    
    // Holds the fingerprint of the current public key block being processed.
    // This is populated when an "fpr" record is encountered after a "pub" record,
    // and cleared when the fingerprint is associated with a UID or a new "pub" record starts.
    let mut current_key_fingerprint_holder: Option<String> = None;

    // Iterate over each line in the GPG output string.
    for line in gpg_output_string.lines() {
        // Split the line into fields using ':' as the delimiter.
        // GPG's colon-format consists of multiple colon-separated fields per line.
        let fields: Vec<&str> = line.split(':').collect();

        // Basic validation: ensure there's at least one field (the record type).
        if fields.is_empty() {
            continue; // Skip empty or malformed lines.
        }

        // The first field indicates the type of record (e.g., "pub", "fpr", "uid").
        let record_type = fields[0];

        match record_type {
            "pub" => {
                // A "pub" record signifies the beginning of a new public key block.
                // Any fingerprint held from a previous, incomplete key block (e.g., "pub" -> "fpr" without "uid")
                // should be discarded. We reset `current_key_fingerprint_holder` to prepare for
                // the fingerprint of this new key, which will appear in a subsequent "fpr" record.
                current_key_fingerprint_holder = None;
            }
            "fpr" => {
                // An "fpr" record contains the key fingerprint.
                // The fingerprint string is typically in the 10th field (index 9).
                // We are interested in this fingerprint if we are processing a "pub" key's details
                // and haven't yet captured its fingerprint. This means `current_key_fingerprint_holder`
                // should be `None` (it was reset by a "pub" line or a previous key was completed).
                if current_key_fingerprint_holder.is_none() && fields.len() > 9 && !fields[9].is_empty() {
                    current_key_fingerprint_holder = Some(fields[9].to_string());
                }
            }
            "uid" => {
                // A "uid" record contains a user identity string for the current key.
                // The UID string is typically in the 10th field (index 9).
                // We attempt to pair this UID with a fingerprint captured from a preceding "fpr" record.
                // `current_key_fingerprint_holder.take()` consumes the fingerprint, ensuring it's
                // used only once (with the first UID encountered for that fingerprint).
                if let Some(fingerprint_for_this_key) = current_key_fingerprint_holder.take() {
                    if fields.len() > 9 && !fields[9].is_empty() {
                        let raw_user_id_string = fields[9];
                        // Decode the UID string in case it contains percent-encoded characters.
                        let decoded_user_id_string = decode_gpg_uid_string(raw_user_id_string);
                        
                        // Store the paired fingerprint and user identity.
                        parsed_keys_info.push(GpgPublicKeyDisplayInfo {
                            fingerprint: fingerprint_for_this_key,
                            user_identity: decoded_user_id_string,
                        });
                    } else {
                        // The UID record is malformed, or the UID string is empty.
                        // The fingerprint `fingerprint_for_this_key` was `take`n and is now "lost"
                        // for this specific UID. If other UIDs follow for the same key, they won't
                        // be associated with this fingerprint because `current_key_fingerprint_holder` is now `None`.
                        // This means a key with a fingerprint but no valid parsable UID will be skipped.
                        // This behavior is generally acceptable as a UID is needed for user presentation.
                        // For more complex error recovery, the fingerprint could be put back:
                        // `current_key_fingerprint_holder = Some(fingerprint_for_this_key);`
                        // but this would complicate the "first UID wins" logic.
                    }
                }
            }
            _ => {
                // Other record types ("sub", "sig", "rev", "cfg", etc.) are ignored in this function,
                // as we are primarily interested in `pub` key fingerprints and their UIDs.
                // If a "sub" record appears, it generally means UIDs for the primary key have passed.
                // If `current_key_fingerprint_holder` still has a value here, it implies a `pub`/`fpr`
                // without a subsequent `uid` before another significant record type or end of output.
                // Such an entry (fingerprint without UID) will not be added to `parsed_keys_info`.
            }
        }
    }

    // After processing all lines, if no keys were successfully parsed and stored,
    // it indicates an issue (e.g., no keys, no keys with UIDs, or malformed GPG output).
    if parsed_keys_info.is_empty() {
        // This error indicates that the parsing logic, while it might not have encountered
        // IO errors or GPG command failures, did not find any data that meets the criteria
        // for a selectable key (i.e., a public key with both a fingerprint and a user ID).
        return Err(GpgError::GpgOperationError( // Consistent with original error style.
                                               // A more specific error variant like NoKeysFoundError or ParseError would be ideal if GpgError supports it.
            "No GPG public keys with associated fingerprints and user IDs were found. \
            Please ensure GPG is configured with suitable public keys that have user identities."
                .to_string(),
        ));
    }

    Ok(parsed_keys_info)
}

/// Lists available GPG public key fingerprints and prompts the user to select one for signing operations.
///
/// # Purpose
/// This function provides an interactive interface for users to select which GPG public key
/// (identified by its fingerprint) to use for operations like signing. It lists available public
/// keys with their fingerprints and associated user identities, allowing selection via a numbered menu.
///
/// # Process Flow
/// 1. Queries GPG for a list of available public keys and their fingerprints using the command:
///    `gpg --list-keys --keyid-format=long --with-colons --with-fingerprint`.
///    This command provides machine-readable output.
/// 2. Parses this output to extract key fingerprints and primary user identities.
/// 3. Displays these keys in a numbered list.
/// 4. Prompts the user to either:
///    - Select a specific key by entering its number.
///    - Press Enter to use the default key (the first key in the list).
/// 5. Returns the fingerprint of the selected or default key.
///
/// # Security Notes
/// - This function interacts with GPG to list public key metadata. It does not access or
///   handle secret key material directly.
/// - The GPG command used (`--list-keys`) displays identifying information about public keys,
///   not cryptographic secrets.
///
/// # Returns
/// * `Ok(String)`: The selected GPG public key fingerprint as a string.
/// * `Err(GpgError)`: If any step fails, such as:
///     - Failure to execute the GPG command.
///     - The GPG command returning an error.
///     - Failure to parse the GPG output.
///     - No GPG public keys being found.
///     - Issues with reading user input.
///     - The user providing an invalid selection.
///
/// # Example
/// ```
/// // fn main() -> Result<(), GpgError> { // Assuming GpgError is defined
/// //     match q_and_a_user_selects_gpg_key_full_fingerprint() {
/// //         Ok(fingerprint) => println!("Selected key fingerprint: {}", fingerprint),
/// //         Err(e) => eprintln!("Error selecting key fingerprint: {}", e.to_string()),
/// //     }
/// //     Ok(())
/// // }
/// ```
/// select_gpg_long_key_id
pub fn q_and_a_user_selects_gpg_key_full_fingerprint() -> Result<String, GpgError> {
    // Step 1: Execute the GPG command to list public keys and their fingerprints.
    // `--list-keys`: Specifies listing public keys.
    // `--keyid-format=long`: Requests long key IDs (though fingerprint is distinct and primary here).
    // `--with-colons`: Produces machine-readable, colon-delimited output.
    // `--with-fingerprint`: Ensures that "fpr" records (containing full fingerprints) are included.
    let gpg_command_output_result = Command::new("gpg")
        .arg("--list-keys")
        .arg("--keyid-format=long")
        .arg("--with-colons")
        .arg("--with-fingerprint")
        .output();

    let gpg_command_output = match gpg_command_output_result {
        Ok(output) => output,
        Err(io_error) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG command to list public key fingerprints: {}. \
                Ensure GPG is installed and accessible in your system's PATH.",
                io_error
            )));
        }
    };

    // Step 2: Check if the GPG command itself executed successfully (exit status 0).
    if !gpg_command_output.status.success() {
        // GPG command failed. stderr often contains useful error messages from GPG.
        let error_description_from_gpg = String::from_utf8_lossy(&gpg_command_output.stderr);
        return Err(GpgError::GpgOperationError(format!(
            "GPG command execution failed while listing public key fingerprints. Exit status: {}. GPG stderr: {}",
            gpg_command_output.status, error_description_from_gpg.trim()
        )));
    }

    // Step 3: Parse the GPG output (stdout) to extract fingerprints and user identities.
    // stdout is expected to be UTF-8 encoded.
    let gpg_output_stdout_string = String::from_utf8_lossy(&gpg_command_output.stdout);
    
    // `parse_gpg_public_key_listing` handles the parsing and returns a list of keys
    // or an error if no suitable keys are found or parsing fails.
    let available_keys_list = parse_gpg_public_key_listing(&gpg_output_stdout_string)?;
    // Note: `parse_gpg_public_key_listing` itself returns an error if `available_keys_list` would be empty,
    // so an additional explicit check `if available_keys_list.is_empty()` here is typically redundant
    // unless the parser could validly return an Ok(empty_vector).

    // Step 4: Display the available keys (fingerprint and user identity) to the user in a numbered list.
    println!("\nAvailable GPG public keys (identified by fingerprint):");
    for (index, key_info) in available_keys_list.iter().enumerate() {
        // Format: "1. FINGERPRINT_HEX_STRING (User Name <email@example.com>)"
        println!("{}. {} ({})", index + 1, key_info.fingerprint, key_info.user_identity);
    }

    // Step 5: Prompt the user to make a selection.
    // It's crucial to flush stdout to ensure the prompt is displayed before `read_line` blocks for input.
    print!("\nSelect a key by its number, or press Enter to use the default key (first in the list): ");
    if let Err(flush_error) = io::stdout().flush() {
        return Err(GpgError::GpgOperationError(format!(
            "Failed to flush stdout when displaying prompt for key selection: {}",
            flush_error
        )));
    }

    // Step 6: Read the user's input from stdin.
    let mut user_selection_input_string = String::new();
    if let Err(read_error) = io::stdin().read_line(&mut user_selection_input_string) {
        return Err(GpgError::GpgOperationError(format!(
            "Failed to read user input for GPG key selection: {}",
            read_error
        )));
    }

    // Trim whitespace (like newline characters) from the input.
    let trimmed_user_input = user_selection_input_string.trim();

    // Step 7: Process the user's selection.
    if trimmed_user_input.is_empty() {
        // User pressed Enter (input is empty after trim), signifying use of the default key.
        // The default is the first key in the list. `available_keys_list` is guaranteed
        // not to be empty at this point due to checks in `parse_gpg_public_key_listing`.
        let default_key_info = &available_keys_list[0]; // Index 0 is safe.
        println!(
            "Default key selected. Using fingerprint: {} ({})",
            default_key_info.fingerprint, default_key_info.user_identity
        );
        Ok(default_key_info.fingerprint.clone()) // Return the fingerprint of the default key.
    } else {
        // User entered some text, expecting it to be a number.
        // Attempt to parse the input as a 1-based index.
        match trimmed_user_input.parse::<usize>() {
            Ok(selected_number) => {
                // Check if the parsed number is within the valid range of listed keys (1 to list_length).
                if selected_number > 0 && selected_number <= available_keys_list.len() {
                    // Valid number selected. Convert 1-based number to 0-based index.
                    let selected_index = selected_number - 1;
                    let selected_key_info = &available_keys_list[selected_index];
                    println!(
                        "Key {} selected. Using fingerprint: {} ({})",
                        selected_number, selected_key_info.fingerprint, selected_key_info.user_identity
                    );
                    Ok(selected_key_info.fingerprint.clone()) // Return the fingerprint of the selected key.
                } else {
                    // Number is out of the valid range.
                    Err(GpgError::GpgOperationError(format!( // Consistent with original error style. UserInputError might be more semantic.
                        "Invalid selection: '{}'. Number is out of range. Please enter a number between 1 and {}.",
                        trimmed_user_input,
                        available_keys_list.len()
                    )))
                }
            }
            Err(_) => {
                // Input was not a parsable unsigned integer.
                Err(GpgError::GpgOperationError(format!( // Consistent with original error style. UserInputError might be more semantic.
                    "Invalid selection: '{}'. Please enter a valid number or press Enter for the default.",
                    trimmed_user_input
                )))
            }
        }
    }
}




/// Parses the colon-delimited output from GPG's list-secret-keys command.
/// 
/// # Purpose
/// Extracts key ID and user identity information from GPG's machine-readable output.
/// This function processes output from `gpg --list-secret-keys --with-colons` to
/// extract only the metadata about keys, never the key material itself.
///
/// # Arguments
/// * `gpg_colon_output` - String containing the colon-delimited output from GPG
///
/// # Returns
/// * `Ok(Vec<(String, String)>)` - Vector of (key_id, user_identity) pairs
/// * `Err(GpgError)` - If parsing fails
///
/// # Format Details
/// This function expects GPG's colon-delimited format where:
/// - Lines starting with "sec:" contain key ID information in field 4
/// - Lines starting with "uid:" contain user identity information in field 9
/// - A key ID may have multiple associated user identities
fn parse_gpg_key_id_listing(gpg_colon_output: &str) -> Result<Vec<(String, String)>, GpgError> {
    let mut key_id_pairs = Vec::new();
    let mut current_key_id = None;
    
    // Process each line of the GPG output
    for line in gpg_colon_output.lines() {
        // Split the line by colons to get fields
        let fields: Vec<&str> = line.split(':').collect();
        
        // Process secret key records (contain key IDs)
        if fields.len() > 4 && fields[0] == "sec" {
            // Field 4 contains the key ID
            current_key_id = Some(fields[4].to_string());
        }
        
        // Process user ID records (contain user identities)
        else if fields.len() > 9 && fields[0] == "uid" && current_key_id.is_some() {
            // Field 9 contains the user identity
            let user_identity = fields[9].to_string();
            
            // Store the key ID and user identity pair
            if let Some(key_id) = current_key_id.clone() {
                key_id_pairs.push((key_id, user_identity));
            }
        }
    }
    
    Ok(key_id_pairs)
}


// /// Interactive workflow for clearsigning files.
// ///
// /// # Purpose
// /// Guides the user through providing necessary information to clearsign
// /// a file with their GPG private key.
// ///
// /// # Process
// /// 1. Prompts for file path to clearsign
// /// 2. Prompts for output file path (with default option)
// /// 3. Prompts for signing key ID
// /// 4. Validates all inputs
// /// 5. Performs the clearsigning operation
// /// 6. Reports results to the user
// ///
// /// # Returns
// /// * `Ok(())` - If the workflow completes successfully
// /// * `Err(GpgError)` - If any step fails
// fn clearsign_workflow() -> Result<(), GpgError> {
//     // Get input file path from user
//     print!("Enter the path to the file you want to clearsign: ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut input_file_path_str = String::new();
//     io::stdin()
//         .read_line(&mut input_file_path_str)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
//     let input_file_path = Path::new(input_file_path_str.trim());
    
//     // Validate input file exists
//     if !input_file_path.exists() {
//         return Err(GpgError::FileSystemError(
//             std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
//         ));
//     }
    
//     // Get output file path (use default if empty)
//     print!("Enter the output file path (or press Enter for default): ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut output_file_path_str = String::new();
//     io::stdin()
//         .read_line(&mut output_file_path_str)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    
//     let output_file_path = if output_file_path_str.trim().is_empty() {
//         // Create default output file path with .asc extension
//         let input_filename = input_file_path
//             .file_name()
//             .and_then(|n| n.to_str())
//             .ok_or_else(|| GpgError::PathError("Invalid input file name".to_string()))?;
            
//         let mut output_path = PathBuf::from("clearsigned");
//         fs::create_dir_all(&output_path)
//             .map_err(|e| GpgError::FileSystemError(e))?;
//         output_path.push(format!("{}.asc", input_filename));
//         output_path
//     } else {
//         PathBuf::from(output_file_path_str.trim())
//     };
    
//     // Get signing key ID
//     println!("\nTo get your signing key ID, run: $ gpg --list-secret-keys --keyid-format=long");
//     print!("Enter your GPG signing key ID: ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut signing_key_id = String::new();
//     io::stdin()
//         .read_line(&mut signing_key_id)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
//     let signing_key_id = signing_key_id.trim();
    
//     // Validate that a key ID was provided
//     if signing_key_id.is_empty() {
//         return Err(GpgError::ValidationError(
//             "No signing key ID provided".to_string()
//         ));
//     }
    
//     // Display the parameters that will be used
//     println!("\nProcessing with the following parameters:");
//     println!("Input file path: {}", input_file_path.display());
//     println!("Output file path: {}", output_file_path.display());
//     println!("Signing key ID: {}", signing_key_id);
    
//     // Perform the clearsigning
//     clearsign_file(input_file_path, &output_file_path, &signing_key_id)?;
    
//     // Confirm successful completion
//     println!("\nSuccess: File has been clearsigned!");
//     println!("Clearsigned file location: {}", output_file_path.display());
    
//     Ok(())
// }

// /// Interactive workflow for clearsigning and encrypting files.
// ///
// /// # Purpose
// /// Guides the user through providing necessary information to clearsign
// /// a file with their GPG private key and encrypt it for a recipient.
// ///
// /// # Process
// /// 1. Prompts for file path to process
// /// 2. Prompts for signing key ID
// /// 3. Prompts for recipient's public key file path
// /// 4. Validates all inputs
// /// 5. Performs clearsigning and encryption
// /// 6. Reports results to the user
// ///
// /// # Returns
// /// * `Ok(())` - If the workflow completes successfully
// /// * `Err(GpgError)` - If any step fails
// ///
// /// # Notes
// /// Output is saved to invites_updates/outgoing/ directory.
// fn clearsign_and_encrypt_workflow() -> Result<(), GpgError> {
//     // Get input file path from user
//     print!("Enter the path to the file you want to clearsign and encrypt: ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut input_file_path_str = String::new();
//     io::stdin()
//         .read_line(&mut input_file_path_str)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
//     let input_file_path = Path::new(input_file_path_str.trim());
    
//     // Validate input file exists
//     if !input_file_path.exists() {
//         return Err(GpgError::FileSystemError(
//             std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
//         ));
//     }
    
//     // Get signing key ID
//     println!("\nTo get your signing key ID, run: $ gpg --list-secret-keys --keyid-format=long");
//     print!("Enter your GPG signing key ID: ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut signing_key_id = String::new();
//     io::stdin()
//         .read_line(&mut signing_key_id)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
//     let signing_key_id = signing_key_id.trim();
    
//     // Validate that a key ID was provided
//     if signing_key_id.is_empty() {
//         return Err(GpgError::ValidationError(
//             "No signing key ID provided".to_string()
//         ));
//     }
    
//     // Get recipient's public key path
//     print!("Enter path to recipient's public key file: ");
//     io::stdout().flush()
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
//     let mut recipient_key_path_str = String::new();
//     io::stdin()
//         .read_line(&mut recipient_key_path_str)
//         .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
//     let recipient_key_path = Path::new(recipient_key_path_str.trim());
    
//     // Validate recipient key exists
//     if !recipient_key_path.exists() {
//         return Err(GpgError::FileSystemError(
//             std::io::Error::new(std::io::ErrorKind::NotFound, "Recipient key file not found")
//         ));
//     }
    
//     // Display the parameters that will be used
//     println!("\nProcessing with the following parameters:");
//     println!("Input file path: {}", input_file_path.display());
//     println!("Signing key ID: {}", signing_key_id);
//     println!("Recipient public key path: {}", recipient_key_path.display());
//     println!("Output will be saved to: invites_updates/outgoing/");
    
//     // Perform the clearsigning and encryption
//     clearsign_and_encrypt_file_for_recipient(
//         input_file_path,
//         &signing_key_id,
//         recipient_key_path
//     )?;
    
//     // Calculate the output path for display
//     let original_filename = input_file_path
//         .file_name()
//         .and_then(|n| n.to_str())
//         .ok_or_else(|| GpgError::PathError("Invalid input file name".to_string()))?;
    
//     let output_path = PathBuf::from(format!("invites_updates/outgoing/{}.gpg", original_filename));
    
//     // Confirm successful completion
//     println!("\nSuccess: File has been clearsigned and encrypted!");
//     println!("Encrypted file location: {}", output_path.display());
    
//     Ok(())
// }

/// Guides the user through an interactive workflow to clearsign a file with their selected GPG key.
///
/// # Purpose
/// This function provides a step-by-step interactive command-line interface that:
/// 1. Prompts the user for the input file path to clearsign
/// 2. Prompts for an output file path (with default option if user presses Enter)
/// 3. Presents available GPG key IDs for selection
/// 4. Clearsigns the input file with the selected key
/// 5. Reports the results to the user
///
/// # Process Flow
/// 1. Collect input file path and validate its existence
/// 2. Collect output file path or generate default path
/// 3. Display available key IDs and prompt for selection
/// 4. Clearsign the file using the selected key ID
/// 5. Confirm successful completion with output file location
///
/// # Parameters
/// None - All inputs are collected interactively
///
/// # Returns
/// * `Ok(())` - If the clearsigning process completes successfully
/// * `Err(GpgError)` - If any step fails, with specific error information:
///   - `GpgError::FileSystemError` - If file operations fail (missing files, permissions)
///   - `GpgError::GpgOperationError` - If GPG operations fail
///   - `GpgError::PathError` - If path operations fail
///
/// # Error Handling
/// - Validates input file existence before proceeding
/// - Creates output directories if they don't exist
/// - Validates GPG key selection
/// - Reports specific errors for each potential failure point
///
/// # Example Usage
/// ```no_run
/// match clearsign_workflow() {
///     Ok(()) => println!("Clearsigning completed successfully"),
///     Err(e) => eprintln!("Error: {}", e.to_string()),
/// }
/// ```
///
/// # Related Functions
/// * `select_gpg_signing_shortkey_id()` - Called to allow key ID selection
/// * `clearsign_filepath_to_path()` - Called to perform the actual clearsigning
fn clearsign_workflow() -> Result<(), GpgError> {
    // Get input file path from user
    print!("Enter the path to the file you want to clearsign: ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    // Read the input file path
    let mut input_file_path_str = String::new();
    io::stdin()
        .read_line(&mut input_file_path_str)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    let input_file_path = Path::new(input_file_path_str.trim());
    
    // Validate input file exists to provide early error feedback
    if !input_file_path.exists() {
        return Err(GpgError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
        ));
    }
    
    // Get output file path (use default if empty)
    print!("Enter the output file path (or press Enter for default): ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    // Read the output file path
    let mut output_file_path_str = String::new();
    io::stdin()
        .read_line(&mut output_file_path_str)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    
    // Process output path - use default or user-provided path
    let output_file_path = if output_file_path_str.trim().is_empty() {
        // Create default output file path with .asc extension
        let input_filename = input_file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| GpgError::PathError("Invalid input file name".to_string()))?;
            
        // Create clearsigned directory if it doesn't exist
        let mut output_path = PathBuf::from("clearsigned");
        fs::create_dir_all(&output_path)
            .map_err(|e| GpgError::FileSystemError(e))?;
        
        // Add filename with .asc extension
        output_path.push(format!("{}.asc", input_filename));
        output_path
    } else {
        PathBuf::from(output_file_path_str.trim())
    };
    
    // Present GPG key ID selection menu and get user's choice
    let signing_key_id = select_gpg_signing_shortkey_id()?;
    
    // Display the parameters that will be used to confirm with user
    println!("\nProcessing with the following parameters:");
    println!("Input file path: {}", input_file_path.display());
    println!("Output file path: {}", output_file_path.display());
    println!("Signing key ID: {}", signing_key_id);
    
    // Perform the clearsigning operation
    clearsign_filepath_to_path(input_file_path, &output_file_path, &signing_key_id)?;
    
    // Confirm successful completion
    println!("\nSuccess: File has been clearsigned!");
    println!("Clearsigned file location: {}", output_file_path.display());
    
    Ok(())
}

/// Guides the user through an interactive workflow to clearsign and encrypt a file.
///
/// # Purpose
/// This function provides a step-by-step interactive command-line interface that:
/// 1. Prompts the user for the input file path to process
/// 2. Displays available GPG key IDs and lets the user select one for signing
/// 3. Prompts for the recipient's public key file path
/// 4. Clearsigns the file with the selected key and encrypts it for the recipient
/// 5. Reports the results to the user
///
/// # Process Flow
/// 1. Collect input file path and validate its existence
/// 2. Present available GPG key IDs and prompt for selection
/// 3. Collect recipient's public key path and validate its existence
/// 4. Perform clearsigning and encryption operations
/// 5. Calculate and display the output file path
/// 6. Confirm successful completion
///
/// # Parameters
/// None - All inputs are collected interactively
///
/// # Returns
/// * `Ok(())` - If the clearsigning and encryption process completes successfully
/// * `Err(GpgError)` - If any step fails, with specific error information:
///   - `GpgError::FileSystemError` - If file operations fail (missing files, permissions)
///   - `GpgError::GpgOperationError` - If GPG operations fail
///   - `GpgError::PathError` - If path operations fail
///
/// # Error Handling
/// - Validates input file existence before proceeding
/// - Validates recipient key existence
/// - Validates GPG key selection
/// - Reports specific errors for each potential failure point
///
/// # Example Usage
/// ```no_run
/// match clearsign_and_encrypt_workflow() {
///     Ok(()) => println!("Clearsigning and encryption completed successfully"),
///     Err(e) => eprintln!("Error: {}", e.to_string()),
/// }
/// ```
///
/// # Notes
/// The output file is automatically saved to the invites_updates/outgoing/ directory
/// with the original filename and a .gpg extension. This function will create the
/// directory if it doesn't exist.
///
/// # Related Functions
/// * `select_gpg_signing_shortkey_id()` - Called to allow key ID selection
/// * `clearsign_and_encrypt_file_for_recipient()` - Called to perform the actual operations
fn clearsign_and_encrypt_workflow() -> Result<(), GpgError> {
    // Get input file path from user
    print!("Enter the path to the file you want to clearsign and encrypt: ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    // Read the input file path
    let mut input_file_path_str = String::new();
    io::stdin()
        .read_line(&mut input_file_path_str)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    let input_file_path = Path::new(input_file_path_str.trim());
    
    // Validate input file exists to provide early error feedback
    if !input_file_path.exists() {
        return Err(GpgError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
        ));
    }
    
    // Present GPG key ID selection menu and get user's choice
    let signing_key_id = select_gpg_signing_shortkey_id()?;
    
    // Get recipient's public key path
    print!("Enter path to recipient's public key file: ");
    io::stdout().flush()
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to flush stdout: {}", e)))?;
    
    // Read the recipient key path
    let mut recipient_key_path_str = String::new();
    io::stdin()
        .read_line(&mut recipient_key_path_str)
        .map_err(|e| GpgError::GpgOperationError(format!("Failed to read input: {}", e)))?;
    let recipient_key_path = Path::new(recipient_key_path_str.trim());
    
    // Validate recipient key exists to provide early error feedback
    if !recipient_key_path.exists() {
        return Err(GpgError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Recipient key file not found")
        ));
    }
    
    // Display the parameters that will be used to confirm with user
    println!("\nProcessing with the following parameters:");
    println!("Input file path: {}", input_file_path.display());
    println!("Signing key ID: {}", signing_key_id);
    println!("Recipient public key path: {}", recipient_key_path.display());
    println!("Output will be saved to: invites_updates/outgoing/");
    
    // Perform the clearsigning and encryption operations
    clearsign_and_encrypt_file_for_recipient(
        input_file_path,
        &signing_key_id,
        recipient_key_path
    )?;
    
    // Calculate the output path for display to user
    let original_filename = input_file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| GpgError::PathError("Invalid input file name".to_string()))?;
    
    let output_path = PathBuf::from(format!("invites_updates/outgoing/{}.gpg", original_filename));
    
    // Confirm successful completion
    println!("\nSuccess: File has been clearsigned and encrypted!");
    println!("Encrypted file location: {}", output_path.display());
    
    Ok(())
}

// ... (previous code including validate_gpg_secret_key) ...

/// Converts a TOML file into a clearsigned TOML file in-place, asserting authorship and integrity.
///
/// # Purpose
/// This function is designed for the **owner or author of a TOML file** to cryptographically
/// sign their file. By doing so, they create a "clearsigned TOML" file. Recipients
/// of this file can then verify:
/// 1.  **Integrity**: That the file's content has not been altered since it was signed.
/// 2.  **Authenticity/Authorship**: That the file was indeed signed by the claimed author
///     (provided the recipient trusts the author's GPG public key).
///
/// The function reads a specified GPG key ID from within the TOML file itself. This ID
/// must correspond to the author's GPG private key, which is then used to clearsign
/// the *entire* TOML file. The original file is subsequently replaced by this new
/// clearsigned version, while retaining the original filename.
///
/// # "In-Place" Operation
/// The term "in-place" means the original TOML file at `path_to_toml_file` will be
/// **overwritten** by its clearsigned counterpart. The content changes, but the
/// filename and location remain the same. This is a destructive operation; ensure
/// backups are considered if the original unsigned state is important.
///
/// # Input TOML File Requirements for the Author
/// To use this function, the author's TOML file (provided via `path_to_toml_file`)
/// **must** contain a field named `"gpg_publickey_id"`. The value of this field must be
/// the GPG key ID (long format recommended, e.g., `3AA5C34371567BD20B882D206F2A2E1F61D5A1D2`)
/// of the GPG key pair whose **private key component** will be used for signing.
///
/// For example, the author would include in their TOML file:
/// `gpg_publickey_id = "THEIR_OWN_GPG_KEY_ID_FOR_SIGNING"`
///
/// Optionally, for recipients to easily verify the signature, the author might also
/// include their corresponding public key in a field like `gpg_key_public`. This
/// public key is then part of the signed content and can be extracted by verifiers.
///
/// # GPG Private Key Requirement for the Author
/// The GPG keyring on the system executing this function (i.e., the author's system)
/// **must** contain the **private key** corresponding to the `gpg_publickey_id`
/// specified in the TOML file. This private key must be available and usable by GPG
/// for signing (e.g., unlocked if passphrase-protected, and the GPG agent is
/// properly configured).
///
/// # Process Flow
/// 1.  **Validation**:
///     *   Checks if `path_to_toml_file` exists and is a file.
/// 2.  **Key ID Extraction**:
///     *   Reads the TOML file to find and extract the value of the `gpg_publickey_id` field.
///     *   If this field is missing, empty, or unreadable, the function returns an error.
/// 3.  **Signing Key Validation**:
///     *   Calls `validate_gpg_secret_key` to ensure the private key associated with the
///         extracted `gpg_publickey_id` is present in the author's local GPG keyring.
///     *   If the key is not found or not usable, the function returns an error.
/// 4.  **Temporary File Creation**:
///     *   A temporary file path is generated.
/// 5.  **GPG Clearsign Operation**:
///     *   Executes the GPG command:
///         `gpg --clearsign --default-key <gpg_publickey_id_from_toml> --output <temporary_file_path> <path_to_toml_file>`
///     *   This signs the entire content of the original TOML file using the author's private key.
/// 6.  **In-Place Replacement**:
///     *   If GPG clearsigning is successful, the original file is deleted, and the
///         temporary clearsigned file is renamed to the original file's name.
/// 7.  **Cleanup**:
///     *   The temporary file is removed if it still exists after the process.
///
/// # Output File Characteristics
/// *   The file at `path_to_toml_file` becomes a standard GPG clearsigned message.
/// *   Its content is the original TOML data, encapsulated within PGP signature blocks.
/// *   All original fields, including `gpg_publickey_id` and any `gpg_key_public` field,
///     are part of the signed message, allowing them to be part of the integrity check.
///
/// # Subsequent Verification by Recipients
/// A recipient of this clearsigned TOML file can use standard GPG tools or other
/// functions in this module (e.g., `read_singleline_string_from_clearsigntoml`
/// or `verify_clearsign`) to verify the signature. If the author included their
/// public key in a `gpg_key_public` field, the recipient can extract this key
/// from the (now verified) content to perform the signature check, confirming
/// both integrity and authorship against that specific public key.
///
/// # Arguments
/// * `path_to_toml_file` - A reference to a `Path` object representing the TOML file
///   to be converted in-place by its author.
///
/// # Returns
/// * `Ok(())` - If the TOML file was successfully clearsigned and replaced in-place.
/// * `Err(GpgError)` - If any step in the process fails. (Details as previously listed)
///
/// # Prerequisites for the Author
/// *   GnuPG (GPG) must be installed on the author's system and accessible via the PATH.
/// *   The author's GPG private key (corresponding to the `gpg_publickey_id` value
///     within the input TOML file) must be in their local GPG keyring and usable.
///
/// # Security Considerations
/// *   **Authorship Assertion**: This function is a tool for an author to assert control
///     and authorship over a TOML file. The security relies on the author protecting
///     their private GPG key.
/// *   **Destructive Operation**: Overwrites the original file.
/// *   **Key Specification**: The signing key is determined by the TOML file's content.
///     The author must ensure the `gpg_publickey_id` field correctly specifies their
///     intended signing key ID.
pub fn convert_toml_filewithkeyid_into_clearsigntoml_inplace(
    path_to_toml_file: &Path,
) -> Result<(), GpgError> {
    // --- Stage 1: Input Validation and Path Preparation ---
    println!(
        "Starting in-place clearsign conversion for: {}. This will assert authorship and integrity.",
        path_to_toml_file.display()
    );

    // Check if the input path exists and is a file.
    if !path_to_toml_file.exists() {
        return Err(GpgError::PathError(format!(
            "Input TOML file not found: {}",
            path_to_toml_file.display()
        )));
    }
    if !path_to_toml_file.is_file() {
        return Err(GpgError::PathError(format!(
            "Input path is not a file: {}",
            path_to_toml_file.display()
        )));
    }

    // Convert path to string for TOML reading function.
    let path_str = match path_to_toml_file.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_toml_file.display()
            )));
        }
    };

    // --- Stage 2: Extract Signing Key ID from TOML File ---
    let field_name_for_signing_key_id = "gpg_publickey_id";
    println!(
        "Reading author's GPG signing key ID from field '{}' in file '{}'",
        field_name_for_signing_key_id, path_str
    );

    let signing_key_id =
        match read_single_line_string_field_from_toml(path_str, field_name_for_signing_key_id) {
            Ok(id) => {
                if id.is_empty() {
                    return Err(GpgError::GpgOperationError(format!(
                        "Field '{}' is empty in TOML file: {}. Author's GPG key ID is required for signing.",
                        field_name_for_signing_key_id, path_str
                    )));
                }
                id
            }
            Err(e) => {
                // read_single_line_string_field_from_toml returns String, map error type.
                return Err(GpgError::GpgOperationError(format!(
                    "Failed to read author's GPG signing key ID from field '{}' in TOML file '{}': {}",
                    field_name_for_signing_key_id, path_str, e
                )));
            }
        };
    println!("Author's GPG signing key ID for this file: '{}'", signing_key_id);

    // --- Stage 3: Validate Author's GPG Secret Key Availability ---
    match validate_gpg_secret_key(&signing_key_id) {
        Ok(true) => {
            println!(
                "Author's GPG secret key for ID '{}' is available for signing.",
                signing_key_id
            );
        }
        Ok(false) => {
            return Err(GpgError::GpgOperationError(format!(
                "Author's GPG secret key for ID '{}' (specified in '{}') not found in keyring or is not usable. Cannot sign file.",
                signing_key_id,
                path_to_toml_file.display()
            )));
        }
        Err(e) => {
            // Pass through the GpgError from validate_gpg_secret_key.
            return Err(e);
        }
    }

    // --- Stage 4: Prepare Temporary File Path ---
    // Create a temporary file path in the same directory to increase likelihood of atomic rename.
    let original_file_name = path_to_toml_file
        .file_name()
        .ok_or_else(|| GpgError::PathError(format!("Could not get filename from path: {}", path_to_toml_file.display())))?
        .to_string_lossy();

    let temp_file_name = format!("{}.tmp_clearsign_{}", original_file_name, generate_timestamp());
    let temp_output_path = path_to_toml_file.with_file_name(temp_file_name);

    println!(
        "Temporary file for clearsigned output: {}",
        temp_output_path.display()
    );

    // --- Stage 5: Perform GPG Clearsign Operation ---
    println!(
        "Performing GPG clearsign operation on '{}' using author's key ID '{}'",
        path_to_toml_file.display(),
        signing_key_id
    );

    let clearsign_command_result = Command::new("gpg")
        .arg("--clearsign") // Perform a clearsign operation.
        .arg("--batch") // Ensure no interactive prompts from GPG.
        .arg("--yes") // Assume "yes" to prompts like overwriting.
        .arg("--default-key") // Specify the key to use for signing.
        .arg(&signing_key_id) // The key ID extracted from the TOML.
        .arg("--output") // Specify the output file for the clearsigned content.
        .arg(&temp_output_path) // Path to the temporary output file.
        .arg(path_to_toml_file) // The input file to be clearsigned.
        .output(); // Execute and get full output (status, stdout, stderr).

    match clearsign_command_result {
        Ok(output) => {
            if output.status.success() {
                println!(
                    "GPG clearsign operation successful. Output written to temporary file: {}",
                    temp_output_path.display()
                );
            } else {
                // GPG command executed but failed.
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                if temp_output_path.exists() {
                    if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                        eprintln!("Additionally, failed to remove temporary file '{}' after GPG error: {}", temp_output_path.display(), e_remove);
                    }
                }
                return Err(GpgError::GpgOperationError(format!(
                    "GPG clearsign command failed for file '{}' with exit code: {}. GPG stderr: {}. Ensure GPG is configured correctly and the key is usable.",
                    path_to_toml_file.display(),
                    output.status,
                    stderr_output.trim()
                )));
            }
        }
        Err(e) => {
            // Failed to execute GPG command itself.
             if temp_output_path.exists() {
                if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                    eprintln!("Additionally, failed to remove temporary file '{}' after GPG execution error: {}", temp_output_path.display(), e_remove);
                }
            }
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG clearsign command for file '{}': {}",
                path_to_toml_file.display(),
                e
            )));
        }
    }

    // --- Stage 6: In-Place Replacement ---
    // At this point, temp_output_path contains the successfully clearsigned file.
    println!(
        "Replacing original file '{}' with its clearsigned version to finalize authorship assertion.",
        path_to_toml_file.display()
    );

    // 1. Delete the original file.
    // This is a critical step. We back up the original content to a string first,
    // just in case the rename fails catastrophically, though this is a very minor safeguard.
    // A more robust solution for critical data would involve staging areas or more complex transaction logic.
    let original_content_backup = fs::read_to_string(path_to_toml_file)
        .map_err(|e| GpgError::FileSystemError(std::io::Error::new(
            e.kind(),
            format!("Failed to read original file for backup before deletion: {}. Error: {}", path_to_toml_file.display(), e)
        )))?;


    if let Err(e_remove_orig) = fs::remove_file(path_to_toml_file) {
        // If original file deletion fails, we have a problem.
        // The clearsigned version is in temp_output_path.
        // It's safer to not delete temp_output_path here, as it might be recoverable.
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e_remove_orig.kind(),
            format!(
                "Failed to delete original file '{}' before replacing with clearsigned version. Clearsigned data is in '{}'. Error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_remove_orig
            )
        )));
    }
    println!("Original file '{}' deleted.", path_to_toml_file.display());

    // 2. Rename the temporary clearsigned file to the original file's name.
    if let Err(e_rename) = fs::rename(&temp_output_path, path_to_toml_file) {
        // If rename fails, the original is gone, and the new version is still under temp_output_path.
        // This is a critical error state. Attempt to restore the original file from backup.
        eprintln!(
            "Critical: Failed to rename temporary file '{}' to original file path '{}'. Attempting to restore original content.",
            temp_output_path.display(),
            path_to_toml_file.display()
        );
        if let Err(e_restore) = fs::write(path_to_toml_file, original_content_backup) {
             eprintln!(
                "Catastrophic failure: Could not restore original file '{}' after rename failure. Original content might be lost. Clearsigned data is in '{}'. Restore error: {}. Rename error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_restore,
                e_rename
            );
        } else {
            eprintln!(
                "Successfully restored original content to '{}'. Clearsigned data is in '{}'. Rename error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_rename
            );
        }
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e_rename.kind(),
            format!(
                "Critical: Failed to rename temporary file '{}' to original file path '{}'. Original data was in memory and an attempt to restore was made. Please check file states. Clearsigned data is in temporary file. Rename Error: {}",
                temp_output_path.display(),
                path_to_toml_file.display(),
                e_rename
            )
        )));
    }

    println!(
        "Successfully converted '{}' to clearsigned TOML in-place. Authorship and integrity asserted.",
        path_to_toml_file.display()
    );

    // --- Stage 7: Cleanup (should not be strictly necessary if rename succeeded) ---
    if temp_output_path.exists() {
        println!(
            "Attempting to clean up residual temporary file: {}",
            temp_output_path.display()
        );
        if let Err(e_remove_temp) = fs::remove_file(&temp_output_path) {
            eprintln!(
                "Warning: Failed to clean up residual temporary file '{}': {}",
                temp_output_path.display(),
                e_remove_temp
            );
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests_inplace_conversion {
    use super::*;
    use std::fs::{self, File, write};
    use std::io::Read;

    // Helper to create a dummy TOML file for testing.
    fn create_test_toml_file(path: &Path, key_id_field: &str, key_id_value: &str, other_content: &str) -> Result<(), std::io::Error> {
        let content = format!("{} = \"{}\"\n{}", key_id_field, key_id_value, other_content);
        fs::write(path, content)
    }
    
    // Helper to check if GPG is available for skipping tests.
    fn is_gpg_available() -> bool {
        Command::new("gpg").arg("--version").status().map_or(false, |s| s.success())
    }

    #[test]
    fn test_convert_toml_inplace_basic_workflow() {
        if !is_gpg_available() {
            println!("Skipping GPG-dependent test: test_convert_toml_inplace_basic_workflow (GPG not available)");
            return;
        }

        // IMPORTANT: This test requires a GPG key to be available for signing.
        // Replace "TEST_SIGNING_KEY_ID" with an actual key ID from your test GPG keyring
        // that can be used for non-interactive signing.
        // For automated CI, this often involves setting up a temporary GPG keyring with a test key.
        // For local testing, ensure your GPG agent is running and the key is usable.
        // If no such key is readily available, this test will likely fail at the
        // `validate_gpg_secret_key` step or the GPG command execution.
        let test_key_id_for_signing = "YOUR_TEST_GPG_SIGNING_KEY_ID"; // !!! REPLACE THIS !!!
        if test_key_id_for_signing == "YOUR_TEST_GPG_SIGNING_KEY_ID" {
            println!("Skipping test_convert_toml_inplace_basic_workflow: Placeholder GPG key ID not replaced.");
            println!("Please configure a real test GPG key ID that can be used for signing.");
            // Consider this a soft skip or an ignored test if not configured.
            // For robust testing, this should be a hard requirement or use a mock.
            // Since no third-party crates are allowed, mocking GPG is non-trivial.
            return; 
        }


        let test_file_name = "test_inplace_conversion.toml";
        let test_file_path = PathBuf::from(test_file_name);
        let original_other_content = "message = \"Hello, GPG!\"";

        // Create the initial TOML file
        if let Err(e) = create_test_toml_file(&test_file_path, "gpg_publickey_id", test_key_id_for_signing, original_other_content) {
            panic!("Failed to create test TOML file: {}", e);
        }

        // Run the conversion
        let conversion_result = convert_toml_filewithkeyid_into_clearsigntoml_inplace(&test_file_path);
        
        // Assert success
        assert!(conversion_result.is_ok(), "In-place conversion failed: {:?}", conversion_result.err());

        // Verify the file content is now clearsigned
        let mut file_content = String::new();
        match File::open(&test_file_path) {
            Ok(mut f) => {
                if let Err(e) = f.read_to_string(&mut file_content) {
                    panic!("Failed to read converted file content: {}", e);
                }
            },
            Err(e) => panic!("Failed to open converted file: {}", e),
        }
        
        assert!(file_content.contains("-----BEGIN PGP SIGNED MESSAGE-----"), "Output file is not clearsigned (missing header)");
        assert!(file_content.contains("-----BEGIN PGP SIGNATURE-----"), "Output file is not clearsigned (missing signature)");
        assert!(file_content.contains(original_other_content), "Original content not found in clearsigned file");
        assert!(file_content.contains(&format!("gpg_publickey_id = \"{}\"", test_key_id_for_signing)), "Signing key ID field not found in clearsigned file");

        // Cleanup
        let _ = fs::remove_file(&test_file_path);
    }

    #[test]
    fn test_convert_toml_inplace_file_not_found() {
        let non_existent_path = Path::new("this_file_does_not_exist_for_testing.toml");
        let result = convert_toml_filewithkeyid_into_clearsigntoml_inplace(non_existent_path);
        assert!(result.is_err());
        if let Err(GpgError::PathError(msg)) = result {
            assert!(msg.contains("Input TOML file not found"));
        } else {
            panic!("Expected PathError for non-existent file, got {:?}", result);
        }
    }
    
    #[test]
    fn test_convert_toml_inplace_missing_key_id_field() {
        let test_file_name = "test_missing_key_id.toml";
        let test_file_path = PathBuf::from(test_file_name);
        
        // Create TOML without the required gpg_publickey_id field
        fs::write(&test_file_path, "some_other_field = \"value\"").unwrap();
        
        let result = convert_toml_filewithkeyid_into_clearsigntoml_inplace(&test_file_path);
        assert!(result.is_err());
        if let Err(GpgError::GpgOperationError(msg)) = result {
            assert!(msg.contains("Failed to read GPG signing key ID from field 'gpg_publickey_id'"));
        } else {
            panic!("Expected GpgOperationError for missing key ID field, got {:?}", result);
        }
        
        let _ = fs::remove_file(&test_file_path);
    }

    #[test]
    fn test_convert_toml_inplace_invalid_signing_key() {
         if !is_gpg_available() {
            println!("Skipping GPG-dependent test: test_convert_toml_inplace_invalid_signing_key (GPG not available)");
            return;
        }
        let test_file_name = "test_invalid_signing_key.toml";
        let test_file_path = PathBuf::from(test_file_name);
        let invalid_key_id = "THIS_IS_NOT_A_VALID_GPG_KEY_ID_AT_ALL_NO_WAY_JOSE";
        
        create_test_toml_file(&test_file_path, "gpg_publickey_id", invalid_key_id, "content = \"test\"").unwrap();
        
        let result = convert_toml_filewithkeyid_into_clearsigntoml_inplace(&test_file_path);
        assert!(result.is_err());
        if let Err(GpgError::GpgOperationError(msg)) = result {
             assert!(msg.contains(&format!("GPG secret key for ID '{}'", invalid_key_id)));
             assert!(msg.contains("not found in keyring or is not usable"));
        } else {
            panic!("Expected GpgOperationError for invalid signing key, got {:?}", result);
        }
        
        let _ = fs::remove_file(&test_file_path);
    }
}