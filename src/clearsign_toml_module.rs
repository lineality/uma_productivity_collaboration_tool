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
There are several different uses and kinds of gpg integration with toml files here,
as well as simpler functions that handle text file reading and file path management.
There are 'clearsign-toml' files and '.gpgtoml' files. These types of .toml files
allow validation, reading, and more private sharing of fiels in stanardized formats.

1. clearsign .toml WITH the public key in the file
	workflow:
	validate clearsign file using the public-gpg-key that is
	there in that file,
	if validated: extract the field

2. clearsign .toml NOT with public key in toml, rather, a config file
    is used based on the owner-filed in the .toml
    workflow:
    the public gpg key is NOT in this type of clearsigned toml
    but ~pointer information about where to find that public gpg key is
    in this type of clearsigned toml. 
    the name of the owner is in this file, and that owner has an addresbook
    file that contains that owner's public gpg key. (likely the addressbook
        file is a .gpgtoml (both encrypted with the local-user's public key
        and clearsigned with the file-owner's public-key))
    1. look at the owner of the file
    2. get the owner's config file from the addressbook-files directory
    addressbook_files_directory_relative is where the addressbook files are
    3. clearsign-read the owner's public gpg key
    4. user the owners public key to try to validate the clearsign file
    5. ONLY IF clearsign is VALIDATED: extract the single field

3. .gpgtoml -> use the current-user's key-id to decrypt-extract a (clearsigned) .toml from
    a fully gpg encrypted file: that file then behaves like either of the above clearsign toml files
    
    a .gogtoml is encrypted with the current user's pubic key,
    so is decrypted with the private key, the key-id for which 
    is obtained from this function:
    
    Get the current-local-user's gpg with something like this:
            // Get GPG key fingerprint
            let full_fingerprint_key_id_string = match q_and_a_user_selects_gpg_key_full_fingerprint() {
                Ok(fingerprint) => {
                    println!("Selected key id (full fingerprint): {}", fingerprint);
                    fingerprint
                }
                Err(e) => {
                    eprintln!("Error selecting GPG key fingerprint: {}", e);
                    return Ok(false);
                }
            };







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
use std::collections::HashMap;



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
pub fn read_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> String {
    // Validate input parameters
    if path.is_empty() || name_of_toml_field_key_to_read.is_empty() {
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
        if line.trim_start().starts_with(name_of_toml_field_key_to_read) {
            // Debug print statement
            println!("Found field '{}' on line {}", name_of_toml_field_key_to_read, line_number);

            // Split the line by '=' and handle malformed lines
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                println!("Malformed TOML line {} - missing '=': {}", line_number, line);
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            // Verify exact field name match (avoiding partial matches)
            if key != name_of_toml_field_key_to_read {
                continue;
            }

            // Handle empty values
            if value.is_empty() {
                println!("Warning: Empty value found for field '{}'", name_of_toml_field_key_to_read);
                return String::new();
            }

            // Debug print statement
            println!("Extracted value: {}", value);

            // Clean up the value: remove quotes and trim spaces
            let cleaned_value = value.trim().trim_matches('"').trim();
            
            // Verify the cleaned value isn't empty
            if cleaned_value.is_empty() {
                println!("Warning: Value became empty after cleaning for field '{}'", name_of_toml_field_key_to_read);
                return String::new();
            }

            return cleaned_value.to_string();
        }
    }

    // If we get here, the field wasn't found
    println!("Field '{}' not found in file", name_of_toml_field_key_to_read);
    String::new()
}

/// Reads all fields from a TOML file that share a common base name (prefix before underscore)
/// and returns a vector of their values. Returns an empty vector if no matching fields are found
/// or if any errors occur.
///
/// # Arguments
/// - `path` - Path to the TOML file
/// - `base_name` - Base name to search for (e.g., "prompt" will match "prompt_1", "prompt_2", etc.)
///
/// # Returns
/// - `Vec<String>` - Vector containing all values for fields matching the base name
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
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<String, String>` - The field value or an error message
pub fn read_single_line_string_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            return Ok(trimmed
                .splitn(2, '=')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string());
        }
    }
    
    Err(format!("Field '{}' not found", name_of_toml_field_key_to_read))
}


/// Reads a u8 integer value from a TOML file.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<u8, String>` - The parsed u8 value or an error message
pub fn read_u8_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<u8, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", name_of_toml_field_key_to_read))?
                .trim();
                
            // Parse the value as u8
            return value_str.parse::<u8>()
                .map_err(|e| format!("Failed to parse '{}' as u8: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", name_of_toml_field_key_to_read))
}

/// Reads a u64 integer value from a TOML file.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<u64, String>` - The parsed u64 value or an error message
pub fn read_u64_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<u64, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", name_of_toml_field_key_to_read))?
                .trim();
                
            // Parse the value as u64
            return value_str.parse::<u64>()
                .map_err(|e| format!("Failed to parse '{}' as u64: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", name_of_toml_field_key_to_read))
}

/// Reads a u64 integer field from a clearsigned TOML file.
///
/// # Purpose
/// This function provides secure reading of u64 values from clearsigned TOML files
/// by first verifying the GPG signature before accessing the data. The GPG public
/// key is expected to be embedded within the same file being read.
///
/// # Process Flow
/// 1. Extracts the GPG public key from the clearsigned TOML file
/// 2. Verifies the file's signature using the extracted key
/// 3. If verification succeeds, reads and parses the requested u64 field
/// 4. Returns the parsed value or an appropriate error
///
/// # Arguments
/// - `path_to_clearsigntoml_with_gpgkey` - Path to the clearsigned TOML file containing both data and GPG key
/// - `name_of_toml_field_key_to_read` - Name of the field containing the u64 value to read
///
/// # Returns
/// - `Ok(u64)` - The parsed u64 value if verification succeeds and field exists
/// - `Err(String)` - Detailed error message if any step fails
///
/// # Errors
/// This function may return errors in several cases:
/// - If the file cannot be opened or read
/// - If the GPG key cannot be extracted from the file
/// - If the GPG signature verification fails
/// - If the specified field doesn't exist in the file
/// - If the field value cannot be parsed as a valid u64
///
/// # Security
/// This function ensures data integrity by verifying the GPG signature before
/// reading any values. This prevents tampering with numeric configuration values
/// that might affect system behavior.
///
/// # Example
/// ```
/// let config_path = "/etc/myapp/config.toml";
/// 
/// match read_u64_from_clearsigntoml(config_path, "max_connections") {
///     Ok(value) => println!("Max connections: {}", value),
///     Err(e) => eprintln!("Error reading max_connections: {}", e)
/// }
/// ```
pub fn read_u64_from_clearsigntoml(
    path_to_clearsigntoml_with_gpgkey: &str, 
    name_of_toml_field_key_to_read: &str
) -> Result<u64, String> {
    // Step 1: Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path_to_clearsigntoml_with_gpgkey, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from file '{}': {}", 
                            path_to_clearsigntoml_with_gpgkey, e))?;

    // Step 2: Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path_to_clearsigntoml_with_gpgkey, &key)
        .map_err(|e| format!("Failed during verification process for file '{}': {}", 
                            path_to_clearsigntoml_with_gpgkey, e))?;

    // Step 3: Check if verification succeeded
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path_to_clearsigntoml_with_gpgkey));
    }

    // Step 4: Only read the field if verification succeeded
    read_u64_field_from_toml(path_to_clearsigntoml_with_gpgkey, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read u64 field '{}' from verified file '{}': {}", 
                            name_of_toml_field_key_to_read, path_to_clearsigntoml_with_gpgkey, e))
}


/// Reads a u64 integer field from a clearsigned TOML file using a GPG key from a separate config file.
///
/// # Purpose
/// This function provides a way to verify and read u64 values from clearsigned TOML files 
/// that don't contain their own GPG keys, instead using a key from a separate centralized 
/// config file. This approach helps maintain consistent key management across multiple 
/// clearsigned files and is particularly useful for numeric configuration values that
/// require integrity protection.
///
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file
/// 3. If verification succeeds, reads and parses the requested u64 field from the verified file
/// 4. Returns the parsed value or an appropriate error
///
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the field containing the u64 value to read
///
/// # Returns
/// - `Ok(u64)` - The parsed u64 value if verification succeeds and field exists
/// - `Err(String)` - Detailed error message if any step fails
///
/// # Errors
/// This function may return errors in several cases:
/// - If the config file cannot be read or doesn't contain a valid GPG key
/// - If the target file cannot be read or its signature cannot be verified with the provided key
/// - If the specified field doesn't exist in the target file
/// - If the field value cannot be parsed as a valid u64 (including overflow conditions)
///
/// # Security Considerations
/// - Ensures that numeric values cannot be tampered with by verifying signatures
/// - Particularly important for values like ports, timeouts, limits, or other security-sensitive numbers
/// - The separation of key storage allows for key rotation without modifying data files
///
/// # Example
/// ```
/// let config_path = "/etc/myapp/security.toml";
/// let data_path = "/var/myapp/limits.toml";
/// 
/// match read_u64_from_clearsigntoml_without_keyid(
///     config_path, 
///     data_path, 
///     "request_timeout_seconds"
/// ) {
///     Ok(timeout) => println!("Request timeout: {} seconds", timeout),
///     Err(e) => eprintln!("Error reading timeout: {}", e)
/// }
/// ```
///
/// # Notes
/// - The function name includes "without_keyid" to indicate that the target file doesn't contain its own key
/// - All paths should be absolute for consistency and to avoid ambiguity
/// - The u64 type supports values from 0 to 18,446,744,073,709,551,615
pub fn read_u64_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<u64, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                            pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process for target file '{}': {}", 
                            pathstr_to_target_clearsigned_file, e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested u64 field from the verified file
    read_u64_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read u64 field '{}' from verified file '{}': {}", 
                            name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

// /// Reads an array of u64 bytes from a TOML file into a Vec<u64>.
// /// 
// /// # Purpose
// /// This function parses a TOML file to extract an array of unsigned 8-bit integers (bytes)
// /// defined by the specified field name. It handles arrays in the format:
// /// ```toml
// /// node_unique_id = [160, 167, 195, 169]
// /// ```
// /// 
// /// # Arguments
// /// - `path` - Path to the TOML file
// /// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of integers in the TOML file)
// /// 
// /// # Returns
// /// - `Result<Vec<u64>, String>` - A vector containing all bytes in the array if successful,
// ///   or an error message if the field is not found or values are out of u64 range (0 to 2^64-1)
// /// 
// /// # Error Handling
// /// This function returns errors when:
// /// - The file cannot be opened or read
// /// - The specified field is not found
// /// - The field is not a valid array format
// /// - Any value in the array is not a valid u64 (outside 0 to 2^64-1 range)
// /// - Any value cannot be parsed as an integer
// /// 
// /// # Example
// /// For a TOML file containing:
// /// ```toml
// /// node_unique_id = [160, 167, 195, 169]
// /// hash_bytes = [255, 0, 128, 64]
// /// ```
// /// 
// /// Usage:
// /// ```
// /// let node_id = read_u64_array_field_from_toml("config.toml", "node_unique_id")?;
// /// // Returns: vec![160, 167, 195, 169]
// /// ```
// /// 
// /// # Implementation Notes
// /// - Values must be in the range 0 to 2^64-1 (valid u64 range)
// /// - Negative numbers will result in an error
// /// - Floating point numbers will result in an error
// /// - The function trims whitespace and handles trailing commas
// pub fn read_u64_array_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
//     // Open the file
//     let file = File::open(path)
//         .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
//     let reader = io::BufReader::new(file);
    
//     // Process each line looking for our field
//     for (line_number, line_result) in reader.lines().enumerate() {
//         // Handle line reading errors
//         let line = line_result
//             .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
//         let trimmed = line.trim();
        
//         // Skip empty lines and comments
//         if trimmed.is_empty() || trimmed.starts_with('#') {
//             continue;
//         }
        
//         // Check if this line contains our field with an array
//         if trimmed.starts_with(&format!("{} = [", name_of_toml_field_key_to_read)) {
//             // Extract the array portion
//             let array_part = trimmed
//                 .splitn(2, '=')
//                 .nth(1)
//                 .ok_or_else(|| format!("Invalid array format for field '{}'", name_of_toml_field_key_to_read))?
//                 .trim()
//                 .trim_start_matches('[')
//                 .trim_end_matches(']')
//                 .trim();
            
//             // If the array is empty, return an empty vector
//             if array_part.is_empty() {
//                 return Ok(Vec::new());
//             }
            
//             // Parse each value as u64
//             let mut byte_values = Vec::new();
            
//             for (index, value_str) in array_part.split(',').enumerate() {
//                 let cleaned_value = value_str.trim();
                
//                 if cleaned_value.is_empty() {
//                     continue; // Skip empty entries (e.g., trailing comma)
//                 }
                
//                 // First parse as i32 to check range, then convert to u64
//                 match cleaned_value.parse::<i32>() {
//                     Ok(int_value) => {
//                         // Check if value is in valid u64 range (0 to 2^64-1)
//                         if int_value < 0 || int_value > 255 {
//                             return Err(format!(
//                                 "Value {} at index {} in array field '{}' is out of valid byte range (0 to 2^64-1)",
//                                 int_value, index, name_of_toml_field_key_to_read
//                             ));
//                         }
//                         // Safe to convert to u64 now
//                         byte_values.push(int_value as u64);
//                     }
//                     Err(e) => {
//                         return Err(format!(
//                             "Failed to parse value '{}' at index {} in array field '{}' as integer: {}",
//                             cleaned_value, index, name_of_toml_field_key_to_read, e
//                         ));
//                     }
//                 }
//             }
            
//             return Ok(byte_values);
//         }
//     }
    
//     // Field not found
//     Err(format!("Byte array field '{}' not found in file '{}'", name_of_toml_field_key_to_read, path))
// }

// /// Reads an array of u64 bytes from a clearsigned TOML file into a Vec<u64>.
// /// 
// /// # Purpose
// /// This function securely reads a byte array from a clearsigned TOML file by:
// /// 1. Extracting the GPG public key from the file
// /// 2. Verifying the clearsign signature
// /// 3. If verification succeeds, reading the requested byte array
// /// 
// /// # Security
// /// This function ensures that the TOML file's content is cryptographically verified 
// /// before any data is extracted, providing integrity protection for the configuration.
// /// No data is returned if signature validation fails.
// /// 
// /// # Arguments
// /// - `path` - Path to the clearsigned TOML file
// /// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of bytes in the TOML file)
// /// 
// /// # Returns
// /// - `Result<Vec<u64>, String>` - A vector containing all bytes in the array if successful and verified,
// ///   or an error message if verification fails or the field cannot be read
// /// 
// /// # Example
// /// For a clearsigned TOML file containing:
// /// ```toml
// /// node_unique_id = [160, 167, 195, 169]
// /// 
// /// gpg_key_public = """
// /// -----BEGIN PGP PUBLIC KEY BLOCK-----
// /// ...
// /// -----END PGP PUBLIC KEY BLOCK-----
// /// """
// /// ```
// /// 
// /// Usage:
// /// ```
// /// let node_id = read_u64_array_from_clearsigntoml("node_config.toml", "node_unique_id")?;
// /// // Returns: vec![160, 167, 195, 169] if signature verification succeeds
// /// ```
// /// 
// /// # Errors
// /// Returns an error if:
// /// - GPG key extraction fails
// /// - Signature verification fails
// /// - The field doesn't exist or isn't a valid byte array
// /// - Any value is outside the valid u64 range (0 to 2^64-1)
// pub fn read_u64_array_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
//     // Step 1: Extract GPG key from the file
//     let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")
//         .map_err(|e| format!("Failed to extract GPG key from file '{}': {}", path, e))?;
    
//     // Step 2: Verify the file's clearsign signature
//     let verification_result = verify_clearsign(path, &key)
//         .map_err(|e| format!("Error during signature verification of file '{}': {}", path, e))?;
    
//     // Step 3: Check if verification was successful
//     if !verification_result {
//         return Err(format!("GPG signature verification failed for file: {}", path));
//     }
    
//     // Step 4: If verification succeeded, read the requested byte array field
//     read_u64_array_field_from_toml(path, name_of_toml_field_key_to_read)
//         .map_err(|e| format!("Failed to read byte array '{}' from verified file '{}': {}", 
//                              name_of_toml_field_key_to_read, path, e))
// }


/// Reads a floating point (f64) value from a TOML file.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<f64, String>` - The parsed f64 value or an error message
pub fn read_float_f64_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<f64, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", name_of_toml_field_key_to_read))?
                .trim();
                
            // Parse the value as f64
            return value_str.parse::<f64>()
                .map_err(|e| format!("Failed to parse '{}' as floating point number: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", name_of_toml_field_key_to_read))
}

/// Reads a floating point (f32) value from a TOML file.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<f32, String>` - The parsed f32 value or an error message
pub fn read_float_f32_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<f32, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            let value_str = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", name_of_toml_field_key_to_read))?
                .trim();
                
            // Parse the value as f32
            return value_str.parse::<f32>()
                .map_err(|e| format!("Failed to parse '{}' as 32-bit floating point number: {}", value_str, e));
        }
    }
    
    Err(format!("Field '{}' not found", name_of_toml_field_key_to_read))
}

/// Reads a multi-line string field (triple-quoted) from a TOML file.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<String, String>` - The concatenated multi-line value or an error message
pub fn read_multi_line_toml_string(path: &str, name_of_toml_field_key_to_read: &str) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Find the start of the field
    let field_start = format!("{} = \"\"\"", name_of_toml_field_key_to_read);
    let start_pos = content.find(&field_start)
        .ok_or_else(|| format!("Multi-line field '{}' not found", name_of_toml_field_key_to_read))?;

    // Find the end of the field (next """)
    let content_after_start = &content[start_pos + field_start.len()..];
    let end_pos = content_after_start.find("\"\"\"")
        .ok_or_else(|| format!("Closing triple quotes not found for field '{}'", name_of_toml_field_key_to_read))?;

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
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
/// 
/// # Returns
/// - `Result<Vec<u64>, String>` - The vector of integers or an error message
pub fn read_integer_array(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let reader = io::BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        
        if trimmed.starts_with(&format!("{} = [", name_of_toml_field_key_to_read)) {
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
    
    Err(format!("Array field '{}' not found", name_of_toml_field_key_to_read))
}

/// Extracts a GPG key from a TOML file.
/// This function assumes the GPG key is stored in a multi-line field.
///
/// # Arguments
/// - `path` - Path to the TOML file
/// - `key_field` - Name of the field containing the GPG key
///
/// # Returns
/// - `Result<String, String>` - The GPG key or an error message
fn extract_gpg_key_from_clearsigntoml(path: &str, key_field: &str) -> Result<String, String> {
    read_multi_line_toml_string(path, key_field)
}

// /// Verifies a clearsigned TOML file using GPG.
// ///
// /// # Arguments
// /// - `path` - Path to the TOML file
// /// - `key` - The GPG key to use for verification
// ///
// /// # Returns
// /// - `Result<(), String>` - Success or error message
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
/// - `path` - Path to the TOML file
/// - `key` - The GPG key to use for verification
///
/// # Returns
/// - `Result<bool, String>` - True if verification succeeds, false if it fails, or an error message
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
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
///
/// # Returns
/// - `Result<String, String>` - The field value or an error message
pub fn read_singleline_string_from_clearsigntoml(path_to_clearsigntoml_with_gpgkey: &str, name_of_toml_field_key_to_read: &str) -> Result<String, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path_to_clearsigntoml_with_gpgkey, "gpg_key_public")?;

    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path_to_clearsigntoml_with_gpgkey, &key)?;

    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path_to_clearsigntoml_with_gpgkey));
    }

    // Only read the field if verification succeeded
    read_single_line_string_field_from_toml(path_to_clearsigntoml_with_gpgkey, name_of_toml_field_key_to_read)
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
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the field to read from the target file
///
/// # Returns
/// - `Ok(String)` - The value of the requested field if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
///
/// # Errors
/// This function may return errors in several cases:
/// - If the config file cannot be read or doesn't contain a valid GPG key
/// - If the target file cannot be read or its signature cannot be verified with the provided key
/// - If the specified field doesn't exist in the target file or has an invalid format
///
/// # Example
/// ```
/// let config_path = "config/security.toml";
/// let target_path = "data/settings.toml";
/// 
/// match read_singleline_string_from_clearsigntoml_without_keyid(
///     config_path, 
///     target_path, 
///     "api_endpoint"
/// ) {
///     Ok(value) => println!("API Endpoint: {}", value),
///     Err(e) => eprintln!("Error: {}", e)
/// }
/// ```
///
pub fn read_singleline_string_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<String, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested field from the verified file
    read_single_line_string_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read field '{}' from verified file '{}': {}", 
                            name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

// // DOC String NEEDED
// pub fn read_singleline_string_from_clearsigntoml_without_keyid(
//     path_to_config_file_with_gpgkey: &str,
//     path_to_clearsigntoml_without_gpgkey: &str, 
//     name_of_toml_field_key_to_read: &str,
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
//         name_of_toml_field_key_to_read
//     )
// }


/// Reads a multi-line string field from a clearsigned TOML file.
///
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
///
/// # Returns
/// - `Result<String, String>` - The field value or an error message
pub fn read_multiline_string_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<String, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_multi_line_toml_string(path, name_of_toml_field_key_to_read)
}

/// Reads an integer array field from a clearsigned TOML file.
///
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read
///
/// # Returns
/// - `Result<Vec<u64>, String>` - The integer array or an error message
pub fn read_integerarray_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_integer_array(path, name_of_toml_field_key_to_read)
}

/* maybe ~duplicate of better read_str_array_field_clearsigntoml()
/// Reads an string array field from a clearsigned TOML file
///...
pub fn read_str_array_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
    // Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")?;
    
    // Verify the file and only proceed if verification succeeds
    let verification_result = verify_clearsign(path, &key)?;
    
    if !verification_result {
        return Err(format!("GPG verification failed for file: {}", path));
    }
    
    // Only read the field if verification succeeded
    read_string_array_field_from_toml(path, name_of_toml_field_key_to_read)
}
*/

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

/// Gets the path to a clearsigned TOML file, checking for both .toml and .gpgtoml variants.
///
/// This function checks for both plain clearsigned `.toml` files and GPG-encrypted `.gpgtoml` 
/// files, handling the appropriate one based on what exists.
///
/// # Behavior
/// - Takes a base path (with or without extension)
/// - Checks for both .toml and .gpgtoml files
/// - If both exist: prefers .toml (already clearsigned)
/// - If only .gpgtoml exists: decrypts to temporary file
/// - If only .toml exists: uses it directly
/// - If neither exists: returns error
///
/// # Arguments
/// - `toml_file_path` - Base path (may include .toml extension which will be stripped)
/// - `gpg_full_fingerprint_key_id_string` - GPG key fingerprint for decrypting `.gpgtoml` files
///
/// # Returns
/// - `Ok((PathBuf, Option<PathBuf>))` - Tuple of:
///   - The path to use (original or temp file)
///   - Optional temp file path that needs cleanup (None for .toml, Some for .gpgtoml)
/// - `Err(GpgError)` - If neither file exists or decryption fails
pub fn get_path_to_clearsign_toml_for_gpgtoml_option(
    toml_file_path: &Path,
    gpg_full_fingerprint_key_id_string: &str,
) -> Result<(PathBuf, Option<PathBuf>), GpgError> {
    // Get base path without extension
    let base_path = if toml_file_path.extension().is_some_and(|ext| ext == "toml" || ext == "gpgtoml") {
        toml_file_path.with_extension("")
    } else {
        toml_file_path.to_path_buf()
    };
    
    // Construct both possible paths
    let toml_path = base_path.with_extension("toml");
    let gpgtoml_path = base_path.with_extension("gpgtoml");
    
    println!("GPTCFGO Checking for files:");
    println!("  - .toml: {}", toml_path.display());
    println!("  - .gpgtoml: {}", gpgtoml_path.display());
    
    // Check which files exist
    let toml_exists = toml_path.exists();
    let gpgtoml_exists = gpgtoml_path.exists();
    
    println!("GPTCFGO File existence: .toml={}, .gpgtoml={}", toml_exists, gpgtoml_exists);
    
    if toml_exists {
        // Prefer .toml if it exists
        println!("GPTCFGO Using clearsigned TOML file: {}", toml_path.display());
        Ok((toml_path, None))
    } else if gpgtoml_exists {
        // Use .gpgtoml and decrypt it
        println!("GPTCFGO Found only .gpgtoml, decrypting: {}", gpgtoml_path.display());
        
        // Generate unique temp filename
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GpgError::TempFileError(
                format!("GPTCFGO Failed to generate timestamp: {}", e)
            ))?
            .as_nanos();
        
        let temp_filename = format!("gpg_decrypt_temp_{}.toml", timestamp);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        
        println!("GPTCFGO Decrypting to temporary file: {}", temp_path.display());
        
        // Execute GPG decryption
        let output = std::process::Command::new("gpg")
            .arg("--quiet")
            .arg("--batch")
            .arg("--yes")
            .arg("--local-user")
            .arg(gpg_full_fingerprint_key_id_string)
            .arg("--decrypt")
            .arg("--output")
            .arg(&temp_path)
            .arg(&gpgtoml_path)
            .output()
            .map_err(|e| GpgError::DecryptionError(
                format!("GPTCFGO Failed to execute GPG decrypt command: {}", e)
            ))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GpgError::DecryptionError(
                format!("GPTCFGO GPG decryption failed: {}", stderr)
            ));
        }
        
        // Verify temp file was created
        if !temp_path.exists() {
            return Err(GpgError::DecryptionError(
                "GPTCFGO GPG decryption succeeded but temporary file was not created".to_string()
            ));
        }
        
        // Set restricted permissions on temp file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| GpgError::FileSystemError(e))?;
        }
        
        println!("GPTCFGO Successfully decrypted to: {}", temp_path.display());
        Ok((temp_path.clone(), Some(temp_path)))
    } else {
        // Neither file exists
        Err(GpgError::PathError(format!(
            "GPTCFGO No addressbook file found. Checked:\n  - {}\n  - {}",
            toml_path.display(),
            gpgtoml_path.display()
        )))
    }
}

/// Cleans up temporary files created by `get_path_to_clearsign_toml_for_gpgtoml_option`.
///
/// This is a convenience function to safely clean up temporary files returned by
/// the path getter function. It only attempts deletion if a temporary path is provided.
///
/// # Arguments
/// - `temp_path_option` - Optional path to temporary file that needs cleanup
///
/// # Note
/// Errors during cleanup are logged but not propagated, as cleanup failures
/// shouldn't typically interrupt the main operation flow.
pub fn cleanup_temp_clearsign_toml(temp_path_option: Option<PathBuf>) {
    if let Some(temp_path) = temp_path_option {
        if let Err(e) = std::fs::remove_file(&temp_path) {
            eprintln!(
                "Warning: Failed to remove temporary file {}: {}",
                temp_path.display(),
                e
            );
        } else {
            println!("Cleaned up temporary file: {}", temp_path.display());
        }
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
/// - `input_file_path` - Path to the file that needs to be clearsigned
/// - `output_file_path` - Path where the clearsigned file will be saved
/// - `signing_key_id` - GPG key ID to use for signing
///
/// # Returns
/// - `Ok(())` if clearsigning succeeds
/// - `Err(GpgError)` if any operation fails
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
/// - `encrypted_file_path` - Path to the encrypted .gpg file
/// - `validator_key_id` - GPG key ID to validate the clearsign signature
/// - `output_path` - Where to save the decrypted and verified file
/// 
/// # Returns
/// - `Ok(())` if decryption and validation succeed
/// - `Err(GpgError)` if any operation fails
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
/// - `encrypted_file_path` - Path to the encrypted GPG file
/// - `output_path` - Path where the decrypted output will be saved
///
/// # Returns
/// - `Ok(())` - If decryption succeeds
/// - `Err(GpgError)` - If any operation fails
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
/// - `clearsigned_file_path` - Path to the clearsigned file
/// - `validator_key_id` - GPG key ID to use for validation
///
/// # Returns
/// - `Ok(())` - If signature validation succeeds
/// - `Err(GpgError)` - If validation fails or any other operation fails
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
/// - `clearsigned_file_path` - Path to the verified clearsigned file
/// - `output_path` - Path where the extracted content will be saved
///
/// # Returns
/// - `Ok(())` - If content extraction succeeds
/// - `Err(GpgError)` - If any operation fails
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
/// - `key_id` - The GPG key ID to check for existence
///
/// # Returns
/// - `Ok(bool)` - True if the key exists, false otherwise
/// - `Err(GpgError)` - If there was an error executing the GPG command
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
/// - `key_id` - The GPG key ID (long format recommended) to check for. This ID typically
///   refers to the public key, but GPG uses it to find the associated secret key.
///
/// # Returns
/// - `Ok(true)` - If the secret key corresponding to the `key_id` exists in the keyring.
/// - `Ok(false)` - If the secret key is not found (GPG command succeeds but indicates no such key).
/// - `Err(GpgError::GpgOperationError)` - If there was an error executing the GPG command itself,
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
/// - `u64` - Current Unix timestamp in seconds
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
/// - `prefix` - Prefix to use for the temporary file name
///
/// # Returns
/// - `Ok(PathBuf)` - Path to the new temporary file
/// - `Err(GpgError)` - If there was an error creating the path
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
/// - `input_file_path` - Path to the file to be clearsigned
/// - `temp_file_path` - Path where the clearsigned output will be saved
/// - `your_key_id` - Your private key ID for signing
///
/// # Returns
/// - `Ok(())` - If clearsigning succeeds
/// - `Err(GpgError)` - If any operation fails
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
/// - `input_file_path` - Path to the file to be encrypted
/// - `output_file_path` - Path where the encrypted output will be saved
/// - `recipient_public_key_path` - Path to the recipient's public key file
///
/// # Returns
/// - `Ok(())` - If encryption succeeds
/// - `Err(GpgError)` - If any operation fails
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
/// - `input_file_path` - Path to the file to be clearsigned and encrypted
/// - `your_signing_key_id` - Your GPG key ID used for clearsigning (e.g., "7673C969D81E94C63D641CF84ED13C31924928A5")
/// - `recipient_public_key_path` - Path to the recipient's public key file (ASCII-armored format)
///
/// # Returns
/// - `Ok(())` - If the operation completes successfully
/// - `Err(GpgError)` - If any step fails, with detailed error information
///
/// # Errors
/// May return various `GpgError` types:
/// - `GpgError::GpgOperationError` - If GPG operations fail (missing keys, invalid keys, etc.)
/// - `GpgError::FileSystemError` - If file operations fail (permission issues, disk full, etc.)
/// - `GpgError::PathError` - If path operations fail (invalid paths, missing directories, etc.)
/// - `GpgError::TempFileError` - If temporary file operations fail
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
/// - `clearsign_file_with_private_key()` - Lower-level function to just clearsign a file
/// - `encrypt_file_with_public_key()` - Lower-level function to just encrypt a file
/// - `validate_gpg_key()` - Used to check if a GPG key exists in the keyring
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
/// - `Ok(())` - If the workflow completes successfully
/// - `Err(GpgError)` - If any step fails
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
/// - `Ok(())` - Operation completed successfully
/// - `Err(GpgError)` - Operation failed with specific error details
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
/// - `Result<PathBuf, io::Error>` - The absolute directory path containing the executable or an error
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
/// - `path_to_make_absolute` - A path to convert to an absolute path relative to 
///   the executable's directory location.
///
/// # Returns
///
/// - `Result<PathBuf, io::Error>` - The absolute path based on the executable's directory or an error
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
/// - `path_to_check` - The path to check for existence
///
/// # Returns
///
/// - `Result<bool, io::Error>` - Whether the path exists or an error
pub fn gpg_abs_executable_directory_relative_exists_boolean_check<P: AsRef<Path>>(path_to_check: P) -> Result<bool, io::Error> {
    let path = path_to_check.as_ref();
    Ok(path.exists())
}

/// Store the entire clearsigned file (still in clearsigned format with all signatures intact) to the output path
/// Decrypts a GPG-encrypted file containing a clearsigned document, verifies the signature,
/// and stores the entire clearsigned file (still clearsigned) to the output path.
///
/// # Arguments
/// - `incoming_gpg_encrypted_path` - Path to the GPG-encrypted file
/// - `gpg_key_id` - GPG key ID to verify the clearsign signature
/// - `output_verified_clearsign_path` - Path where to store the verified clearsigned file
///
/// # Returns
/// - `Result<(), GpgError>` - Success or failure
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
/// - `input_file_path` - Path to the GPG-encrypted input file
/// - `output_file_path` - Path where the decrypted content should be saved
///
/// # Returns
/// - `Ok(())` if the decryption succeeds
/// - `Err(GpgError)` if the decryption fails
///
/// # Errors
/// - `GpgError::PathError` - If the input file doesn't exist or output path is invalid
/// - `GpgError::GpgOperationError` - If the GPG decryption operation fails
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
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of strings in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<String>, String>` - A vector containing all strings in the array if successful,
///   or an error message if the field is not found or cannot be parsed correctly
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The specified field is not found
/// - The field is not a valid array format
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
pub fn read_string_array_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<String>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Variables to track multi-line array parsing
    let mut in_array = false;
    let mut array_values = Vec::new();
    let array_start_pattern = format!("{} = [", name_of_toml_field_key_to_read);
    
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
                    format!("Malformed array format for field '{}': opening bracket missing", name_of_toml_field_key_to_read))?;
                
                let bracket_end = trimmed.rfind(']').ok_or_else(|| 
                    format!("Malformed array format for field '{}': closing bracket missing", name_of_toml_field_key_to_read))?;
                
                // Make sure closing bracket comes after opening bracket
                if bracket_end <= bracket_start {
                    return Err(format!("Malformed array format for field '{}'", name_of_toml_field_key_to_read));
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
                name_of_toml_field_key_to_read, path);
        return Ok(array_values);
    }
    
    // If we get here, we didn't find the array
    Err(format!("String array field '{}' not found in file '{}'", name_of_toml_field_key_to_read, path))
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
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of strings in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<String>, String>` - A vector containing all strings in the array if successful and verified,
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
pub fn read_str_array_field_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<String>, String> {
    // Step 1: Extract GPG key from the file
    let key = extract_gpg_key_from_clearsigntoml(path, "gpg_key_public")
        .map_err(|e| format!("in read_str_array_field_clearsigntoml() Failed to extract GPG key from file '{}': {}", path, e))?;
    
    // Step 2: Verify the file's clearsign signature
    let verification_result = verify_clearsign(path, &key)
        .map_err(|e| format!("in read_str_array_field_clearsigntoml()  Error during signature verification of file '{}': {}", path, e))?;
    
    // Step 3: Check if verification was successful
    if !verification_result {
        return Err(format!("in read_str_array_field_clearsigntoml()  GPG signature verification failed for file: {}", path));
    }
    
    // Step 4: If verification succeeded, read the requested field
    read_string_array_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("in read_str_array_field_clearsigntoml()  Failed to read string array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
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
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the string array field to read from the target file
/// 
/// # Returns
/// - `Ok(Vec<String>)` - The string array values if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let addresses_file = "network_config.toml";
/// 
/// let ipv4_addresses = read_stringarray_from_clearsigntoml_without_keyid(
///     config_path,
///     addresses_file, 
///     "ipv4_addresses"
/// )?;
/// // Returns: vec!["10.0.0.213", "192.168.1.1"] if verification succeeds
/// ```
pub fn read_stringarray_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Vec<String>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested field from the verified file
    read_string_array_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read string array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

/// Verifies a clearsigned file and extracts its content to a separate output file
///
/// This function performs two distinct operations:
/// 1. Verifies the signature on a clearsigned file using a provided public key file
/// 2. If verification succeeds, extracts just the content portion (without signature blocks)
///    and writes it to the specified output file
///
/// # Arguments
/// - `clearsigned_input_path` - Path to the clearsigned file to verify
/// - `public_key_file_path` - Path to the file containing the public key for verification
/// - `extracted_content_output_path` - Path where the extracted content should be saved
///
/// # Returns
/// - `Ok(())` if both verification and extraction succeed
/// - `Err(GpgError)` if either verification or extraction fails
///
/// # Errors
/// - `GpgError::PathError` - If input files don't exist or paths are invalid
/// - `GpgError::ValidationError` - If signature verification fails
/// - `GpgError::GpgOperationError` - If GPG operations fail
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
/// - `Ok(String)` - The selected GPG key ID
/// - `Err(GpgError)` - If listing keys fails, no keys are available, or user input is invalid
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
/// - `encoded_uid_string`: A string slice representing the GPG UID, potentially containing
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
/// - `gpg_output_string`: A string slice containing the raw, colon-delimited output from GPG.
///
/// # Returns
/// - `Ok(Vec<GpgPublicKeyDisplayInfo>)`: A vector of `GpgPublicKeyDisplayInfo` structs. Each struct
///   represents a public key, containing its fingerprint and primary user identity.
///   The vector will be empty if no keys are found or if keys lack necessary information (fingerprint/UID).
/// - `Err(GpgError::GpgOperationError)`: If the parsing logic determines that no valid key information
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
/// - `Ok(String)`: The selected GPG public key fingerprint as a string.
/// - `Err(GpgError)`: If any step fails, such as:
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
/// - `gpg_colon_output` - String containing the colon-delimited output from GPG
///
/// # Returns
/// - `Ok(Vec<(String, String)>)` - Vector of (key_id, user_identity) pairs
/// - `Err(GpgError)` - If parsing fails
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
// /// - `Ok(())` - If the workflow completes successfully
// /// - `Err(GpgError)` - If any step fails
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
// /// - `Ok(())` - If the workflow completes successfully
// /// - `Err(GpgError)` - If any step fails
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
/// - `Ok(())` - If the clearsigning process completes successfully
/// - `Err(GpgError)` - If any step fails, with specific error information:
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
/// - `select_gpg_signing_shortkey_id()` - Called to allow key ID selection
/// - `clearsign_filepath_to_path()` - Called to perform the actual clearsigning
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
/// - `Ok(())` - If the clearsigning and encryption process completes successfully
/// - `Err(GpgError)` - If any step fails, with specific error information:
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
/// - `select_gpg_signing_shortkey_id()` - Called to allow key ID selection
/// - `clearsign_and_encrypt_file_for_recipient()` - Called to perform the actual operations
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


/// Converts a path to an absolute path based on the executable's directory location.
/// Does NOT check if the path exists or attempt to create anything.
///
/// # Arguments
///
/// - `path_to_make_absolute` - A path to convert to an absolute path relative to 
///   the executable's directory location.
///
/// # Returns
///
/// - `Result<PathBuf, io::Error>` - The absolute path based on the executable's directory or an error
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
pub fn make_input_path_name_abs_executabledirectoryrelative_nocheck<P: AsRef<Path>>(path_to_make_absolute: P) -> Result<PathBuf, io::Error> {
    // Get the directory where the executable is located
    let executable_directory = get_absolute_path_to_executable_parentdirectory()?;
    
    // Create a path by joining the executable directory with the provided path
    let target_path = executable_directory.join(path_to_make_absolute);
    
    // If the path doesn't exist, we still return the absolute path without trying to canonicalize
    if !abs_executable_directory_relative_exists(&target_path)? {
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
/// - `path_to_check` - The path to check for existence
///
/// # Returns
///
/// - `Result<bool, io::Error>` - Whether the path exists or an error
pub fn abs_executable_directory_relative_exists<P: AsRef<Path>>(path_to_check: P) -> Result<bool, io::Error> {
    let path = path_to_check.as_ref();
    Ok(path.exists())
}

/// Gets the directory where the current executable is located.
///
/// # Returns
///
/// - `Result<PathBuf, io::Error>` - The absolute directory path containing the executable or an error
///   if it cannot be determined.
pub fn get_absolute_path_to_executable_parentdirectory() -> Result<PathBuf, io::Error> {
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


/// Gets an absolute path for an existing directory relative to the executable's directory.
/// Returns an error if the directory doesn't exist or isn't a directory.
///
/// # Arguments
///
/// - `dir_path` - A directory path to convert to an absolute path relative to 
///   the executable's directory location.
///
/// # Returns
///
/// - `Result<PathBuf, io::Error>` - The absolute directory path or an error
pub fn make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error<P: AsRef<Path>>(dir_path: P) -> Result<PathBuf, io::Error> {
    let path = make_input_path_name_abs_executabledirectoryrelative_nocheck(dir_path)?;
    
    // Check if the path exists and is a directory
    if !abs_executable_directory_relative_exists(&path)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Directory does not exist",
        ));
    } else if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path exists but is not a directory",
        ));
    }
    
    // Canonicalize the path (should succeed because we've verified it exists)
    path.canonicalize().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to canonicalize directory path: {}", e),
        )
    })
}



/// Converts a TOML file into a clearsigned TOML file in-place, using owner-based GPG key lookup.
///
/// # Purpose
/// This function is designed for signing TOML files where the GPG key ID is not stored within
/// the file itself, but rather is determined by looking up the file owner's addressbook entry.
/// This enforces a centralized key management system where:
/// 1. Each file declares its owner via an `"owner"` field
/// 2. Each owner has a registered addressbook file containing their GPG key ID
/// 3. Files can only be signed by their declared owners
///
/// Like `convert_toml_filewithkeyid_into_clearsigntoml_inplace`, this function creates a
/// clearsigned TOML file that recipients can verify for:
/// 1. **Integrity**: That the file's content has not been altered since signing
/// 2. **Authenticity**: That the file was signed by the declared owner
///
/// # Key Lookup Process
/// Instead of reading the GPG key ID directly from the target TOML file, this function:
/// 1. Reads the owner's username from the target file's `"owner"` field
/// 2. Constructs the path to the owner's addressbook file: `{username}__collaborator.toml`
/// 3. Reads the GPG key ID from the addressbook file's `"gpg_publickey_id"` field
/// 4. Uses that key ID to sign the target file
///
/// # "In-Place" Operation
/// The term "in-place" means the original TOML file at `path_to_toml_file` will be
/// **overwritten** by its clearsigned counterpart. The content changes, but the
/// filename and location remain the same. This is a destructive operation; ensure
/// backups are considered if the original unsigned state is important.
///
/// # Input TOML File Requirements
/// The target TOML file (provided via `path_to_toml_file`) **must** contain:
/// - An `"owner"` field with the username of the file's owner
/// - This owner must have a corresponding addressbook file in the collaborator directory
///
/// The target file **must not** contain a `"gpg_publickey_id"` field, as this function
/// is specifically for files where the key ID is managed externally.
///
/// # Addressbook File Requirements
/// The owner's addressbook file (`{owner}__collaborator.toml`) must:
/// - Exist in the collaborator addressbook directory
/// - Be a valid clearsigned TOML file
/// - Contain a `"gpg_publickey_id"` field with the owner's GPG key ID
///
/// # GPG Private Key Requirement
/// The GPG keyring on the system executing this function **must** contain the **private key**
/// corresponding to the GPG key ID found in the owner's addressbook file. This private key
/// must be available and usable by GPG for signing.
///
/// # Process Flow
/// 1. **Input Validation**:
///    - Checks if `path_to_toml_file` exists and is a file
/// 2. **Owner Extraction**:
///    - Reads the TOML file to find and extract the value of the `"owner"` field
///    - If this field is missing, empty, or unreadable, returns an error
/// 3. **Addressbook Path Construction**:
///    - Builds the absolute path to the collaborator addressbook directory
///    - Constructs the owner's addressbook filename: `{owner}__collaborator.toml`
/// 4. **Key ID Lookup**:
///    - Reads the owner's addressbook file (which is already clearsigned)
///    - Extracts the `"gpg_publickey_id"` field value
/// 5. **Signing Key Validation**:
///    - Validates that the private key for the looked-up key ID exists locally
/// 6. **Clearsign Operation**:
///    - Creates a temporary file
///    - Uses GPG to clearsign the original file with the looked-up key ID
/// 7. **In-Place Replacement**:
///    - Deletes the original file
///    - Renames the temporary clearsigned file to the original filename
/// 8. **Cleanup**:
///    - Removes any remaining temporary files
///
/// # Arguments
/// - `path_to_toml_file` - A reference to a `Path` object representing the TOML file
///   to be converted in-place. Must contain an `"owner"` field.
///
/// # Returns
/// - `Ok(())` - If the TOML file was successfully clearsigned and replaced in-place
/// - `Err(GpgError)` - If any step in the process fails:
///   - `PathError`: File not found, invalid path, or path encoding issues
///   - `GpgOperationError`: Missing fields, GPG command failures, or key lookup failures
///   - `FileSystemError`: I/O errors during file operations
///
/// # Prerequisites
/// - GnuPG (GPG) must be installed and accessible via PATH
/// - The collaborator addressbook directory must exist and be accessible
/// - The owner specified in the file must have a valid addressbook file
/// - The GPG private key from the addressbook must be in the local keyring
///
/// # Security Considerations
/// - **Centralized Key Management**: Keys are managed via addressbook files, not individual files
/// - **Owner Enforcement**: Files can only be signed by their declared owners
/// - **Destructive Operation**: Overwrites the original file
/// - **Trust Chain**: Security depends on the integrity of the addressbook files
pub fn convert_tomlfile_without_keyid_into_clearsigntoml_inplace(
    path_to_toml_file: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<(), GpgError> {
    // --- Stage 1: Input Validation ---
    println!(
        "Starting in-place clearsign conversion with owner-based key lookup for: {}",
        path_to_toml_file.display()
    );

    // Validate that the input path exists and is a file
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

    // Convert path to string for TOML reading function
    let path_str = match path_to_toml_file.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_toml_file.display()
            )));
        }
    };

    // --- Stage 2: Extract Owner from Target TOML File ---
    let owner_name_of_toml_field_key_to_read = "owner";
    println!(
        "Reading file owner from field '{}' in file '{}'",
        owner_name_of_toml_field_key_to_read, path_str
    );

    // Read the owner username from the plain TOML file
    let file_owner_username = match read_single_line_string_field_from_toml(path_str, owner_name_of_toml_field_key_to_read) {
        Ok(username) => {
            if username.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "Field '{}' is empty in TOML file: {}. File owner is required for key lookup.",
                    owner_name_of_toml_field_key_to_read, path_str
                )));
            }
            username
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read file owner from field '{}' in TOML file '{}': {}",
                owner_name_of_toml_field_key_to_read, path_str, e
            )));
        }
    };
    println!("File owner username: '{}'", file_owner_username);

    // --- Stage 3: Construct Addressbook File Path ---
    println!(
        "Constructing path to owner's addressbook file for user: '{}'",
        file_owner_username
    );

    // Get the relative path to the collaborator addressbook directory
    // let addressbook_files_directory_relative = collaborator_addressbook_base_path;
    
    // Convert to absolute path and verify the directory exists
    let collaborator_files_directory_absolute = 
        match make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
            addressbook_files_directory_relative
        ) {
            Ok(path) => path,
            Err(io_error) => {
                return Err(GpgError::FileSystemError(io_error));
            }
        };

    println!(
        "Collaborator addressbook directory: {}",
        collaborator_files_directory_absolute.display()
    );

    // Construct the filename for this owner's addressbook file
    let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    let user_addressbook_path = collaborator_files_directory_absolute.join(&collaborator_filename);

    println!(
        "Owner's addressbook file path: {}",
        user_addressbook_path.display()
    );

    // Verify the addressbook file exists
    if !user_addressbook_path.exists() {
        return Err(GpgError::PathError(format!(
            "Addressbook file not found for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }
    if !user_addressbook_path.is_file() {
        return Err(GpgError::PathError(format!(
            "Addressbook path is not a file for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }

    // Convert addressbook path to string for the clearsigned TOML reading function
    let user_addressbook_path_str = match user_addressbook_path.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for addressbook file: {}",
                user_addressbook_path.display()
            )));
        }
    };

    // --- Stage 4: Extract GPG Key ID from Addressbook File ---
    let gpg_key_id_name_of_toml_field_key_to_read = "gpg_publickey_id";
    println!(
        "Reading GPG key ID from clearsigned addressbook file field '{}' in '{}'",
        gpg_key_id_name_of_toml_field_key_to_read,
        user_addressbook_path_str
    );

    // Read the GPG key ID from the clearsigned addressbook file
    let signing_key_id = match read_singleline_string_from_clearsigntoml(
        user_addressbook_path_str,
        gpg_key_id_name_of_toml_field_key_to_read
    ) {
        Ok(key_id) => {
            if key_id.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "Field '{}' is empty in addressbook file for owner '{}': {}",
                    gpg_key_id_name_of_toml_field_key_to_read,
                    file_owner_username,
                    user_addressbook_path_str
                )));
            }
            key_id
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read GPG key ID from field '{}' in clearsigned addressbook file '{}': {}",
                gpg_key_id_name_of_toml_field_key_to_read,
                user_addressbook_path_str,
                e
            )));
        }
    };
    println!(
        "GPG signing key ID for owner '{}': '{}'",
        file_owner_username, signing_key_id
    );

    // --- Stage 5: Validate GPG Secret Key Availability ---
    println!(
        "Validating GPG secret key availability for key ID: '{}'",
        signing_key_id
    );

    match validate_gpg_secret_key(&signing_key_id) {
        Ok(true) => {
            println!(
                "GPG secret key for ID '{}' (owner: '{}') is available for signing.",
                signing_key_id, file_owner_username
            );
        }
        Ok(false) => {
            return Err(GpgError::GpgOperationError(format!(
                "GPG secret key for ID '{}' (from addressbook of owner '{}') not found in keyring or is not usable. Cannot sign file.",
                signing_key_id,
                file_owner_username
            )));
        }
        Err(e) => {
            // Pass through the GpgError from validate_gpg_secret_key
            return Err(e);
        }
    }

    // --- Stage 6: Prepare Temporary File Path ---
    // Create a temporary file path in the same directory for atomic rename
    let original_file_name = match path_to_toml_file.file_name() {
        Some(name) => name.to_string_lossy(),
        None => {
            return Err(GpgError::PathError(format!(
                "Could not get filename from path: {}",
                path_to_toml_file.display()
            )));
        }
    };

    let temp_file_name = format!("{}.tmp_clearsign_{}", original_file_name, generate_timestamp());
    let temp_output_path = path_to_toml_file.with_file_name(temp_file_name);

    println!(
        "Temporary file for clearsigned output: {}",
        temp_output_path.display()
    );

    // --- Stage 7: Perform GPG Clearsign Operation ---
    println!(
        "Performing GPG clearsign operation on '{}' using key ID '{}' (owner: '{}')",
        path_to_toml_file.display(),
        signing_key_id,
        file_owner_username
    );

    let clearsign_command_result = Command::new("gpg")
        .arg("--clearsign")              // Perform a clearsign operation
        .arg("--batch")                  // Ensure no interactive prompts
        .arg("--yes")                    // Assume "yes" to prompts
        .arg("--default-key")            // Specify the key to use
        .arg(&signing_key_id)            // The key ID from addressbook
        .arg("--output")                 // Specify output file
        .arg(&temp_output_path)          // Temporary output path
        .arg(path_to_toml_file)          // Input file to clearsign
        .output();                       // Execute and get output

    match clearsign_command_result {
        Ok(output) => {
            if output.status.success() {
                println!(
                    "GPG clearsign operation successful. Output written to temporary file: {}",
                    temp_output_path.display()
                );
            } else {
                // GPG command executed but failed
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                // Clean up temporary file if it exists
                if temp_output_path.exists() {
                    if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                        eprintln!(
                            "Additionally, failed to remove temporary file '{}' after GPG error: {}",
                            temp_output_path.display(),
                            e_remove
                        );
                    }
                }
                return Err(GpgError::GpgOperationError(format!(
                    "GPG clearsign command failed for file '{}' with exit code: {}. GPG stderr: {}",
                    path_to_toml_file.display(),
                    output.status,
                    stderr_output.trim()
                )));
            }
        }
        Err(e) => {
            // Failed to execute GPG command
            if temp_output_path.exists() {
                if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                    eprintln!(
                        "Additionally, failed to remove temporary file '{}' after GPG execution error: {}",
                        temp_output_path.display(),
                        e_remove
                    );
                }
            }
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG clearsign command for file '{}': {}",
                path_to_toml_file.display(),
                e
            )));
        }
    }

    // --- Stage 8: In-Place Replacement ---
    println!(
        "Replacing original file '{}' with its clearsigned version",
        path_to_toml_file.display()
    );

    // Read original content as backup in case of catastrophic failure
    let original_content_backup = match fs::read_to_string(path_to_toml_file) {
        Ok(content) => content,
        Err(e) => {
            return Err(GpgError::FileSystemError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read original file for backup before deletion: {}. Error: {}",
                    path_to_toml_file.display(),
                    e
                ),
            )));
        }
    };

    // Delete the original file
    if let Err(e_remove_orig) = fs::remove_file(path_to_toml_file) {
        // Critical error: couldn't delete original
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e_remove_orig.kind(),
            format!(
                "Failed to delete original file '{}' before replacing with clearsigned version. Clearsigned data is in '{}'. Error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_remove_orig
            ),
        )));
    }
    println!("Original file '{}' deleted.", path_to_toml_file.display());

    // Rename the temporary clearsigned file to the original filename
    if let Err(e_rename) = fs::rename(&temp_output_path, path_to_toml_file) {
        // Critical error: rename failed after deleting original
        eprintln!(
            "Critical: Failed to rename temporary file '{}' to original file path '{}'. Attempting to restore original content.",
            temp_output_path.display(),
            path_to_toml_file.display()
        );
        
        // Attempt to restore original content
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
                "Critical: Failed to rename temporary file '{}' to original file path '{}'. Original data was in memory and an attempt to restore was made. Please check file states. Rename Error: {}",
                temp_output_path.display(),
                path_to_toml_file.display(),
                e_rename
            ),
        )));
    }

    println!(
        "Successfully converted '{}' to clearsigned TOML in-place using owner '{}' key.",
        path_to_toml_file.display(),
        file_owner_username
    );

    // --- Stage 9: Cleanup ---
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


/// Converts a TOML file into a clearsigned TOML file in-place, using owner-based GPG key lookup.
///
/// # Purpose
/// This function is designed for signing TOML files where the GPG key ID is not stored within
/// the file itself, but rather is determined by looking up the file owner's addressbook entry.
/// This enforces a centralized key management system where:
/// 1. Each file declares its owner via an `"owner"` field
/// 2. Each owner has a registered addressbook file containing their GPG key ID
/// 3. Files can only be signed by their declared owners
///
/// Like `convert_toml_filewithkeyid_into_clearsigntoml_inplace`, this function creates a
/// clearsigned TOML file that recipients can verify for:
/// 1. **Integrity**: That the file's content has not been altered since signing
/// 2. **Authenticity**: That the file was signed by the declared owner
///
/// # Key Lookup Process
/// Instead of reading the GPG key ID directly from the target TOML file, this function:
/// 1. Reads the owner's username from the target file's `"owner"` field
/// 2. Constructs the path to the owner's addressbook file: `{username}__collaborator.toml`
/// 3. Reads the GPG key ID from the addressbook file's `"gpg_publickey_id"` field
/// 4. Uses that key ID to sign the target file
///
/// # "In-Place" Operation
/// The term "in-place" means the original TOML file at `path_to_toml_file` will be
/// **overwritten** by its clearsigned counterpart. The content changes, but the
/// filename and location remain the same. This is a destructive operation; ensure
/// backups are considered if the original unsigned state is important.
///
/// # Input TOML File Requirements
/// The target TOML file (provided via `path_to_toml_file`) **must** contain:
/// - An `"owner"` field with the username of the file's owner
/// - This owner must have a corresponding addressbook file in the collaborator directory
///
/// The target file **must not** contain a `"gpg_publickey_id"` field, as this function
/// is specifically for files where the key ID is managed externally.
///
/// # Addressbook File Requirements
/// The owner's addressbook file (`{owner}__collaborator.toml`) must:
/// - Exist in the collaborator addressbook directory
/// - Be a valid clearsigned TOML file
/// - Contain a `"gpg_publickey_id"` field with the owner's GPG key ID
///
/// # GPG Private Key Requirement
/// The GPG keyring on the system executing this function **must** contain the **private key**
/// corresponding to the GPG key ID found in the owner's addressbook file. This private key
/// must be available and usable by GPG for signing.
///
/// # Process Flow
/// 1. **Input Validation**:
///    - Checks if `path_to_toml_file` exists and is a file
/// 2. **Owner Extraction**:
///    - Reads the TOML file to find and extract the value of the `"owner"` field
///    - If this field is missing, empty, or unreadable, returns an error
/// 3. **Addressbook Path Construction**:
///    - Builds the absolute path to the collaborator addressbook directory
///    - Constructs the owner's addressbook filename: `{owner}__collaborator.toml`
/// 4. **Key ID Lookup**:
///    - Reads the owner's addressbook file (which is already clearsigned)
///    - Extracts the `"gpg_publickey_id"` field value
/// 5. **Signing Key Validation**:
///    - Validates that the private key for the looked-up key ID exists locally
/// 6. **Clearsign Operation**:
///    - Creates a temporary file
///    - Uses GPG to clearsign the original file with the looked-up key ID
/// 7. **In-Place Replacement**:
///    - Deletes the original file
///    - Renames the temporary clearsigned file to the original filename
/// 8. **Cleanup**:
///    - Removes any remaining temporary files
///
/// # Arguments
/// - `path_to_toml_file` - A reference to a `Path` object representing the TOML file
///   to be converted in-place. Must contain an `"owner"` field.
///
/// # Returns
/// - `Ok(())` - If the TOML file was successfully clearsigned and replaced in-place
/// - `Err(GpgError)` - If any step in the process fails:
///   - `PathError`: File not found, invalid path, or path encoding issues
///   - `GpgOperationError`: Missing fields, GPG command failures, or key lookup failures
///   - `FileSystemError`: I/O errors during file operations
///
/// # Prerequisites
/// - GnuPG (GPG) must be installed and accessible via PATH
/// - The collaborator addressbook directory must exist and be accessible
/// - The owner specified in the file must have a valid addressbook file
/// - The GPG private key from the addressbook must be in the local keyring
///
/// # Security Considerations
/// - **Centralized Key Management**: Keys are managed via addressbook files, not individual files
/// - **Owner Enforcement**: Files can only be signed by their declared owners
/// - **Destructive Operation**: Overwrites the original file
/// - **Trust Chain**: Security depends on the integrity of the addressbook files
pub fn convert_tomlfile_without_keyid_using_gpgtomlkeyid_into_clearsigntoml_inplace(
    path_to_toml_file: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
    gpg_full_fingerprint_key_id_string: &str,
) -> Result<(), GpgError> {
    // --- Stage 1: Input Validation ---
    println!(
        "ctwKUGci Starting in-place clearsign conversion with owner-based key lookup for: {}",
        path_to_toml_file.display()
    );

    // Validate that the input path exists and is a file
    if !path_to_toml_file.exists() {
        return Err(GpgError::PathError(format!(
            "ctwKUGci Input TOML file not found: {}",
            path_to_toml_file.display()
        )));
    }
    if !path_to_toml_file.is_file() {
        return Err(GpgError::PathError(format!(
            "ctwKUGci Input path is not a file: {}",
            path_to_toml_file.display()
        )));
    }

    // Convert path to string for TOML reading function
    let path_str = match path_to_toml_file.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "ctwKUGci Invalid path encoding for: {}",
                path_to_toml_file.display()
            )));
        }
    };

    // --- Stage 2: Extract Owner from Target TOML File ---
    let owner_name_of_toml_field_key_to_read = "owner";
    println!(
        "ctwKUGci Reading file owner from field '{}' in file '{}'",
        owner_name_of_toml_field_key_to_read, path_str
    );

    // Read the owner username from the plain TOML file
    let file_owner_username = match read_single_line_string_field_from_toml(path_str, owner_name_of_toml_field_key_to_read) {
        Ok(username) => {
            if username.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "ctwKUGci Field '{}' is empty in TOML file: {}. File owner is required for key lookup.",
                    owner_name_of_toml_field_key_to_read, path_str
                )));
            }
            username
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "ctwKUGci Failed to read file owner from field '{}' in TOML file '{}': {}",
                owner_name_of_toml_field_key_to_read, path_str, e
            )));
        }
    };
    println!("ctwKUGci File owner username: '{}'", file_owner_username);

    // --- Stage 3: Construct Addressbook File Path ---
    println!(
        "ctwKUGci Constructing path to owner's addressbook file for user: '{}'",
        file_owner_username
    );

    // Get the relative path to the collaborator addressbook directory
    // let addressbook_files_directory_relative = collaborator_addressbook_base_path;
    
    // Convert to absolute path and verify the directory exists
    let collaborator_files_directory_absolute = 
        match make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
            addressbook_files_directory_relative
        ) {
            Ok(path) => path,
            Err(io_error) => {
                return Err(GpgError::FileSystemError(io_error));
            }
        };

    println!(
        "ctwKUGci Collaborator addressbook directory: {}",
        collaborator_files_directory_absolute.display()
    );

    // Construct the filename for this owner's addressbook file
    let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    let proto_useraddressbook_path = collaborator_files_directory_absolute.join(&collaborator_filename);

    println!(
        "ctwKUGci Owner's addressbook file path: {}",
        proto_useraddressbook_path.display()
    );
    
    
    
    // // In your existing functions, you can now use:
    // let (user_addressbook_path, temp_to_cleanup) = get_path_to_clearsign_toml_for_gpgtoml_option(
    //     &proto_useraddressbook_path,
    //     &gpg_full_fingerprint_key_id_string
    // )?;
        
    // Better error handling with explicit logging
    let (user_addressbook_path, temp_to_cleanup) = match get_path_to_clearsign_toml_for_gpgtoml_option(
        &proto_useraddressbook_path,
        &gpg_full_fingerprint_key_id_string
    ) {
        Ok(result) => {
            println!("Successfully got path: {:?}", result.0);
            result
        }
        Err(gpg_error) => {
            // Log the specific error
            eprintln!("ERROR: get_path_to_clearsign_toml_for_gpgtoml_option failed!");
            eprintln!("  Input path: {}", proto_useraddressbook_path.display());
            eprintln!("  GPG key: {}", gpg_full_fingerprint_key_id_string);
            eprintln!("  Error: {}", gpg_error.to_string());
            
            // Convert to the appropriate error type for your function
            return Err(GpgError::GpgOperationError(format!(
                "Failed to process addressbook file '{}': {}",
                proto_useraddressbook_path.display(),
                gpg_error.to_string()
            )));
        }
    };

    // Add logging to see what's happening
    println!("Using addressbook path: {}", user_addressbook_path.display());
    if let Some(ref temp) = temp_to_cleanup {
        println!("Created temporary file: {}", temp.display());
    }
    
    println!(
        "ctwKUGci user_addressbook_path: {}",
        user_addressbook_path.display()
    );
    
    /*
    NOTE: use this at end of function
    // At the end, clean up:
    cleanup_temp_clearsign_toml(temp_to_cleanup);
    */

    // Use path_to_read for reading operations...

    // Verify the addressbook file exists
    if !user_addressbook_path.exists() {
        return Err(GpgError::PathError(format!(
            "ctwKUGci Addressbook file not found for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }
    if !user_addressbook_path.is_file() {
        return Err(GpgError::PathError(format!(
            "ctwKUGci Addressbook path is not a file for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }

    // Convert addressbook path to string for the clearsigned TOML reading function
    let user_addressbook_path_str = match user_addressbook_path.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "ctwKUGci Invalid path encoding for addressbook file: {}",
                user_addressbook_path.display()
            )));
        }
    };

    // --- Stage 4: Extract GPG Key ID from Addressbook File ---
    let gpg_key_id_name_of_toml_field_key_to_read = "gpg_publickey_id";
    println!(
        "ctwKUGci Reading GPG key ID from clearsigned addressbook file field '{}' in '{}'",
        gpg_key_id_name_of_toml_field_key_to_read,
        user_addressbook_path_str
    );

    // Read the GPG key ID from the clearsigned addressbook file
    let signing_key_id = match read_singleline_string_from_clearsigntoml(
        user_addressbook_path_str,
        gpg_key_id_name_of_toml_field_key_to_read
    ) {
        Ok(key_id) => {
            if key_id.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "ctwKUGci Field '{}' is empty in addressbook file for owner '{}': {}",
                    gpg_key_id_name_of_toml_field_key_to_read,
                    file_owner_username,
                    user_addressbook_path_str
                )));
            }
            key_id
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "ctwKUGci Failed to read GPG key ID from field '{}' in clearsigned addressbook file '{}': {}",
                gpg_key_id_name_of_toml_field_key_to_read,
                user_addressbook_path_str,
                e
            )));
        }
    };
    println!(
        "ctwKUGci GPG signing key ID for owner '{}': '{}'",
        file_owner_username, signing_key_id
    );

    // --- Stage 5: Validate GPG Secret Key Availability ---
    println!(
        "ctwKUGci Validating GPG secret key availability for key ID: '{}'",
        signing_key_id
    );

    match validate_gpg_secret_key(&signing_key_id) {
        Ok(true) => {
            println!(
                "ctwKUGci GPG secret key for ID '{}' (owner: '{}') is available for signing.",
                signing_key_id, file_owner_username
            );
        }
        Ok(false) => {
            return Err(GpgError::GpgOperationError(format!(
                "ctwKUGci GPG secret key for ID '{}' (from addressbook of owner '{}') not found in keyring or is not usable. Cannot sign file.",
                signing_key_id,
                file_owner_username
            )));
        }
        Err(e) => {
            // Pass through the GpgError from validate_gpg_secret_key
            return Err(e);
        }
    }
    
    // And the time is cleanup the time!
    cleanup_temp_clearsign_toml(temp_to_cleanup);

    // --- Stage 6: Prepare Temporary File Path ---
    // Create a temporary file path in the same directory for atomic rename
    let original_file_name = match path_to_toml_file.file_name() {
        Some(name) => name.to_string_lossy(),
        None => {
            return Err(GpgError::PathError(format!(
                "ctwKUGci: ERROR Could not get filename from path: {}",
                path_to_toml_file.display()
            )));
        }
    };

    let temp_file_name = format!("{}.tmp_clearsign_{}", original_file_name, generate_timestamp());
    let temp_output_path = path_to_toml_file.with_file_name(temp_file_name);

    println!(
        "ctwKUGci Temporary file for clearsigned output: {}",
        temp_output_path.display()
    );

    // --- Stage 7: Perform GPG Clearsign Operation ---
    println!(
        "ctwKUGci: Performing GPG clearsign operation on '{}' using key ID '{}' (owner: '{}')",
        path_to_toml_file.display(),
        signing_key_id,
        file_owner_username
    );

    let clearsign_command_result = Command::new("gpg")
        .arg("--clearsign")              // Perform a clearsign operation
        .arg("--batch")                  // Ensure no interactive prompts
        .arg("--yes")                    // Assume "yes" to prompts
        .arg("--default-key")            // Specify the key to use
        .arg(&signing_key_id)            // The key ID from addressbook
        .arg("--output")                 // Specify output file
        .arg(&temp_output_path)          // Temporary output path
        .arg(path_to_toml_file)          // Input file to clearsign
        .output();                       // Execute and get output

    match clearsign_command_result {
        Ok(output) => {
            if output.status.success() {
                println!(
                    "ctwKUGci: GPG clearsign operation successful. Output written to temporary file: {}",
                    temp_output_path.display()
                );
            } else {
                // GPG command executed but failed
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                // Clean up temporary file if it exists
                if temp_output_path.exists() {
                    if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                        eprintln!(
                            "ctwKUGci:  Additionally, failed to remove temporary file '{}' after GPG error: {}",
                            temp_output_path.display(),
                            e_remove
                        );
                    }
                }
                return Err(GpgError::GpgOperationError(format!(
                    "ctwKUGci: GPG clearsign command failed for file '{}' with exit code: {}. GPG stderr: {}",
                    path_to_toml_file.display(),
                    output.status,
                    stderr_output.trim()
                )));
            }
        }
        Err(e) => {
            // Failed to execute GPG command
            if temp_output_path.exists() {
                if let Err(e_remove) = fs::remove_file(&temp_output_path) {
                    eprintln!(
                        "ctwKUGci: Additionally, failed to remove temporary file '{}' after GPG execution error: {}",
                        temp_output_path.display(),
                        e_remove
                    );
                }
            }
            return Err(GpgError::GpgOperationError(format!(
                "ctwKUGci: Failed to execute GPG clearsign command for file '{}': {}",
                path_to_toml_file.display(),
                e
            )));
        }
    }

    // --- Stage 8: In-Place Replacement ---
    println!(
        "ctwKUGci: Replacing original file '{}' with its clearsigned version",
        path_to_toml_file.display()
    );

    // Read original content as backup in case of catastrophic failure
    let original_content_backup = match fs::read_to_string(path_to_toml_file) {
        Ok(content) => content,
        Err(e) => {
            return Err(GpgError::FileSystemError(std::io::Error::new(
                e.kind(),
                format!(
                    "ctwKUGci: Failed to read original file for backup before deletion: {}. Error: {}",
                    path_to_toml_file.display(),
                    e
                ),
            )));
        }
    };

    // Delete the original file
    if let Err(e_remove_orig) = fs::remove_file(path_to_toml_file) {
        // Critical error: couldn't delete original
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e_remove_orig.kind(),
            format!(
                "ctwKUGci: Failed to delete original file '{}' before replacing with clearsigned version. Clearsigned data is in '{}'. Error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_remove_orig
            ),
        )));
    }
    println!("ctwKUGci: Original file '{}' deleted.", path_to_toml_file.display());

    // Rename the temporary clearsigned file to the original filename
    if let Err(e_rename) = fs::rename(&temp_output_path, path_to_toml_file) {
        // Critical error: rename failed after deleting original
        eprintln!(
            "ctwKUGci: Critical: Failed to rename temporary file '{}' to original file path '{}'. Attempting to restore original content.",
            temp_output_path.display(),
            path_to_toml_file.display()
        );
        
        // Attempt to restore original content
        if let Err(e_restore) = fs::write(path_to_toml_file, original_content_backup) {
            eprintln!(
                "ctwKUGci: Catastrophic failure: Could not restore original file '{}' after rename failure. Original content might be lost. Clearsigned data is in '{}'. Restore error: {}. Rename error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_restore,
                e_rename
            );
        } else {
            eprintln!(
                "ctwKUGci: Successfully restored original content to '{}'. Clearsigned data is in '{}'. Rename error: {}",
                path_to_toml_file.display(),
                temp_output_path.display(),
                e_rename
            );
        }
        
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e_rename.kind(),
            format!(
                "ctwKUGci: Critical: Failed to rename temporary file '{}' to original file path '{}'. Original data was in memory and an attempt to restore was made. Please check file states. Rename Error: {}",
                temp_output_path.display(),
                path_to_toml_file.display(),
                e_rename
            ),
        )));
    }

    println!(
        "ctwKUGci: Successfully converted '{}' to clearsigned TOML in-place using owner '{}' key.",
        path_to_toml_file.display(),
        file_owner_username
    );

    // --- Stage 9: Cleanup ---
    if temp_output_path.exists() {
        println!(
            "ctwKUGci: Attempting to clean up residual temporary file: {}",
            temp_output_path.display()
        );
        if let Err(e_remove_temp) = fs::remove_file(&temp_output_path) {
            eprintln!(
                "ctwKUGci: Warning: Failed to clean up residual temporary file '{}': {}",
                temp_output_path.display(),
                e_remove_temp
            );
        }
    }

    Ok(())
}

/// Re-clearsigns an already clearsigned TOML file in-place, using owner-based GPG key lookup.
///
/// # Purpose
/// This function is designed for scenarios where a clearsigned TOML file needs to be
/// modified and re-signed. It handles the complete workflow of:
/// 1. **Validating** the existing signature (ensuring integrity and authenticity)
/// 2. Extracting the plain TOML content from the validated clearsigned file
/// 3. Re-signing it using the owner-based key lookup system
///
/// # Security Model
/// This function **always** validates the existing signature before extraction.
/// This ensures:
/// - The file hasn't been tampered with
/// - The previous signature was valid
/// - We maintain a chain of trust
/// 
/// This is especially important in educational environments where:
/// - Students need to learn proper security practices
/// - File integrity must be maintained
/// - Trust chains should never be broken
///
/// # Process Flow
/// 1. **Clearsign Validation** (MANDATORY):
///    - Reads the clearsigned TOML file
///    - Validates the existing signature using GPG
///    - Only proceeds if validation succeeds
///
/// 2. **Content Extraction**:
///    - Extracts the plain TOML content from the validated clearsigned file
///    - This happens as part of the GPG validation process
///
/// 3. **Re-signing**:
///    - Temporarily replaces the file with extracted plain content
///    - Delegates to `convert_tomlfile_without_keyid_into_clearsigntoml_inplace()`
///    - Uses owner-based lookup to determine the signing key
///    - Creates a new clearsigned version of the file
///
/// # Security Considerations
/// - **Always Validates**: The existing signature is always checked - no exceptions
/// - **Maintains Trust Chain**: Only valid signed content can be re-signed
/// - **Fail-Safe**: If validation fails, the operation is aborted
/// - **Educational Value**: Teaches students that signature validation is non-negotiable
pub fn re_clearsign_clearsigntoml_file_without_keyid_into_clearsigntoml_inplace(
    path_to_clearsigned_toml_file: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<(), GpgError> {
    // --- Stage 1: Input Validation ---
    println!(
        "Starting secure re-clearsign process for: {}",
        path_to_clearsigned_toml_file.display()
    );
    println!("Note: Existing signature will be validated to ensure security.");

    // Validate that the input path exists and is a file
    if !path_to_clearsigned_toml_file.exists() {
        return Err(GpgError::PathError(format!(
            "Clearsigned TOML file not found: {}",
            path_to_clearsigned_toml_file.display()
        )));
    }
    if !path_to_clearsigned_toml_file.is_file() {
        return Err(GpgError::PathError(format!(
            "Path is not a file: {}",
            path_to_clearsigned_toml_file.display()
        )));
    }

    // --- Stage 2: Read Existing Clearsigned Content for Backup ---
    println!("Reading existing clearsigned content for backup...");
    
    let original_clearsigned_backup = fs::read_to_string(path_to_clearsigned_toml_file)
        .map_err(|e| {
            GpgError::FileSystemError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read clearsigned file '{}': {}",
                    path_to_clearsigned_toml_file.display(),
                    e
                ),
            ))
        })?;

    // --- Stage 3: Validate Signature and Extract Content ---
    println!("Validating existing signature and extracting content...");
    println!("This ensures the file hasn't been tampered with.");
    
    // Create a temporary file for GPG verification output
    let temp_verify_file = path_to_clearsigned_toml_file.with_extension("tmp_verify");
    
    // Run GPG verification and extraction
    // Using --decrypt which both verifies and extracts
    let verify_result = Command::new("gpg")
        .arg("--decrypt")           // Verify signature and output plain content
        .arg("--batch")             // Non-interactive mode
        .arg("--yes")               // Assume yes to questions
        .arg("--status-fd")         // Output status info
        .arg("2")                   // Status to stderr
        .arg("--output")            // Output to file
        .arg(&temp_verify_file)     // Temporary output path
        .arg(path_to_clearsigned_toml_file) // Input clearsigned file
        .output();

    let plain_toml_content = match verify_result {
        Ok(output) => {
            if output.status.success() {
                println!("✓ Signature validation PASSED. File integrity confirmed.");
                
                // Read the extracted content
                let content = fs::read_to_string(&temp_verify_file).map_err(|e| {
                    // Clean up temp file
                    let _ = fs::remove_file(&temp_verify_file);
                    GpgError::FileSystemError(std::io::Error::new(
                        e.kind(),
                        format!("Failed to read extracted content: {}", e),
                    ))
                })?;
                
                // Clean up temp file
                if let Err(e) = fs::remove_file(&temp_verify_file) {
                    eprintln!("Warning: Failed to remove temporary file: {}", e);
                }
                
                content
            } else {
                // Clean up temp file if it exists
                let _ = fs::remove_file(&temp_verify_file);
                
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                return Err(GpgError::GpgOperationError(format!(
                    "GPG signature validation FAILED for '{}'. \
                     This file may have been tampered with or corrupted. \
                     For security reasons, re-signing is not allowed. \
                     GPG output: {}",
                    path_to_clearsigned_toml_file.display(),
                    stderr_output.trim()
                )));
            }
        }
        Err(e) => {
            // Clean up temp file if it exists
            let _ = fs::remove_file(&temp_verify_file);
            
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG verify command: {}. \
                 Ensure GPG is installed and accessible.",
                e
            )));
        }
    };

    println!(
        "Successfully extracted {} bytes of validated plain TOML content",
        plain_toml_content.len()
    );

    // --- Stage 4: Temporarily Replace File with Plain Content ---
    println!("Preparing file for re-signing...");
    
    // Write the plain TOML content to the file
    // This is necessary because the signing function expects plain TOML
    if let Err(e) = fs::write(path_to_clearsigned_toml_file, &plain_toml_content) {
        return Err(GpgError::FileSystemError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to write plain content to file '{}': {}",
                path_to_clearsigned_toml_file.display(),
                e
            ),
        )));
    }

    // --- Stage 5: Re-sign the File Using Owner-based Lookup ---
    println!("Re-signing file using owner-based key lookup...");
    
    // Call the existing function to sign the now-plain TOML file
    match convert_tomlfile_without_keyid_into_clearsigntoml_inplace(
        path_to_clearsigned_toml_file,
        addressbook_files_directory_relative,
    ) {
        Ok(()) => {
            println!(
                "✓ Successfully re-signed file: {}",
                path_to_clearsigned_toml_file.display()
            );
            println!("The file now has a fresh signature from the owner's current key.");
            Ok(())
        }
        Err(e) => {
            // If re-signing fails, attempt to restore the original clearsigned content
            eprintln!(
                "Re-signing failed. Attempting to restore original clearsigned content..."
            );
            
            if let Err(restore_err) = fs::write(
                path_to_clearsigned_toml_file,
                &original_clearsigned_backup,
            ) {
                eprintln!(
                    "CRITICAL: Failed to restore original clearsigned content: {}. \
                     File may be in inconsistent state! \
                     Manual intervention may be required.",
                    restore_err
                );
            } else {
                println!("✓ Original clearsigned content restored after signing failure.");
            }
            
            // Return the original error
            Err(e)
        }
    }
}

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
/// -   The file at `path_to_toml_file` becomes a standard GPG clearsigned message.
/// -   Its content is the original TOML data, encapsulated within PGP signature blocks.
/// -   All original fields, including `gpg_publickey_id` and any `gpg_key_public` field,
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
/// - `path_to_toml_file` - A reference to a `Path` object representing the TOML file
///   to be converted in-place by its author.
///
/// # Returns
/// - `Ok(())` - If the TOML file was successfully clearsigned and replaced in-place.
/// - `Err(GpgError)` - If any step in the process fails. (Details as previously listed)
///
/// # Prerequisites for the Author
/// -   GnuPG (GPG) must be installed on the author's system and accessible via the PATH.
/// -   The author's GPG private key (corresponding to the `gpg_publickey_id` value
///     within the input TOML file) must be in their local GPG keyring and usable.
///
/// # Security Considerations
/// -   **Authorship Assertion**: This function is a tool for an author to assert control
///     and authorship over a TOML file. The security relies on the author protecting
///     their private GPG key.
/// -   **Destructive Operation**: Overwrites the original file.
/// -   **Key Specification**: The signing key is determined by the TOML file's content.
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
    let name_of_toml_field_key_to_read_for_signing_key_id = "gpg_publickey_id";
    println!(
        "Reading author's GPG signing key ID from field '{}' in file '{}'",
        name_of_toml_field_key_to_read_for_signing_key_id, path_str
    );

    let signing_key_id =
        match read_single_line_string_field_from_toml(path_str, name_of_toml_field_key_to_read_for_signing_key_id) {
            Ok(id) => {
                if id.is_empty() {
                    return Err(GpgError::GpgOperationError(format!(
                        "Field '{}' is empty in TOML file: {}. Author's GPG key ID is required for signing.",
                        name_of_toml_field_key_to_read_for_signing_key_id, path_str
                    )));
                }
                id
            }
            Err(e) => {
                // read_single_line_string_field_from_toml returns String, map error type.
                return Err(GpgError::GpgOperationError(format!(
                    "Failed to read author's GPG signing key ID from field '{}' in TOML file '{}': {}",
                    name_of_toml_field_key_to_read_for_signing_key_id, path_str, e
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
            // Updated to match the actual error message that includes "author's"
            assert!(msg.contains("Failed to read author's GPG signing key ID from field 'gpg_publickey_id'"));
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


/*
for uma team-channel node and similar struct fields

## Refined Function Scope

**Purpose**: Read nested port assignments from a clearsigned TOML file that uses owner-based key lookup (same pattern as `convert_tomlfile_without_keyid_into_clearsigntoml_inplace`).

**Key Requirements**:
1. **Security-First**: The function MUST validate the clearsign signature before reading ANY data
2. **Owner-Based Key Lookup**: 
   - The target TOML file contains an `owner` field
   - The owner's GPG key is stored in their addressbook file: `{owner}__collaborator.toml`
   - The addressbook file contains the `gpg_publickey_id` used to verify the signature
3. **No Direct Reading**: If signature validation fails, NO data is returned - security is mandatory
4. **Nested Structure Parsing**: After validation, parse the complex nested structure without third-party libraries

**Validation Flow** (same as `convert_tomlfile_without_keyid_into_clearsigntoml_inplace`):
1. Read the `owner` field from the target file
2. Construct path to owner's addressbook: `{collaborator_files_directory}/{owner}__collaborator.toml`
3. Extract `gpg_publickey_id` from the addressbook (which itself is clearsigned)
4. Use that key to verify the target file's signature
5. Only if verification succeeds, proceed to parse the port assignments

**Data Extraction**:
- Parse the `abstract_collaborator_port_assignments` table structure
- Extract port assignments for each collaborator pair
- Each assignment includes: `user_name`, `ready_port`, `intray_port`, `gotit_port`
*/

/// Represents a single collaborator's port assignments within a team channel.
///
/// This structure holds the network port configuration for a specific collaborator,
/// including ports for different communication channels (ready, intray, gotit).
#[derive(Debug, Clone, PartialEq)]
pub struct CollaboratorPortAssignment {
    /// The username of the collaborator
    pub user_name: String,
    /// The port number for "ready" status communication
    pub ready_port: u16,
    /// The port number for "intray" (inbox) communication
    pub intray_port: u16,
    /// The port number for "gotit" (acknowledgment) communication
    pub gotit_port: u16,
}

/// Reads port assignments for a specific collaborator pair from a clearsigned TOML file using owner-based GPG key lookup.
///
/// # Purpose
/// This function extracts network port assignments for a specific pair of collaborators from a
/// clearsigned team channel configuration file. It enforces security by requiring GPG signature
/// validation before any data extraction occurs.
///
/// # Security Model
/// This function implements a strict security-first approach:
/// 1. **No data access without validation**: The clearsigned file MUST be validated before any content is read
/// 2. **Owner-based key management**: The signing key is determined by the file's owner field
/// 3. **Chain of trust**: Validation uses keys from the collaborator addressbook system
///
/// # Validation Process
/// 1. Reads the `owner` field from the target clearsigned TOML file
/// 2. Constructs the path to the owner's addressbook file: `{owner}__collaborator.toml`
/// 3. Extracts the GPG key ID from the addressbook (which is itself clearsigned and validated)
/// 4. Uses that key to verify the target file's signature
/// 5. Only proceeds with data extraction if signature validation succeeds
///
/// # Data Structure
/// The function expects the TOML file to contain a structure like:
/// ```toml
/// [abstract_collaborator_port_assignments.alice_bob]
/// collaborator_ports = [
///     { user_name = "alice", ready_port = 50001, intray_port = 50002, gotit_port = 50003 },
///     { user_name = "bob", ready_port = 50004, intray_port = 50005, gotit_port = 50006 },
/// ]
/// ```
///
/// # Arguments
/// - `path_to_clearsigned_toml` - Path to the clearsigned TOML file containing port assignments
/// - `addressbook_files_directory_relative` - Relative path to the directory containing collaborator addressbook files
/// - `pair_name` - The name of the collaborator pair (e.g., "alice_bob")
///
/// # Returns
/// - `Ok(Vec<CollaboratorPortAssignment>)` - A vector of port assignments for the specified pair
/// - `Err(GpgError)` - If any step fails:
///   - `PathError`: File not found or invalid path
///   - `GpgOperationError`: GPG validation failure or missing required fields
///   - `FileSystemError`: I/O errors
///
/// # Example
/// ```no_run
/// let assignments = read_specific_pair_port_assignments_from_clearsigntoml(
///     Path::new("team_channel_config.toml"),
///     "collaborators",
///     "alice_bob"
/// )?;
/// 
/// for assignment in assignments {
///     println!("{}: ready={}, intray={}, gotit={}", 
///              assignment.user_name, 
///              assignment.ready_port,
///              assignment.intray_port,
///              assignment.gotit_port);
/// }
/// ```
pub fn read_specific_pair_port_assignments_from_clearsigntoml(
    path_to_clearsigned_toml: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
    pair_name: &str,
) -> Result<Vec<CollaboratorPortAssignment>, GpgError> {
    // --- Stage 1: Input Validation ---
    println!(
        "Starting secure port assignment extraction for pair '{}' from: {}",
        pair_name,
        path_to_clearsigned_toml.display()
    );

    // Validate that the input path exists and is a file
    if !path_to_clearsigned_toml.exists() {
        return Err(GpgError::PathError(format!(
            "Clearsigned TOML file not found: {}",
            path_to_clearsigned_toml.display()
        )));
    }
    if !path_to_clearsigned_toml.is_file() {
        return Err(GpgError::PathError(format!(
            "Path is not a file: {}",
            path_to_clearsigned_toml.display()
        )));
    }

    // Convert path to string for reading functions
    let path_str = match path_to_clearsigned_toml.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_clearsigned_toml.display()
            )));
        }
    };

    // --- Stage 2: Extract Owner for Key Lookup ---
    let owner_name_of_toml_field_key_to_read = "owner";
    println!(
        "Reading file owner from field '{}' for security validation",
        owner_name_of_toml_field_key_to_read
    );

    // Note: We're reading from a clearsigned file, but we need the owner field first
    // This is safe because we'll validate the entire file before using any other data
    let file_owner_username = match read_single_line_string_field_from_toml(path_str, owner_name_of_toml_field_key_to_read) {
        Ok(username) => {
            if username.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "Field '{}' is empty in TOML file. File owner is required for security validation.",
                    owner_name_of_toml_field_key_to_read
                )));
            }
            username
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read file owner from field '{}': {}",
                owner_name_of_toml_field_key_to_read, e
            )));
        }
    };
    println!("File owner: '{}'", file_owner_username);

    // --- Stage 3: Construct Addressbook Path and Extract GPG Key ---
    println!("Looking up GPG key for owner '{}' in addressbook", file_owner_username);

    // Convert collaborator directory to absolute path
    let collaborator_files_directory_absolute = 
        match make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
            addressbook_files_directory_relative
        ) {
            Ok(path) => path,
            Err(io_error) => {
                return Err(GpgError::FileSystemError(io_error));
            }
        };

    // Construct addressbook filename
    let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    let user_addressbook_path = collaborator_files_directory_absolute.join(&collaborator_filename);

    println!("Owner's addressbook path: {}", user_addressbook_path.display());

    // Verify addressbook exists
    if !user_addressbook_path.exists() {
        return Err(GpgError::PathError(format!(
            "Addressbook file not found for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }

    // Convert addressbook path to string
    let user_addressbook_path_str = match user_addressbook_path.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for addressbook file: {}",
                user_addressbook_path.display()
            )));
        }
    };

    // Extract GPG key ID from addressbook
    let gpg_key_id_name_of_toml_field_key_to_read = "gpg_publickey_id";
    let signing_key_id = match read_singleline_string_from_clearsigntoml(
        user_addressbook_path_str,
        gpg_key_id_name_of_toml_field_key_to_read
    ) {
        Ok(key_id) => {
            if key_id.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "GPG key ID is empty in addressbook for owner '{}'",
                    file_owner_username
                )));
            }
            key_id
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read GPG key ID from addressbook: {}",
                e
            )));
        }
    };
    println!("Found GPG key ID for validation: '{}'", signing_key_id);

    // --- Stage 4: Create Temporary File for Validation ---
    let temp_validation_path = create_temp_file_path("validate_ports")?;
    
    // --- Stage 5: Verify Signature and Extract Content ---
    println!("Validating clearsigned file signature...");
    
    // Decrypt (which validates) the clearsigned file
    let validation_result = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")
        .arg("--status-fd")
        .arg("2")
        .arg("--output")
        .arg(&temp_validation_path)
        .arg(path_to_clearsigned_toml)
        .output();

    match validation_result {
        Ok(output) => {
            if !output.status.success() {
                // Cleanup temp file
                let _ = fs::remove_file(&temp_validation_path);
                
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                return Err(GpgError::GpgOperationError(format!(
                    "GPG signature validation FAILED. File may be tampered. GPG output: {}",
                    stderr_output.trim()
                )));
            }
            println!("✓ Signature validation PASSED. File integrity confirmed.");
        }
        Err(e) => {
            // Cleanup temp file
            let _ = fs::remove_file(&temp_validation_path);
            
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG validation: {}",
                e
            )));
        }
    }

    // --- Stage 6: Parse Port Assignments from Validated Content ---
    println!("Extracting port assignments for pair '{}'", pair_name);
    
    // Now we can safely read from the validated content
    let validated_content = match fs::read_to_string(&temp_validation_path) {
        Ok(content) => content,
        Err(e) => {
            // Cleanup temp file
            let _ = fs::remove_file(&temp_validation_path);
            return Err(GpgError::FileSystemError(e));
        }
    };

    // Cleanup temp file
    let _ = fs::remove_file(&temp_validation_path);

    // Parse the specific table section we're looking for
    let table_header = format!("[abstract_collaborator_port_assignments.{}]", pair_name);
    let mut port_assignments = Vec::new();
    let mut in_target_section = false;
    let mut in_ports_array = false;
    let mut current_port_entry: Option<PartialPortEntry> = None;

    // Helper structure for parsing
    #[derive(Default)]
    struct PartialPortEntry {
        user_name: Option<String>,
        ready_port: Option<u16>,
        intray_port: Option<u16>,
        gotit_port: Option<u16>,
    }

    for line in validated_content.lines() {
        let trimmed = line.trim();
        
        // Check if we're entering our target section
        if trimmed == table_header {
            in_target_section = true;
            continue;
        }
        
        // Check if we're leaving our section (new section starts)
        if in_target_section && trimmed.starts_with('[') && trimmed != table_header {
            break; // We've passed our section
        }
        
        // Skip if not in our section
        if !in_target_section {
            continue;
        }
        
        // Check for collaborator_ports array start
        if trimmed.starts_with("collaborator_ports = [") {
            in_ports_array = true;
            continue;
        }
        
        // Check for array end
        if in_ports_array && trimmed == "]" {
            break; // End of our data
        }
        
        // Parse array entries
        if in_ports_array {
            // Handle start of a new port entry
            if trimmed.starts_with('{') || trimmed.contains("{ user_name") {
                current_port_entry = Some(PartialPortEntry::default());
            }
            
            // Parse fields within the entry
            if let Some(ref mut entry) = current_port_entry {
                // Parse user_name
                if trimmed.contains("user_name = ") {
                    if let Some(value) = extract_quoted_value(trimmed, "user_name") {
                        entry.user_name = Some(value);
                    }
                }
                
                // Parse ready_port
                if trimmed.contains("ready_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "ready_port") {
                        entry.ready_port = Some(value);
                    }
                }
                
                // Parse intray_port
                if trimmed.contains("intray_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "intray_port") {
                        entry.intray_port = Some(value);
                    }
                }
                
                // Parse gotit_port
                if trimmed.contains("gotit_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "gotit_port") {
                        entry.gotit_port = Some(value);
                    }
                }
            }
            
            // Check for end of entry
            if trimmed.ends_with("},") || trimmed.ends_with('}') {
                if let Some(entry) = current_port_entry.take() {
                    // Validate we have all required fields
                    match (entry.user_name, entry.ready_port, entry.intray_port, entry.gotit_port) {
                        (Some(user), Some(ready), Some(intray), Some(gotit)) => {
                            port_assignments.push(CollaboratorPortAssignment {
                                user_name: user,
                                ready_port: ready,
                                intray_port: intray,
                                gotit_port: gotit,
                            });
                        }
                        _ => {
                            return Err(GpgError::GpgOperationError(format!(
                                "Incomplete port assignment entry for pair '{}'. Missing required fields.",
                                pair_name
                            )));
                        }
                    }
                }
            }
        }
    }

    // Check if we found the section
    if !in_target_section {
        return Err(GpgError::GpgOperationError(format!(
            "Collaborator pair '{}' not found in abstract_collaborator_port_assignments",
            pair_name
        )));
    }

    println!(
        "Successfully extracted {} port assignments for pair '{}'",
        port_assignments.len(),
        pair_name
    );

    Ok(port_assignments)
}

/// Helper function to extract quoted string values from TOML lines
///
/// # Arguments
/// - `line` - The line containing the field
/// - `name_of_toml_field_key_to_read` - The name of the field to extract
///
/// # Returns
/// - `Option<String>` - The extracted value without quotes, or None if not found
fn extract_quoted_value(line: &str, name_of_toml_field_key_to_read: &str) -> Option<String> {
    let field_pattern = format!("{} = ", name_of_toml_field_key_to_read);
    if let Some(start_pos) = line.find(&field_pattern) {
        let value_start = start_pos + field_pattern.len();
        let value_part = &line[value_start..].trim();
        
        // Remove quotes and any trailing comma
        let cleaned = value_part
            .trim_start_matches('"')
            .trim_end_matches(',')
            .trim_end_matches('"');
            
        Some(cleaned.to_string())
    } else {
        None
    }
}

/// Helper function to extract port number values from TOML lines
///
/// # Arguments
/// - `line` - The line containing the field
/// - `name_of_toml_field_key_to_read` - The name of the field to extract
///
/// # Returns
/// - `Option<u16>` - The parsed port number, or None if not found or invalid
fn extract_port_value(line: &str, name_of_toml_field_key_to_read: &str) -> Option<u16> {
    let field_pattern = format!("{} = ", name_of_toml_field_key_to_read);
    if let Some(start_pos) = line.find(&field_pattern) {
        let value_start = start_pos + field_pattern.len();
        let value_part = &line[value_start..].trim();
        
        // Remove any trailing comma and parse
        let cleaned = value_part.trim_end_matches(',').trim();
        cleaned.parse::<u16>().ok()
    } else {
        None
    }
}

/// Reads all collaborator pair port assignments from a clearsigned TOML file using owner-based GPG key lookup.
///
/// # Purpose
/// This function extracts network port assignments for ALL collaborator pairs from a
/// clearsigned team channel configuration file. It enforces the same security model as
/// `read_specific_pair_port_assignments_from_clearsigntoml`, requiring GPG signature
/// validation before any data extraction.
///
/// # Security Model
/// Identical to `read_specific_pair_port_assignments_from_clearsigntoml`:
/// - Mandatory signature validation before data access
/// - Owner-based key management via addressbook lookup
/// - Complete chain of trust enforcement
///
/// # Implementation
/// This function:
/// 1. Validates the clearsigned file using owner-based key lookup
/// 2. Identifies all collaborator pairs in the `abstract_collaborator_port_assignments` table
/// 3. Calls `read_specific_pair_port_assignments_from_clearsigntoml` for each pair
/// 4. Aggregates results into a HashMap
///
/// # Arguments
/// - `path_to_clearsigned_toml` - Path to the clearsigned TOML file containing port assignments
/// - `addressbook_files_directory_relative` - Relative path to the directory containing collaborator addressbook files
///
/// # Returns
/// - `Ok(HashMap<String, Vec<CollaboratorPortAssignment>>)` - A map of pair names to their port assignments
/// - `Err(GpgError)` - If validation fails or no assignments are found
///
/// # Example
/// ```no_run
/// let all_assignments = read_abstract_collaborator_port_assignments_from_clearsigntoml(
///     Path::new("team_channel_config.toml"),
///     "collaborators"
/// )?;
/// 
/// for (pair_name, assignments) in all_assignments {
///     println!("Pair: {}", pair_name);
///     for assignment in assignments {
///         println!("  {}: ports {}, {}, {}", 
///                  assignment.user_name,
///                  assignment.ready_port,
///                  assignment.intray_port,
///                  assignment.gotit_port);
///     }
/// }
/// ```
pub fn read_abstract_collaborator_port_assignments_from_clearsigntoml(
    path_to_clearsigned_toml: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<HashMap<String, Vec<CollaboratorPortAssignment>>, GpgError> {
    println!(
        "Starting extraction of all collaborator port assignments from: {}",
        path_to_clearsigned_toml.display()
    );

    // First, we need to validate the file and get the list of pairs
    // We'll do this by reading the validated content once to find all pairs
    
    // Perform the same validation steps as the specific function
    // This code is duplicated for clarity and to ensure independent validation
    
    // --- Stage 1: Input Validation ---
    if !path_to_clearsigned_toml.exists() {
        return Err(GpgError::PathError(format!(
            "Clearsigned TOML file not found: {}",
            path_to_clearsigned_toml.display()
        )));
    }
    if !path_to_clearsigned_toml.is_file() {
        return Err(GpgError::PathError(format!(
            "Path is not a file: {}",
            path_to_clearsigned_toml.display()
        )));
    }

    let path_str = match path_to_clearsigned_toml.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_clearsigned_toml.display()
            )));
        }
    };

    // --- Stage 2: Owner-based Validation (same as specific function) ---
    let owner_name_of_toml_field_key_to_read = "owner";
    let file_owner_username = match read_single_line_string_field_from_toml(path_str, owner_name_of_toml_field_key_to_read) {
        Ok(username) => {
            if username.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "Field '{}' is empty. File owner is required for security validation.",
                    owner_name_of_toml_field_key_to_read
                )));
            }
            username
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read file owner: {}",
                e
            )));
        }
    };

    // Get collaborator directory and addressbook path
    let collaborator_files_directory_absolute = 
        match make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
            addressbook_files_directory_relative
        ) {
            Ok(path) => path,
            Err(io_error) => return Err(GpgError::FileSystemError(io_error)),
        };

    let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    let user_addressbook_path = collaborator_files_directory_absolute.join(&collaborator_filename);
    let user_addressbook_path_str = match user_addressbook_path.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for addressbook file"
            )));
        }
    };

    // Extract GPG key ID
    let gpg_key_id_name_of_toml_field_key_to_read = "gpg_publickey_id";
    let signing_key_id = match read_singleline_string_from_clearsigntoml(
        user_addressbook_path_str,
        gpg_key_id_name_of_toml_field_key_to_read
    ) {
        Ok(key_id) => {
            if key_id.is_empty() {
                return Err(GpgError::GpgOperationError(
                    "GPG key ID is empty in addressbook".to_string()
                ));
            }
            key_id
        }
        Err(e) => return Err(GpgError::GpgOperationError(format!(
            "Failed to read GPG key ID: {}",
            e
        ))),
    };

    // --- Stage 3: Validate and Extract Content Once ---
    let temp_validation_path = create_temp_file_path("validate_all_ports")?;
    
    let validation_result = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")
        .arg("--status-fd")
        .arg("2")
        .arg("--output")
        .arg(&temp_validation_path)
        .arg(path_to_clearsigned_toml)
        .output();

    match validation_result {
        Ok(output) => {
            if !output.status.success() {
                let _ = fs::remove_file(&temp_validation_path);
                return Err(GpgError::GpgOperationError(
                    "GPG signature validation FAILED".to_string()
                ));
            }
        }
        Err(e) => {
            let _ = fs::remove_file(&temp_validation_path);
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG validation: {}",
                e
            )));
        }
    }

    // Read validated content to find all pairs
    let validated_content = match fs::read_to_string(&temp_validation_path) {
        Ok(content) => content,
        Err(e) => {
            let _ = fs::remove_file(&temp_validation_path);
            return Err(GpgError::FileSystemError(e));
        }
    };
    
    // Cleanup temp file
    let _ = fs::remove_file(&temp_validation_path);

    // --- Stage 4: Find All Collaborator Pairs ---
    let mut pair_names = Vec::new();
    let table_prefix = "[abstract_collaborator_port_assignments.";
    
    for line in validated_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(table_prefix) && trimmed.ends_with(']') {
            // Extract pair name from table header
            let start = table_prefix.len();
            let end = trimmed.len() - 1;
            let pair_name = &trimmed[start..end];
            pair_names.push(pair_name.to_string());
        }
    }
    
    if pair_names.is_empty() {
        return Err(GpgError::GpgOperationError(
            "No collaborator pairs found in abstract_collaborator_port_assignments".to_string()
        ));
    }
    
    println!("Found {} collaborator pairs to process", pair_names.len());

    // --- Stage 5: Call Specific Function for Each Pair ---
    let mut all_assignments = HashMap::new();
    
    for pair_name in pair_names {
        println!("Processing pair: {}", pair_name);
        
        match read_specific_pair_port_assignments_from_clearsigntoml(
            path_to_clearsigned_toml,
            addressbook_files_directory_relative,
            &pair_name,
        ) {
            Ok(assignments) => {
                all_assignments.insert(pair_name, assignments);
            }
            Err(e) => {
                // Log the error but continue with other pairs
                eprintln!("Warning: Failed to read assignments for pair '{}': {}", pair_name, e.to_string());
                // Optionally, you might want to fail fast instead:
                // return Err(e);
            }
        }
    }
    
    if all_assignments.is_empty() {
        return Err(GpgError::GpgOperationError(
            "No port assignments could be extracted from any collaborator pairs".to_string()
        ));
    }
    
    println!(
        "Successfully extracted port assignments for {} pairs",
        all_assignments.len()
    );
    
    Ok(all_assignments)
}

/// Reads all collaborator pair port assignments from a clearsigned TOML file using owner-based GPG key lookup (optimized version).
///
/// # Purpose
/// This function extracts network port assignments for ALL collaborator pairs from a
/// clearsigned team channel configuration file in a single pass. Unlike the previous version
/// that calls the specific function multiple times, this version validates the file once
/// and extracts all data efficiently.
///
/// # Security Model
/// This function implements the same strict security-first approach:
/// 1. **Mandatory validation**: The clearsigned file MUST be validated before ANY data extraction
/// 2. **Owner-based key management**: Uses the file's owner field to look up the validation key
/// 3. **Chain of trust**: Validation uses keys from the collaborator addressbook system
/// 4. **Single validation pass**: Optimized to validate once and extract all data
///
/// # Validation Process
/// 1. Reads the `owner` field from the target clearsigned TOML file
/// 2. Constructs the path to the owner's addressbook file: `{owner}__collaborator.toml`
/// 3. Extracts the GPG key ID from the addressbook (which is itself clearsigned and validated)
/// 4. Uses that key to verify the target file's signature ONCE
/// 5. Extracts all port assignments in a single pass through the validated content
///
/// # Data Structure Expected
/// The function expects the TOML file to contain:
/// ```toml
/// [abstract_collaborator_port_assignments.alice_bob]
/// collaborator_ports = [
///     { user_name = "alice", ready_port = 50001, intray_port = 50002, gotit_port = 50003 },
///     { user_name = "bob", ready_port = 50004, intray_port = 50005, gotit_port = 50006 },
/// ]
/// 
/// [abstract_collaborator_port_assignments.alice_charlotte]
/// collaborator_ports = [
///     { user_name = "alice", ready_port = 50007, intray_port = 50008, gotit_port = 50009 },
///     { user_name = "charlotte", ready_port = 50010, intray_port = 50011, gotit_port = 50012 },
/// ]
/// ```
///
/// # Arguments
/// - `path_to_clearsigned_toml` - Path to the clearsigned TOML file containing port assignments
/// - `addressbook_files_directory_relative` - Relative path to the directory containing collaborator addressbook files
///
/// # Returns
/// - `Ok(HashMap<String, Vec<CollaboratorPortAssignment>>)` - A map where:
///   - Keys are collaborator pair names (e.g., "alice_bob")
///   - Values are vectors of port assignments for that pair
/// - `Err(GpgError)` - If any step fails:
///   - `PathError`: File not found, invalid path, or path encoding issues
///   - `GpgOperationError`: GPG validation failure, missing required fields, or parsing errors
///   - `FileSystemError`: I/O errors during file operations
///
/// # Performance
/// This optimized version:
/// - Performs GPG validation only ONCE (vs. once per pair in the previous version)
/// - Reads the file content only ONCE
/// - Parses all assignments in a single pass
/// - Significantly faster for files with many collaborator pairs
///
/// # Example
/// ```no_run
/// let all_assignments = read_all_collaborator_port_assignments_clearsigntoml_optimized(
///     Path::new("team_channel_config.toml"),
///     "collaborators"
/// )?;
/// 
/// // Display all assignments
/// for (pair_name, assignments) in &all_assignments {
///     println!("Collaborator pair: {}", pair_name);
///     for assignment in assignments {
///         println!("  {} -> ready: {}, intray: {}, gotit: {}", 
///                  assignment.user_name,
///                  assignment.ready_port,
///                  assignment.intray_port,
///                  assignment.gotit_port);
///     }
/// }
/// 
/// // Access specific pair
/// if let Some(alice_bob_ports) = all_assignments.get("alice_bob") {
///     println!("Alice-Bob communication ports: {:?}", alice_bob_ports);
/// }
/// ```
pub fn read_all_collaborator_port_assignments_clearsigntoml_optimized(
    path_to_clearsigned_toml: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<HashMap<String, Vec<CollaboratorPortAssignment>>, GpgError> {
    // --- Stage 1: Input Validation ---
    println!(
        "Starting optimized extraction of all collaborator port assignments from: {}",
        path_to_clearsigned_toml.display()
    );
    println!("This version validates once and extracts all data in a single pass.");

    // Validate that the input path exists and is a file
    if !path_to_clearsigned_toml.exists() {
        return Err(GpgError::PathError(format!(
            "Clearsigned TOML file not found: {}",
            path_to_clearsigned_toml.display()
        )));
    }
    if !path_to_clearsigned_toml.is_file() {
        return Err(GpgError::PathError(format!(
            "Path is not a file: {}",
            path_to_clearsigned_toml.display()
        )));
    }

    // Convert path to string for reading functions
    let path_str = match path_to_clearsigned_toml.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_clearsigned_toml.display()
            )));
        }
    };

    // --- Stage 2: Extract Owner for Key Lookup ---
    let owner_name_of_toml_field_key_to_read = "owner";
    println!(
        "Reading file owner from field '{}' for security validation",
        owner_name_of_toml_field_key_to_read
    );

    // Read owner from the file (before validation, but we won't use other data until validated)
    let file_owner_username = match read_single_line_string_field_from_toml(path_str, owner_name_of_toml_field_key_to_read) {
        Ok(username) => {
            if username.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "Field '{}' is empty in TOML file. File owner is required for security validation.",
                    owner_name_of_toml_field_key_to_read
                )));
            }
            username
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read file owner from field '{}': {}",
                owner_name_of_toml_field_key_to_read, e
            )));
        }
    };
    println!("File owner: '{}'", file_owner_username);

    // --- Stage 3: Construct Addressbook Path and Extract GPG Key ---
    println!("Looking up GPG key for owner '{}' in addressbook", file_owner_username);

    // Convert collaborator directory to absolute path
    let collaborator_files_directory_absolute = 
        match make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
            addressbook_files_directory_relative
        ) {
            Ok(path) => path,
            Err(io_error) => {
                return Err(GpgError::FileSystemError(io_error));
            }
        };
        
    // TODO: gpg toml?

    // Construct addressbook filename
    let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    let user_addressbook_path = collaborator_files_directory_absolute.join(&collaborator_filename);

    println!("Owner's addressbook path: {}", user_addressbook_path.display());

    // Verify addressbook exists
    if !user_addressbook_path.exists() {
        return Err(GpgError::PathError(format!(
            "Addressbook file not found for owner '{}': {}",
            file_owner_username,
            user_addressbook_path.display()
        )));
    }

    // Convert addressbook path to string
    let user_addressbook_path_str = match user_addressbook_path.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for addressbook file: {}",
                user_addressbook_path.display()
            )));
        }
    };

    // Extract GPG key ID from addressbook (which validates the addressbook's signature)
    let gpg_key_id_name_of_toml_field_key_to_read = "gpg_publickey_id";
    let signing_key_id = match read_singleline_string_from_clearsigntoml(
        user_addressbook_path_str,
        gpg_key_id_name_of_toml_field_key_to_read
    ) {
        Ok(key_id) => {
            if key_id.is_empty() {
                return Err(GpgError::GpgOperationError(format!(
                    "GPG key ID is empty in addressbook for owner '{}'",
                    file_owner_username
                )));
            }
            key_id
        }
        Err(e) => {
            return Err(GpgError::GpgOperationError(format!(
                "Failed to read GPG key ID from addressbook: {}",
                e
            )));
        }
    };
    println!("Found GPG key ID for validation: '{}'", signing_key_id);

    // --- Stage 4: Create Temporary File for Validation ---
    let temp_validation_path = create_temp_file_path("validate_all_ports_optimized")?;
    
    // --- Stage 5: Verify Signature and Extract Content (ONCE) ---
    println!("Validating clearsigned file signature...");
    
    // Decrypt (which validates) the clearsigned file
    let validation_result = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")
        .arg("--status-fd")
        .arg("2")
        .arg("--output")
        .arg(&temp_validation_path)
        .arg(path_to_clearsigned_toml)
        .output();

    match validation_result {
        Ok(output) => {
            if !output.status.success() {
                // Cleanup temp file
                let _ = fs::remove_file(&temp_validation_path);
                
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                return Err(GpgError::GpgOperationError(format!(
                    "GPG signature validation FAILED. File may be tampered. GPG output: {}",
                    stderr_output.trim()
                )));
            }
            println!("✓ Signature validation PASSED. File integrity confirmed.");
            println!("Now extracting all port assignments in a single pass...");
        }
        Err(e) => {
            // Cleanup temp file
            let _ = fs::remove_file(&temp_validation_path);
            
            return Err(GpgError::GpgOperationError(format!(
                "Failed to execute GPG validation: {}",
                e
            )));
        }
    }

    // --- Stage 6: Parse ALL Port Assignments from Validated Content ---
    
    // Read the validated content once
    let validated_content = match fs::read_to_string(&temp_validation_path) {
        Ok(content) => content,
        Err(e) => {
            // Cleanup temp file
            let _ = fs::remove_file(&temp_validation_path);
            return Err(GpgError::FileSystemError(e));
        }
    };

    // Cleanup temp file immediately after reading
    let _ = fs::remove_file(&temp_validation_path);

    // Parse all collaborator pair sections in one pass
    let mut all_assignments: HashMap<String, Vec<CollaboratorPortAssignment>> = HashMap::new();
    let table_prefix = "[abstract_collaborator_port_assignments.";
    
    // State tracking for parsing
    let mut current_pair_name: Option<String> = None;
    let mut current_pair_assignments: Vec<CollaboratorPortAssignment> = Vec::new();
    let mut in_ports_array = false;
    let mut current_port_entry: Option<PartialPortEntry> = None;

    // Helper structure for parsing (reused from the specific function)
    #[derive(Default)]
    struct PartialPortEntry {
        user_name: Option<String>,
        ready_port: Option<u16>,
        intray_port: Option<u16>,
        gotit_port: Option<u16>,
    }

    // Process each line of the validated content
    for line in validated_content.lines() {
        let trimmed = line.trim();
        
        // Check if we're entering a new collaborator pair section
        if trimmed.starts_with(table_prefix) && trimmed.ends_with(']') {
            // Save previous pair's data if any
            if let Some(pair_name) = current_pair_name.take() {
                if !current_pair_assignments.is_empty() {
                    all_assignments.insert(pair_name, current_pair_assignments.clone());
                    current_pair_assignments.clear();
                }
            }
            
            // Extract new pair name
            let start = table_prefix.len();
            let end = trimmed.len() - 1;
            current_pair_name = Some(trimmed[start..end].to_string());
            in_ports_array = false;
            println!("  Processing pair: {}", current_pair_name.as_ref().unwrap());
            continue;
        }
        
        // Skip lines if we're not in a pair section
        if current_pair_name.is_none() {
            continue;
        }
        
        // Check for collaborator_ports array start
        if trimmed.starts_with("collaborator_ports = [") {
            in_ports_array = true;
            
            // Check if it's a single-line array (for simple cases)
            if trimmed.contains(']') {
                // TODO: Handle single-line array parsing if needed
                in_ports_array = false;
            }
            continue;
        }
        
        // Check for array end
        if in_ports_array && trimmed == "]" {
            in_ports_array = false;
            continue;
        }
        
        // Parse array entries
        if in_ports_array {
            // Handle start of a new port entry
            if trimmed.starts_with('{') || trimmed.contains("{ user_name") {
                // If we had a previous incomplete entry, it's an error
                if current_port_entry.is_some() {
                    return Err(GpgError::GpgOperationError(format!(
                        "Malformed port entry in pair '{}'",
                        current_pair_name.as_ref().unwrap()
                    )));
                }
                current_port_entry = Some(PartialPortEntry::default());
            }
            
            // Parse fields within the entry
            if let Some(ref mut entry) = current_port_entry {
                // Parse all fields that might be on this line
                
                // Parse user_name
                if trimmed.contains("user_name = ") {
                    if let Some(value) = extract_quoted_value(trimmed, "user_name") {
                        entry.user_name = Some(value);
                    }
                }
                
                // Parse ready_port
                if trimmed.contains("ready_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "ready_port") {
                        entry.ready_port = Some(value);
                    }
                }
                
                // Parse intray_port
                if trimmed.contains("intray_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "intray_port") {
                        entry.intray_port = Some(value);
                    }
                }
                
                // Parse gotit_port
                if trimmed.contains("gotit_port = ") {
                    if let Some(value) = extract_port_value(trimmed, "gotit_port") {
                        entry.gotit_port = Some(value);
                    }
                }
            }
            
            // Check for end of entry
            if trimmed.ends_with("},") || trimmed.ends_with('}') {
                if let Some(entry) = current_port_entry.take() {
                    // Validate we have all required fields
                    match (entry.user_name, entry.ready_port, entry.intray_port, entry.gotit_port) {
                        (Some(user), Some(ready), Some(intray), Some(gotit)) => {
                            current_pair_assignments.push(CollaboratorPortAssignment {
                                user_name: user,
                                ready_port: ready,
                                intray_port: intray,
                                gotit_port: gotit,
                            });
                        }
                        _ => {
                            return Err(GpgError::GpgOperationError(format!(
                                "Incomplete port assignment entry for pair '{}'. Missing required fields.",
                                current_pair_name.as_ref().unwrap()
                            )));
                        }
                    }
                }
            }
        }
    }
    
    // Don't forget the last pair if the file doesn't end with another section
    if let Some(pair_name) = current_pair_name.take() {
        if !current_pair_assignments.is_empty() {
            all_assignments.insert(pair_name, current_pair_assignments);
        }
    }
    
    // --- Stage 7: Validate Results ---
    if all_assignments.is_empty() {
        return Err(GpgError::GpgOperationError(
            "No collaborator port assignments found in abstract_collaborator_port_assignments".to_string()
        ));
    }
    
    // Log summary
    println!(
        "✓ Successfully extracted port assignments for {} collaborator pairs:",
        all_assignments.len()
    );
    for (pair_name, assignments) in &all_assignments {
        println!("  - {}: {} port assignments", pair_name, assignments.len());
    }
    
    Ok(all_assignments)
}

/// Reads all collaborator usernames who have access to the team channel from a clearsigned TOML file.
///
/// # Purpose
/// This function extracts the list of collaborators who have access to a team channel
/// from the `teamchannel_collaborators_with_access` field in a clearsigned TOML file.
/// It enforces the same security model as other functions in this module, requiring
/// GPG signature validation before any data extraction.
///
/// # Security Model
/// - Mandatory signature validation before data access
/// - Owner-based key management via addressbook lookup
/// - No data returned if validation fails
///
/// # Expected Data Structure
/// The function expects the TOML file to contain:
/// ```toml
/// teamchannel_collaborators_with_access = ["alice", "bob", "charlotte"]
/// ```
///
/// # Arguments
/// - `path_to_clearsigned_toml` - Path to the clearsigned TOML file
/// - `addressbook_files_directory_relative` - Relative path to the collaborator addressbook directory
///
/// # Returns
/// - `Ok(Vec<String>)` - A vector of collaborator usernames who have access
/// - `Err(GpgError)` - If validation fails or the field is not found
///
/// # Example
/// ```no_run
/// let collaborators = read_teamchannel_collaborators_with_access_from_clearsigntoml(
///     Path::new("team_channel_config.toml"),
///     "collaborators"
/// )?;
/// 
/// println!("Team channel collaborators: {:?}", collaborators);
/// // Output: ["alice", "bob", "charlotte"]
/// ```
pub fn read_teamchannel_collaborators_with_access_from_clearsigntoml(
    path_to_clearsigned_toml: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<Vec<String>, GpgError> {
    println!(
        "Reading team channel collaborators with access from: {}",
        path_to_clearsigned_toml.display()
    );

    // Convert path to string for the reading function
    let path_str = match path_to_clearsigned_toml.to_str() {
        Some(s) => s,
        None => {
            return Err(GpgError::PathError(format!(
                "Invalid path encoding for: {}",
                path_to_clearsigned_toml.display()
            )));
        }
    };

    // Use the existing string array reading function with owner-based validation
    match read_stringarray_from_clearsigntoml_without_keyid(
        addressbook_files_directory_relative,  // This should be the config file path
        path_str,                               // This is the target file
        "teamchannel_collaborators_with_access"
    ) {
        Ok(collaborators) => {
            println!(
                "Successfully extracted {} collaborators with access",
                collaborators.len()
            );
            Ok(collaborators)
        }
        Err(e) => {
            Err(GpgError::GpgOperationError(format!(
                "Failed to read teamchannel_collaborators_with_access: {}",
                e
            )))
        }
    }
}

/// Validates that all collaborators mentioned in port assignments are listed in the access list.
///
/// # Purpose
/// This helper function ensures consistency between the port assignments and the
/// list of collaborators who have access to the team channel. It checks that every
/// username appearing in port assignments is also listed in `teamchannel_collaborators_with_access`.
///
/// # Arguments
/// - `port_assignments` - HashMap of pair names to their port assignments
/// - `authorized_collaborators` - List of collaborators authorized for the team channel
///
/// # Returns
/// - `Ok(())` - If all collaborators in port assignments are authorized
/// - `Err(Vec<String>)` - List of unauthorized collaborators found in port assignments
///
/// # Example
/// ```no_run
/// let authorized = vec!["alice".to_string(), "bob".to_string()];
/// let assignments = read_all_collaborator_port_assignments_clearsigntoml_optimized(...)?;
/// 
/// match validate_port_assignment_collaborators(&assignments, &authorized) {
///     Ok(()) => println!("All collaborators are authorized"),
///     Err(unauthorized) => println!("Unauthorized collaborators: {:?}", unauthorized),
/// }
/// ```
pub fn validate_port_assignment_collaborators(
    port_assignments: &HashMap<String, Vec<CollaboratorPortAssignment>>,
    authorized_collaborators: &[String],
) -> Result<(), Vec<String>> {
    let mut unauthorized_users = Vec::new();
    let authorized_set: std::collections::HashSet<&String> = authorized_collaborators.iter().collect();
    
    // Check each port assignment
    for (pair_name, assignments) in port_assignments {
        for assignment in assignments {
            if !authorized_set.contains(&assignment.user_name) {
                unauthorized_users.push(assignment.user_name.clone());
            }
        }
    }
    
    // Remove duplicates
    unauthorized_users.sort();
    unauthorized_users.dedup();
    
    if unauthorized_users.is_empty() {
        Ok(())
    } else {
        Err(unauthorized_users)
    }
}

/// Reads an array of u8 bytes from a TOML file into a Vec<u8>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an array of unsigned 8-bit integers (bytes)
/// defined by the specified field name. It handles arrays in the format:
/// ```toml
/// node_unique_id = [160, 167, 195, 169]
/// ```
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of integers in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<u8>, String>` - A vector containing all bytes in the array if successful,
///   or an error message if the field is not found or values are out of u8 range (0-255)
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The specified field is not found
/// - The field is not a valid array format
/// - Any value in the array is not a valid u8 (outside 0-255 range)
/// - Any value cannot be parsed as an integer
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// node_unique_id = [160, 167, 195, 169]
/// hash_bytes = [255, 0, 128, 64]
/// ```
/// 
/// Usage:
/// ```
/// let node_id = read_u8_array_field_from_toml("config.toml", "node_unique_id")?;
/// // Returns: vec![160, 167, 195, 169]
/// ```
/// 
/// # Implementation Notes
/// - Values must be in the range 0-255 (valid u8 range)
/// - Negative numbers will result in an error
/// - Floating point numbers will result in an error
/// - The function trims whitespace and handles trailing commas
pub fn read_u8_array_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u8>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field with an array
        if trimmed.starts_with(&format!("{} = [", name_of_toml_field_key_to_read)) {
            // Extract the array portion
            let array_part = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid array format for field '{}'", name_of_toml_field_key_to_read))?
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim();
            
            // If the array is empty, return an empty vector
            if array_part.is_empty() {
                return Ok(Vec::new());
            }
            
            // Parse each value as u8
            let mut byte_values = Vec::new();
            
            for (index, value_str) in array_part.split(',').enumerate() {
                let cleaned_value = value_str.trim();
                
                if cleaned_value.is_empty() {
                    continue; // Skip empty entries (e.g., trailing comma)
                }
                
                // First parse as i32 to check range, then convert to u8
                match cleaned_value.parse::<i32>() {
                    Ok(int_value) => {
                        // Check if value is in valid u8 range (0-255)
                        if int_value < 0 || int_value > 255 {
                            return Err(format!(
                                "Value {} at index {} in array field '{}' is out of valid byte range (0-255)",
                                int_value, index, name_of_toml_field_key_to_read
                            ));
                        }
                        // Safe to convert to u8 now
                        byte_values.push(int_value as u8);
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to parse value '{}' at index {} in array field '{}' as integer: {}",
                            cleaned_value, index, name_of_toml_field_key_to_read, e
                        ));
                    }
                }
            }
            
            return Ok(byte_values);
        }
    }
    
    // Field not found
    Err(format!("Byte array field '{}' not found in file '{}'", name_of_toml_field_key_to_read, path))
}

/// Reads an array of u8 bytes from a clearsigned TOML file into a Vec<u8>.
/// 
/// # Purpose
/// This function securely reads a byte array from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the requested byte array
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for the configuration.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of bytes in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<u8>, String>` - A vector containing all bytes in the array if successful and verified,
///   or an error message if verification fails or the field cannot be read
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// node_unique_id = [160, 167, 195, 169]
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let node_id = read_u8_array_from_clearsigntoml("node_config.toml", "node_unique_id")?;
/// // Returns: vec![160, 167, 195, 169] if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field doesn't exist or isn't a valid byte array
/// - Any value is outside the valid u8 range (0-255)
pub fn read_u8_array_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u8>, String> {
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
    
    // Step 4: If verification succeeded, read the requested byte array field
    read_u8_array_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read byte array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an array of u8 bytes from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read byte arrays from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// This approach helps maintain consistent key management across multiple clearsigned files.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the requested byte array field
/// 4. Returns the byte array or an appropriate error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the byte array field to read from the target file
/// 
/// # Returns
/// - `Ok(Vec<u8>)` - The byte array values if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let node_file = "node_config.toml";
/// 
/// let node_unique_id = read_u8_array_from_clearsigntoml_without_keyid(
///     config_path,
///     node_file, 
///     "node_unique_id"
/// )?;
/// // Returns: vec![160, 167, 195, 169] if verification succeeds
/// ```
pub fn read_u8_array_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Vec<u8>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested byte array field from the verified file
    read_u8_array_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read byte array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_u8_array_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_u8_array_from_toml_valid() {
        // Create a test TOML file with byte arrays
        let test_content = r#"
# Test TOML file with byte arrays
node_unique_id = [160, 167, 195, 169]
empty_array = []
single_byte = [42]
max_values = [0, 255, 128]
"#;
        let test_file = "test_u8_array.toml";
        fs::write(test_file, test_content).unwrap();

        // Test normal array
        let result = read_u8_array_field_from_toml(test_file, "node_unique_id");
        assert_eq!(result.unwrap(), vec![160, 167, 195, 169]);

        // Test empty array
        let result = read_u8_array_field_from_toml(test_file, "empty_array");
        assert_eq!(result.unwrap(), vec![]);

        // Test single value
        let result = read_u8_array_field_from_toml(test_file, "single_byte");
        assert_eq!(result.unwrap(), vec![42]);

        // Test boundary values
        let result = read_u8_array_field_from_toml(test_file, "max_values");
        assert_eq!(result.unwrap(), vec![0, 255, 128]);

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_u8_array_out_of_range() {
        // Create test file with out-of-range values
        let test_content = r#"
too_large = [256]
negative = [-1]
mixed = [100, 300, 50]
"#;
        let test_file = "test_u8_array_invalid.toml";
        fs::write(test_file, test_content).unwrap();

        // Test value too large
        let result = read_u8_array_field_from_toml(test_file, "too_large");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of valid byte range"));

        // Test negative value
        let result = read_u8_array_field_from_toml(test_file, "negative");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of valid byte range"));

        // Test mixed valid/invalid
        let result = read_u8_array_field_from_toml(test_file, "mixed");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of valid byte range"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_u8_array_invalid_format() {
        // Create test file with invalid formats
        let test_content = r#"
not_array = "not an array"
float_values = [12.5, 13.7]
malformed = [100, "text", 50]
"#;
        let test_file = "test_u8_array_format.toml";
        fs::write(test_file, test_content).unwrap();

        // Test non-array field
        let result = read_u8_array_field_from_toml(test_file, "not_array");
        assert!(result.is_err());

        // Test float values (should fail to parse as integers)
        let result = read_u8_array_field_from_toml(test_file, "float_values");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));

        // Test mixed types
        let result = read_u8_array_field_from_toml(test_file, "malformed");
        assert!(result.is_err());

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_u8_array_field_not_found() {
        let test_content = "other_field = [1, 2, 3]";
        let test_file = "test_u8_array_missing.toml";
        fs::write(test_file, test_content).unwrap();

        let result = read_u8_array_field_from_toml(test_file, "node_unique_id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    // Note: Testing clearsigned versions requires GPG setup, so those tests
    // would be similar to existing clearsign tests in the module
}

/// Reads an array of u64 values from a clearsigned TOML file into a Vec<u64>.
/// 
/// # Purpose
/// This function securely reads a u64 array from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the requested u64 array
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for the configuration.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of u64 values in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<u64>, String>` - A vector containing all u64 values in the array if successful and verified,
///   or an error message if verification fails or the field cannot be read
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// node_timestamp_array = [1640995200000, 1640995260000, 1640995320000]
/// large_id_array = [18446744073709551615, 9223372036854775807, 1000000000000000000]
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let timestamps = read_u64_array_from_clearsigntoml("node_config.toml", "node_timestamp_array")?;
/// // Returns: vec![1640995200000, 1640995260000, 1640995320000] if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field doesn't exist or isn't a valid u64 array
/// - Any value is outside the valid u64 range (0 to 18,446,744,073,709,551,615)
/// - Any value is negative or a floating point number
pub fn read_u64_array_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
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
    
    // Step 4: If verification succeeded, read the requested u64 array field
    read_u64_array_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read u64 array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an array of u64 values from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read u64 arrays from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// This approach helps maintain consistent key management across multiple clearsigned files.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the requested u64 array field
/// 4. Returns the u64 array or an appropriate error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the u64 array field to read from the target file
/// 
/// # Returns
/// - `Ok(Vec<u64>)` - The u64 array values if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let node_file = "node_config.toml";
/// 
/// let node_timestamps = read_u64_array_from_clearsigntoml_without_keyid(
///     config_path,
///     node_file, 
///     "node_timestamp_array"
/// )?;
/// // Returns: vec![1640995200000, 1640995260000, 1640995320000] if verification succeeds
/// ```
/// 
/// # Use Cases
/// - Reading timestamp arrays from node configuration files
/// - Reading large identifier arrays from verified configuration files
/// - Reading sequence numbers or version arrays from secure configuration files
/// - Reading capacity or limit arrays from authenticated configuration files
pub fn read_u64_array_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Vec<u64>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested u64 array field from the verified file
    read_u64_array_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read u64 array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

/// Reads an array of u64 values from a TOML file into a Vec<u64>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an array of unsigned 64-bit integers
/// defined by the specified field name. It handles arrays in the format:
/// ```toml
/// node_timestamp_array = [1640995200000, 1640995260000, 1640995320000]
/// ```
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be an array of integers in the TOML file)
/// 
/// # Returns
/// - `Result<Vec<u64>, String>` - A vector containing all u64 values in the array if successful,
///   or an error message if the field is not found or values are out of u64 range
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The specified field is not found
/// - The field is not a valid array format
/// - Any value in the array is not a valid u64 (outside 0 to 18,446,744,073,709,551,615 range)
/// - Any value cannot be parsed as an integer
/// - Any value is negative or a floating point number
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// node_timestamp_array = [1640995200000, 1640995260000, 1640995320000]
/// large_numbers = [18446744073709551615, 0, 9223372036854775807]
/// ```
/// 
/// Usage:
/// ```
/// let timestamps = read_u64_array_field_from_toml("config.toml", "node_timestamp_array")?;
/// // Returns: vec![1640995200000, 1640995260000, 1640995320000]
/// ```
/// 
/// # Implementation Notes
/// - Values must be in the range 0 to 18,446,744,073,709,551,615 (valid u64 range)
/// - Negative numbers will result in an error
/// - Floating point numbers will result in an error
/// - The function trims whitespace and handles trailing commas
/// - Scientific notation is not supported
/// - String values in quotes will be rejected
pub fn read_u64_array_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Vec<u64>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field with an array
        if trimmed.starts_with(&format!("{} = [", name_of_toml_field_key_to_read)) {
            // Extract the array portion
            let array_part = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid array format for field '{}'", name_of_toml_field_key_to_read))?
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim();
            
            // If the array is empty, return an empty vector
            if array_part.is_empty() {
                return Ok(Vec::new());
            }
            
            // Parse each value as u64
            let mut u64_values = Vec::new();
            
            for (index, value_str) in array_part.split(',').enumerate() {
                let cleaned_value = value_str.trim();
                
                if cleaned_value.is_empty() {
                    continue; // Skip empty entries (e.g., trailing comma)
                }
                
                // Check for quoted strings (invalid for u64)
                if (cleaned_value.starts_with('"') && cleaned_value.ends_with('"')) || 
                   (cleaned_value.starts_with('\'') && cleaned_value.ends_with('\'')) {
                    return Err(format!(
                        "String value '{}' at index {} in array field '{}' cannot be parsed as u64 - strings are not valid for u64 type",
                        cleaned_value, index, name_of_toml_field_key_to_read
                    ));
                }
                
                // Check for negative values before parsing
                if cleaned_value.starts_with('-') {
                    return Err(format!(
                        "Negative value '{}' at index {} in array field '{}' is not valid for u64 type",
                        cleaned_value, index, name_of_toml_field_key_to_read
                    ));
                }
                
                // Check for floating point notation
                if cleaned_value.contains('.') || cleaned_value.contains('e') || cleaned_value.contains('E') {
                    return Err(format!(
                        "Floating point value '{}' at index {} in array field '{}' is not valid for u64 type",
                        cleaned_value, index, name_of_toml_field_key_to_read
                    ));
                }
                
                // Parse as u64 directly
                match cleaned_value.parse::<u64>() {
                    Ok(u64_value) => {
                        u64_values.push(u64_value);
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to parse value '{}' at index {} in array field '{}' as u64: {}",
                            cleaned_value, index, name_of_toml_field_key_to_read, e
                        ));
                    }
                }
            }
            
            return Ok(u64_values);
        }
    }
    
    // Field not found
    Err(format!("u64 array field '{}' not found in file '{}'", name_of_toml_field_key_to_read, path))
}

#[cfg(test)]
mod test_u64_array_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_u64_array_from_toml_valid() {
        // Create a test TOML file with u64 arrays
        let test_content = r#"
# Test TOML file with u64 arrays
node_timestamp_array = [1640995200000, 1640995260000, 1640995320000]
empty_array = []
single_value = [9223372036854775807]
boundary_values = [0, 18446744073709551615, 1000000000000000000]
large_numbers = [18446744073709551614, 18446744073709551613, 18446744073709551612]
"#;
        let test_file = "test_u64_array.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test normal timestamp array
        let result = read_u64_array_field_from_toml(test_file, "node_timestamp_array");
        assert_eq!(result.expect("Failed to read timestamp array"), vec![1640995200000, 1640995260000, 1640995320000]);

        // Test empty array
        let result = read_u64_array_field_from_toml(test_file, "empty_array");
        assert_eq!(result.expect("Failed to read empty array"), vec![]);

        // Test single value
        let result = read_u64_array_field_from_toml(test_file, "single_value");
        assert_eq!(result.expect("Failed to read single value"), vec![9223372036854775807]);

        // Test boundary values (including max u64)
        let result = read_u64_array_field_from_toml(test_file, "boundary_values");
        assert_eq!(result.expect("Failed to read boundary values"), vec![0, 18446744073709551615, 1000000000000000000]);

        // Test large numbers
        let result = read_u64_array_field_from_toml(test_file, "large_numbers");
        assert_eq!(result.expect("Failed to read large numbers"), vec![18446744073709551614, 18446744073709551613, 18446744073709551612]);

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }

    #[test]
    fn test_read_u64_array_invalid_values() {
        // Create test file with invalid values for u64
        let test_content = r#"
negative_values = [-1, -100, -9223372036854775808]
floating_point = [123.456, 789.012]
scientific_notation = [1.23e10, 4.56E12]
mixed_invalid = [100, -50, 200]
"#;
        let test_file = "test_u64_array_invalid.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test negative values
        let result = read_u64_array_field_from_toml(test_file, "negative_values");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Negative value"));
        assert!(error_msg.contains("not valid for u64 type"));

        // Test floating point values
        let result = read_u64_array_field_from_toml(test_file, "floating_point");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Floating point value"));
        assert!(error_msg.contains("not valid for u64 type"));

        // Test scientific notation
        let result = read_u64_array_field_from_toml(test_file, "scientific_notation");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Floating point value"));
        assert!(error_msg.contains("not valid for u64 type"));

        // Test mixed valid/invalid values
        let result = read_u64_array_field_from_toml(test_file, "mixed_invalid");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Negative value"));

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }

    #[test]
    fn test_read_u64_array_malformed_data() {
        // Create test file with malformed data
        let test_content = r#"
not_array = "this is not an array"
text_in_array = [100, "hello", 200]
empty_values = [100, , 200]
overflow_test = [18446744073709551616]
"#;
        let test_file = "test_u64_array_malformed.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test non-array field
        let result = read_u64_array_field_from_toml(test_file, "not_array");
        assert!(result.is_err());

        // Test text in array - should now be caught by string detection
        let result = read_u64_array_field_from_toml(test_file, "text_in_array");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        // Updated assertion to match the new error message
        assert!(error_msg.contains("String value") && error_msg.contains("cannot be parsed as u64"));

        // Test empty values in array (should be skipped)
        let result = read_u64_array_field_from_toml(test_file, "empty_values");
        assert_eq!(result.expect("Failed to read array with empty values"), vec![100, 200]);

        // Test overflow (larger than max u64)
        let result = read_u64_array_field_from_toml(test_file, "overflow_test");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Failed to parse"));

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }

    #[test]
    fn test_read_u64_array_string_values() {
        // Test specifically for string values in arrays
        let test_content = r#"
double_quoted = [100, "hello", 200]
single_quoted = [300, 'world', 400]
mixed_quotes = [500, "test", 'another', 600]
"#;
        let test_file = "test_u64_array_strings.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test double quoted strings
        let result = read_u64_array_field_from_toml(test_file, "double_quoted");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("String value"));
        assert!(error_msg.contains("cannot be parsed as u64"));

        // Test single quoted strings
        let result = read_u64_array_field_from_toml(test_file, "single_quoted");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("String value"));
        assert!(error_msg.contains("cannot be parsed as u64"));

        // Test mixed quotes
        let result = read_u64_array_field_from_toml(test_file, "mixed_quotes");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("String value"));
        assert!(error_msg.contains("cannot be parsed as u64"));

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }

    #[test]
    fn test_read_u64_array_field_not_found() {
        let test_content = r#"
other_field = [1, 2, 3]
another_field = [100, 200, 300]
"#;
        let test_file = "test_u64_array_missing.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test missing field
        let result = read_u64_array_field_from_toml(test_file, "node_timestamp_array");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("not found"));
        assert!(error_msg.contains("node_timestamp_array"));

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }

    #[test]
    fn test_read_u64_array_file_not_found() {
        // Test with non-existent file
        let result = read_u64_array_field_from_toml("non_existent_file.toml", "some_field");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Failed to open file"));
        assert!(error_msg.contains("non_existent_file.toml"));
    }

    #[test]
    fn test_read_u64_array_with_trailing_commas() {
        // Test array with trailing commas and various spacing
        let test_content = r#"
trailing_comma = [100, 200, 300, ]
extra_spaces = [ 400 , 500 , 600 ]
mixed_spacing = [700,800, 900 ,1000]
"#;
        let test_file = "test_u64_array_spacing.toml";
        fs::write(test_file, test_content).expect("Failed to write test file");

        // Test trailing comma
        let result = read_u64_array_field_from_toml(test_file, "trailing_comma");
        assert_eq!(result.expect("Failed to read trailing comma array"), vec![100, 200, 300]);

        // Test extra spaces
        let result = read_u64_array_field_from_toml(test_file, "extra_spaces");
        assert_eq!(result.expect("Failed to read extra spaces array"), vec![400, 500, 600]);

        // Test mixed spacing
        let result = read_u64_array_field_from_toml(test_file, "mixed_spacing");
        assert_eq!(result.expect("Failed to read mixed spacing array"), vec![700, 800, 900, 1000]);

        // Cleanup
        fs::remove_file(test_file).expect("Failed to remove test file");
    }
}

/// Reads a path string from a TOML file and converts it to a PathBuf.
/// 
/// # Purpose
/// This function parses a TOML file to extract a path string defined by the specified field name
/// and converts it to a PathBuf. It handles paths in the format:
/// ```toml
/// directory_path = "/home/user/project/data"
/// relative_path = "config/settings"
/// windows_path = "C:\\Users\\Documents\\project"
/// ```
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be a string containing a path in the TOML file)
/// 
/// # Returns
/// - `Result<PathBuf, String>` - A PathBuf if successful, or an error message if the field 
///   is not found or cannot be parsed
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The specified field is not found
/// - The field value is empty or contains only whitespace
/// 
/// # Path Handling
/// - The function preserves the path exactly as written in the TOML file (after trimming)
/// - It does NOT check if the path exists
/// - It does NOT canonicalize or resolve the path
/// - Both absolute and relative paths are accepted
/// - Platform-specific path separators are handled by PathBuf
/// - Leading and trailing whitespace is trimmed
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// directory_path = "/42/uma_productivity_collaboration_tool/target/debug/project_graph_data/team_channels/tofu"
/// config_dir = "./config"
/// ```
/// 
/// Usage:
/// ```
/// let dir_path = read_pathbuf_field_from_toml("config.toml", "directory_path")?;
/// // Returns: PathBuf from "/42/uma_productivity_collaboration_tool/target/debug/project_graph_data/team_channels/tofu"
/// ```
/// 
/// # Implementation Notes
/// - Empty strings or whitespace-only strings result in an error
/// - The path is not validated or normalized
/// - Quotes around the path string in TOML are handled automatically
pub fn read_pathbuf_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<PathBuf, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field
        if trimmed.starts_with(&format!("{} = ", name_of_toml_field_key_to_read)) {
            // Extract the value after the equals sign
            let value_part = trimmed
                .splitn(2, '=')
                .nth(1)
                .ok_or_else(|| format!("Invalid format for field '{}'", name_of_toml_field_key_to_read))?
                .trim();
            
            // Remove surrounding quotes if present and trim whitespace
            let path_str = value_part
                .trim_matches('"')
                .trim_matches('\'')
                .trim(); // Add trim() here to remove whitespace
            
            // Check for empty path (including whitespace-only)
            if path_str.is_empty() {
                return Err(format!(
                    "Path field '{}' is empty or contains only whitespace in file '{}'",
                    name_of_toml_field_key_to_read, path
                ));
            }
            
            // Convert to PathBuf
            let path_buf = PathBuf::from(path_str);
            
            // Log what we found for debugging
            println!(
                "Read path field '{}': '{}'",
                name_of_toml_field_key_to_read, path_buf.display()
            );
            
            return Ok(path_buf);
        }
    }
    
    // Field not found
    Err(format!("Path field '{}' not found in file '{}'", name_of_toml_field_key_to_read, path))
}

/// Reads a path from a clearsigned TOML file and converts it to a PathBuf.
/// 
/// # Purpose
/// This function securely reads a path from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the requested path field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for path configurations.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (must be a string path in the TOML file)
/// 
/// # Returns
/// - `Result<PathBuf, String>` - A PathBuf if successful and verified,
///   or an error message if verification fails or the field cannot be read
/// 
/// # Path Validation
/// - The function does NOT check if the path exists
/// - The function does NOT canonicalize the path
/// - It returns the path exactly as specified in the TOML file
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// directory_path = "/42/uma_productivity_collaboration_tool/target/debug/project_graph_data/team_channels/tofu"
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let dir_path = read_pathbuf_from_clearsigntoml("node_config.toml", "directory_path")?;
/// // Returns: PathBuf if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field doesn't exist
/// - The field value is empty
pub fn read_pathbuf_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<PathBuf, String> {
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
    
    // Step 4: If verification succeeded, read the requested path field
    read_pathbuf_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read path '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads a path from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read paths from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// This approach helps maintain consistent key management across multiple clearsigned files.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the requested path field
/// 4. Returns the PathBuf or an appropriate error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the path field to read from the target file
/// 
/// # Returns
/// - `Ok(PathBuf)` - The path if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Path Handling
/// - Returns the path exactly as specified in the TOML file
/// - Does NOT verify the path exists
/// - Does NOT canonicalize or resolve the path
/// - Both absolute and relative paths are preserved as-is
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let node_file = "node_config.toml";
/// 
/// let directory_path = read_pathbuf_from_clearsigntoml_without_keyid(
///     config_path,
///     node_file, 
///     "directory_path"
/// )?;
/// // Returns: PathBuf from the verified file
/// ```
pub fn read_pathbuf_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<PathBuf, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the requested path field from the verified file
    read_pathbuf_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read path '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_pathbuf_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_pathbuf_from_toml_valid() {
        // Create a test TOML file with various path formats
        let test_content = r#"
# Test TOML file with paths
directory_path = "/42/uma_productivity_collaboration_tool/target/debug/project_graph_data/team_channels/tofu"
relative_path = "./config/settings.toml"
simple_path = "data"
home_path = "~/documents/project"
quoted_path = "/path/with spaces/folder"
"#;
        let test_file = "test_pathbuf.toml";
        fs::write(test_file, test_content).unwrap();

        // Test absolute path
        let result = read_pathbuf_field_from_toml(test_file, "directory_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(
            path.to_str().unwrap(), 
            "/42/uma_productivity_collaboration_tool/target/debug/project_graph_data/team_channels/tofu"
        );

        // Test relative path
        let result = read_pathbuf_field_from_toml(test_file, "relative_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_str().unwrap(), "./config/settings.toml");

        // Test simple path
        let result = read_pathbuf_field_from_toml(test_file, "simple_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_str().unwrap(), "data");

        // Test home path (tilde is NOT expanded, preserved as-is)
        let result = read_pathbuf_field_from_toml(test_file, "home_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_str().unwrap(), "~/documents/project");

        // Test path with spaces
        let result = read_pathbuf_field_from_toml(test_file, "quoted_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_str().unwrap(), "/path/with spaces/folder");

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_pathbuf_empty_path() {
        // Create test file with empty path
        let test_content = r#"
empty_path = ""
whitespace_path = "   "
"#;
        let test_file = "test_pathbuf_empty.toml";
        fs::write(test_file, test_content).unwrap();

        // Test empty path
        let result = read_pathbuf_field_from_toml(test_file, "empty_path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is empty"));

        // Test whitespace-only path (should also be empty after trimming quotes)
        let result = read_pathbuf_field_from_toml(test_file, "whitespace_path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is empty"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_pathbuf_field_not_found() {
        let test_content = "other_field = \"some value\"";
        let test_file = "test_pathbuf_missing.toml";
        fs::write(test_file, test_content).unwrap();

        let result = read_pathbuf_field_from_toml(test_file, "directory_path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_pathbuf_special_characters() {
        // Test paths with special characters
        let test_content = r#"
unicode_path = "/home/user/文档/项目"
escaped_path = "C:\\Program Files\\Application"
mixed_separators = "/home/user\\documents/file.txt"
"#;
        let test_file = "test_pathbuf_special.toml";
        fs::write(test_file, test_content).unwrap();

        // Test Unicode path
        let result = read_pathbuf_field_from_toml(test_file, "unicode_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.to_str().unwrap(), "/home/user/文档/项目");

        // Test escaped backslashes
        let result = read_pathbuf_field_from_toml(test_file, "escaped_path");
        assert!(result.is_ok());
        let path = result.unwrap();
        // Note: TOML parsing handles the escape sequences
        assert!(path.to_str().unwrap().contains("Program Files"));

        // Test mixed separators
        let result = read_pathbuf_field_from_toml(test_file, "mixed_separators");
        assert!(result.is_ok());

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    // Note: Testing clearsigned versions requires GPG setup, so those tests
    // would be similar to existing clearsign tests in the module
}

/// Reads an optional boolean field from a TOML file into an Option<bool>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an optional boolean value defined by the 
/// specified field name. It handles cases where the field may or may not exist, returning
/// None if the field is absent and Some(bool) if present with a valid boolean value.
/// 
/// # TOML Boolean Format
/// Valid TOML boolean values are:
/// - `true` (lowercase)
/// - `false` (lowercase)
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If the field does not exist in the file
/// - `Ok(Some(true))` - If the field exists and has value `true`
/// - `Ok(Some(false))` - If the field exists and has value `false`
/// - `Err(String)` - If the file cannot be read or the field has an invalid value
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The field exists but has a non-boolean value
/// - The field exists but has an invalid format (including empty values)
/// 
/// Note: A missing field is NOT an error - it returns Ok(None)
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// message_post_is_public_bool = true
/// message_post_user_confirms_bool = false
/// # field_not_present is missing
/// ```
/// 
/// Usage:
/// ```
/// let is_public = read_option_bool_field_from_toml("config.toml", "message_post_is_public_bool")?;
/// // Returns: Some(true)
/// 
/// let confirms = read_option_bool_field_from_toml("config.toml", "message_post_user_confirms_bool")?;
/// // Returns: Some(false)
/// 
/// let missing = read_option_bool_field_from_toml("config.toml", "field_not_present")?;
/// // Returns: None
/// ```
/// 
/// # Implementation Notes
/// - Field absence returns None (not an error)
/// - Boolean values must be lowercase `true` or `false`
/// - Quoted booleans (e.g., "true") are treated as strings and will cause an error
/// - Empty values after `=` cause an error
pub fn read_option_bool_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<bool>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field (more flexible parsing)
        // Split by = and check if the first part matches our field name
        if let Some(equals_pos) = trimmed.find('=') {
            let key_part = trimmed[..equals_pos].trim();
            
            if key_part == name_of_toml_field_key_to_read {
                // Found our field, now parse the value
                let value_part = trimmed[equals_pos + 1..].trim();
                
                // Check for empty value
                if value_part.is_empty() {
                    return Err(format!(
                        "Field '{}' in file '{}' has empty value",
                        name_of_toml_field_key_to_read, path
                    ));
                }
                
                // Parse the boolean value
                match value_part {
                    "true" => {
                        println!("Read optional boolean field '{}': Some(true)", name_of_toml_field_key_to_read);
                        return Ok(Some(true));
                    },
                    "false" => {
                        println!("Read optional boolean field '{}': Some(false)", name_of_toml_field_key_to_read);
                        return Ok(Some(false));
                    },
                    _ => {
                        // Invalid boolean value
                        return Err(format!(
                            "Field '{}' in file '{}' has invalid boolean value: '{}'. Expected 'true' or 'false'",
                            name_of_toml_field_key_to_read, path, value_part
                        ));
                    }
                }
            }
        }
    }
    
    // Field not found - this is OK for optional fields
    println!("Optional boolean field '{}' not found in file '{}', returning None", name_of_toml_field_key_to_read, path);
    Ok(None)
}

/// Reads an optional boolean field from a clearsigned TOML file into an Option<bool>.
/// 
/// # Purpose
/// This function securely reads an optional boolean field from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the optional boolean field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for configuration.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(bool))` - If verification succeeds and the field has a valid boolean value
/// - `Err(String)` - If verification fails or the field has an invalid value
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// message_post_is_public_bool = true
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let is_public = read_option_bool_from_clearsigntoml("config.toml", "message_post_is_public_bool")?;
/// // Returns: Some(true) if signature verification succeeds
/// 
/// let missing = read_option_bool_from_clearsigntoml("config.toml", "field_not_present")?;
/// // Returns: None if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field exists but has an invalid boolean value
pub fn read_option_bool_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<bool>, String> {
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
    
    // Step 4: If verification succeeded, read the optional boolean field
    read_option_bool_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional boolean '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an optional boolean field from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read optional boolean fields from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the optional boolean field
/// 4. Returns None if field doesn't exist, Some(bool) if it does, or an error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the optional boolean field to read from the target file
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(bool))` - If verification succeeds and the field has a valid boolean value
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let settings_file = "message_settings.toml";
/// 
/// let is_public = read_option_bool_from_clearsigntoml_without_keyid(
///     config_path,
///     settings_file, 
///     "message_post_is_public_bool"
/// )?;
/// // Returns: Some(true), Some(false), or None depending on the field value
/// ```
pub fn read_option_bool_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Option<bool>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the optional boolean field from the verified file
    read_option_bool_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional boolean '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_option_bool_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_option_bool_from_toml_valid() {
        // Create a test TOML file with boolean fields
        let test_content = r#"
# Test TOML file with optional booleans
message_post_is_public_bool = true
message_post_user_confirms_bool = false
other_field = "not a boolean"
# commented_bool = true
"#;
        let test_file = "test_option_bool.toml";
        fs::write(test_file, test_content).unwrap();

        // Test true value
        let result = read_option_bool_field_from_toml(test_file, "message_post_is_public_bool");
        assert_eq!(result.unwrap(), Some(true));

        // Test false value
        let result = read_option_bool_field_from_toml(test_file, "message_post_user_confirms_bool");
        assert_eq!(result.unwrap(), Some(false));

        // Test missing field (should return None, not error)
        let result = read_option_bool_field_from_toml(test_file, "field_not_present");
        assert_eq!(result.unwrap(), None);

        // Test commented field (should return None)
        let result = read_option_bool_field_from_toml(test_file, "commented_bool");
        assert_eq!(result.unwrap(), None);

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_bool_invalid_values() {
        // Create test file with invalid boolean values
        let test_content = r#"
invalid_bool1 = "true"
invalid_bool2 = True
invalid_bool3 = 1
invalid_bool4 = yes
empty_value = 
"#;
        let test_file = "test_option_bool_invalid.toml";
        fs::write(test_file, test_content).unwrap();

        // Test quoted boolean (string, not boolean)
        let result = read_option_bool_field_from_toml(test_file, "invalid_bool1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid boolean value"));

        // Test capitalized True
        let result = read_option_bool_field_from_toml(test_file, "invalid_bool2");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid boolean value"));

        // Test numeric 1
        let result = read_option_bool_field_from_toml(test_file, "invalid_bool3");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid boolean value"));

        // Test yes
        let result = read_option_bool_field_from_toml(test_file, "invalid_bool4");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid boolean value"));

        // Test empty value
        let result = read_option_bool_field_from_toml(test_file, "empty_value");
        assert!(result.is_err());

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_bool_edge_cases() {
        // Test edge cases
        let test_content = r#"
# Field with spaces around value
spaced_bool = true
# Field with tabs
tabbed_bool =	false
# Multiple fields on one line shouldn't work in our parser
"#;
        let test_file = "test_option_bool_edge.toml";
        fs::write(test_file, test_content).unwrap();

        // Test with spaces (should work due to trim)
        let result = read_option_bool_field_from_toml(test_file, "spaced_bool");
        assert_eq!(result.unwrap(), Some(true));

        // Test with tabs (should work due to trim)
        let result = read_option_bool_field_from_toml(test_file, "tabbed_bool");
        assert_eq!(result.unwrap(), Some(false));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_bool_file_not_found() {
        let result = read_option_bool_field_from_toml("nonexistent.toml", "some_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open file"));
    }

    // Note: Testing clearsigned versions requires GPG setup, so those tests
    // would be similar to existing clearsign tests in the module
}

/// Reads an optional usize field from a TOML file into an Option<usize>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an optional unsigned size value (usize) defined 
/// by the specified field name. It handles cases where the field may or may not exist, returning
/// None if the field is absent and Some(usize) if present with a valid non-negative integer value.
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If the field does not exist in the file
/// - `Ok(Some(value))` - If the field exists and has a valid usize value
/// - `Err(String)` - If the file cannot be read or the field has an invalid value
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The field exists but has a non-numeric value
/// - The field exists but has a negative value
/// - The field exists but the value is too large for usize
/// - The field exists but has an empty value
/// 
/// Note: A missing field is NOT an error - it returns Ok(None)
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// message_post_data_format_specs_int_string_max_string_length = 256
/// small_limit = 10
/// # missing_limit is not present
/// ```
/// 
/// Usage:
/// ```
/// let max_len = read_option_usize_field_from_toml("config.toml", "message_post_data_format_specs_int_string_max_string_length")?;
/// // Returns: Some(256)
/// 
/// let small = read_option_usize_field_from_toml("config.toml", "small_limit")?;
/// // Returns: Some(10)
/// 
/// let missing = read_option_usize_field_from_toml("config.toml", "missing_limit")?;
/// // Returns: None
/// ```
/// 
/// # Implementation Notes
/// - Field absence returns None (not an error)
/// - Only non-negative integers are valid
/// - The value must fit within the platform's usize range
/// - Floating point numbers are not accepted
pub fn read_option_usize_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<usize>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field
        if let Some(equals_pos) = trimmed.find('=') {
            let key_part = trimmed[..equals_pos].trim();
            
            if key_part == name_of_toml_field_key_to_read {
                // Found our field, now parse the value
                let value_part = trimmed[equals_pos + 1..].trim();
                
                // Check for empty value
                if value_part.is_empty() {
                    return Err(format!(
                        "Field '{}' in file '{}' has empty value",
                        name_of_toml_field_key_to_read, path
                    ));
                }
                
                // Parse the usize value
                match value_part.parse::<usize>() {
                    Ok(value) => {
                        println!("Read optional usize field '{}': Some({})", name_of_toml_field_key_to_read, value);
                        return Ok(Some(value));
                    },
                    Err(e) => {
                        // Check if it might be a negative number
                        if value_part.starts_with('-') {
                            return Err(format!(
                                "Field '{}' in file '{}' has negative value '{}'. Expected non-negative integer",
                                name_of_toml_field_key_to_read, path, value_part
                            ));
                        }
                        // Otherwise it's just not a valid number
                        return Err(format!(
                            "Field '{}' in file '{}' has invalid numeric value: '{}'. Parse error: {}",
                            name_of_toml_field_key_to_read, path, value_part, e
                        ));
                    }
                }
            }
        }
    }
    
    // Field not found - this is OK for optional fields
    println!("Optional usize field '{}' not found in file '{}', returning None", name_of_toml_field_key_to_read, path);
    Ok(None)
}

/// Reads an optional usize field from a clearsigned TOML file into an Option<usize>.
/// 
/// # Purpose
/// This function securely reads an optional usize field from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the optional usize field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for size/length configurations.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(value))` - If verification succeeds and the field has a valid usize value
/// - `Err(String)` - If verification fails or the field has an invalid value
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// message_post_data_format_specs_int_string_max_string_length = 256
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let max_len = read_option_usize_from_clearsigntoml("config.toml", "message_post_data_format_specs_int_string_max_string_length")?;
/// // Returns: Some(256) if signature verification succeeds
/// 
/// let missing = read_option_usize_from_clearsigntoml("config.toml", "field_not_present")?;
/// // Returns: None if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field exists but has an invalid numeric value
/// - The field exists but has a negative value
pub fn read_option_usize_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<usize>, String> {
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
    
    // Step 4: If verification succeeded, read the optional usize field
    read_option_usize_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional usize '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an optional usize field from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read optional usize fields from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the optional usize field
/// 4. Returns None if field doesn't exist, Some(usize) if it does, or an error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the optional usize field to read from the target file
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(value))` - If verification succeeds and the field has a valid usize value
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let settings_file = "message_settings.toml";
/// 
/// let max_string_len = read_option_usize_from_clearsigntoml_without_keyid(
///     config_path,
///     settings_file, 
///     "message_post_data_format_specs_int_string_max_string_length"
/// )?;
/// // Returns: Some(256), or None if field doesn't exist
/// ```
pub fn read_option_usize_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Option<usize>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the optional usize field from the verified file
    read_option_usize_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional usize '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_option_usize_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_option_usize_from_toml_valid() {
        // Create a test TOML file with usize fields
        let test_content = r#"
# Test TOML file with optional usize values
message_post_data_format_specs_int_string_max_string_length = 256
small_limit = 10
zero_value = 0
large_value = 1000000
# commented_value = 100
"#;
        let test_file = "test_option_usize.toml";
        fs::write(test_file, test_content).unwrap();

        // Test normal value
        let result = read_option_usize_field_from_toml(test_file, "message_post_data_format_specs_int_string_max_string_length");
        assert_eq!(result.unwrap(), Some(256));

        // Test small value
        let result = read_option_usize_field_from_toml(test_file, "small_limit");
        assert_eq!(result.unwrap(), Some(10));

        // Test zero value (valid for usize)
        let result = read_option_usize_field_from_toml(test_file, "zero_value");
        assert_eq!(result.unwrap(), Some(0));

        // Test large value
        let result = read_option_usize_field_from_toml(test_file, "large_value");
        assert_eq!(result.unwrap(), Some(1000000));

        // Test missing field (should return None, not error)
        let result = read_option_usize_field_from_toml(test_file, "field_not_present");
        assert_eq!(result.unwrap(), None);

        // Test commented field (should return None)
        let result = read_option_usize_field_from_toml(test_file, "commented_value");
        assert_eq!(result.unwrap(), None);

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_usize_invalid_values() {
        // Create test file with invalid usize values
        let test_content = r#"
negative_value = -10
float_value = 10.5
string_value = "not a number"
quoted_number = "100"
empty_value = 
hex_value = 0xFF
"#;
        let test_file = "test_option_usize_invalid.toml";
        fs::write(test_file, test_content).unwrap();

        // Test negative value
        let result = read_option_usize_field_from_toml(test_file, "negative_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("negative value"));

        // Test float value
        let result = read_option_usize_field_from_toml(test_file, "float_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test string value
        let result = read_option_usize_field_from_toml(test_file, "string_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test quoted number
        let result = read_option_usize_field_from_toml(test_file, "quoted_number");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test empty value
        let result = read_option_usize_field_from_toml(test_file, "empty_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty value"));

        // Test hex value (not supported in our parser)
        let result = read_option_usize_field_from_toml(test_file, "hex_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_usize_edge_cases() {
        // Test edge cases
        let test_content = r#"
# Field with spaces around value
spaced_value = 42
# Field with tabs
tabbed_value =	100
# Very large number (might overflow on some platforms)
max_value = 18446744073709551615
"#;
        let test_file = "test_option_usize_edge.toml";
        fs::write(test_file, test_content).unwrap();

        // Test with spaces (should work due to trim)
        let result = read_option_usize_field_from_toml(test_file, "spaced_value");
        assert_eq!(result.unwrap(), Some(42));

        // Test with tabs (should work due to flexible parsing)
        let result = read_option_usize_field_from_toml(test_file, "tabbed_value");
        assert_eq!(result.unwrap(), Some(100));

        // Test max value (on 64-bit systems this should work)
        let result = read_option_usize_field_from_toml(test_file, "max_value");
        // This test might fail on 32-bit systems where usize is smaller
        if std::mem::size_of::<usize>() == 8 {
            assert!(result.is_ok());
        }

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_usize_file_not_found() {
        let result = read_option_usize_field_from_toml("nonexistent.toml", "some_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open file"));
    }
}


/// Reads an optional u64 field from a TOML file into an Option<u64>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an optional signed 64-bit integer value (u64) 
/// defined by the specified field name. It handles cases where the field may or may not exist, 
/// returning None if the field is absent and Some(u64) if present with a valid integer value.
/// This is particularly useful for POSIX timestamps which can be negative (dates before 1970).
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If the field does not exist in the file
/// - `Ok(Some(value))` - If the field exists and has a valid u64 value
/// - `Err(String)` - If the file cannot be read or the field has an invalid value
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The field exists but has a non-numeric value
/// - The field exists but the value is outside the u64 range
/// - The field exists but has an empty value
/// 
/// Note: A missing field is NOT an error - it returns Ok(None)
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// message_post_start_date_utc_posix = 1672531200
/// message_post_end_date_utc_posix = 1704067200
/// past_date = -86400
/// # missing_date is not present
/// ```
/// 
/// Usage:
/// ```
/// let start_date = read_option_u64_field_from_toml("config.toml", "message_post_start_date_utc_posix")?;
/// // Returns: Some(1672531200)
/// 
/// let past_date = read_option_u64_field_from_toml("config.toml", "past_date")?;
/// // Returns: Some(-86400)
/// 
/// let missing = read_option_u64_field_from_toml("config.toml", "missing_date")?;
/// // Returns: None
/// ```
/// 
/// # Implementation Notes
/// - Field absence returns None (not an error)
/// - Both positive and negative integers are valid
/// - The value must fit within the u64 range (-9223372036854775808 to 9223372036854775807)
/// - Floating point numbers are not accepted
pub fn read_option_u64_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<u64>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field
        if let Some(equals_pos) = trimmed.find('=') {
            let key_part = trimmed[..equals_pos].trim();
            
            if key_part == name_of_toml_field_key_to_read {
                // Found our field, now parse the value
                let value_part = trimmed[equals_pos + 1..].trim();
                
                // Check for empty value
                if value_part.is_empty() {
                    return Err(format!(
                        "Field '{}' in file '{}' has empty value",
                        name_of_toml_field_key_to_read, path
                    ));
                }
                
                // Parse the u64 value
                match value_part.parse::<u64>() {
                    Ok(value) => {
                        println!("Read optional u64 field '{}': Some({})", name_of_toml_field_key_to_read, value);
                        return Ok(Some(value));
                    },
                    Err(e) => {
                        return Err(format!(
                            "Field '{}' in file '{}' has invalid numeric value: '{}'. Parse error: {}",
                            name_of_toml_field_key_to_read, path, value_part, e
                        ));
                    }
                }
            }
        }
    }
    
    // Field not found - this is OK for optional fields
    println!("Optional u64 field '{}' not found in file '{}', returning None", name_of_toml_field_key_to_read, path);
    Ok(None)
}

/// Reads an optional u64 field from a clearsigned TOML file into an Option<u64>.
/// 
/// # Purpose
/// This function securely reads an optional u64 field from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the optional u64 field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for timestamp configurations.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(value))` - If verification succeeds and the field has a valid u64 value
/// - `Err(String)` - If verification fails or the field has an invalid value
/// 
/// # POSIX Timestamp Support
/// This function fully supports POSIX timestamps including:
/// - Positive values (dates after January 1, 1970)
/// - Negative values (dates before January 1, 1970)
/// - Zero (exactly January 1, 1970 00:00:00 UTC)
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// message_post_start_date_utc_posix = 1672531200
/// message_post_end_date_utc_posix = 1704067200
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let start_date = read_option_u64_from_clearsigntoml("config.toml", "message_post_start_date_utc_posix")?;
/// // Returns: Some(1672531200) if signature verification succeeds
/// 
/// let missing = read_option_u64_from_clearsigntoml("config.toml", "field_not_present")?;
/// // Returns: None if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field exists but has an invalid numeric value
/// - The field exists but the value is outside u64 range
pub fn read_option_u64_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<u64>, String> {
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
    
    // Step 4: If verification succeeded, read the optional u64 field
    read_option_u64_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional u64 '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an optional i64 field from a TOML file into an Option<i64>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an optional signed 64-bit integer value (i64) 
/// defined by the specified field name. It handles cases where the field may or may not exist, 
/// returning None if the field is absent and Some(i64) if present with a valid integer value.
/// This is particularly useful for POSIX timestamps which can be negative (dates before 1970).
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If the field does not exist in the file
/// - `Ok(Some(value))` - If the field exists and has a valid i64 value
/// - `Err(String)` - If the file cannot be read or the field has an invalid value
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The field exists but has a non-numeric value
/// - The field exists but the value is outside the i64 range
/// - The field exists but has an empty value
/// 
/// Note: A missing field is NOT an error - it returns Ok(None)
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// message_post_start_date_utc_posix = 1672531200
/// message_post_end_date_utc_posix = 1704067200
/// past_date = -86400
/// # missing_date is not present
/// ```
/// 
/// Usage:
/// ```
/// let start_date = read_option_i64_field_from_toml("config.toml", "message_post_start_date_utc_posix")?;
/// // Returns: Some(1672531200)
/// 
/// let past_date = read_option_i64_field_from_toml("config.toml", "past_date")?;
/// // Returns: Some(-86400)
/// 
/// let missing = read_option_i64_field_from_toml("config.toml", "missing_date")?;
/// // Returns: None
/// ```
/// 
/// # Implementation Notes
/// - Field absence returns None (not an error)
/// - Both positive and negative integers are valid
/// - The value must fit within the i64 range (-9223372036854775808 to 9223372036854775807)
/// - Floating point numbers are not accepted
pub fn read_option_i64_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<i64>, String> {
    // Open the file
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let reader = io::BufReader::new(file);
    
    // Process each line looking for our field
    for (line_number, line_result) in reader.lines().enumerate() {
        // Handle line reading errors
        let line = line_result
            .map_err(|e| format!("Failed to read line {} from file '{}': {}", line_number + 1, path, e))?;
        
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field
        if let Some(equals_pos) = trimmed.find('=') {
            let key_part = trimmed[..equals_pos].trim();
            
            if key_part == name_of_toml_field_key_to_read {
                // Found our field, now parse the value
                let value_part = trimmed[equals_pos + 1..].trim();
                
                // Check for empty value
                if value_part.is_empty() {
                    return Err(format!(
                        "Field '{}' in file '{}' has empty value",
                        name_of_toml_field_key_to_read, path
                    ));
                }
                
                // Parse the i64 value
                match value_part.parse::<i64>() {
                    Ok(value) => {
                        println!("Read optional i64 field '{}': Some({})", name_of_toml_field_key_to_read, value);
                        return Ok(Some(value));
                    },
                    Err(e) => {
                        return Err(format!(
                            "Field '{}' in file '{}' has invalid numeric value: '{}'. Parse error: {}",
                            name_of_toml_field_key_to_read, path, value_part, e
                        ));
                    }
                }
            }
        }
    }
    
    // Field not found - this is OK for optional fields
    println!("Optional i64 field '{}' not found in file '{}', returning None", name_of_toml_field_key_to_read, path);
    Ok(None)
}

/// Reads an optional i64 field from a clearsigned TOML file into an Option<i64>.
/// 
/// # Purpose
/// This function securely reads an optional i64 field from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the optional i64 field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for timestamp configurations.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(value))` - If verification succeeds and the field has a valid i64 value
/// - `Err(String)` - If verification fails or the field has an invalid value
/// 
/// # POSIX Timestamp Support
/// This function fully supports POSIX timestamps including:
/// - Positive values (dates after January 1, 1970)
/// - Negative values (dates before January 1, 1970)
/// - Zero (exactly January 1, 1970 00:00:00 UTC)
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// message_post_start_date_utc_posix = 1672531200
/// message_post_end_date_utc_posix = 1704067200
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let start_date = read_option_i64_from_clearsigntoml("config.toml", "message_post_start_date_utc_posix")?;
/// // Returns: Some(1672531200) if signature verification succeeds
/// 
/// let missing = read_option_i64_from_clearsigntoml("config.toml", "field_not_present")?;
/// // Returns: None if signature verification succeeds
/// ```
/// 
/// # Errors
/// Returns an error if:
/// - GPG key extraction fails
/// - Signature verification fails
/// - The field exists but has an invalid numeric value
/// - The field exists but the value is outside i64 range
pub fn read_option_i64_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<i64>, String> {
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
    
    // Step 4: If verification succeeded, read the optional i64 field
    read_option_i64_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional i64 '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an optional i64 field from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read optional i64 fields from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// This is particularly useful for timestamp fields that need secure storage and transmission.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the optional i64 field
/// 4. Returns None if field doesn't exist, Some(i64) if it does, or an error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the optional i64 field to read from the target file
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(value))` - If verification succeeds and the field has a valid i64 value
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let settings_file = "message_settings.toml";
/// 
/// let start_date = read_option_i64_from_clearsigntoml_without_keyid(
///     config_path,
///     settings_file, 
///     "message_post_start_date_utc_posix"
/// )?;
/// // Returns: Some(1672531200), or None if field doesn't exist
/// 
/// let end_date = read_option_i64_from_clearsigntoml_without_keyid(
///     config_path,
///     settings_file, 
///     "message_post_end_date_utc_posix"  
/// )?;
/// // Returns: Some(1704067200), or None if field doesn't exist
/// ```
pub fn read_option_i64_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Option<i64>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the optional i64 field from the verified file
    read_option_i64_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional i64 '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_option_i64_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_option_i64_from_toml_valid() {
        // Create a test TOML file with i64 fields
        let test_content = r#"
# Test TOML file with optional i64 values
message_post_start_date_utc_posix = 1672531200
message_post_end_date_utc_posix = 1704067200
negative_timestamp = -86400
zero_timestamp = 0
large_positive = 9223372036854775807
large_negative = -9223372036854775808
# commented_value = 1000000
"#;
        let test_file = "test_option_i64.toml";
        fs::write(test_file, test_content).unwrap();

        // Test positive timestamp
        let result = read_option_i64_field_from_toml(test_file, "message_post_start_date_utc_posix");
        assert_eq!(result.unwrap(), Some(1672531200));

        // Test another positive timestamp
        let result = read_option_i64_field_from_toml(test_file, "message_post_end_date_utc_posix");
        assert_eq!(result.unwrap(), Some(1704067200));

        // Test negative value (valid for timestamps before 1970)
        let result = read_option_i64_field_from_toml(test_file, "negative_timestamp");
        assert_eq!(result.unwrap(), Some(-86400));

        // Test zero value (Unix epoch)
        let result = read_option_i64_field_from_toml(test_file, "zero_timestamp");
        assert_eq!(result.unwrap(), Some(0));

        // Test max positive i64
        let result = read_option_i64_field_from_toml(test_file, "large_positive");
        assert_eq!(result.unwrap(), Some(9223372036854775807));

        // Test min negative i64
        let result = read_option_i64_field_from_toml(test_file, "large_negative");
        assert_eq!(result.unwrap(), Some(-9223372036854775808));

        // Test missing field (should return None, not error)
        let result = read_option_i64_field_from_toml(test_file, "field_not_present");
        assert_eq!(result.unwrap(), None);

        // Test commented field (should return None)
        let result = read_option_i64_field_from_toml(test_file, "commented_value");
        assert_eq!(result.unwrap(), None);

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i64_invalid_values() {
        // Create test file with invalid i64 values
        let test_content = r#"
float_value = 10.5
string_value = "not a number"
quoted_number = "1672531200"
empty_value = 
hex_value = 0xFF
too_large = 9223372036854775808
"#;
        let test_file = "test_option_i64_invalid.toml";
        fs::write(test_file, test_content).unwrap();

        // Test float value
        let result = read_option_i64_field_from_toml(test_file, "float_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test string value
        let result = read_option_i64_field_from_toml(test_file, "string_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test quoted number
        let result = read_option_i64_field_from_toml(test_file, "quoted_number");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test empty value
        let result = read_option_i64_field_from_toml(test_file, "empty_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty value"));

        // Test hex value (not supported in our parser)
        let result = read_option_i64_field_from_toml(test_file, "hex_value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Test value too large for i64
        let result = read_option_i64_field_from_toml(test_file, "too_large");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid numeric value"));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i64_edge_cases() {
        // Test edge cases
        let test_content = r#"
# Field with spaces around value
spaced_value = -42
# Field with tabs
tabbed_value =	1000000
# Year 2038 problem timestamp (still within i64 range)
year_2038 = 2147483648
# Far future timestamp
far_future = 253402300799
# Far past timestamp  
far_past = -62135596800
"#;
        let test_file = "test_option_i64_edge.toml";
        fs::write(test_file, test_content).unwrap();

        // Test with spaces (should work due to trim)
        let result = read_option_i64_field_from_toml(test_file, "spaced_value");
        assert_eq!(result.unwrap(), Some(-42));

        // Test with tabs (should work due to flexible parsing)
        let result = read_option_i64_field_from_toml(test_file, "tabbed_value");
        assert_eq!(result.unwrap(), Some(1000000));

        // Test year 2038 timestamp (beyond 32-bit limit but within i64)
        let result = read_option_i64_field_from_toml(test_file, "year_2038");
        assert_eq!(result.unwrap(), Some(2147483648));

        // Test far future (year 9999)
        let result = read_option_i64_field_from_toml(test_file, "far_future");
        assert_eq!(result.unwrap(), Some(253402300799));

        // Test far past (year 1)
        let result = read_option_i64_field_from_toml(test_file, "far_past");
        assert_eq!(result.unwrap(), Some(-62135596800));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i64_file_not_found() {
        let result = read_option_i64_field_from_toml("nonexistent.toml", "some_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to open file"));
    }
}

/// Reads an optional array of i32 tuples from a TOML file into an Option<Vec<(i32, i32)>>.
/// 
/// # Purpose
/// This function parses a TOML file to extract an optional array of integer tuples (pairs)
/// defined by the specified field name. Each tuple represents a range or pair of i32 values.
/// It handles cases where the field may or may not exist, returning None if the field is 
/// absent and Some(Vec<(i32, i32)>) if present with valid tuple values.
/// 
/// # TOML Format
/// The expected TOML format is an array of arrays, where each inner array has exactly 2 elements:
/// ```toml
/// name_of_toml_field_key_to_read = [[1, 10], [20, 30], [50, 100]]
/// ```
/// Or multi-line:
/// ```toml
/// name_of_toml_field_key_to_read = [
///     [1, 10],
///     [20, 30],
///     [50, 100]
/// ]
/// ```
/// 
/// # Arguments
/// - `path` - Path to the TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If the field does not exist in the file
/// - `Ok(Some(vec![]))` - If the field exists but is an empty array
/// - `Ok(Some(vec![(a,b), ...]))` - If the field exists with valid tuple pairs
/// - `Err(String)` - If the file cannot be read or the field has invalid format/values
/// 
/// # Error Handling
/// This function returns errors when:
/// - The file cannot be opened or read
/// - The field exists but is not an array
/// - Any inner array doesn't have exactly 2 elements
/// - Any value in the tuples is not a valid i32
/// - The field exists but has an empty value
/// 
/// Note: A missing field is NOT an error - it returns Ok(None)
/// 
/// # Example
/// For a TOML file containing:
/// ```toml
/// message_post_data_format_specs_integer_ranges_from_to_tuple_array = [[1, 100], [-50, 50]]
/// message_post_data_format_specs_int_string_ranges_from_to_tuple_array = [[0, 255], [1000, 9999]]
/// empty_ranges = []
/// # missing_ranges is not present
/// ```
/// 
/// Usage:
/// ```
/// let ranges = read_option_i32_tuple_array_field_from_toml("config.toml", "message_post_data_format_specs_integer_ranges_from_to_tuple_array")?;
/// // Returns: Some(vec![(1, 100), (-50, 50)])
/// 
/// let empty = read_option_i32_tuple_array_field_from_toml("config.toml", "empty_ranges")?;
/// // Returns: Some(vec![])
/// 
/// let missing = read_option_i32_tuple_array_field_from_toml("config.toml", "missing_ranges")?;
/// // Returns: None
/// ```
/// 
/// # Implementation Notes
/// - Field absence returns None (not an error)
/// - Empty arrays are valid and return Some(vec![])
/// - Each tuple must have exactly 2 elements
/// - Both positive and negative i32 values are accepted
/// - The parser handles nested array syntax
pub fn read_option_i32_tuple_array_field_from_toml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<Vec<(i32, i32)>>, String> {
    // Open and read the entire file
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
    
    // Split into lines but keep track of line endings for reconstruction
    let lines: Vec<&str> = content.lines().collect();
    
    // Find the line with our field
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // Check if this line contains our field
        if let Some(equals_pos) = trimmed.find('=') {
            let key_part = trimmed[..equals_pos].trim();
            
            if key_part == name_of_toml_field_key_to_read {
                // Found our field
                let value_part = trimmed[equals_pos + 1..].trim();
                
                // Check for empty value
                if value_part.is_empty() {
                    return Err(format!(
                        "Field '{}' in file '{}' has empty value",
                        name_of_toml_field_key_to_read, path
                    ));
                }
                
                // Check if it's a single-line array
                if value_part.starts_with('[') {
                    // Count brackets to see if it's complete on this line
                    let mut bracket_count = 0;
                    for ch in value_part.chars() {
                        match ch {
                            '[' => bracket_count += 1,
                            ']' => bracket_count -= 1,
                            _ => {}
                        }
                    }
                    
                    if bracket_count == 0 {
                        // Complete single-line array
                        println!("Parsing single-line tuple array for field '{}': {}", name_of_toml_field_key_to_read, value_part);
                        return parse_i32_tuple_array_simple(value_part, name_of_toml_field_key_to_read, path).map(Some);
                    } else {
                        // Multi-line array - collect all lines until brackets balance
                        let mut array_content = String::from(value_part);
                        
                        for line in lines.iter().skip(idx + 1) {
                            array_content.push('\n');
                            array_content.push_str(line);
                            
                            // Update bracket count
                            for ch in line.chars() {
                                match ch {
                                    '[' => bracket_count += 1,
                                    ']' => bracket_count -= 1,
                                    _ => {}
                                }
                            }
                            
                            if bracket_count == 0 {
                                // Found the end
                                println!("Parsing multi-line tuple array for field '{}'", name_of_toml_field_key_to_read);
                                return parse_i32_tuple_array_simple(&array_content, name_of_toml_field_key_to_read, path).map(Some);
                            }
                        }
                        
                        return Err(format!(
                            "Field '{}' in file '{}' has unclosed array brackets",
                            name_of_toml_field_key_to_read, path
                        ));
                    }
                } else {
                    return Err(format!(
                        "Field '{}' in file '{}' is not an array (doesn't start with '[')",
                        name_of_toml_field_key_to_read, path
                    ));
                }
            }
        }
    }
    
    // Field not found - this is OK for optional fields
    println!("Optional i32 tuple array field '{}' not found in file '{}', returning None", name_of_toml_field_key_to_read, path);
    Ok(None)
}

/// Simplified helper function to parse an i32 tuple array from a string
fn parse_i32_tuple_array_simple(array_str: &str, name_of_toml_field_key_to_read: &str, file_path: &str) -> Result<Vec<(i32, i32)>, String> {
    let trimmed = array_str.trim();
    
    // Verify it's wrapped in brackets
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(format!(
            "Field '{}' in file '{}' has invalid array format",
            name_of_toml_field_key_to_read, file_path
        ));
    }
    
    // Remove outer brackets and trim
    let inner_content = trimmed[1..trimmed.len()-1].trim();
    
    // Handle empty array
    if inner_content.is_empty() {
        return Ok(Vec::new());
    }
    
    // For robustness, let's manually parse the tuples
    let mut tuples = Vec::new();
    let mut current_tuple = String::new();
    let mut bracket_depth = 0;
    
    for ch in inner_content.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current_tuple.push(ch);
            }
            ']' => {
                bracket_depth -= 1;
                current_tuple.push(ch);
                
                // If we've closed a tuple
                if bracket_depth == 0 && !current_tuple.trim().is_empty() {
                    let parsed = parse_single_i32_tuple(&current_tuple.trim(), name_of_toml_field_key_to_read, file_path)?;
                    tuples.push(parsed);
                    current_tuple.clear();
                }
            }
            ',' if bracket_depth == 0 => {
                // Comma outside of brackets, skip it
                continue;
            }
            '\n' | '\r' => {
                // Preserve newlines within tuples if needed
                if bracket_depth > 0 {
                    current_tuple.push(' '); // Replace with space
                }
            }
            _ => {
                if bracket_depth > 0 || !ch.is_whitespace() {
                    current_tuple.push(ch);
                }
            }
        }
    }
    
    // Handle any remaining tuple
    if !current_tuple.trim().is_empty() {
        return Err(format!(
            "Unclosed tuple in field '{}' in file '{}'",
            name_of_toml_field_key_to_read, file_path
        ));
    }
    
    Ok(tuples)
}

/// Reads an opt
/// Helper function to parse a single i32 tuple from a string like "[1, 10]"
fn parse_single_i32_tuple(tuple_str: &str, name_of_toml_field_key_to_read: &str, file_path: &str) -> Result<(i32, i32), String> {
    let trimmed = tuple_str.trim();
    
    // Remove brackets
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(format!(
            "Invalid tuple format in field '{}' in file '{}': '{}'",
            name_of_toml_field_key_to_read, file_path, tuple_str
        ));
    }
    
    let inner = trimmed[1..trimmed.len()-1].trim();
    
    // Split by comma
    let parts: Vec<&str> = inner.split(',').collect();
    
    if parts.len() != 2 {
        return Err(format!(
            "Tuple in field '{}' in file '{}' must have exactly 2 elements, found {}: '{}'",
            name_of_toml_field_key_to_read, file_path, parts.len(), tuple_str
        ));
    }
    
    // Parse the two values
    let first = parts[0].trim().parse::<i32>()
        .map_err(|e| format!(
            "First element '{}' in tuple of field '{}' in file '{}' is not a valid i32: {}",
            parts[0].trim(), name_of_toml_field_key_to_read, file_path, e
        ))?;
        
    let second = parts[1].trim().parse::<i32>()
        .map_err(|e| format!(
            "Second element '{}' in tuple of field '{}' in file '{}' is not a valid i32: {}",
            parts[1].trim(), name_of_toml_field_key_to_read, file_path, e
        ))?;
    
    Ok((first, second))
}

/// Reads an optional array of i32 tuples from a clearsigned TOML file into an Option<Vec<(i32, i32)>>.
/// 
/// # Purpose
/// This function securely reads an optional array of i32 tuples from a clearsigned TOML file by:
/// 1. Extracting the GPG public key from the file
/// 2. Verifying the clearsign signature
/// 3. If verification succeeds, reading the optional tuple array field
/// 
/// # Security
/// This function ensures that the TOML file's content is cryptographically verified 
/// before any data is extracted, providing integrity protection for range configurations.
/// No data is returned if signature validation fails.
/// 
/// # Arguments
/// - `path` - Path to the clearsigned TOML file
/// - `name_of_toml_field_key_to_read` - Name of the field to read (may or may not exist in the TOML file)
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(vec![]))` - If verification succeeds and the field is an empty array
/// - `Ok(Some(vec![(a,b), ...]))` - If verification succeeds and the field has valid tuples
/// - `Err(String)` - If verification fails or the field has invalid format/values
/// 
/// # Example
/// For a clearsigned TOML file containing:
/// ```toml
/// message_post_data_format_specs_integer_ranges_from_to_tuple_array = [[1, 100], [-50, 50]]
/// 
/// gpg_key_public = """
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// """
/// ```
/// 
/// Usage:
/// ```
/// let ranges = read_option_i32_tuple_array_from_clearsigntoml("config.toml", "message_post_data_format_specs_integer_ranges_from_to_tuple_array")?;
/// // Returns: Some(vec![(1, 100), (-50, 50)]) if signature verification succeeds
/// ```
pub fn read_option_i32_tuple_array_from_clearsigntoml(path: &str, name_of_toml_field_key_to_read: &str) -> Result<Option<Vec<(i32, i32)>>, String> {
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
    
    // Step 4: If verification succeeded, read the optional tuple array field
    read_option_i32_tuple_array_field_from_toml(path, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional i32 tuple array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, path, e))
}

/// Reads an optional array of i32 tuples from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read optional tuple array fields from clearsigned 
/// TOML files that don't contain their own GPG keys, instead using a key from a separate 
/// centralized config file. This is useful for range specifications and validation rules.
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the optional tuple array field
/// 4. Returns None if field doesn't exist, Some(vec) if it does, or an error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `name_of_toml_field_key_to_read` - Name of the optional tuple array field to read from the target file
/// 
/// # Returns
/// - `Ok(None)` - If verification succeeds and the field does not exist
/// - `Ok(Some(vec))` - If verification succeeds and the field has valid tuple array
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # Example
/// ```
/// let config_path = "security_config.toml";
/// let validation_file = "validation_rules.toml";
/// 
/// let ranges = read_option_i32_tuple_array_from_clearsigntoml_without_keyid(
///     config_path,
///     validation_file, 
///     "message_post_data_format_specs_integer_ranges_from_to_tuple_array"
/// )?;
/// // Returns: Some(vec![(1, 100), (200, 300)]), or None if field doesn't exist
/// ```
pub fn read_option_i32_tuple_array_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str, 
    name_of_toml_field_key_to_read: &str,
) -> Result<Option<Vec<(i32, i32)>>, String> {
    // Step 1: Extract GPG key from the config file
    let key = extract_gpg_key_from_clearsigntoml(pathstr_to_config_file_that_contains_gpg_key, "gpg_key_public")
        .map_err(|e| format!("Failed to extract GPG key from config file '{}': {}", 
                             pathstr_to_config_file_that_contains_gpg_key, e))?;

    // Step 2: Verify the target file using the extracted key
    let verification_result = verify_clearsign(pathstr_to_target_clearsigned_file, &key)
        .map_err(|e| format!("Failed during verification process: {}", e))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    // Step 4: Read the optional tuple array field from the verified file
    read_option_i32_tuple_array_field_from_toml(pathstr_to_target_clearsigned_file, name_of_toml_field_key_to_read)
        .map_err(|e| format!("Failed to read optional i32 tuple array '{}' from verified file '{}': {}", 
                             name_of_toml_field_key_to_read, pathstr_to_target_clearsigned_file, e))
}

#[cfg(test)]
mod test_option_i32_tuple_array_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_option_i32_tuple_array_from_toml_valid() {
        // Create a test TOML file with tuple arrays
        let test_content = r#"
    # Test TOML file with optional tuple arrays
    message_post_data_format_specs_integer_ranges_from_to_tuple_array = [[1, 100], [-50, 50], [1000, 9999]]
    message_post_data_format_specs_int_string_ranges_from_to_tuple_array = [[0, 255]]
    single_tuple = [[42, 84]]
    empty_array = []
    # commented_array = [[1, 2], [3, 4]]
    "#;
        let test_file = "test_option_tuple_array.toml";
        fs::write(test_file, test_content).unwrap();

        // Test normal array
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "message_post_data_format_specs_integer_ranges_from_to_tuple_array");
        assert_eq!(result.unwrap(), Some(vec![(1, 100), (-50, 50), (1000, 9999)]));

        // Test single range array
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "message_post_data_format_specs_int_string_ranges_from_to_tuple_array");
        assert_eq!(result.unwrap(), Some(vec![(0, 255)]));

        // Test single tuple
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "single_tuple");
        assert_eq!(result.unwrap(), Some(vec![(42, 84)]));

        // Test empty array
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "empty_array");
        assert_eq!(result.unwrap(), Some(vec![]));

        // Test missing field (should return None, not error)
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "field_not_present");
        assert_eq!(result.unwrap(), None);

        // Test commented field (should return None)
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "commented_array");
        assert_eq!(result.unwrap(), None);

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i32_tuple_array_multiline() {
        // Test multi-line format
        let test_content = r#"
# Multi-line tuple array
ranges = [
    [1, 10],
    [20, 30],
    [40, 50]
]

compact_ranges = [[1,2],[3,4],[5,6]]
"#;
        let test_file = "test_tuple_multiline.toml";
        fs::write(test_file, test_content).unwrap();

        // Test multi-line array
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "ranges");
        assert_eq!(result.unwrap(), Some(vec![(1, 10), (20, 30), (40, 50)]));

        // Test compact format (no spaces)
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "compact_ranges");
        assert_eq!(result.unwrap(), Some(vec![(1, 2), (3, 4), (5, 6)]));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i32_tuple_array_invalid() {
        // Create test file with invalid tuple arrays
        let test_content = r#"
not_array = "not an array"
wrong_element_count = [[1, 2, 3], [4, 5]]
single_elements = [1, 2, 3]
mixed_types = [[1, "two"], [3, 4]]
non_integer = [[1.5, 2.5]]
empty_tuple = [[]]
single_value_tuple = [[42]]
"#;
        let test_file = "test_tuple_invalid.toml";
        fs::write(test_file, test_content).unwrap();

        // Test non-array
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "not_array");
        assert!(result.is_err());

        // Test tuples with wrong element count
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "wrong_element_count");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exactly 2 elements"));

        // Test array of single elements (not tuples)
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "single_elements");
        assert!(result.is_err());

        // Test empty tuple
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "empty_tuple");
        assert!(result.is_err());

        // Test single value tuple
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "single_value_tuple");
        assert!(result.is_err());

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_read_option_i32_tuple_array_edge_cases() {
        // Test edge cases
        let test_content = r#"
# Negative ranges
negative_ranges = [[-100, -50], [-10, 10], [0, 100]]

# Large values  
large_ranges = [[-2147483648, 2147483647]]

# Same values (zero-width range)
zero_width = [[42, 42], [0, 0]]
"#;
        let test_file = "test_tuple_edge.toml";
        fs::write(test_file, test_content).unwrap();

        // Test negative ranges
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "negative_ranges");
        assert_eq!(result.unwrap(), Some(vec![(-100, -50), (-10, 10), (0, 100)]));

        // Test i32 min/max values
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "large_ranges");
        assert_eq!(result.unwrap(), Some(vec![(-2147483648, 2147483647)]));

        // Test zero-width ranges
        let result = read_option_i32_tuple_array_field_from_toml(test_file, "zero_width");
        assert_eq!(result.unwrap(), Some(vec![(42, 42), (0, 0)]));

        // Cleanup
        fs::remove_file(test_file).unwrap();
    }
}

/// Wrapper struct for reading team channel collaborator ports from TOML files.
/// 
/// This struct represents the intermediate TOML structure used when reading
/// port assignments. In the TOML file, port assignments are organized as
/// arrays of arrays, where each top-level array element contains a 
/// `collaborator_ports` array with the actual port assignments.
/// 
/// # TOML Structure
/// ```toml
/// [[abstract_collaborator_port_assignments.alice_bob]]
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "alice"
/// ready_port = 62002
/// intray_port = 49595
/// gotit_port = 49879
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "bob"
/// ready_port = 59980
/// intray_port = 52755
/// gotit_port = 60575
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ReadTeamchannelCollaboratorPortsToml {
    /// Vector of port assignments for collaborators in this channel
    pub collaborator_ports: Vec<CollaboratorPortAssignment>,
}

/// Reads all collaborator port assignments into the format expected by CoreNode.
/// 
/// # Purpose
/// This function reads the port assignments from a clearsigned TOML file and returns
/// them in the exact format needed by CoreNode's `abstract_collaborator_port_assignments`
/// field, which is `HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>`.
/// 
/// # Security Model
/// This function enforces the same strict security requirements:
/// 1. Validates the clearsigned file using owner-based key lookup
/// 2. No data is returned if signature validation fails
/// 3. Maintains complete chain of trust
/// 
/// # TOML Structure Expected
/// The function expects the TOML file to contain sections like:
/// ```toml
/// [[abstract_collaborator_port_assignments.alice_bob]]
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "alice"
/// ready_port = 62002
/// intray_port = 49595
/// gotit_port = 49879
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "bob"
/// ready_port = 59980
/// intray_port = 52755
/// gotit_port = 60575
/// ```
/// 
/// # Arguments
/// - `path_to_clearsigned_toml` - Path to the clearsigned TOML file containing port assignments
/// - `addressbook_files_directory_relative` - Relative path to the directory containing collaborator addressbook files
/// 
/// # Returns
/// - `Ok(HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>)` - Port assignments in CoreNode format
/// - `Err(GpgError)` - If validation fails or parsing errors occur
/// 
/// # Example
/// ```no_run
/// let port_assignments = read_hashmap_corenode_ports_struct_from_clearsigntoml(
///     Path::new("team_channel_config.toml"),
///     "collaborators"
/// )?;
/// 
/// // Use with translate_port_assignments
/// let role_based_ports = translate_port_assignments(
///     "alice",
///     "bob", 
///     port_assignments
/// )?;
/// ```
pub fn read_hashmap_corenode_ports_struct_from_clearsigntoml(
    path_to_clearsigned_toml: &Path,
    addressbook_files_directory_relative: &str,  // pass in constant here
) -> Result<HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>, GpgError> {
    // First, use our existing optimized reader to get the data
    let raw_assignments = read_all_collaborator_port_assignments_clearsigntoml_optimized(
        path_to_clearsigned_toml,
        addressbook_files_directory_relative,
    )?;
    
    // Now transform the data into the format CoreNode expects
    let mut corenode_format: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();
    
    for (pair_name, collaborator_assignments) in raw_assignments {
        // Create a single ReadTeamchannelCollaboratorPortsToml that contains all collaborators for this pair
        let wrapper = ReadTeamchannelCollaboratorPortsToml {
            collaborator_ports: collaborator_assignments,
        };
        
        // Store it in a Vec (even though there's only one element, to match the expected type)
        corenode_format.insert(pair_name, vec![wrapper]);
    }
    
    println!(
        "Transformed {} collaborator pairs into CoreNode format",
        corenode_format.len()
    );
    
    Ok(corenode_format)
}

/// Reads collaborator port assignments from a clearsigned TOML file using a GPG key from a separate config file.
/// 
/// # Purpose
/// This function provides a way to verify and read port assignments from clearsigned TOML files
/// that don't contain their own GPG keys, instead using a key from a separate centralized config file.
/// This approach maintains consistent key management across multiple clearsigned files and is useful
/// when the team channel configuration files don't embed their own GPG keys.
/// 
/// # Security Model
/// This function enforces the same strict security requirements:
/// 1. Extracts the validation key from a separate config file
/// 2. Validates the target file's signature using that key
/// 3. No data is returned if signature validation fails
/// 4. Maintains complete chain of trust
/// 
/// # Process Flow
/// 1. Extracts the GPG public key from the specified config file
/// 2. Uses this key to verify the signature of the target clearsigned TOML file  
/// 3. If verification succeeds, reads the port assignments
/// 4. Transforms the data into CoreNode's expected format
/// 5. Returns the HashMap or an appropriate error
/// 
/// # Arguments
/// - `pathstr_to_config_file_that_contains_gpg_key` - Path to a clearsigned TOML file containing the GPG public key
/// - `pathstr_to_target_clearsigned_file` - Path to the clearsigned TOML file to read from (without its own GPG key)
/// - `addressbook_files_directory_relative` - Relative path to the directory containing collaborator addressbook files
/// 
/// # Returns
/// - `Ok(HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>)` - Port assignments in CoreNode format if verification succeeds
/// - `Err(String)` - Detailed error message if any step fails
/// 
/// # TOML Structure Expected
/// The target file should contain sections like:
/// ```toml
/// [[abstract_collaborator_port_assignments.alice_bob]]
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "alice"
/// ready_port = 62002
/// intray_port = 49595
/// gotit_port = 49879
/// 
/// [[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
/// user_name = "bob"
/// ready_port = 59980
/// intray_port = 52755
/// gotit_port = 60575
/// ```
/// 
/// # Example
/// ```no_run
/// let config_path = "security_config.toml";
/// let team_channel_file = "team_channel_config.toml";
/// 
/// let port_assignments = read_hashmap_corenode_ports_from_clearsigntoml_without_keyid(
///     config_path,
///     team_channel_file,
///     "collaborators"
/// )?;
/// 
/// // Use with translate_port_assignments
/// let role_based_ports = translate_port_assignments(
///     "alice",
///     "bob", 
///     port_assignments
/// )?;
/// ```
/// 
/// # Error Handling
/// Returns an error if:
/// - The config file cannot be read or doesn't contain a valid GPG key
/// - The target file cannot be read or its signature cannot be verified
/// - The port assignment structure is malformed or missing
/// - Any collaborator pair has invalid or incomplete port data
pub fn read_hashmap_corenode_ports_from_clearsigntoml_without_keyid(
    pathstr_to_config_file_that_contains_gpg_key: &str,
    pathstr_to_target_clearsigned_file: &str,
    addressbook_files_directory_relative: &str,
) -> Result<HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>, String> {
    // Step 1: Extract GPG key from the config file
    println!(
        "Extracting GPG key from config file: {}",
        pathstr_to_config_file_that_contains_gpg_key
    );
    
    let key = extract_gpg_key_from_clearsigntoml(
        pathstr_to_config_file_that_contains_gpg_key, 
        "gpg_key_public"
    )
    .map_err(|e| format!(
        "Failed to extract GPG key from config file '{}': {}", 
        pathstr_to_config_file_that_contains_gpg_key, 
        e
    ))?;

    // Step 2: Verify the target file using the extracted key
    println!(
        "Verifying signature of target file: {}",
        pathstr_to_target_clearsigned_file
    );
    
    let verification_result = verify_clearsign(
        pathstr_to_target_clearsigned_file, 
        &key
    )
    .map_err(|e| format!(
        "Failed during verification process for file '{}': {}", 
        pathstr_to_target_clearsigned_file,
        e
    ))?;

    // Step 3: Check verification result
    if !verification_result {
        return Err(format!(
            "GPG signature verification failed for file '{}' using key from '{}'",
            pathstr_to_target_clearsigned_file,
            pathstr_to_config_file_that_contains_gpg_key
        ));
    }

    println!("Signature verification passed, proceeding to read port assignments");

    // Step 4: Convert string path to Path for the existing function
    let target_path = Path::new(pathstr_to_target_clearsigned_file);
    
    // Step 5: Call the existing function to read and transform the port assignments
    match read_hashmap_corenode_ports_struct_from_clearsigntoml(
        target_path,
        addressbook_files_directory_relative,
    ) {
        Ok(port_assignments) => {
            println!(
                "Successfully read {} collaborator pair port assignments",
                port_assignments.len()
            );
            Ok(port_assignments)
        }
        Err(gpg_error) => {
            // Convert GpgError to String for consistent error type
            Err(format!(
                "Failed to read port assignments from verified file '{}': {}",
                pathstr_to_target_clearsigned_file,
                gpg_error.to_string()
            ))
        }
    }
}

#[cfg(test)]
mod test_corenode_port_readers {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_corenode_port_assignments_structure() {
        // This test verifies the structure matches what translate_port_assignments expects
        
        // Create a test TOML file with the exact structure from the sample
        let test_content = r#"
owner = "alice"

[[abstract_collaborator_port_assignments.alice_bob]]

[[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
user_name = "alice"
ready_port = 62002
intray_port = 49595
gotit_port = 49879

[[abstract_collaborator_port_assignments.alice_bob.collaborator_ports]]
user_name = "bob"
ready_port = 59980
intray_port = 52755
gotit_port = 60575

[[abstract_collaborator_port_assignments.alice_charlotte]]

[[abstract_collaborator_port_assignments.alice_charlotte.collaborator_ports]]
user_name = "alice"
ready_port = 50001
intray_port = 50002
gotit_port = 50003

[[abstract_collaborator_port_assignments.alice_charlotte.collaborator_ports]]
user_name = "charlotte"
ready_port = 50004
intray_port = 50005
gotit_port = 50006
"#;
        let test_file = "test_corenode_ports.toml";
        fs::write(test_file, test_content).unwrap();

        // Note: This would need GPG setup to actually test
        // For unit testing, we'd test the transformation logic separately
        
        // Cleanup
        fs::remove_file(test_file).unwrap();
    }
    
    #[test]
    fn test_wrapper_struct_usage() {
        // Test that ReadTeamchannelCollaboratorPortsToml works as expected
        let port1 = CollaboratorPortAssignment {
            user_name: "alice".to_string(),
            ready_port: 50001,
            intray_port: 50002,
            gotit_port: 50003,
        };
        
        let port2 = CollaboratorPortAssignment {
            user_name: "bob".to_string(),
            ready_port: 50004,
            intray_port: 50005,
            gotit_port: 50006,
        };
        
        let wrapper = ReadTeamchannelCollaboratorPortsToml {
            collaborator_ports: vec![port1.clone(), port2.clone()],
        };
        
        // Verify we can access the nested data as translate_port_assignments does
        assert_eq!(wrapper.collaborator_ports.len(), 2);
        assert_eq!(wrapper.collaborator_ports[0].user_name, "alice");
        assert_eq!(wrapper.collaborator_ports[1].user_name, "bob");
        
        // Test the HashMap structure
        let mut test_map: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();
        test_map.insert("alice_bob".to_string(), vec![wrapper]);
        
        // Simulate how translate_port_assignments accesses the data
        let meeting_room_ports = test_map.get("alice_bob").unwrap();
        for port_data in meeting_room_ports {
            for port_set in &port_data.collaborator_ports {
                if port_set.user_name == "alice" {
                    assert_eq!(port_set.ready_port, 50001);
                }
            }
        }
    }
}

/// gpgtoml


// old
// /// Returns a path to a temporary copy of a collaborator's addressbook file.
// ///
// /// # INPUT
// /// - `collaborator_name: &str` - Name of the collaborator (e.g., "alice")
// /// - `addressbook_files_directory_relative: &str` - Directory path relative to executable where addressbook files are stored
// /// - `gpg_full_fingerprint_key_id_string: &str` - Full 40-character GPG fingerprint for decryption
// ///
// /// # OUTPUT
// /// - Returns: `Result<(PathBuf, PathBuf), GpgError>`
// /// - On success: Two identical PathBuf values, both pointing to the SAME temporary file path
// /// - On error: GpgError describing what went wrong
// ///
// /// The returned PATH points to a temporary file in the system temp directory that:
// /// - Contains the addressbook content ready to read
// /// - Must be deleted by the caller after use
// /// - Is safe to delete (will never be an original file)
// ///
// /// # What This Function Does
// ///
// /// This function locates a collaborator's addressbook file (either .toml or .gpgtoml format)
// /// and creates a temporary copy that can be safely read and then deleted. For encrypted
// /// .gpgtoml files, the temporary copy contains the decrypted content. For .toml files,
// /// the temporary copy is an exact copy of the original.
// ///
// /// # IMPORTANT SECURITY NOTE
// ///
// /// This function does NOT perform GPG signature verification on .toml files.
// /// It does NOT validate that .toml files are properly clearsigned.
// /// It does NOT check if signatures are from trusted keys.
// /// It ONLY creates temporary copies for safe file handling.
// ///
// /// Creates a temporary copy of a collaborator's addressbook file for safe reading.
// ///
// /// This function locates a collaborator's addressbook file (either .toml or .gpgtoml format)
// /// and creates a temporary copy that can be safely read and then deleted. For encrypted
// /// .gpgtoml files, the temporary copy contains the decrypted content. For .toml files,
// /// the temporary copy is an exact copy of the original.
// ///
// /// # IMPORTANT SECURITY NOTE
// ///
// /// This function does NOT perform GPG signature verification on .toml files.
// /// It does NOT validate that .toml files are properly clearsigned.
// /// It does NOT check if signatures are from trusted keys.
// /// It ONLY creates temporary copies for safe file handling.
// ///
// /// If you need GPG signature verification, that must be done separately after reading the file.
// ///
// /// # What This Function Actually Does
// ///
// /// 1. Looks for {collaborator_name}__collaborator.toml (plain text, possibly clearsigned)
// /// 2. If not found, looks for {collaborator_name}__collaborator.gpgtoml (GPG encrypted)
// /// 3. Creates a temporary file in the system temp directory
// /// 4. For .toml: Copies the content to the temp file
// /// 5. For .gpgtoml: Decrypts the content to the temp file using GPG
// /// 6. Returns the path to the temporary file which must be deleted after use
// ///
// /// # Arguments
// ///
// /// - `collaborator_name` - The name of the collaborator. Used to construct filenames.
// ///                        Must not be empty.
// ///
// /// - `addressbook_files_directory_relative` - The directory path (relative to executable)
// ///                                           where addressbook files are stored.
// ///                                           Must not be empty.
// ///
// /// - `gpg_full_fingerprint_key_id_string` - The full GPG fingerprint for decryption.
// ///                                          Only used if a .gpgtoml file is found.
// ///                                          Must not be empty.
// ///
// /// # Returns
// ///
// /// Returns `Result<(PathBuf, PathBuf), GpgError>` where both PathBuf values are identical
// /// and point to the same temporary file. This redundancy emphasizes that the file is
// /// temporary and must be cleaned up.
// ///
// /// The temporary file will be in the system temp directory with a name like:
// /// `temp_addressbook_copy_{collaborator}_{timestamp}.toml`
// ///
// /// # Errors
// ///
// /// - `GpgError::ValidationError` - If any input parameter is empty or if neither
// ///                                .toml nor .gpgtoml file exists
// /// - `GpgError::PathError` - If path resolution to absolute paths fails  
// /// - `GpgError::FileSystemError` - If reading the original file fails
// /// - `GpgError::TempFileError` - If creating or writing the temp file fails
// /// - `GpgError::GpgOperationError` - If GPG decryption fails (only for .gpgtoml files)
// ///
// /// # Temporary File Cleanup
// ///
// /// The caller MUST delete the returned temporary file after use. Use the
// /// `cleanup_temp_addressbook_file()` function for safe cleanup.
// ///
// /// If this function returns an error after creating a temp file, the temp file
// /// is automatically cleaned up.
// ///
// /// # Example Usage
// ///
// /// ```rust
// /// // Get a temporary copy of the addressbook file
// /// let temp_file_path = get_temp_copy_of_addressbook_toml_or_decrypt_gpgtoml(
// ///     "alice",
// ///     "config/addressbooks",
// ///     "1234567890ABCDEF1234567890ABCDEF12345678"
// /// )?;
// ///
// /// // Read from the temporary file
// /// let content = std::fs::read_to_string(&temp_file_path)?;
// ///
// /// // IMPORTANT: Clean up the temporary file
// /// cleanup_temp_addressbook_file(&temp_file_path)?;
// /// ```
// pub fn get_addressbook_path_to_temp_readcopy_of_toml_or_decrypt_gpgtoml(
//     collaborator_name: &str,
//     addressbook_files_directory_relative: &str,
//     gpg_full_fingerprint_key_id_string: &str,
// ) -> Result<PathBuf, GpgError> {
    
//     // TODO add 2x retry after maybe .3 sec?
//     //     to make read-copy of file
//     // maybe use...standard temp dir to be deleted routinely?
    
//     // new version get_path_to_temp_readcopy_of_toml_or_decrypt_gpgtoml
//     // not formatting for name-in-file-name{}
                
//     // Validate input parameters before proceeding
//     if collaborator_name.is_empty() {
//         return Err(GpgError::ValidationError(
//             "Collaborator name cannot be empty".to_string()
//         ));
//     }
    
//     if gpg_full_fingerprint_key_id_string.is_empty() {
//         return Err(GpgError::ValidationError(
//             "GPG fingerprint key ID cannot be empty".to_string()
//         ));
//     }
    
//     // Step 1: Construct relative paths for both possible file types
//     // Using the pattern: {collaborator_name}__collaborator.{extension}
//     let toml_filename = format!("{}__collaborator.toml", collaborator_name);
//     let gpgtoml_filename = format!("{}__collaborator.gpgtoml", collaborator_name);
    
//     let toml_relative_path = Path::new(addressbook_files_directory_relative)
//         .join(&toml_filename);
//     let gpgtoml_relative_path = Path::new(addressbook_files_directory_relative)
//         .join(&gpgtoml_filename);
    
//     // Step 2: Convert relative paths to absolute paths using the provided helper function
//     let toml_absolute_path = make_input_path_name_abs_executabledirectoryrelative_nocheck(&toml_relative_path)
//         .map_err(|e| GpgError::PathError(
//             format!("Failed to create absolute path for .toml file '{}': {}", toml_filename, e)
//         ))?;
    
//     let gpgtoml_absolute_path = make_input_path_name_abs_executabledirectoryrelative_nocheck(&gpgtoml_relative_path)
//         .map_err(|e| GpgError::PathError(
//             format!("Failed to create absolute path for .gpgtoml file '{}': {}", gpgtoml_filename, e)
//         ))?;
    
//     // Variable to track temporary file for cleanup on error
//     let mut temp_file_created: Option<PathBuf> = None;
    
//     // Use a closure to ensure cleanup on any error after temp file creation
//     let create_temp_result = (|| -> Result<PathBuf, GpgError> {
//         // Generate unique temporary filename using timestamp
//         let timestamp_nanos = std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .map_err(|e| GpgError::TempFileError(
//                 format!("Failed to get system time for temp file creation: {}", e)
//             ))?
//             .as_nanos();
        
//         // Create temporary filename with collaborator name and timestamp for uniqueness
//         // Use .toml extension regardless of source type for consistency
//         let temp_filename = format!("collab_addressbook_{}_{}.toml", collaborator_name, timestamp_nanos);
//         let temp_file_path = std::env::temp_dir().join(&temp_filename);
        
//         println!("ROCST: Creating temporary file for addressbook content: {:?}", temp_file_path);
        
//         // Step 3: Check which source file exists and create appropriate temporary copy
//         if toml_absolute_path.exists() {
//             // Case 1: Clearsigned .toml file exists - create a temporary copy
//             println!("ROCST: Found clearsigned .toml file for collaborator '{}' at path: {:?}", 
//                        collaborator_name, toml_absolute_path);
//             println!("ROCST: Creating temporary copy to ensure original file safety");
            
//             // Read the original file content
//             let original_content = std::fs::read(&toml_absolute_path)
//                 .map_err(|e| GpgError::FileSystemError(
//                     std::io::Error::new(
//                         std::io::ErrorKind::Other,
//                         format!("Failed to read original .toml file '{}': {}", toml_absolute_path.display(), e)
//                     )
//                 ))?;
            
//             // Create the temporary file with restricted permissions
//             #[cfg(unix)]
//             {
//                 use std::os::unix::fs::OpenOptionsExt;
//                 use std::io::Write;
                
//                 // Create file with restricted permissions atomically
//                 let mut temp_file = std::fs::OpenOptions::new()
//                     .create(true)
//                     .write(true)
//                     .truncate(true)
//                     .mode(0o600)  // Owner read/write only
//                     .open(&temp_file_path)
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to create secure temporary file '{}': {}", temp_filename, e)
//                     ))?;
                
//                 // Mark that we've created a temp file that needs cleanup on error
//                 temp_file_created = Some(temp_file_path.clone());
                
//                 // Write the content to the temporary file
//                 temp_file.write_all(&original_content)
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to write content to temporary file: {}", e)
//                     ))?;
                
//                 temp_file.flush()
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to flush temporary file: {}", e)
//                     ))?;
//             }
            
//             #[cfg(not(unix))]
//             {
//                 // On non-Unix systems, create file normally then write content
//                 std::fs::write(&temp_file_path, &original_content)
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to create temporary file '{}': {}", temp_filename, e)
//                     ))?;
                
//                 temp_file_created = Some(temp_file_path.clone());
//             }
            
//             println!("ROCST: Successfully created temporary copy of .toml file");
            
//         } else if gpgtoml_absolute_path.exists() {
//             // Case 2: Encrypted .gpgtoml file exists - decrypt to temporary file
//             println!("ROCST: Found encrypted .gpgtoml file for collaborator '{}' at path: {:?}", 
//                        collaborator_name, gpgtoml_absolute_path);
            
//             // Create empty temporary file with restricted permissions first
//             #[cfg(unix)]
//             {
//                 use std::os::unix::fs::OpenOptionsExt;
                
//                 // Create file with restricted permissions atomically
//                 std::fs::OpenOptions::new()
//                     .create(true)
//                     .write(true)
//                     .truncate(true)
//                     .mode(0o600)  // Owner read/write only
//                     .open(&temp_file_path)
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to create secure temporary file '{}': {}", temp_filename, e)
//                     ))?;
                
//                 // Mark that we've created a temp file that needs cleanup on error
//                 temp_file_created = Some(temp_file_path.clone());
//             }
            
//             #[cfg(not(unix))]
//             {
//                 // On non-Unix systems, just create the file
//                 std::fs::File::create(&temp_file_path)
//                     .map_err(|e| GpgError::TempFileError(
//                         format!("Failed to create temporary file '{}': {}", temp_filename, e)
//                     ))?;
                
//                 temp_file_created = Some(temp_file_path.clone());
//             }
            
//             // Execute GPG to decrypt the .gpgtoml file into our temporary file
//             println!("ROCST: Executing GPG to decrypt {} to temporary file {}", 
//                        gpgtoml_absolute_path.display(), temp_file_path.display());
            
//             let gpg_output = std::process::Command::new("gpg")
//                 .arg("--quiet")                          // Suppress informational messages
//                 .arg("--batch")                          // Non-interactive mode
//                 .arg("--yes")                            // Automatically answer yes to prompts
//                 .arg("--local-user")                     // Specify which key to use
//                 .arg(gpg_full_fingerprint_key_id_string)
//                 .arg("--decrypt")                        // Decrypt operation
//                 .arg("--output")                         // Output file
//                 .arg(&temp_file_path)
//                 .arg(&gpgtoml_absolute_path)             // Input file
//                 .output()
//                 .map_err(|e| {
//                     let error_msg = format!(
//                         "Failed to execute GPG decrypt command for collaborator '{}': {}", 
//                         collaborator_name, e
//                     );
//                     eprintln!("\nERROR: {}", error_msg);
//                     eprintln!("Press Enter to continue...");
//                     let _ = std::io::stdin().read_line(&mut String::new());
//                     GpgError::GpgOperationError(error_msg)
//                 })?;
            
//             // Check if GPG decryption was successful
//             if !gpg_output.status.success() {
//                 let stderr_text = String::from_utf8_lossy(&gpg_output.stderr);
//                 let error_msg = format!(
//                     "GPG decryption failed for collaborator '{}' file '{}': {}", 
//                     collaborator_name, gpgtoml_absolute_path.display(), stderr_text
//                 );
//                 eprintln!("\nERROR: {}", error_msg);
//                 eprintln!("Press Enter to continue...");
//                 let _ = std::io::stdin().read_line(&mut String::new());
//                 return Err(GpgError::GpgOperationError(error_msg));
//             }
            
//             println!("ROCST: Successfully decrypted .gpgtoml file to temporary file");
            
//         } else {
//             // Case 3: Neither file exists - this is an error
//             return Err(GpgError::ValidationError(format!(
//                 "No addressbook file found for collaborator '{}'. Checked for both '{}' and '{}' in directory '{}'",
//                 collaborator_name, toml_filename, gpgtoml_filename, addressbook_files_directory_relative
//             )));
//         }
        
//         // Return the temporary file path TWICE - both values are the same temp file
//         // This makes it crystal clear that this is a temporary file safe to delete
//         Ok(temp_file_path)
//     })();
    
//     // If any error occurred and we created a temp file, clean it up before propagating error
//     match create_temp_result {
//         Ok(result) => {
//             println!("ROCST: Successfully prepared temporary addressbook file: {:?}", result);
//             Ok(result)
//         },
//         Err(e) => {
//             // Clean up temporary file if it was created
//             if let Some(temp_path) = temp_file_created {
//                 println!("ROCST: Error occurred, cleaning up temporary file: {:?}", temp_path);
//                 let _ = std::fs::remove_file(&temp_path); // Ignore cleanup errors
//             }
//             Err(e)
//         }
//     }
// }


/// Returns a path to a temporary copy of a collaborator's addressbook file.
///
/// # INPUT
/// - `collaborator_name: &str` - Name of the collaborator (e.g., "alice")
/// - `addressbook_files_directory_relative: &str` - Directory path relative to executable where addressbook files are stored
/// - `gpg_full_fingerprint_key_id_string: &str` - Full 40-character GPG fingerprint for decryption
///
/// # OUTPUT
/// - Returns: `Result<PathBuf, GpgError>`
/// - On success: PathBuf pointing to the temporary file path
/// - On error: GpgError describing what went wrong
///
/// The returned PATH points to a temporary file in the system temp directory that:
/// - Contains the addressbook content ready to read
/// - Must be deleted by the caller after use
/// - Is safe to delete (will never be an original file)
///
/// # What This Function Does
///
/// This function locates a collaborator's addressbook file (either .toml or .gpgtoml format)
/// and creates a temporary copy that can be safely read and then deleted. For encrypted
/// .gpgtoml files, the temporary copy contains the decrypted content. For .toml files,
/// the temporary copy is an exact copy of the original.
///
/// # FILE COPY RETRY MECHANISM
///
/// When copying .toml files, the function will attempt the copy operation up to 2 times
/// with a 300ms delay between attempts. This handles cases where another process might
/// temporarily have the file open for reading.
///
/// # IMPORTANT SECURITY NOTE
///
/// This function does NOT perform GPG signature verification on .toml files.
/// It does NOT validate that .toml files are properly clearsigned.
/// It does NOT check if signatures are from trusted keys.
/// It ONLY creates temporary copies for safe file handling.
///
/// Creates a temporary copy of a collaborator's addressbook file for safe reading.
///
/// This function locates a collaborator's addressbook file (either .toml or .gpgtoml format)
/// and creates a temporary copy that can be safely read and then deleted. For encrypted
/// .gpgtoml files, the temporary copy contains the decrypted content. For .toml files,
/// the temporary copy is an exact copy of the original.
///
/// # IMPORTANT SECURITY NOTE
///
/// This function does NOT perform GPG signature verification on .toml files.
/// It does NOT validate that .toml files are properly clearsigned.
/// It does NOT check if signatures are from trusted keys.
/// It ONLY creates temporary copies for safe file handling.
///
/// If you need GPG signature verification, that must be done separately after reading the file.
///
/// # What This Function Actually Does
///
/// 1. Looks for {collaborator_name}__collaborator.toml (plain text, possibly clearsigned)
/// 2. If not found, looks for {collaborator_name}__collaborator.gpgtoml (GPG encrypted)
/// 3. Creates a temporary file in the system temp directory
/// 4. For .toml: Copies the content to the temp file (with up to 2 retry attempts)
/// 5. For .gpgtoml: Decrypts the content to the temp file using GPG
/// 6. Returns the path to the temporary file which must be deleted after use
///
/// # Arguments
///
/// - `collaborator_name` - The name of the collaborator. Used to construct filenames.
///                        Must not be empty.
///
/// - `addressbook_files_directory_relative` - The directory path (relative to executable)
///                                           where addressbook files are stored.
///                                           Must not be empty.
///
/// - `gpg_full_fingerprint_key_id_string` - The full GPG fingerprint for decryption.
///                                          Only used if a .gpgtoml file is found.
///                                          Must not be empty.
///
/// # Returns
///
/// Returns `Result<PathBuf, GpgError>` where the PathBuf points to a temporary file.
/// This temporary file must be cleaned up by the caller after use.
///
/// The temporary file will be in the system temp directory with a name like:
/// `collab_addressbook_{collaborator}_{timestamp}.toml`
///
/// # Errors
///
/// - `GpgError::ValidationError` - If any input parameter is empty or if neither
///                                .toml nor .gpgtoml file exists
/// - `GpgError::PathError` - If path resolution to absolute paths fails  
/// - `GpgError::FileSystemError` - If reading the original file fails after retry attempts
/// - `GpgError::TempFileError` - If creating or writing the temp file fails after retry attempts
/// - `GpgError::GpgOperationError` - If GPG decryption fails (only for .gpgtoml files)
///
/// # Temporary File Cleanup
///
/// The caller MUST delete the returned temporary file after use. Use the
/// `cleanup_temp_addressbook_file()` function for safe cleanup.
///
/// If this function returns an error after creating a temp file, the temp file
/// is automatically cleaned up.
///
/// # Example Usage
///
/// ```rust
/// // Get a temporary copy of the addressbook file
/// let temp_file_path = get_addressbook_path_to_temp_readcopy_of_toml_or_decrypt_gpgtoml(
///     "alice",
///     "config/addressbooks",
///     "1234567890ABCDEF1234567890ABCDEF12345678"
/// )?;
///
/// // Read from the temporary file
/// let content = std::fs::read_to_string(&temp_file_path)?;
///
/// // IMPORTANT: Clean up the temporary file
/// cleanup_temp_addressbook_file(&temp_file_path)?;
/// ```
pub fn get_addressbook_path_to_temp_readcopy_of_toml_or_decrypt_gpgtoml(
    collaborator_name: &str,
    addressbook_files_directory_relative: &str,
    gpg_full_fingerprint_key_id_string: &str,
) -> Result<PathBuf, GpgError> {
    
    // Validate input parameters before proceeding
    if collaborator_name.is_empty() {
        return Err(GpgError::ValidationError(
            "Collaborator name cannot be empty".to_string()
        ));
    }
    
    if gpg_full_fingerprint_key_id_string.is_empty() {
        return Err(GpgError::ValidationError(
            "GPG fingerprint key ID cannot be empty".to_string()
        ));
    }
    
    // Step 1: Construct relative paths for both possible file types
    // Using the pattern: {collaborator_name}__collaborator.{extension}
    let toml_filename = format!("{}__collaborator.toml", collaborator_name);
    let gpgtoml_filename = format!("{}__collaborator.gpgtoml", collaborator_name);
    
    let toml_relative_path = Path::new(addressbook_files_directory_relative)
        .join(&toml_filename);
    let gpgtoml_relative_path = Path::new(addressbook_files_directory_relative)
        .join(&gpgtoml_filename);
    
    // Step 2: Convert relative paths to absolute paths using the provided helper function
    let toml_absolute_path = make_input_path_name_abs_executabledirectoryrelative_nocheck(&toml_relative_path)
        .map_err(|e| GpgError::PathError(
            format!("Failed to create absolute path for .toml file '{}': {}", toml_filename, e)
        ))?;
    
    let gpgtoml_absolute_path = make_input_path_name_abs_executabledirectoryrelative_nocheck(&gpgtoml_relative_path)
        .map_err(|e| GpgError::PathError(
            format!("Failed to create absolute path for .gpgtoml file '{}': {}", gpgtoml_filename, e)
        ))?;
    
    // Variable to track temporary file for cleanup on error
    let mut temp_file_created: Option<PathBuf> = None;
    
    // Use a closure to ensure cleanup on any error after temp file creation
    let create_temp_result = (|| -> Result<PathBuf, GpgError> {
        // Generate unique temporary filename using timestamp
        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GpgError::TempFileError(
                format!("Failed to get system time for temp file creation: {}", e)
            ))?
            .as_nanos();
        
        // Create temporary filename with collaborator name and timestamp for uniqueness
        // Use .toml extension regardless of source type for consistency
        let temp_filename = format!("collab_addressbook_{}_{}.toml", collaborator_name, timestamp_nanos);
        let temp_file_path = std::env::temp_dir().join(&temp_filename);
        
        println!("ROCST: Creating temporary file for addressbook content: {:?}", temp_file_path);
        
        // Step 3: Check which source file exists and create appropriate temporary copy
        if toml_absolute_path.exists() {
            // Case 1: Clearsigned .toml file exists - create a temporary copy
            println!("ROCST: Found clearsigned .toml file for collaborator '{}' at path: {:?}", 
                       collaborator_name, toml_absolute_path);
            println!("ROCST: Creating temporary copy to ensure original file safety");
            
            // Read the original file content with retry mechanism
            // We'll try up to 2 times with a 300ms delay between attempts
            let mut original_content = Vec::new();
            let max_retry_attempts = 2;
            let retry_delay_millis = 300;
            let mut last_read_error = None;
            
            for attempt in 1..=max_retry_attempts {
                println!("ROCST: Attempting to read original file (attempt {} of {})", attempt, max_retry_attempts);
                
                match std::fs::read(&toml_absolute_path) {
                    Ok(content) => {
                        // Successfully read the file
                        original_content = content;
                        println!("ROCST: Successfully read original file on attempt {}", attempt);
                        break;
                    }
                    Err(e) => {
                        // Failed to read file
                        last_read_error = Some(e);
                        
                        if attempt < max_retry_attempts {
                            // Not the last attempt, wait and retry
                            println!("ROCST: Failed to read file on attempt {}: {}. Waiting {}ms before retry...", 
                                       attempt, last_read_error.as_ref().unwrap(), retry_delay_millis);
                            std::thread::sleep(std::time::Duration::from_millis(retry_delay_millis));
                        } else {
                            // Final attempt failed
                            println!("ROCST: Failed to read file after {} attempts", max_retry_attempts);
                        }
                    }
                }
            }
            
            // Check if we successfully read the file
            if original_content.is_empty() && last_read_error.is_some() {
                // All attempts failed
                return Err(GpgError::FileSystemError(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to read original .toml file '{}' after {} attempts: {}", 
                                toml_absolute_path.display(), max_retry_attempts, last_read_error.unwrap())
                    )
                ));
            }
            
            // Create the temporary file with restricted permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                use std::io::Write;
                
                // Write to temporary file with retry mechanism
                let mut write_success = false;
                let mut last_write_error = None;
                
                for attempt in 1..=max_retry_attempts {
                    println!("ROCST: Attempting to write to temporary file (attempt {} of {})", attempt, max_retry_attempts);
                    
                    // Try to create and write to the file
                    let write_result = (|| -> Result<(), std::io::Error> {
                        // Create file with restricted permissions atomically
                        let mut temp_file = std::fs::OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .mode(0o600)  // Owner read/write only
                            .open(&temp_file_path)?;
                        
                        // Mark that we've created a temp file that needs cleanup on error
                        if attempt == 1 {
                            temp_file_created = Some(temp_file_path.clone());
                        }
                        
                        // Write the content to the temporary file
                        temp_file.write_all(&original_content)?;
                        
                        // Ensure all data is written to disk
                        temp_file.flush()?;
                        
                        Ok(())
                    })();
                    
                    match write_result {
                        Ok(()) => {
                            // Successfully wrote the file
                            write_success = true;
                            println!("ROCST: Successfully wrote temporary file on attempt {}", attempt);
                            break;
                        }
                        Err(e) => {
                            // Failed to write file
                            last_write_error = Some(e);
                            
                            if attempt < max_retry_attempts {
                                // Not the last attempt, wait and retry
                                println!("ROCST: Failed to write temporary file on attempt {}: {}. Waiting {}ms before retry...", 
                                           attempt, last_write_error.as_ref().unwrap(), retry_delay_millis);
                                std::thread::sleep(std::time::Duration::from_millis(retry_delay_millis));
                                
                                // Clean up the failed temp file before retry
                                let _ = std::fs::remove_file(&temp_file_path);
                            } else {
                                // Final attempt failed
                                println!("ROCST: Failed to write temporary file after {} attempts", max_retry_attempts);
                            }
                        }
                    }
                }
                
                if !write_success && last_write_error.is_some() {
                    // All attempts failed
                    return Err(GpgError::TempFileError(
                        format!("Failed to write content to temporary file after {} attempts: {}", 
                                max_retry_attempts, last_write_error.unwrap())
                    ));
                }
            }
            
            #[cfg(not(unix))]
            {
                // On non-Unix systems, create file normally then write content with retry
                let mut write_success = false;
                let mut last_write_error = None;
                
                for attempt in 1..=max_retry_attempts {
                    println!("ROCST: Attempting to write to temporary file (attempt {} of {})", attempt, max_retry_attempts);
                    
                    match std::fs::write(&temp_file_path, &original_content) {
                        Ok(()) => {
                            // Successfully wrote the file
                            write_success = true;
                            if attempt == 1 {
                                temp_file_created = Some(temp_file_path.clone());
                            }
                            println!("ROCST: Successfully wrote temporary file on attempt {}", attempt);
                            break;
                        }
                        Err(e) => {
                            // Failed to write file
                            last_write_error = Some(e);
                            
                            if attempt < max_retry_attempts {
                                // Not the last attempt, wait and retry
                                println!("ROCST: Failed to write temporary file on attempt {}: {}. Waiting {}ms before retry...", 
                                           attempt, last_write_error.as_ref().unwrap(), retry_delay_millis);
                                std::thread::sleep(std::time::Duration::from_millis(retry_delay_millis));
                                
                                // Clean up the failed temp file before retry
                                let _ = std::fs::remove_file(&temp_file_path);
                            } else {
                                // Final attempt failed
                                println!("ROCST: Failed to write temporary file after {} attempts", max_retry_attempts);
                            }
                        }
                    }
                }
                
                if !write_success && last_write_error.is_some() {
                    // All attempts failed
                    return Err(GpgError::TempFileError(
                        format!("Failed to create temporary file '{}' after {} attempts: {}", 
                                temp_filename, max_retry_attempts, last_write_error.unwrap())
                    ));
                }
            }
            
            println!("ROCST: Successfully created temporary copy of .toml file");
            
        } else if gpgtoml_absolute_path.exists() {
            // Case 2: Encrypted .gpgtoml file exists - decrypt to temporary file
            println!("ROCST: Found encrypted .gpgtoml file for collaborator '{}' at path: {:?}", 
                       collaborator_name, gpgtoml_absolute_path);
            
            // Create empty temporary file with restricted permissions first
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                
                // Create file with restricted permissions atomically
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)  // Owner read/write only
                    .open(&temp_file_path)
                    .map_err(|e| GpgError::TempFileError(
                        format!("Failed to create secure temporary file '{}': {}", temp_filename, e)
                    ))?;
                
                // Mark that we've created a temp file that needs cleanup on error
                temp_file_created = Some(temp_file_path.clone());
            }
            
            #[cfg(not(unix))]
            {
                // On non-Unix systems, just create the file
                std::fs::File::create(&temp_file_path)
                    .map_err(|e| GpgError::TempFileError(
                        format!("Failed to create temporary file '{}': {}", temp_filename, e)
                    ))?;
                
                temp_file_created = Some(temp_file_path.clone());
            }
            
            // Execute GPG to decrypt the .gpgtoml file into our temporary file
            // Note: GPG operations are not retried as they typically either work or fail definitively
            println!("ROCST: Executing GPG to decrypt {} to temporary file {}", 
                       gpgtoml_absolute_path.display(), temp_file_path.display());
            
            let gpg_output = std::process::Command::new("gpg")
                .arg("--quiet")                          // Suppress informational messages
                .arg("--batch")                          // Non-interactive mode
                .arg("--yes")                            // Automatically answer yes to prompts
                .arg("--local-user")                     // Specify which key to use
                .arg(gpg_full_fingerprint_key_id_string)
                .arg("--decrypt")                        // Decrypt operation
                .arg("--output")                         // Output file
                .arg(&temp_file_path)
                .arg(&gpgtoml_absolute_path)             // Input file
                .output()
                .map_err(|e| {
                    let error_msg = format!(
                        "Failed to execute GPG decrypt command for collaborator '{}': {}", 
                        collaborator_name, e
                    );
                    eprintln!("\nERROR: {}", error_msg);
                    eprintln!("Press Enter to continue...");
                    let _ = std::io::stdin().read_line(&mut String::new());
                    GpgError::GpgOperationError(error_msg)
                })?;
            
            // Check if GPG decryption was successful
            if !gpg_output.status.success() {
                let stderr_text = String::from_utf8_lossy(&gpg_output.stderr);
                let error_msg = format!(
                    "GPG decryption failed for collaborator '{}' file '{}': {}", 
                    collaborator_name, gpgtoml_absolute_path.display(), stderr_text
                );
                eprintln!("\nERROR: {}", error_msg);
                eprintln!("Press Enter to continue...");
                let _ = std::io::stdin().read_line(&mut String::new());
                return Err(GpgError::GpgOperationError(error_msg));
            }
            
            println!("ROCST: Successfully decrypted .gpgtoml file to temporary file");
            
        } else {
            // Case 3: Neither file exists - this is an error
            return Err(GpgError::ValidationError(format!(
                "No addressbook file found for collaborator '{}'. Checked for both '{}' and '{}' in directory '{}'",
                collaborator_name, toml_filename, gpgtoml_filename, addressbook_files_directory_relative
            )));
        }
        
        // Return the temporary file path
        Ok(temp_file_path)
    })();
    
    // If any error occurred and we created a temp file, clean it up before propagating error
    match create_temp_result {
        Ok(result) => {
            println!("ROCST: Successfully prepared temporary addressbook file: {:?}", result);
            Ok(result)
        },
        Err(e) => {
            // Clean up temporary file if it was created
            if let Some(temp_path) = temp_file_created {
                println!("ROCST: Error occurred, cleaning up temporary file: {:?}", temp_path);
                let _ = std::fs::remove_file(&temp_path); // Ignore cleanup errors
            }
            Err(e)
        }
    }
}

/// Safely removes a temporary file created during addressbook file processing.
///
/// This function should be called to clean up temporary files created by
/// `get_path_to_validated_addressbook_toml_or_gpgtoml()`. It includes safety checks
/// to ensure only temporary files are deleted.
///
/// # CRITICAL SAFETY DESIGN
///
/// This function includes a safety check to verify that the file being deleted is actually
/// in the system temporary directory. This prevents accidental deletion of original addressbook
/// files if the API is misused.
///
/// # Arguments
///
/// - `temp_file_path` - The absolute path to the temporary file to remove.
///                      This should be one of the paths returned by
///                      `get_path_to_validated_addressbook_toml_or_gpgtoml()`.
///
/// # Returns
///
/// Returns `Result<(), GpgError>` indicating success or failure of the cleanup operation.
///
/// # Errors
///
/// Returns `GpgError::TempFileError` if:
/// - The file path is not in the system temporary directory (safety check failed)
/// - The file exists but cannot be removed due to permissions or file system errors
/// - The path is invalid or inaccessible
///
/// Note: If the file doesn't exist, this function returns `Ok(())` as the goal
/// of cleanup is already achieved.
///
/// # Security Considerations
///
/// - Verifies the file is in the temp directory before deletion as a safety measure
/// - Always call this function in a `finally` pattern or before returning from your function
/// - Temporary files may contain decrypted sensitive data and must not be left on disk
/// - Even if this function returns an error, the program should continue (log the error)
///
/// # Examples
///
/// ```rust
/// // Safe cleanup pattern - the file is always a temp file from our function
/// let (temp_file_path, _) = get_path_to_validated_addressbook_toml_or_gpgtoml(...)?;
/// 
/// // Use the file...
/// let content = std::fs::read_to_string(&temp_file_path)?;
/// 
/// // Always cleanup - this is always safe because our function only returns temp files
/// if let Err(e) = cleanup_collaborator_temp_file(&temp_file_path) {
///     eprintln!("Warning: Failed to cleanup temporary file: {}", e);
///     // Continue despite cleanup failure
/// }
/// ```
pub fn cleanup_collaborator_temp_file(temp_file_path: &Path) -> Result<(), GpgError> {
    println!("ROCST: Attempting to clean up temporary file: {:?}", temp_file_path);
    
    // CRITICAL SAFETY CHECK: Verify this file is actually in the temp directory
    // This prevents accidental deletion of original addressbook files
    let temp_dir = std::env::temp_dir();
    let canonical_temp_path = temp_file_path
        .canonicalize()
        .map_err(|e| GpgError::TempFileError(
            format!("Failed to canonicalize temp file path '{}': {}", temp_file_path.display(), e)
        ))?;
    
    // Check if the file path starts with the temp directory path
    if !canonical_temp_path.starts_with(&temp_dir) {
        let error_msg = format!(
            "SAFETY VIOLATION: Refusing to delete file '{}' - not in temp directory '{}'",
            canonical_temp_path.display(), temp_dir.display()
        );
        eprintln!("ERROR: {}", error_msg);
        return Err(GpgError::TempFileError(error_msg));
    }
    
    // Check if the file exists before attempting removal
    if canonical_temp_path.exists() {
        // Attempt to remove the file
        std::fs::remove_file(&canonical_temp_path)
            .map_err(|e| {
                let error_msg = format!(
                    "Failed to remove temporary file '{}': {}. File may contain sensitive decrypted data.",
                    canonical_temp_path.display(), e
                );
                eprintln!("WARNING: {}", error_msg);
                GpgError::TempFileError(error_msg)
            })?;
        
        println!("ROCST: Successfully removed temporary file");
        Ok(())
    } else {
        // File doesn't exist - this is actually fine, our goal is achieved
        println!("ROCST: Temporary file does not exist, no cleanup needed: {:?}", canonical_temp_path);
        Ok(())
    }
}