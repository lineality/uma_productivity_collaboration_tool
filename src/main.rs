/*
Uma
2024.09-11
Uma Productivity Collaboration Tools for Project-Alignment 
https://github.com/lineality/uma_productivity_collaboration_tool
In memory of Eleanor Th. Vadala 1923-2023: aviator, astronomer, engineer, pioneer, leader, friend. 

cargo.toml ->

[package]
name = "uma"
version = "0.1.0"
edition = "2021"

[dependencies]
walkdir = "2.5.0"
toml = "0.8.19"
serde = { version = "1.0.210", features = ["derive"] }
rand = "0.8.5"
getifaddrs = "0.1.4"

https://docs.rs/getifaddrs/latest/getifaddrs/


// tiny_tui_module.rs
pub mod tiny_tui {
    use std::path::Path;

    pub fn render_list(list: &Vec<String>, current_path: &Path) {
        // 1. Get the path components
        let path_components: Vec<_> = current_path.components().collect();

        // 2. Display the path, skipping the first two components 
        if path_components.len() > 2 {
            let relevant_path = path_components[2..].iter()
                .map(|c| c.as_os_str().to_string_lossy()) 
                .collect::<Vec<_>>()
                .join("/");
            println!("Current Path: /{}", relevant_path); 
        } else {
            println!("Select a Team-Channel (by number):"); // Home directory (root) 
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }

    pub fn get_input() -> Result<String, std::io::Error> {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}

*/

// Set debug flag (future: add time stamp with 24 check)
const DEBUG_FLAG: bool = true;

// use std::sync::mpsc;
use std::io;
use std::io::{
    Error,
    ErrorKind,
    Write,
    // Read,
};
use std::process::Stdio;
use std::error::Error as StdError; 
use walkdir::WalkDir;
use std::path::Path;
use std::path::{
    PathBuf,
};
use std::time::{
    SystemTime, 
    UNIX_EPOCH,
    // Instant,
};

use std::fs;
use std::fs::{
    File,
    remove_file,
    create_dir_all,
    OpenOptions,
    read_to_string,
    write,
    remove_dir_all,
    read_dir,
};
use toml;
use toml::Value;
use serde::{
    Deserialize,
    Serialize,
    
};

use std::ffi::OsStr;
use std::collections::HashMap;
use std::collections::HashSet;
// use std::sync::mpsc::channel;
// use std::sync::mpsc::Sender;

use std::process::Command;
// use std::sync::mpsc;

// For Sync
use rand::prelude::{
    // SliceRandom,
    // IteratorRandom,
    Rng,
};

use std::thread;
use std::num::ParseIntError;
use std::time::Duration;
use std::net::{
    IpAddr, 
    Ipv4Addr, 
    Ipv6Addr,
    TcpListener,
    // TcpStream,
    SocketAddr,
    UdpSocket,
};
// https://docs.rs/getifaddrs/latest/getifaddrs/
use getifaddrs::{getifaddrs, InterfaceFlags};

// For TUI
mod tiny_tui_module;
use tiny_tui_module::tiny_tui;

const CONTINUE_UMA_PATH: &str = "project_graph_data/session_state_items/continue_uma.txt";
const HARD_RESTART_FLAG_PATH: &str = "project_graph_data/session_state_items/yes_hard_restart_flag.txt";
const SYNC_START_OK_FLAG_PATH: &str = "project_graph_data/session_state_items/ok_to_start_sync_flag.txt";

/// utility: Gets a list of all IPv4 and IPv6 addresses associated with the current system's network interfaces.
///
/// Returns:
/// - `Ok(Vec<IpAddr>)`: A vector of IP addresses on success.
/// - `Err(io::Error)`: An error if obtaining network interface information fails.
/// From: https://docs.rs/getifaddrs/latest/getifaddrs/
/// use getifaddrs::{getifaddrs, InterfaceFlags};
fn get_local_ip_addresses() -> Result<Vec<IpAddr>, std::io::Error> {
    // https://docs.rs/getifaddrs/latest/getifaddrs/
    
    // Test Print in Debug Log
    for interface in getifaddrs()? {
        debug_log("fn get_local_ip_addresses() -> std::io::Result<()> {");
        debug_log!("Interface: {}", interface.name);
        debug_log!("  Address: {}", interface.address);
        if let Some(netmask) = interface.netmask {
            debug_log!("  Netmask: {}", netmask);
        }
        debug_log!("  Flags: {:?}", interface.flags);
        if interface.flags.contains(InterfaceFlags::UP) {
            debug_log!("  Status: Up");
        } else {
            debug_log!("  Status: Down");
        }
        debug_log!();
    }

    let mut addresses = Vec::new();

    for interface in getifaddrs()? {
        if interface.flags.contains(InterfaceFlags::UP) && // Interface is up
           !interface.flags.contains(InterfaceFlags::LOOPBACK) { // Not a loopback interface
               match interface.address {
                   IpAddr::V4(addr) => addresses.push(IpAddr::V4(addr)),
                   IpAddr::V6(addr) => addresses.push(IpAddr::V6(addr)),
               }
           }
    }

    Ok(addresses)
}

enum IpAddrKind { V4, V6 }

pub enum SyncError {
    ConnectionError(std::io::Error),
    ChecksumMismatch,
    Timeout,
    FileReadError(std::io::Error),
    FileWriteError(std::io::Error),
    // ... other potential errors ...
}

// #[derive(Debug, Deserialize, Serialize, Clone)]
// struct CollaboratorPairPorts {
//     collaborator_ports: Vec<ReadTeamchannelCollaboratorPortsToml>,
// }

#[derive(Debug)]
enum MyCustomError {
    IoError(std::io::Error),
    TomlDeserializationError(toml::de::Error),
    InvalidData(String),
    PortCollision(String), 
    // ... other variants as needed ...
}

// Implement PartialEq manually:
impl PartialEq for MyCustomError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MyCustomError::IoError(ref e1), MyCustomError::IoError(ref e2)) => {
                e1.kind() == e2.kind() // Compare the ErrorKind
                // Or you can use:
                // e1.to_string() == e2.to_string() 
            },
            (MyCustomError::TomlDeserializationError(e1), MyCustomError::TomlDeserializationError(e2)) => e1 == e2, 
            // Add other arms for your variants as needed
            _ => false, // Different variants are never equal
        }
    }
}

// Implement the std::error::Error trait
impl StdError for MyCustomError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            MyCustomError::IoError(ref err) => Some(err),
            MyCustomError::TomlDeserializationError(ref err) => Some(err),
            _ => None, // No underlying source for these variants
        }
    }
}

impl std::fmt::Display for MyCustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MyCustomError::IoError(err) => write!(f, "IO Error: {}", err),
            // MyCustomError::TomlDeserializationError(err) => write!(f, "TOML Error: {}", err),
            MyCustomError::TomlDeserializationError(err) => write!(f, "TOML Error: {}", err),
            // &MyCustomError::InvalidData(_) => todo!(),
            &MyCustomError::InvalidData(_) => todo!(),
            &MyCustomError::PortCollision(_) => todo!(),
        }
    }
}

// Implement the From trait for easy conversion from io::Error and toml::de::Error:
impl From<io::Error> for MyCustomError {
    fn from(error: io::Error) -> Self {
        MyCustomError::IoError(error)
    }
}

impl From<toml::de::Error> for MyCustomError {
    fn from(error: toml::de::Error) -> Self {
        MyCustomError::TomlDeserializationError(error)
    }
}

#[derive(Debug)]
pub enum ThisProjectError {
    IoError(std::io::Error),
    TomlDeserializationError(toml::de::Error), // May be depricated along with serde-crate
    TomlVanillaDeserialStrError(String), // use without serede crate (good)
    InvalidData(String),
    PortCollision(String), 
    NetworkError(String),
    WalkDirError(walkdir::Error),
    ParseIntError(ParseIntError),
    GpgError(String),  // GPG-specific error type
}

// Implement From<walkdir::Error> for ThisProjectError
impl From<walkdir::Error> for ThisProjectError {
    fn from(err: walkdir::Error) -> Self {
        ThisProjectError::WalkDirError(err)
    }
}

// Implement From<ParseIntError> for ThisProjectError
impl From<ParseIntError> for ThisProjectError {
    fn from(err: ParseIntError) -> Self {
        ThisProjectError::ParseIntError(err)
    }
}

// Implement From<toml::de::Error> for ThisProjectError
impl From<toml::de::Error> for ThisProjectError {
    fn from(err: toml::de::Error) -> Self {
        ThisProjectError::TomlDeserializationError(err)
    }
}

// Implement the std::error::Error trait for ThisProjectError
impl std::error::Error for ThisProjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ThisProjectError::IoError(ref err) => Some(err),
            ThisProjectError::TomlDeserializationError(ref err) => Some(err),
            _ => None, 
        }
    }
}

// Implement the Display trait for ThisProjectError for easy printing 
impl std::fmt::Display for ThisProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            ThisProjectError::IoError(ref err) => write!(f, "IO Error: {}", err),
            ThisProjectError::TomlDeserializationError(ref err) => write!(f, "TOML TomlDeserializationError  Error: {}", err),
            ThisProjectError::TomlVanillaDeserialStrError(ref err) => write!(f, "TomlVanillaDeserialStrError TOML Error: {}", err),
            ThisProjectError::InvalidData(ref msg) => write!(f, "Invalid Data: {}", msg),
            ThisProjectError::PortCollision(ref msg) => write!(f, "Port Collision: {}", msg),
            ThisProjectError::NetworkError(ref msg) => write!(f, "Network Error: {}", msg),
            ThisProjectError::WalkDirError(ref err) => write!(f, "WalkDir Error: {}", err), // Add this arm
            ThisProjectError::ParseIntError(ref err) => write!(f, "ParseInt Error: {}", err), // Add this arm
            ThisProjectError::ParseIntError(ref err) => write!(f, "ParseInt Error: {}", err),
            ThisProjectError::GpgError(_) => todo!(), // Add this arm
            // ... add formatting for other error types
        }
    }
}

// Implement From<ThisProjectError> for MyCustomError
impl From<ThisProjectError> for MyCustomError {
    fn from(error: ThisProjectError) -> Self {
        match error {
            ThisProjectError::IoError(e) => MyCustomError::IoError(e),
            ThisProjectError::TomlDeserializationError(e) => MyCustomError::TomlDeserializationError(e),
            ThisProjectError::InvalidData(msg) => MyCustomError::InvalidData(msg),
            ThisProjectError::PortCollision(msg) => MyCustomError::PortCollision(msg),
            // ... add other conversions for your variants ...
            _ => MyCustomError::InvalidData("Unknown error".to_string()), // Default case
        }
    }
}


// Implement the From trait to easily convert from other error types into ThisProjectError
impl From<io::Error> for ThisProjectError {
    fn from(err: io::Error) -> ThisProjectError {
        ThisProjectError::IoError(err)
    }
}

// impl From<toml::de::Error> for ThisProjectError {
//     fn from(err: toml::de::Error) -> ThisProjectError {
//         ThisProjectError::TomlDeserializationError(err)
//     }
// }


/*
Seri_Deseri Serialize To Start
*/



/// Serialize struct to .toml file
/// Serializes a `CollaboratorTomlData` struct into a TOML-formatted string.
///
/// This function takes a `CollaboratorTomlData` struct and manually constructs 
/// a TOML-formatted string representation of the data. 
///
/// # No `serde` Crate
///
/// This function implements TOML serialization *without* using the `serde` 
/// crate. It manually formats each field of the `CollaboratorTomlData` struct 
/// into the TOML syntax.
///
/// This approach is taken to avoid the dependency on the `serde` crate 
/// while still providing a way to generate TOML output.
///
/// # TOML Format
///
/// The function generates a TOML string with the following structure:
///
/// ```toml
/// user_name = "value"
/// user_salt_list = [
///     "0xhex_value",
///     "0xhex_value",
///     ...
/// ]
/// ipv4_addresses = [
///     "ip_address",
///     "ip_address",
///     ...
/// ]
/// ipv6_addresses = [
///     "ip_address",
///     "ip_address",
///     ...
/// ]
/// gpg_key_public = "value"
/// sync_interval = value
/// updated_at_timestamp = value
/// ```
///
/// # Helper Function
///
/// The `serialize_ip_addresses` helper function is used to format the 
/// `ipv4_addresses` and `ipv6_addresses` fields into TOML array syntax.
///
/// # Parameters
///
/// - `collaborator`: A reference to the `CollaboratorTomlData` struct to be serialized.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok`: The TOML-formatted string representation of the `CollaboratorTomlData`.
/// - `Err`: A `ThisProjectError` if an error occurs during serialization (although 
///           errors are unlikely in this simplified implementation). 
/// 
/// # use with
/// // Serialize the collaborator data to a TOML string
/// match serialize_collaborator_to_toml(&collaborator) {
///     Ok(toml_string) => {
///         println!("Serialized TOML:\n{}", toml_string);
///
///         // Write the TOML string to a file (example file path)
///         match write_toml_to_file("collaborator_data.toml", &toml_string) {
///             Ok(_) => println!("TOML data written to file successfully."),
///             Err(e) => println!("Error writing to file: {}", e),
///         }
///     }
///     Err(e) => println!("Error serializing to TOML: {}", e),
/// }
fn serialize_collaborator_to_toml(collaborator: &CollaboratorTomlData) -> Result<String, ThisProjectError> {
    let mut toml_string = String::new();

    // Add user_name
    toml_string.push_str(&format!("user_name = \"{}\"\n", collaborator.user_name));

    // Add user_salt_list
    toml_string.push_str("user_salt_list = [\n");
    for salt in &collaborator.user_salt_list {
        toml_string.push_str(&format!("    \"0x{:x}\",\n", salt));
    }
    toml_string.push_str("]\n");

    // Add ipv4_addresses
    serialize_ip_addresses(&mut toml_string, "ipv4_addresses", &collaborator.ipv4_addresses)?;

    // Add ipv6_addresses
    serialize_ip_addresses(&mut toml_string, "ipv6_addresses", &collaborator.ipv6_addresses)?;

    // Add gpg_publickey_id
    toml_string.push_str(&format!("gpg_publickey_id = \"{}\"\n", collaborator.gpg_publickey_id));
    
    // Add gpg_key_public
    toml_string.push_str(&format!("gpg_key_public = \"{}\"\n", collaborator.gpg_key_public));

    // Add sync_interval
    toml_string.push_str(&format!("sync_interval = {}\n", collaborator.sync_interval));

    // Add updated_at_timestamp
    toml_string.push_str(&format!("updated_at_timestamp = {}\n", collaborator.updated_at_timestamp));

    Ok(toml_string)
}

// Helper function to serialize IP addresses to TOML array format
fn serialize_ip_addresses<T: std::fmt::Display>(
    toml_string: &mut String, 
    key: &str, 
    addresses: &Option<Vec<T>>
) -> Result<(), ThisProjectError> {
    if let Some(addr_vec) = addresses {
        toml_string.push_str(&format!("{} = [\n", key));
        for addr in addr_vec {
            toml_string.push_str(&format!("    \"{}\",\n", addr));
        }
        toml_string.push_str("]\n");
    }
    Ok(()) // Return Ok(()) if the addresses field is None
}

// Function to write a TOML string to a file
// Function to write a TOML string to a file
fn write_toml_to_file(file_path: &str, toml_string: &str) -> Result<(), ThisProjectError> {
    // Attempt to create the file. 
    let mut file = match File::create(file_path) {
        Ok(file) => file,
        Err(e) => return Err(ThisProjectError::IoError(e)), 
    };

    // Attempt to write to the file.
    if let Err(e) = file.write_all(toml_string.as_bytes()) {
        return Err(ThisProjectError::IoError(e));
    }

    // Everything successful!
    Ok(()) 
}
/*
Seri_Deseri Serialize To TOml File End
*/

/*
Seri_Deseri Deserialize From .toml Start
*/

/// Vanilla-Rust File Deserialization
/// Toml Deserialization: Reads collaborator setup data from TOML files in a specified directory.
///
/// # Requires: 
/// the toml crate (use a current version)
/// 
/// [dependencies]
/// toml = "0.8"
/// 
/// # Terms:
/// Serialization: The process of converting a data structure (like your CollaboratorTomlData struct) into a textual representation (like a TOML file).
/// 
/// Deserialization: The process of converting a textual representation (like a TOML file) into a data structure (like your CollaboratorTomlData struct).
/// 
/// This function reads and parses TOML files located in the directory 
/// `project_graph_data/collaborator_files_address_book`. Each file is expected to 
/// contain data for a single collaborator in a structure that can be mapped to 
/// the `CollaboratorTomlData` struct.
///
/// # No `serde` Crate
///
/// This function implements TOML parsing *without* using the `serde` crate. 
/// It manually extracts values from the TOML data using the `toml` crate's 
/// `Value` enum and pattern matching. 
///
/// This approach is taken to avoid the dependency on the `serde` crate 
/// while still providing a way to parse TOML files.
///
/// # Data Extraction
///
/// The function extracts the following fields from one TOML file:
///
/// - `user_name` (String)
/// - `user_salt_list` (Vec<u128>): Stored as hexadecimal strings in the TOML file.
/// - `ipv4_addresses` (Option<Vec<Ipv4Addr>>): Stored as strings in the TOML file.
/// - `ipv6_addresses` (Option<Vec<Ipv6Addr>>): Stored as strings in the TOML file.
/// - `gpg_key_public` (String)
/// - `sync_interval` (u64)
/// - `updated_at_timestamp` (u64)
///
/// # Helper Functions
///
/// The following helper functions are used to extract and parse specific data types:
///
/// - `extract_ipv4_addresses`: Parses a string array into `Option<Vec<Ipv4Addr>>`.
/// - `extract_ipv6_addresses`: Parses a string array into `Option<Vec<Ipv6Addr>>`.
/// - `extract_u64`: Parses a TOML integer into a `u64` value, handling potential errors.
///
/// Reads collaborator setup data from a TOML file for a specific user.
///
/// This function reads and parses a TOML file located at 
/// `project_graph_data/collaborator_files_address_book/{collaborator_name}__collaborator.toml`.
/// The file is expected to contain data for a single collaborator in a structure that 
/// can be mapped to the `CollaboratorTomlData` struct.
///
/// # Error Handling
///
/// This function uses a centralized error handling approach. If any error occurs during:
///
/// - File reading (e.g., file not found)
/// - TOML parsing (e.g., invalid TOML syntax)
/// - Data extraction (e.g., missing required fields, invalid data formats)
///
/// The function will immediately return an `Err` containing a `ThisProjectError` that describes the error.
/// 
/// This approach simplifies error propagation and allows for early exit on error. 
/// If any part of the parsing or data extraction process fails, the function will stop 
/// and return the error without attempting to process the rest of the file.
///
/// # Example
///
/// ```
/// let collaborator_data = read_one_collaborator_setup_toml("alice");
///
/// match collaborator_data {
///     Ok(data) => { /* ... process the collaborator data */ },
///     Err(e) => { /* ... handle the error */ },
/// }
/// ```
///
/// # Example TOML File
///
/// ```toml
/// user_name = "Alice"
/// user_salt_list = ["0x11111111111111111111111111111111", "0x11111111111111111111111111111112"]
/// ipv4_addresses = ["192.168.1.1", "10.0.0.1"]
/// ipv6_addresses = ["fe80::1", "::1"]
/// gpg_key_public = "-----BEGIN PGP PUBLIC KEY BLOCK----- ..."
/// sync_interval = 60
/// updated_at_timestamp = 1728307160
/// ```
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok`: A tuple with:
///     - A vector of successfully parsed `CollaboratorTomlData` instances.
///     - A vector of any `ThisProjectError` encountered during parsing.
/// - `Err`: A `ThisProjectError` if there was an error reading the directory or any file.
/// 
/// This was developed for the UMA project, as the naming reflects:
/// https://github.com/lineality/uma_productivity_collaboration_tool
/// 
/// # Use with:
/// // Specify the username of the collaborator to read
/// let username = "alice";
///
/// /// Read the collaborator data from the TOML file
/// match read_one_collaborator_setup_toml(username) {
///     Ok(collaborator) => {
///         // Print the collaborator data
///         println!("Collaborator Data for {}:", username);
///         println!("{:#?}", collaborator); /// Use {:#?} for pretty-printing
///     }
///     Err(e) => {
///         // Print an error message if there was an error reading or parsing the TOML file
///         println!("Error reading collaborator data for {}: {}", username, e);
///     }
/// }
fn read_one_collaborator_setup_toml(collaborator_name: &str) -> Result<CollaboratorTomlData, ThisProjectError> {

    // 1. Construct File Path
    let file_path = Path::new("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", collaborator_name));

    // 2. Read TOML File
    let toml_string = fs::read_to_string(&file_path)?; 

    // 3. Parse TOML Data
    // 3. Parse TOML Data (handle potential toml::de::Error)
    let toml_value = match toml::from_str::<Value>(&toml_string) {
        Ok(value) => value,
        Err(e) => return Err(ThisProjectError::TomlVanillaDeserialStrError(e.to_string())), 
    };

    // 4. Extract Data from TOML Value (similar to your previous code)
    if let Value::Table(table) = toml_value {

        // Extract user_name
        let user_name = if let Some(Value::String(s)) = table.get("user_name") {
            s.clone()
        } else {
            return Err(ThisProjectError::TomlVanillaDeserialStrError("Missing user_name".into()));
        };

        // Extract user_salt_list
        let user_salt_list = if let Some(Value::Array(arr)) = table.get("user_salt_list") {
            arr.iter()
                .map(|val| {
                    if let Value::String(s) = val {
                        u128::from_str_radix(s.trim_start_matches("0x"), 16)
                            .map_err(|e| ThisProjectError::ParseIntError(e))
                    } else {
                        Err(ThisProjectError::TomlVanillaDeserialStrError("Invalid salt format: Expected string".into()))
                    }
                })
                .collect::<Result<Vec<u128>, ThisProjectError>>()?
        } else {
            return Err(ThisProjectError::TomlVanillaDeserialStrError("Missing user_salt_list".into()));
        };

        // Extract ipv4_addresses
        let ipv4_addresses = extract_ipv4_addresses(&table, "ipv4_addresses")?;

        // Extract ipv6_addresses
        let ipv6_addresses = extract_ipv6_addresses(&table, "ipv6_addresses")?;

        // Extract gpg_publickey_id
        let gpg_publickey_id = if let Some(Value::String(s)) = table.get("gpg_publickey_id") {
            s.clone()
        } else {
            return Err(ThisProjectError::TomlVanillaDeserialStrError("Missing or invalid gpg_publickey_id".into()));
        };        
        
        // Extract gpg_key_public
        let gpg_key_public = if let Some(Value::String(s)) = table.get("gpg_key_public") {
            s.clone()
        } else {
            return Err(ThisProjectError::TomlVanillaDeserialStrError("Missing or invalid gpg_key_public".into()));
        };

        // Extract sync_interval
        let sync_interval = extract_u64(&table, "sync_interval")?;

        // Extract updated_at_timestamp
        let updated_at_timestamp = extract_u64(&table, "updated_at_timestamp")?;

        // 5. Return CollaboratorTomlData 
        Ok(CollaboratorTomlData {
            user_name,
            user_salt_list,
            ipv4_addresses,
            ipv6_addresses,
            gpg_publickey_id,
            gpg_key_public,
            sync_interval,
            updated_at_timestamp,
        })
    } else {
        Err(ThisProjectError::TomlVanillaDeserialStrError("Invalid TOML structure: Expected a table".into()))
    }
}

fn extract_ipv4_addresses(table: &toml::map::Map<String, Value>, key: &str) -> Result<Option<Vec<Ipv4Addr>>, ThisProjectError> {
    if let Some(Value::Array(arr)) = table.get(key) {
        let mut addresses = Vec::new();
        for val in arr {
            if let Value::String(s) = val {
                match s.parse::<Ipv4Addr>() {
                    Ok(ip) => addresses.push(ip),
                    Err(e) => return Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Invalid {} format: {}. Skipping this address.", key, e))), 
                }
            } else {
                return Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Invalid {} format: Expected string. Skipping this address.", key)));
            }
        }

        if addresses.is_empty() { 
            Ok(None)
        } else {
            Ok(Some(addresses))
        }
    } else {
        Ok(None) 
    }
}

fn extract_ipv6_addresses(table: &toml::map::Map<String, Value>, key: &str) -> Result<Option<Vec<Ipv6Addr>>, ThisProjectError> {
    if let Some(Value::Array(arr)) = table.get(key) {
        let mut addresses = Vec::new();
        for val in arr {
            if let Value::String(s) = val {
                match s.parse::<Ipv6Addr>() {
                    Ok(ip) => addresses.push(ip),
                    Err(e) => return Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Invalid {} format: {}. Skipping this address.", key, e))), 
                }
            } else {
                return Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Invalid {} format: Expected string. Skipping this address.", key)));
            }
        }

        if addresses.is_empty() { 
            Ok(None)
        } else {
            Ok(Some(addresses))
        }
    } else {
        Ok(None) 
    }
}

// Helper function to extract a u64 from a toml::Value::Table
/// Extracts a `u64` value from a `toml::Value::Table` for a given key.
///
/// This helper function attempts to extract a `u64` value associated with the 
/// specified `key` from a `toml::map::Map` (representing a TOML table). It 
/// handles cases where the key is missing, the value is not an integer, or 
/// the integer value is outside the valid range for a `u64`.
///
/// # Parameters
///
/// - `table`: A reference to the `toml::map::Map` (TOML table) from which to extract the value.
/// - `key`: The key (as a string slice) associated with the value to extract.
/// - `errors`: A mutable reference to a vector of `ThisProjectError` to collect any errors encountered during extraction.
///
/// # Error Handling
///
/// The function uses a `Result` type to handle potential errors. It returns:
///
/// - `Ok(u64)`: If the key is found and the value can be successfully parsed as a `u64`.
/// - `Err(ThisProjectError)`: If:
///     - The key is missing from the table.
///     - The value associated with the key is not a `toml::Value::Integer`.
///     - The integer value is negative or exceeds the maximum value of a `u64`.
///
/// In case of errors, a descriptive error message is added to the `errors` vector.
///
/// # Example
///
/// ```rust
/// use toml::Value;
///
/// let mut errors = Vec::new();
/// let mut table = toml::map::Map::new();
/// table.insert("my_key".to_string(), Value::Integer(12345));
///
/// let my_value = extract_u64(&table, "my_key", &mut errors);
///
/// assert_eq!(my_value.unwrap(), 12345);
/// assert!(errors.is_empty()); // No errors
/// ```
// Helper function to extract a u64 from a toml::Value::Table
fn extract_u64(table: &toml::map::Map<String, Value>, key: &str) -> Result<u64, ThisProjectError> {
    if let Some(Value::Integer(i)) = table.get(key) {
        if *i >= 0 && *i <= i64::MAX {
            Ok(*i as u64) 
        } else {
            Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Invalid {}: Out of range for u64", key)))
        }
    } else {
        Err(ThisProjectError::TomlVanillaDeserialStrError(format!("Missing or invalid {}", key)))
    }
}

/// Extracts the `updated_at_timestamp` from TOML data.
///
/// This function takes a byte slice containing TOML data and attempts to extract
/// the `updated_at_timestamp` field as a `u64`.  It handles the cases where
/// the field is missing, has an invalid type, or is out of the valid `u64` range.
///
/// # Arguments
///
/// * `toml_data`: The TOML data as a byte slice.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`: The `updated_at_timestamp` on success, or a
///    `ThisProjectError` if an error occurs.
fn extract_updated_at_timestamp(file_content: &[u8]) -> Result<u64, ThisProjectError> {
    // 1. Convert to String (handle UTF-8 errors).
    let file_str = std::str::from_utf8(file_content).map_err(|_| {
        ThisProjectError::InvalidData("Invalid UTF-8 in file content".into())
    })?;

    // 2. Check for "updated_at_timestamp = " line (TOML-style).
    for line in file_str.lines() {
        if line.starts_with("updated_at_timestamp = ") {
            let value_str = line.trim_start_matches("updated_at_timestamp = ");
            let timestamp = value_str.parse().map_err(|e: ParseIntError| {
                ThisProjectError::InvalidData(format!("Invalid timestamp: {}", e))
            })?;
            return Ok(timestamp);
        }
    }

    // 3. (Optional) If not TOML, try other formats (e.g., JSON).  Add this as needed.
    // ... (Code to handle other formats, checking for similar timestamp fields) ...

    // 4. If no recognized timestamp format is found.
    Err(ThisProjectError::InvalidData("Timestamp field not found in any recognized format".into()))
}

/*
Seri_Deseri Deserialize From End
*/

/// get unix time 
/// e.g. for use with updated_at_timestamp
fn get_current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before the Unix epoch!") // Handle errors appropriately
        .as_secs()
}


fn check_all_ports_in_team_channels() -> Result<(), ThisProjectError> {
    let team_channels_dir = Path::new("project_graph_data/team_channels");
    let mut ports_in_use = HashSet::new();

    // Iterate over all team channel directories
    for entry in WalkDir::new(team_channels_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
    {
        let node_toml_path = entry.path().join("node.toml");
        if node_toml_path.exists() {
            // Read the node.toml file
            let toml_string = std::fs::read_to_string(&node_toml_path)?;
            let toml_value: Value = toml::from_str(&toml_string)?;

            // Extract the teamchannel_collaborators_with_access array
            if let Some(collaborators_array) = toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array) {
                for collaborator_data in collaborators_array {
                    // Extract each port and check if it's in use
                    if let Some(ready_port) = collaborator_data.get("ready_port").and_then(|v| v.as_integer()).map(|p| p as u16) {
                        if is_port_in_use(ready_port) && !ports_in_use.insert(ready_port) {
                            return Err(ThisProjectError::PortCollision(format!("Port {} is already in use.", ready_port)));
                        }
                    }
                    // Repeat for intray_port, gotit_port, self_ready_port, self_intray_port, self_gotit_port
                    // ... (add similar checks for the other five ports) 
                }
            }
        }
    }

    Ok(()) // No port collisions found
}


/// check for port collision
/// Checks if a given port is currently in use.
///
/// This function attempts to bind a TCP listener to the specified port on the loopback 
/// interface (127.0.0.1). If the binding is successful, it means the port is likely 
/// available. If the binding fails, it suggests the port is already in use.
///
/// # Caveats:
///
/// * **TCP-Specific:** This check only verifies if a TCP listener can be bound. 
///   It does not guarantee that the port is not being used by a UDP process
///   or a process using a different protocol. 
/// * **UMA is UDP-Only:** Ideally, this function should be replaced with a more
///   accurate check that is specific to UDP port availability. 
/// * **Resource Usage:** Binding a TCP listener, even momentarily, consumes system resources. 
/// * **Race Conditions:** It's possible for another process to bind to the port 
///   between the time this check is performed and the time UMA actually attempts
///   to use the port.
///
/// # Arguments
///
/// * `port` - The port number to check.
///
/// # Returns
///
/// * `bool` - `true` if the port is likely in use, `false` if it's likely available. 
fn is_port_in_use(port: u16) -> bool {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => false, // Port is available
        Err(_) => true, // Port is in use
    }
}

/// Function for broadcasting to theads to wrapup and end uma session: quit
fn should_halt_uma() -> bool {
    // 1. Read the 'continue_uma.txt' file
    let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading 'continue_uma.txt': {:?}", e); // Log the error
            return false; // Don't halt on error reading the file
        }
    };

    // 2. Check if the file content is "0"
    file_content.trim() == "0"
}

/// Check for a Restart
/// The logic here is easy to get backwards:
/// There are two flags that are checked
/// regarding shut-down.
/// There is the normal shoud_continue flag,
/// which is checked with a should_halt_uma checker.
/// To keep things symetric, there is a parallel
/// system for hard-reboot, working the same way
/// with one exception:
/// If you should restart this also re-resets the 'quit'
/// function (so you are not in an infinite loop of quit-restart).
/// if you check should_not_hard_restart() (this function)
/// and find that you should (quite) not-restart, it works the same way.
fn should_not_hard_restart() -> bool {
    // 1. Read the 'hard_restart_flag.txt' file
    let file_content = match fs::read_to_string(HARD_RESTART_FLAG_PATH) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading 'yes_hard_restart_flag.txt': {:?}", e); // Log the error
            return false; // Don't halt on error reading the file
        }
    };

    if file_content.trim() == "0" {
        return true; // Hard restart requested
    } else {
        // Reset the quit flag using the safe function
        // In the case that you ARE restarting.
        // So you don't loop from restart to quit-again.
        initialize_continue_uma_signal();
        return false;
    }
}

fn dir_at_path_is_empty_returns_false(path_to_dir: &Path) -> bool { 

    debug_log!("dir_at_path_is_empty_returns_false()-> Checking if directory is empty: {:?}", path_to_dir);
    if let Ok(mut entries) = fs::read_dir(path_to_dir) {
        
        entries.next().is_some() // Returns false if the directory is empty
    } else {
        true // Assume directory is NOT empty if an error occurs reading it
    }
}

fn get_ipv4_addresses() -> Result<Option<Vec<Ipv4Addr>>, io::Error> {
    let mut addresses = Vec::new();
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.to_lowercase() == "done" {
            break; 
        } else if input.is_empty() { 
            return Ok(None);
        }

        let addr: Ipv4Addr = input.parse()
                               .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IPv4 address"))?; 
        addresses.push(addr);
    }
    Ok(Some(addresses))
}

fn get_ipv6_addresses() -> Result<Option<Vec<Ipv6Addr>>, io::Error> {
    let mut addresses = Vec::new();
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.to_lowercase() == "done" {
            break;
        } else if input.is_empty() {
            return Ok(None);
        }

        let addr: Ipv6Addr = input.parse() 
                               .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IPv6 address"))?; 
        addresses.push(addr);
    }
    Ok(Some(addresses))
}

// pub fn sign_toml_file(file_path: &Path) -> Result<(), Error> {
//     let output = Command::new("gpg")
//         .arg("--clearsign") 
//         .arg(file_path)
//         .output() 
//         .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to run GPG: {}", e)))?;

//     if output.status.success() {
//         fs::write(file_path, output.stdout)?; // Overwrite with the signed content 
//         debug_log!("File {} successfully signed with GPG.", file_path.display()); 
//         Ok(())
//     } else {
//         debug_log!("GPG signing failed: {}", String::from_utf8_lossy(&output.stderr));
//         Err(Error::new(ErrorKind::Other, "GPG signing failed"))
//     }
// }

pub fn verify_toml_signature(file_path: &Path) -> Result<(), Error> {
    let output = Command::new("gpg") 
        .arg("--verify") 
        .arg(file_path) 
        .output()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to run GPG: {}", e)))?;

    if output.status.success() {
        debug_log!("GPG signature of {} is valid.", file_path.display()); 
        Ok(())
    } else {
        debug_log!("GPG verification failed: {}", String::from_utf8_lossy(&output.stderr));
        Err(Error::new(ErrorKind::Other, "GPG signature invalid"))
    }
}



fn debug_log(message: &str) {
    if DEBUG_FLAG {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("uma.log")
            .expect("Failed to open log file");
    
        writeln!(file, "{}", message).expect("Failed to write to log file");
    }
}

/// read timestamps from .toml files, like you were born to do just that...on Mars!!
fn get_toml_file_timestamp(file_path: &Path) -> Result<u64, ThisProjectError> {
    debug_log!(
        "Starting get_toml_file_timestamp, file_path -> {:?}",
        file_path   
    );

    let toml_string = std::fs::read_to_string(file_path)?;
    let toml_value: Value = toml::from_str(&toml_string)?;

    let timestamp = toml_value
        .get("updated_at_timestamp") // Access the "updated_at_timestamp" field
        .and_then(Value::as_integer) // Try to convert to an integer
        .and_then(|ts| ts.try_into().ok()) // Try to convert to u64
        .ok_or_else(|| {
            ThisProjectError::InvalidData(format!(
                "Missing or invalid 'updated_at_timestamp' in TOML file: {}",
                file_path.display()
            ))
        })?;

    debug_log!(
        "[Done] get_toml_file_timestamp, timestamp -> {:?}",
        timestamp   
    );
    
    Ok(timestamp)
}


// fn get_local_owner_field(field_name: String,)





// alpha testing
#[macro_export] 
macro_rules! debug_log {
    ($($arg:tt)*) => (
        if DEBUG_FLAG {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("uma.log")
                .expect("Failed to open log file");

            writeln!(file, $($arg)*).expect("Failed to write to log file");
        } 
    )
}

// maybe deprecated
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RemoteCollaboratorPortsData {
    remote_collaborator_name: String,
    remote_ipv6_address: Ipv6Addr,
    remote_collaborator_gpg_publickey_id: String,
    remote_public_gpg: String,
    remote_sync_interval: u64, // depricated? controlled by team-channel? 
    remote_ready_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
    remote_intray_port__their_desk_you_send: u16, // locally: 'you' add files to their port on 'their' desk
    remote_gotit_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
}

/// struct for reading/extracting raw abstract port assignments 
/// from the team_channels/NAME/node.toml
#[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq)] // Add
struct AbstractTeamchannelNodeTomlPortsData {
    user_name: String,
    ready_port: u16,
    intray_port: u16,
    gotit_port: u16, // locally: 'you' listen to their port on 'their' desk
}

/// Instance-Role-Specific Local-Meeting-Room-Struct
/// This is no longer for an abstract set of data 
/// that can be used in different ways in different instances, 
/// This is now one of those specific instances with local roles 
/// and one local way of using those data.
/// The abstract port-assignements will be converted into a 
/// disambiguated and clarified specific local instance roles 
/// set of port assignments:
/// - local_user_role, 
/// - remote_collaborator_role.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct MeetingRoomSyncDataset {
    local_user_name: String,
    local_user_salt_list: Vec<u128>,
    local_user_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    local_user_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
    local_user_gpg_publickey_id: String,
    local_user_public_gpg: String,
    local_user_sync_interval: u64,
    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen for files sent by the other collaborator
    local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    
    remote_collaborator_name: String,
    remote_collaborator_salt_list: Vec<u128>,
    remote_collaborator_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    remote_collaborator_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
    remote_collaborator_gpg_publickey_id: String,
    remote_collaborator_public_gpg: String,
    remote_collaborator_sync_interval: u64,
    remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
    remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' add files to their port on 'their' desk
    remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
}

/// ForLocalOwnerDeskThread data from MeetingRoomSyncDataset
/// Get Needed, When Needed
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ForLocalOwnerDeskThread {
    local_user_name: String,
    remote_collaborator_name: String,
    local_user_salt_list: Vec<u128>,
    remote_collaborator_salt_list: Vec<u128>,
    local_user_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    local_user_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
    local_user_gpg_publickey_id: String,
    local_user_public_gpg: String,
    local_user_sync_interval: u64,
    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen for files sent by the other collaborator
    local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
}

/// ForRemoteCollaboratorDeskThread data from MeetingRoomSyncDataset
/// Get Needed, When Needed
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ForRemoteCollaboratorDeskThread {
    remote_collaborator_name: String,
    local_user_name: String,
    remote_collaborator_salt_list: Vec<u128>,
    local_user_salt_list: Vec<u128>,
    remote_collaborator_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    remote_collaborator_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
    remote_collaborator_gpg_publickey_id: String,
    remote_collaborator_public_gpg: String,
    remote_collaborator_sync_interval: u64,
    remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
    remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' add files to their port on 'their' desk
    remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
}

/// for translate_port_assignments() to export as
/// Get Needed, When Needed
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RoleBasedLocalPortSet {
    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen for files sent by the other collaborator
    local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
    remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' add files to their port on 'their' desk
    remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen to their port on 'their' desk
}

fn translate_port_assignments(
    local_user_name: &str,
    remote_collaborator_name: &str,
    abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
) -> Result<RoleBasedLocalPortSet, MyCustomError> {
    debug_log!("tpa: Entering translate_port_assignments() function");

    // 1. Construct the key for the meeting room based on user names
    let meeting_room_key = get_meeting_room_lookup_fieldkey(local_user_name, remote_collaborator_name);
    debug_log!("tpa 1. Meeting room key: {}", meeting_room_key);

    // 2. Get the port assignment array for this meeting room
    let meeting_room_ports = abstract_collaborator_port_assignments
        .get(&meeting_room_key)
        .ok_or_else(|| MyCustomError::from(io::Error::new(
            io::ErrorKind::NotFound,
            format!("tpa 2. Port assignments not found for meeting room: {}", meeting_room_key),
        )))?;

    // 3. Extract local and remote ports from the vector
    let mut local_ports = None;
    let mut remote_ports = None;

    // Iterate through the ReadTeamchannelCollaboratorPortsToml structs
    for port_data in meeting_room_ports {
        // Iterate through the collaborator_ports vector within each struct
        for port_set in &port_data.collaborator_ports { 
            if port_set.user_name == local_user_name {
                local_ports = Some(port_set.clone());
            } else if port_set.user_name == remote_collaborator_name {
                remote_ports = Some(port_set.clone());
            }
        }
    }

    // 4. Ensure both local and remote ports were found
    let local_ports = local_ports.ok_or_else(|| MyCustomError::from(io::Error::new(
        io::ErrorKind::NotFound,
        format!("tpa 4. Local port assignments not found for user: {}", local_user_name),
    )))?;
    let remote_ports = remote_ports.ok_or_else(|| MyCustomError::from(io::Error::new(
        io::ErrorKind::NotFound,
        format!("tpa 4. Remote port assignments not found for user: {}", remote_collaborator_name),
    )))?;

    // 5. Construct and return the RoleBasedLocalPortSet
    Ok(RoleBasedLocalPortSet {
        local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: local_ports.ready_port,
        localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: local_ports.intray_port,
        local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: local_ports.gotit_port,
        remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: remote_ports.ready_port,
        remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: remote_ports.intray_port,
        remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: remote_ports.gotit_port,
    })
}

/// Encrypts data using GPG with the specified recipient's public key.
///
/// This function uses the `gpg` command-line tool to encrypt the data. It assumes that `gpg`
/// is installed and accessible in the system's PATH. 
///
/// # Arguments 
///
/// * `data`: The data to encrypt as a byte slice.
/// * `recipient_public_key`: The recipient's public GPG key. 
///
/// # Returns 
/// 
/// * `Result<Vec<u8>, ThisProjectError>`:  A `Result` containing the encrypted data as a `Vec<u8>` on success,
///   or a `ThisProjectError` on failure.
fn encrypt_with_gpg(data: &[u8], recipient_public_key: &str) -> Result<Vec<u8>, ThisProjectError> {
    let mut child = Command::new("gpg")
        .arg("--encrypt")
        .arg("--recipient")
        .arg(recipient_public_key)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()) 
        .spawn()?;

    // Write the data to encrypt to the GPG process's standard input
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| ThisProjectError::NetworkError("Failed to open stdin for GPG process".to_string()))?;
        stdin.write_all(data)?; 
    }

    let output = child.wait_with_output()?;

    if output.status.success() {
        Ok(output.stdout) // Return the encrypted data
    } else {
        // Log the GPG error 
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug_log!("GPG encryption error: {}", stderr);
        Err(ThisProjectError::NetworkError(format!("GPG encryption failed: {}", stderr)))
    }
}

// // Helper function for translate_port_assignments
// // to construct the meeting room key
// Helper function to construct the meeting room key
fn get_meeting_room_lookup_fieldkey(user1: &str, user2: &str) -> String {
    let mut names = vec![user1, user2];
    names.sort(); // Ensure consistent key regardless of user order
    format!("{}_{}", names[0], names[1])
}

// Helper function to extract ports from a TOML table
fn extract_ports_from_table(port_set: &toml::map::Map<String, Value>) -> Result<AbstractTeamchannelNodeTomlPortsData, MyCustomError> {
    Ok(AbstractTeamchannelNodeTomlPortsData {
        user_name: port_set
            .get("user_name")
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing 'user_name' in port set",
            )))?
            .as_str()
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "'user_name' is not a string",
            )))?
            .to_string(),
        ready_port: port_set
            .get("ready_port")
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing 'ready_port' in port set",
            )))?
            .as_integer()
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "'ready_port' is not an integer",
            )))? as u16,
        intray_port: port_set
            .get("intray_port")
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing 'intray_port' in port set",
            )))?
            .as_integer()
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "'intray_port' is not an integer",
            )))? as u16,
        gotit_port: port_set
            .get("gotit_port")
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing 'gotit_port' in port set",
            )))?
            .as_integer()
            .ok_or_else(|| MyCustomError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "'gotit_port' is not an integer",
            )))? as u16,
    })
}

/// Extracts the list of collaborator names from a team channel's `node.toml` file.
///
/// This function reads the `node.toml` file at the specified path, parses the TOML data,
/// and extracts the collaborator names from the `abstract_collaborator_port_assignments` table.
///
/// # Arguments
///
/// * `node_toml_path` - The path to the team channel's `node.toml` file.
///
/// # Returns
///
/// * `Result<Vec<String>, String>` - A `Result` containing a vector of collaborator names
///   on success, or a `String` describing the error on failure.
fn get_collaborator_names_from_node_toml(node_toml_path: &Path) -> Result<Vec<String>, String> {
    debug_log!("4. Entering get_collaborator_names_from_node_toml() with path: {:?}", node_toml_path);

    // 1. Read the node.toml file
    let toml_string = match std::fs::read_to_string(node_toml_path) {
        Ok(content) => {
            debug_log!("Successfully read node.toml file. Contents:\n{}", content);
            content
        },
        Err(e) => return Err(format!("Error reading node.toml file: {}", e)),
    };

    // 2. Parse the TOML data
    let toml_value: Value = match toml::from_str(&toml_string) {
        Ok(value) => {
            debug_log!("Successfully parsed TOML data. Value: {:?}", value);
            value
        },
        Err(e) => return Err(format!("Error parsing node.toml data: {}", e)),
    };

    // 3. Extract collaborator names from abstract_collaborator_port_assignments
    let mut collaborator_names = Vec::new();
    debug_log!("Looking for table 'abstract_collaborator_port_assignments'");
    if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
        debug_log!("Found table 'abstract_collaborator_port_assignments'. Entries: {:?}", collaborator_assignments_table);
        for (pair_name, _) in collaborator_assignments_table {
            debug_log!("Processing pair: {}", pair_name);
            // Split the pair name (e.g., "alice_bob") into individual names
            let names: Vec<&str> = pair_name.split('_').collect();
            collaborator_names.extend(names.iter().map(|&s| s.to_string()));
        }
    } else {
        debug_log!("Table 'abstract_collaborator_port_assignments' not found.");
    }

    debug_log!("Exiting get_collaborator_names_from_node_toml() with names: {:?}", collaborator_names);
    // 4. Return the list of collaborator names
    Ok(collaborator_names)
}

/// Extracts the abstract port assignments from a team channel's `node.toml` file.
///
/// This function reads the `node.toml` file, parses the TOML data, and extracts the
/// `collaborator_port_assignments` table, returning it as a HashMap.
///
/// # Arguments
///
/// * `node_toml_path` - The path to the team channel's `node.toml` file.
///
/// # Returns
///
/// * `Result<HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>, String>` - A `Result` containing a HashMap of 
///   collaborator pair names to their port assignments on success, or a `String` describing the error on failure.
fn get_abstract_port_assignments_from_node_toml(
    node_toml_path: &Path
) -> Result<HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>, String> {
    debug_log!("5. starting get_abstract_port_assignments_from_node_toml(): 1. Entering function with path: {:?}", node_toml_path);

    // 1. Read the node.toml file
    let toml_string = match std::fs::read_to_string(node_toml_path) {
        Ok(content) => {
            debug_log!("get_abstract_port_assignments_from_node_toml: 2. Successfully read node.toml file.");
            content
        },
        Err(e) => {
            let error_message = format!("get_abstract_port_assignments_from_node_toml: Error reading node.toml file: {}", e);
            debug_log!("{}", error_message);
            return Err(error_message);
        }
    };

    // 2. Parse the TOML data
    let toml_value: Value = match toml::from_str(&toml_string) {
        Ok(value) => {
            debug_log!("get_abstract_port_assignments_from_node_toml: 3. Successfully parsed TOML data.");
            value
        },
        Err(e) => {
            let error_message = format!("get_abstract_port_assignments_from_node_toml: Error parsing node.toml data: {}", e);
            debug_log!("{}", error_message);
            return Err(error_message);
        }
    };

    // 3. Extract the abstract_collaborator_port_assignments table
    let mut abstract_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();
    debug_log!("get_abstract_port_assignments_from_node_toml: 4. Looking for 'abstract_collaborator_port_assignments' table.");
    if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
        debug_log!("get_abstract_port_assignments_from_node_toml: 5. Found 'abstract_collaborator_port_assignments' table.");
        for (pair_name, pair_data) in collaborator_assignments_table {
            debug_log!("get_abstract_port_assignments_from_node_toml: 6. Processing pair: {}", pair_name);
            if let Some(ports_array) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
                debug_log!("get_abstract_port_assignments_from_node_toml: 7. Found 'collaborator_ports' array for pair: {}", pair_name);
                let mut ports_for_pair = Vec::new();
                for port_data in ports_array {
                    debug_log!("get_abstract_port_assignments_from_node_toml: 8. Processing port data: {:?}", port_data);
                    let port_data_str = toml::to_string(&port_data).unwrap();
                    let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str)
                        .map_err(|e| format!("get_abstract_port_assignments_from_node_toml: Error deserializing collaborator port: {}", e))?;
                    debug_log!("get_abstract_port_assignments_from_node_toml: 9. Deserialized port data: {:?}", collaborator_port);
                    ports_for_pair.push(ReadTeamchannelCollaboratorPortsToml {
                        collaborator_ports: vec![collaborator_port],
                    });
                }
                debug_log!("get_abstract_port_assignments_from_node_toml: 10. Inserting ports for pair: {} into HashMap.", pair_name);
                abstract_port_assignments.insert(pair_name.to_string(), ports_for_pair);
            } else {
                debug_log!("get_abstract_port_assignments_from_node_toml: 11. 'collaborator_ports' array not found for pair: {}", pair_name);
            }
        }
    } else {
        debug_log!("get_abstract_port_assignments_from_node_toml: 12. 'abstract_collaborator_port_assignments' table not found.");
    }

    debug_log!("get_abstract_port_assignments_from_node_toml: 13. Exiting function with port assignments: {:?}", abstract_port_assignments);
    // 4. Return the abstract_port_assignments HashMap
    Ok(abstract_port_assignments)
}

// ALPHA VERSION
// Function to read a simple string from a file
pub fn read_state_string(file_name: &str) -> Result<String, std::io::Error> {
    let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
    fs::read_to_string(file_path)
}

// ALPHA VERSION
// Function to validate a simple string 
/*
Where: Add this to  state_utils.rs module or a similar location.

Purpose: You can define validation rules based on the specific session state item. For example, checking if a string is not empty, if a TOML file has the expected structure, or even performing GPG signature verification.
*/
pub fn validate_state_string(value: &str) -> bool {
    !value.is_empty()
}

// Compression Algorithm Enum
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
enum CompressionAlgorithm {
    Deflate,
    Brotli,
    Zstd,
    None,
}

/// Represents the different input modes of the UMA application's TUI. 
///
/// The TUI can be in one of these modes at a time, determining how user input 
/// is interpreted and handled. 
#[derive(PartialEq)]
enum InputMode {
    /// Command Mode:  The default mode. The user can type commands (e.g., "help", "quit", "m") 
    /// to navigate the project graph or interact with UMA features.
    Command,
    /// Insert Text Mode:  Used for entering text, such as instant messages. In this mode, 
    /// user input is treated as text to be added to the current context.
    InsertText,
}

struct App {
    tui_directory_list: Vec<String>, // For directories in the current path
    tui_file_list: Vec<String>,       // For files in the current path
    tui_focus: usize,                  // Index of the highlighted item in the TUI list
    tui_textmessage_list: Vec<String>, // Content of messages in the current IM conversation
    tui_width: usize,  
    tui_height: usize,
    
    current_path: PathBuf,              // Current directory being used
    input_mode: InputMode, 
    command_input_integer:  Option<usize>,
    current_command_input: Option<String>,
    current_text_input: Option<String>,
    graph_navigation_instance_state: GraphNavigationInstanceState,
}


impl App {
    /*

    */
    fn new(graph_navigation_instance_state: GraphNavigationInstanceState) -> App {
        App {
            tui_focus: 0,
            current_path: PathBuf::from("project_graph_data/team_channels"),
            input_mode: InputMode::Command, 
            tui_file_list: Vec::new(), // Initialize files
            tui_directory_list: Vec::new(), // Initialize files
            tui_textmessage_list: Vec::new(), // Initialize files
            tui_width: 80, // default posix terminal size
            tui_height: 42, // default posix terminal size
            command_input_integer: None,
            current_command_input: None,
            current_text_input: None,
            graph_navigation_instance_state, // Initialize the field
            
        }
    }

    fn handle_tui_action(&mut self) -> Result<(), io::Error> { // Now returns Result
        debug_log("app fn handle_tui_action() started");
        
        if self.is_in_team_channel_list() {
            debug_log("is_in_team_channel_list");
            debug_log(&format!("current_path: {:?}", self.current_path));
            
            let input = tiny_tui::get_input()?; // Get input here
            if let Ok(index) = input.parse::<usize>() { 
                let item_index = index - 1; // Adjust for 0-based indexing
                if item_index < self.tui_directory_list.len() {
                    let selected_channel = &self.tui_directory_list[item_index];
                    debug_log(&format!("Selected channel: {}", selected_channel)); // Log the selected channel name
                    
                    self.current_path = self.current_path.join(selected_channel);
                    
                    debug_log(&format!("New current_path: {:?}", self.current_path)); // Log the updated current path
                    
                    self.graph_navigation_instance_state.current_full_file_path = self.current_path.clone();
                    self.graph_navigation_instance_state.look_read_node_toml(); 

                    // Log the state after loading node.toml
                    debug_log(&format!("handle_tui_action() State after look_read_node_toml: {:?}", self.graph_navigation_instance_state));
                    
                    // ... enter IM browser or other features ...
                } else {
                    debug_log("Invalid index.");
                }
            } 
        } else if self.is_in_instant_message_browser_directory() {
            // ... handle other TUI actions ...
            debug_log("else if self.is_in_instant_message_browser_directory()");
            
            
        }
        debug_log("end app fn handle_tui_action()");
        Ok(()) // Return Ok if no errors
    }

    fn get_focused_channel_path(&self) -> Option<PathBuf> {
        let channel_name = self.tui_file_list.get(self.tui_focus)?;
        Some(self.current_path.join(channel_name))
    }

    fn enter_instant_message_browser(&mut self, channel_path: PathBuf) { 
        // Update the current path to the instant message browser directory within the selected channel
        self.current_path = channel_path.join("instant_message_browser"); 
        // Load the instant messages for this channel
        self.load_im_messages(); // No need to pass any arguments 
        // Reset the TUI focus to the beginning of the message list
        self.tui_focus = 0;     
    } 

    fn load_im_messages(&mut self) {
        debug_log("load_im_messages called"); 
        debug_log(&format!("self.current_path  {:?}", self.current_path));
        self.tui_textmessage_list.clear(); 

        if self.current_path.is_dir() {
            debug_log(&format!("self.current_path  {:?}", self.current_path));
            let entries: Vec<_> = WalkDir::new(&self.current_path)
                .max_depth(1) // Add this line to limit depth                    
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().is_file())
                .collect();

            // Inspection block (print file paths)
            debug_log("=== Files in entries ===");
            for entry in &entries { 
                debug_log(&format!("  {:?}", entry.path()));
            }
            debug_log("=== End of entries ===");

            // Check if only 0.toml exists (or if the directory is empty)
            if entries.is_empty() || 
            (entries.len() == 1 && entries[0].path().file_name().unwrap() == OsStr::new("0.toml")) {
                // Only 0.toml exists (or no files exist), prompt for the first message
                println!("This channel is empty. Write a welcoming message:");
                let mut first_message = String::new();
                io::stdin().read_line(&mut first_message).unwrap();

                // Assuming 'local_owner_user' is already loaded in your main function
                let local_owner_user = self.graph_navigation_instance_state.local_owner_user.clone(); // Access from graph_navigation_instance_state
                
                let this_file_name = format!("1__{}.toml", local_owner_user);
                let last_section = extract_last_section(&self.current_path);

                // Add the first message (assuming the current user is the owner)
                /*
                TODO Top priority area:
                
                maybe used GraphNavigationInstanceState node data to fill in these values

                fn add_im_message(
                    path: &Path,
                    owner: &str,
                    text: &str,
                    signature: Option<String>,
                    graph_navigation_instance_state: &GraphNavigationInstanceState, // Pass local_user_metadata here
                ) -> Result<(), io::Error> {
                */

                    
                debug_log(&format!("this_file_name {:?}", this_file_name));
                // debug_log(&format!("self.current_path.join(this_file_name)  {:?}", self.current_path.join(this_file_name)));    
                    
                add_im_message(
                    &self.current_path.join(this_file_name), // path
                    &local_owner_user, // owner
                    first_message.trim(), // text
                    None, // signature
                    &self.graph_navigation_instance_state, // use GraphNavigationInstanceState
                ).expect("Failed to add first message");
                    
                
                // Reload entries after adding the first message 
                self.load_im_messages(); // No arguments needed
                return; 
            }

            // Load messages (excluding 0.toml)
            for entry in entries {
                if entry.path().is_file() {
                    let file_name = entry.path().file_name().unwrap().to_string_lossy().to_string();
                    if file_name != "0.toml" {
                        // Read the file contents
                        let file_contents = fs::read_to_string(entry.path()).expect("Failed to read message file"); 

                        // Assuming you're parsing the TOML into a InstantMessageFile struct called 'message'
                        let message: InstantMessageFile = toml::from_str(&file_contents).unwrap(); 

                        debug_log(&format!("file_name from {}", file_name)); 
                        debug_log(&format!("Added message from {}", message.owner)); 

                        // Add the message to the list for display
                        self.tui_textmessage_list.push(format!("{}: {}", message.owner, message.text_message)); 
                    }
                }
            }
        }

        // Render the message list (assuming this is implemented in tiny_tui_module)
        tiny_tui::render_list(&self.tui_textmessage_list, &self.current_path); 
    } 
   
    fn next(&mut self) {
        if self.tui_focus < self.tui_file_list.len() - 1 {
            self.tui_focus += 1;
        }
    }

    fn previous(&mut self) {
        if self.tui_focus > 0 {
            self.tui_focus -= 1;
        }
    }

    // What is wrong with the brain of the person who invented this function?
    fn is_in_team_channel_list(&self) -> bool {
        self.current_path == PathBuf::from("project_graph_data/team_channels")
    }

    fn is_in_instant_message_browser_directory(&self) -> bool {
        self.current_path.ends_with("instant_message_browser")
    }
    
    fn get_tui_focus_node_path(&self) -> Option<PathBuf> { 
        if let Some(tui_focus_file) = self.tui_file_list.get(self.tui_focus) {
            Some(PathBuf::from(tui_focus_file))
        } else {
            None
        }
    }

    fn display_error(&mut self, message: &str) {
        // Implement logic to display the error message in the input box or status bar
        // ... (e.g., update a field in App that's displayed in the UI)
        println!("Error: {}", message); // Example: Print the error to the console for now
    }


    fn get_current_list(&self) -> &Vec<String> {
        match self.tui_focus {
            0 => &self.tui_directory_list,
            1 => &self.tui_file_list,
            2 => &self.tui_textmessage_list,
            _ => panic!("Invalid tui_focus value"), 
        }
    }        
    
    
    fn update_directory_list(&mut self) -> io::Result<()> {
        self.tui_directory_list.clear(); 
    
        for entry in fs::read_dir(&self.current_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() { // Only add directories to the list
                let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                self.tui_directory_list.push(file_name);
            }
        }
    
        Ok(())
    }

}    
// end impl App {


#[derive(Debug, Deserialize, serde::Serialize, Clone)]
struct LocalUserUma {
    uma_local_owner_user: String,
    uma_default_im_messages_expiration_days: u64,
    uma_default_task_nodes_expiration_days: u64,
    log_mode_refresh: f32,
}

impl LocalUserUma {
    fn new(uma_local_owner_user: String) -> LocalUserUma {
        LocalUserUma { 
            uma_local_owner_user,
            uma_default_im_messages_expiration_days: 28, // Default to 7 days
            uma_default_task_nodes_expiration_days: 90, // Default to 30 days 
            log_mode_refresh: 1.5 // how fast log mode refreshes
            }
    }


    fn save_owner_to_file(&self, path: &Path) -> Result<(), io::Error> {
        let toml_string = toml::to_string(&self).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
        })?;
        fs::write(path, toml_string)?;
        Ok(())
    }
}

/// Extract Salt Value:
/// It uses get("user_salt") to access the user_salt field in the TOML data.
/// and_then(Value::as_integer) attempts to convert the value to an integer.
/// and_then(|salt| salt.try_into().ok()) attempts to convert the integer to a u8.
/// ok_or_else(|| ...) handles the case where the salt is missing or invalid, 
/// returning a ThisProjectError::InvalidData.
fn get_team_member_collaborator_salt(collaborator_name: &str) -> Result<u8, ThisProjectError> {
    // 1. Construct File Path
    let file_path = Path::new("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", collaborator_name));

    // 2. Read File Contents
    let toml_string = fs::read_to_string(&file_path)?;

    // 3. Parse TOML Data
    let toml_value: Value = toml::from_str(&toml_string)?;

    // 4. Extract Salt Value
    let user_salt: u8 = toml_value
        .get("user_salt")
        .and_then(Value::as_integer)
        .and_then(|salt| salt.try_into().ok())
        .ok_or_else(|| {
            ThisProjectError::InvalidData(format!(
                "Missing or invalid 'user_salt' in collaborator file: {}",
                file_path.display()
            ))
        })?;

    // 5. Return Salt
    Ok(user_salt)
}

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
struct CollaboratorTomlData {
    user_name: String,
    user_salt_list: Vec<u128>,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_publickey_id: String,
    gpg_key_public: String,
    sync_interval: u64,
    updated_at_timestamp: u64,
}

/// for an intermediate step in converting data types
#[derive(Debug, Deserialize, serde::Serialize, Clone)]
struct RawProtoDataToml {
    user_name: String,
    user_salt_list: Vec<String>,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_publickey_id: String,
    gpg_key_public: String,
    sync_interval: u64,
    updated_at_timestamp: u64,
}

impl CollaboratorTomlData {
    fn new(
        user_name: String, 
        user_salt_list: Vec<u128>,
        ipv4_addresses: Option<Vec<Ipv4Addr>>,
        ipv6_addresses: Option<Vec<Ipv6Addr>>,
        gpg_publickey_id: String,
        gpg_key_public: String, 
        sync_interval: u64,
        updated_at_timestamp: u64,
    ) -> CollaboratorTomlData {
        CollaboratorTomlData {
            user_name,
            user_salt_list, 
            ipv4_addresses,
            ipv6_addresses,
            gpg_publickey_id,
            gpg_key_public,
            sync_interval,
            updated_at_timestamp,
        }
    }

    // Add any other methods you need here
}

fn add_collaborator_setup_file(
    user_name: String,
    user_salt_list: Vec<u128>,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_publickey_id: String,
    gpg_key_public: String,
    sync_interval: u64,
    updated_at_timestamp: u64,
) -> Result<(), std::io::Error> {
    debug_log("Starting: fn add_collaborator_setup_file( ...cupa tea?");
    // Create the CollaboratorTomlData instance using the existing new() method:
    let collaborator = CollaboratorTomlData::new(
        user_name, 
        user_salt_list,
        ipv4_addresses,
        ipv6_addresses,
        gpg_publickey_id,
        gpg_key_public,
        sync_interval,
        updated_at_timestamp,
    );

    // maybe not needed as salts are required input
    // // Generate 4 random u128 salts
    // let user_salt_list: Vec<u128> = (0..4)
    //     .map(|_| rand::thread_rng().gen())
    //     .collect();
    
    
    // Serialize the data:
    let toml_string = toml::to_string(&collaborator).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("TOML serialization error: {}", e),
        )
    })?;

    // Construct the file path:
    let file_path = Path::new("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", collaborator.user_name));

     // Log the constructed file path:
     debug_log!("Attempting to write collaborator file to: {:?}", file_path); 
    
    // Create the file and write the data:
    let mut file = File::create(file_path.clone())?;
    file.write_all(toml_string.as_bytes())?;

     // Log the constructed file path:



     // Check for potential errors during file creation:
     match File::create(&file_path) {
         Ok(mut file) => {
             debug_log!("File creation succeeded.");

             // Check for errors while writing to the file: 
             match file.write_all(toml_string.as_bytes()) {
                 Ok(_) => { 
                     debug_log!("Collaborator file written successfully."); 
                 },
                 Err(err) => {
                     debug_log!("Error writing data to collaborator file: {:?}", err);
                     // Consider returning the error here for more explicit error handling
                     // return Err(err);
                 }
             } 
         },
         Err(err) => {
             debug_log!("Error creating collaborator file: {:?}", err);
             // Return the error here to propagate it
             return Err(err); 
         }
     } 
    
    Ok(()) 
}

fn check_collaborator_collisions(
    new_collaborator: &CollaboratorTomlData, 
    existing_collaborators: &Vec<CollaboratorTomlData> 
 ) -> Option<String> { 
    for existing in existing_collaborators { 
        if existing.user_name == new_collaborator.user_name { 
            return Some("Error: A collaborator with that username already exists!".to_string());
        } 
        // Add checks for IP and port conflicts
    }
    None // No collisions
}

fn add_collaborator_qa(
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> Result<(), io::Error> {

    println!("Name: Enter collaborator user name:");
    let mut new_username = String::new();
    io::stdin().read_line(&mut new_username)?;
    let new_username = new_username.trim().to_string();

    // Salt List!
    println!("Salt List: Press Enter for random, or type 'manual' for manual input");
    let mut new_usersalt_list_input = String::new();
    io::stdin().read_line(&mut new_usersalt_list_input)?;
    let new_usersalt_list_input = new_usersalt_list_input.trim().to_string();

    let new_usersalt_list: Vec<u128> = if new_usersalt_list_input == "manual" {
        let mut salts = Vec::new();
        for i in 1..=4 {
            println!("Enter salt {} (u128):", i);
            let mut salt_input = String::new();
            io::stdin().read_line(&mut salt_input)?;
            let salt: u128 = salt_input.trim().parse().expect("Invalid input, so using u128 input for salt");
            salts.push(salt);
        }
        salts
    } else {
        // Generate 4 random u128 salts
        (0..4)
            .map(|_| rand::thread_rng().gen())
            .collect()
    };
    
    println!("Using salts: {:?}", new_usersalt_list);
    
    
    // choice...
    // Get IP address input method
    // TODO for auto-detect don't use local-only ports... duh!!
    println!("Do you want to auto-detect IPv6 and IPv4? ('yes' or 'no' for manual input)");
    let mut pick_ip_find_method = String::new();
    io::stdin().read_line(&mut pick_ip_find_method)?;
    let pick_ip_find_method = pick_ip_find_method.trim().to_string();

    let (ipv4_addresses, ipv6_addresses) = if pick_ip_find_method == "yes" { 
        // Auto-detect IP addresses
        let detected_addresses = get_local_ip_addresses()?;
        let mut ipv4_addresses: Option<Vec<Ipv4Addr>> = None;
        let mut ipv6_addresses: Option<Vec<Ipv6Addr>> = None;

        for addr in detected_addresses {
            match addr {
                IpAddr::V4(v4) => {
                    if ipv4_addresses.is_none() {
                        ipv4_addresses = Some(Vec::new());
                    }
                    ipv4_addresses.as_mut().unwrap().push(v4);
                }
                IpAddr::V6(v6) => {
                    if ipv6_addresses.is_none() {
                        ipv6_addresses = Some(Vec::new());
                    }
                    ipv6_addresses.as_mut().unwrap().push(v6);
                }
            }
        }
        (ipv4_addresses, ipv6_addresses) // Return the detected addresses
    } else {
        // Manual IP address input
        println!("Enter IPv4 address (or 'done' if finished, leave blank to skip):");
        let ipv4_addresses = get_ipv4_addresses()?; 

        println!("Enter IPv6 address (or 'done' if finished, leave blank to skip):");
        let ipv6_addresses = get_ipv6_addresses()?; 
        (ipv4_addresses, ipv6_addresses) // Return the manually entered addresses
    };

    println!("Enter the collaborator's public GPG key ID (public, NOT PRIVATE!!):");
    let mut gpg_publickey_id = String::new();
    io::stdin().read_line(&mut gpg_publickey_id)?; 
    let gpg_publickey_id = gpg_publickey_id.trim().to_string();    
    
    println!("Enter the collaborator's public GPG key is ascii armored lines (public, NOT PRIVATE!!):");
    let mut gpg_key_public = String::new();
    io::stdin().read_line(&mut gpg_key_public)?; 
    let gpg_key_public = gpg_key_public.trim().to_string();

    println!("Enter the collaborator's sync interval in seconds (default: 60):");
    let mut sync_interval_input = String::new();
    io::stdin().read_line(&mut sync_interval_input)?;
    let sync_interval: u64 = sync_interval_input.trim().parse().unwrap_or(60);

    // Error Handling (You'll want to add more robust error handling here)
    if new_username.is_empty() { 
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Username cannot be empty",
        ));
    }

    // Create the CollaboratorTomlData struct
    let new_collaborator = CollaboratorTomlData::new(
        new_username, // for: user_name
        new_usersalt_list, // for: user_salt
        ipv4_addresses, 
        ipv6_addresses,
        gpg_publickey_id,
        gpg_key_public,
        sync_interval,
        get_current_unix_timestamp(), // for: updated_at_timestamp
    ); 

    // Load existing collaborators from files
    // let existing_collaborators = read_a_collaborator_setup_toml().unwrap_or_default();
    // let (existing_collaborators, errors) = read_one_collaborator_setup_toml().unwrap_or_default(); 

    // Persist the new collaborator
    add_collaborator_setup_file(
        new_collaborator.user_name.clone(), 
        new_collaborator.user_salt_list.clone(), 
        new_collaborator.ipv4_addresses, 
        new_collaborator.ipv6_addresses,
        new_collaborator.gpg_publickey_id, 
        new_collaborator.gpg_key_public, 
        new_collaborator.sync_interval,
        new_collaborator.updated_at_timestamp,
    )?; 

    println!("CollaboratorTomlData '{}' added!", new_collaborator.user_name); 
    Ok(())
} 

fn check_team_channel_collision(channel_name: &str) -> bool {
     let team_channels_dir = Path::new("project_graph_data/team_channels");
     let channel_path = team_channels_dir.join(channel_name);
     channel_path.exists() 
}

/// Represents the current state of a user's navigation within the UMA project graph.
///
/// This struct holds information about the currently active team channel, the current node,
/// and other session-related data. It is used to manage user navigation and track the context
/// of user interactions.
///
/// In UMA, the file path of the `node.toml` file within the `project_graph_data/team_channels` 
/// directory uniquely identifies a team channel. This method reads data from the `node.toml` 
/// file at the current path to determine the active team channel and load relevant information.
#[derive(Debug, Deserialize, Serialize, Clone)]
struct GraphNavigationInstanceState {
    local_owner_user: String, // Store the local user data here
    // local_owner_hash_list: Vec<u8>,
    active_team_channel: String,  // TODO new
    default_im_messages_expiration_days: u64,
    default_task_nodes_expiration_days: u64,
    tui_height: u8,
    tui_width: u8,
    current_full_file_path: PathBuf,
    current_node_teamchannel_collaborators_with_access: Vec<String>,
    current_node_name: String,
    current_node_owner: String,
    current_node_description_for_tui: String,
    current_node_directory_path: PathBuf,
    current_node_unique_id: u64,
    current_node_members: Vec<String>,
    home_square_one: bool,
    // app.&App,  // TODO really?
}

impl GraphNavigationInstanceState {
    /// Loads and updates the `GraphNavigationInstanceState` based on the `current_full_file_path`.
    ///
    /// This method is called whenever the user navigates to a new directory within the 
    /// UMA project graph. It determines the type of node (team-channel, project, 
    ///  messages, tasks, etc., etc.)
    /// based on the `current_full_file_path` and loads relevant information from the 
    /// `node.toml` file, updating the internal state accordingly.
    /// 
    /// ## Team Channel Nodes
    ///
    /// If the `current_full_file_path` indicates a team-channel node (a directory within 
    /// `project_graph_data/team_channels`), this method performs the following:
    ///
    /// 1. Sets the `active_team_channel` to the name of the team-channel. 
    /// 2. Loads collaborator port assignments from the `node.toml` file.
    /// 3. Populates the `collaborator_ports` field with a `HashMap` mapping collaborator 
    ///    usernames to their respective `CollaboratorPorts` struct. 
    ///
    /// ## Other Node Types
    ///
    /// For project nodes and task nodes, this method will load relevant data from 
    /// the `node.toml` file but will NOT load collaborator port assignments, as these 
    /// are only relevant at the team-channel level.
    /// 
    /// ## Error Handling
    ///
    /// If the `node.toml` file is not found or cannot be parsed, the method logs an error 
    /// message and returns without updating the state. 
    ///
    /// This function specifically loads Port assignments if the `current_full_file_path`
    /// corresponds to a team-channel node, as indicated by the path being within the 
    /// `project_graph_data/team_channels` directory. 
    ///
    /// Not all information has the same owner-author and privacy requirements and so cannot be obtained from any mythical singularity. Port-assignments are made by the owner of the team-channel so as to be guaranteed not to collide and adding a new user/collaborator will not disrupt existing processes/collaborators/users/workers/participants/network-connections. 
    /// A user's ip addresses and gpg keys and screen-name can only come from, and be owned by, that user/collaborator. 
    ///
    /// Likewise, the list of possible collaborators is set by the team-channel-owner. But whether another collaborator has actually shared their private connection data with you is and must be 100% their choice done by them and owned by them GPG signed by them and GPG encrypted for only 'you' (the current user) to use. 
    ///
    /// The 'collaborators' for your session are then an intersection between these two categories of sources of truth: the collaborators who have connected with you (their choice, their owned documents), and the collaborators invited to the team-channel by the team-channel-owner (their choice, their owned document). 
    /// Note: Your no-context set of all-collaborators is everyone in every channel, a general no-context address-book. 
    /// By analogy: Tom is organizing a flower show and says Alice Bob and you are invited, and he asks you to call them.
    /// Bob is the one who chooses who to invite.
    /// You have an address book that includes Alice and Bob and everyone else in your address book.
    ///
    /// To make these call-connections you need to find the intersection between these two sets:
    /// 1. Who did the team-owner (Tom) invite to the flower show?
    /// 2. Who is in your address book?
    ///
    /// You cannot call everyone in your address book, because Tom didn't invite everyone in your address book.
    /// And Tom can't tell you Bob's phone number and call availability information, because only Bob can tell you his own private information. 
    ///
    /// This means there are at least two sources or two different categories of truths that must be used when loading "state" for a session in a team-channel in Uma. 
    ///
    /// Note: it is crutial that he source of truth for whether a node is a team-channel node be the file-structure itself
    /// and that code to extract team-channel connection data (such as port-assignments) is never attempted used in other
    /// nodes such as non-team-channel nodes within that team-channel (nearly ~everything is a node, only a few are team-channels)
    fn look_read_node_toml(&mut self) {
        debug_log(&format!("fn look_read_node_toml() self.current_full_file_path -> {:?}", self.current_full_file_path)); 

        let node_toml_path = self.current_full_file_path.join("node.toml");
        debug_log!("node_toml_path -> {:?}", node_toml_path);
        
        // 2. Check if node.toml exists 
        if node_toml_path.exists() { 
            debug_log!("node.toml found at: {:?}", node_toml_path);

            // --- UPDATE current_node_directory_path.txt HERE ---
            let team_channel_dir_path = self.current_full_file_path.clone(); 
            if let Err(e) = fs::write(
                "project_graph_data/session_state_items/current_node_directory_path.txt", 
                team_channel_dir_path.to_string_lossy().as_bytes(), // Convert to byte slice
            ) {
                debug_log!("Error writing team channel directory path to file: {}", e);
                // Handle the error appropriately (e.g., display an error message)
            }

            
            // 1. Handle File Existence Error
            if !node_toml_path.exists() {
                debug_log!("ERROR: node.toml not found at {:?}. This directory is not a node.", node_toml_path);
                return; 
            }

            // 2. Handle TOML Parsing Error
            let this_node = match load_core_node_from_toml_file(&node_toml_path) { 
                Ok(node) => node,
                Err(e) => {
                    debug_log!("ERROR: Failed to load node.toml: {}", e); 
                    return; 
                }
            };

            // 3. Check if this is a Team Channel Node 
            // TODO maybe also check for a node.toml file
            let path_components: Vec<_> = self.current_full_file_path.components().collect();
            if path_components.len() >= 2 
                && path_components[path_components.len() - 2].as_os_str() == "team_channels" 
            {
                self.active_team_channel = this_node.node_name.clone();

                //maybe also check for a node.toml file
                
                // 5. Update GraphNavigationInstanceState with node.toml data (for Team Channel Nodes)
                self.current_node_teamchannel_collaborators_with_access = this_node.teamchannel_collaborators_with_access.clone();
                self.current_node_name = this_node.node_name.clone();
                self.current_node_owner = this_node.owner.clone();
                self.current_node_description_for_tui = this_node.description_for_tui.clone();
                self.current_node_directory_path = this_node.directory_path.clone();
                self.current_node_unique_id = this_node.node_unique_id;
                self.home_square_one = false;
                // Note: `current_node_members` appears to be unused, consider removing it
                
            }
        } // End of Team Channel Node Handling

        // ... (Rest of your logic for handling other node types) ...
    }    

    fn bootstrap_uma_session_network(state: &mut GraphNavigationInstanceState, app: &mut App) {
        // 1. Display list of available team-channels (using the TUI)
        // ... (You'll need to adapt your TUI code for this) ...
    
        // 2. Get user input (team-channel selection)
        // ...
    
        // 3. Load the selected team-channel's node.toml 
        // ...
    
        // 4. Establish sync state
        // ... (Follow the steps outlined in my previous response for establishing sync state) ... 
    
        // 5. Update app.current_path to the selected team-channel directory 
        // ...
    
        // 6. (Optional) Trigger an initial sync
        // ...
    }

    fn save_to_session_items(&self) -> Result<(), io::Error> {
            let session_items_path = Path::new("project_graph_data/session_state_items");

            // 1. Save simple string values as plain text:
            fs::write(session_items_path.join("local_owner_user.txt"), &self.local_owner_user)?;
            fs::write(session_items_path.join("active_team_channel.txt"), &self.active_team_channel)?;
            // ... (save other simple string values)

            // 2. Save u64 values as plain text:
            fs::write(session_items_path.join("default_im_messages_expiration_days.txt"), self.default_im_messages_expiration_days.to_string())?;
            fs::write(session_items_path.join("default_task_nodes_expiration_days.txt"), self.default_task_nodes_expiration_days.to_string())?;
            fs::write(session_items_path.join("current_node_unique_id.txt"), self.current_node_unique_id.to_string())?;

            // 3. Save PathBuf as plain text:
            // fs::write(session_items_path.join("current_full_file_path.txt"), self.current_full_file_path.to_string_lossy())?;
            // fs::write(session_items_path.join("current_node_directory_path.txt"), self.current_node_directory_path.to_string_lossy())?;
            fs::write(
                session_items_path.join("current_full_file_path.txt"), 
                self.current_full_file_path.as_os_str().to_string_lossy().as_bytes(), 
            )?;
        
            fs::write(
                session_items_path.join("current_node_directory_path.txt"), 
                self.current_node_directory_path.as_os_str().to_string_lossy().as_bytes(), 
            )?; 
            
            // 4. Save Vec<String> as TOML:
            let collaborators_toml = toml::to_string(&self.current_node_teamchannel_collaborators_with_access).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to serialize collaborators to TOML: {}", e),
                )
            })?;
            fs::write(session_items_path.join("current_node_teamchannel_collaborators_with_access.toml"), collaborators_toml)?;
            
            // ... (save other Vec<String> values similarly)

            Ok(())
    }
}
    

//e.g.
// // Load active_team_channel:
// self.active_team_channel = fs::read_to_string(session_items_path.join("active_team_channel.txt"))?;
    
    
#[derive(Debug, Deserialize, Serialize, Clone)]
enum NodePriority {
    High,
    Medium,
    Low,
}


/// Represents port assignments for a collaborator in a `CoreNode`.
///
/// This struct holds six different ports used for communication and synchronization
/// between two collaborators. 
/// Because Rust does not automatically deal with 'list of dicts' in python terms
/// this struct is a list (array) of 'dictionaries/hashmaps' which are a separate struct
/// so this list is a single list, that is a list of other structs that are dicts/hashmaps
#[derive(Debug, Deserialize, Serialize, Clone)]
struct ReadTeamchannelCollaboratorPortsToml {
    /// The port used by the REMOTE collaborator to signal readiness to receive data.
    collaborator_ports: Vec<AbstractTeamchannelNodeTomlPortsData>,
}


/*
the .toml files and the overall Uma~browser must be able to know their location in the overall project_graph_data/file-system

1. command 'make node' needs to be filled in to make a node in the 'current'
graph-dungeon location.
2. produce a .toml file in the node when node is made
3. load from the .toml file node is navigated into
4. node_name needs to be integrated, and accessed when the node is navigated into
*/

/// Represents a core node in the UMA project graph.
///
/// This struct holds information about a node, including its name, description, collaborators,
/// port assignments for collaborators, and other metadata. It is used to save and load node
/// data to and from `node.toml` files.
///
/// # Collaborator Ports
/// 
/// Collaborator port assignments are stored in the `abstract_collaborator_port_assignments` field, which is a 
/// `HashMap`. The keys of the `HashMap` are the usernames of the collaborators (strings), 
/// and the values are instances of the `CollaboratorPorts` struct. 
///
/// The `CollaboratorPorts` struct contains six `u16` fields representing the different ports 
/// assigned to each collaborator for synchronization purposes:
///  - `ready_port`: The port used by a collaborator to signal they are ready to receive data.
///  - `tray_port`: The port used to send files to a collaborator (their "in-tray").
///  - `gotit_port`: The port used by a collaborator to confirm receipt of a file.
///  - `self_ready_port`: The port this node listens on for ready signals from the collaborator.
///  - `self_tray_port`: The port this node listens on for incoming files from the collaborator.
///  - `self_gotit_port`: The port this node uses to confirm file receipt to the collaborator. 
///
/// ## Serialization and Deserialization
///
/// When saving a `CoreNode` to a `node.toml` file (using the `save_node_to_file` function), 
/// the `abstract_collaborator_port_assignments` field is serialized as a TOML table where the keys are the 
/// collaborator usernames and the values are tables containing the six port assignments.
///
/// When loading a `CoreNode` from a `node.toml` file (using the `load_node_from_file` function),
/// the TOML table representing collaborator ports is deserialized into the 
/// `abstract_collaborator_port_assignments` field. 
///
/// ## Example `node.toml` Section 
/// 
/// ```toml
/// [abstract_collaborator_port_assignments]
/// alice = { ready_port = 50001, tray_port = 50002, gotit_port = 50003, self_ready_port = 50004, self_tray_port = 50005, self_gotit_port = 50006 }
/// bob = { ready_port = 50011, tray_port = 50012, gotit_port = 50013, self_ready_port = 50014, self_tray_port = 50015, self_gotit_port = 50016 }
/// ```
/// 
/// there is a design and security debate over how to define a team-channel node
/// I think it is safer to define it as a physical directory basal location, in the team_channels direcorry
/// rather than give it ia declarative-definiiton where anyone could invent or uninvent a team-channel 
/// and all the port use that goes along with that
#[derive(Debug, Deserialize, Serialize, Clone)]
struct CoreNode {
    /// The name of the node. This is used for display and identification.
    node_name: String,
    /// A description of the node, intended for display in the TUI.
    description_for_tui: String,
    /// A unique identifier for the node, generated using a timestamp at node creation.
    node_unique_id: u64,
    /// The path to the directory on the file system where the node's data is stored.
    directory_path: PathBuf,
    /// An order number used to define the node's position within a list or hierarchy.
    order_number: u32,
    /// The priority of the node, which can be High, Medium, or Low.
    priority: NodePriority,
    /// The username of the owner of the node.
    owner: String,
    /// The Unix timestamp representing when the node was last updated.
    updated_at_timestamp: u64,
    /// The Unix timestamp representing when the node will expire.
    expires_at: u64,
    /// A vector of `CoreNode` structs representing the child nodes of this node.
    children: Vec<CoreNode>,
    /// An ordered vector of collaborator usernames associated with this node.
    teamchannel_collaborators_with_access: Vec<String>,
    /// A map containing port assignments for each collaborator associated with the node.
    abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
}

/// update_collaborator_sendqueue_timestamp_log
/// ### making a new timestamp (maybe good to do each session)
/// 1. pick a target collaborator
/// 2. make sure path exists:
/// ```path
/// sync_data/team_channel/collaborator_name/
/// ```
/// 2. make a mut u64 variable called back_of_queue_timestamp = 0
/// 3. crawl through the files and subdirectories (recursively) in the teamchannel (only the team_channel directory tree, not all of uma) looking at files:
/// 4. if a .toml file, 
/// 5. if owner=target_collaborator, 
/// 6. if updated_at_timestamp exists
/// 7. write/rewrite a stub-file of that timestamp to:
/// ```path
/// sync_data/team_channel/collaborator_name/372385339229
/// ```
/// 8. if timestamp is higher than back_of_queue_timestamp, then
/// back_of_queue_timestamp = new value
/// 9. write/rewrite:
/// ```path
/// sync_data/team_channel/collaborator_name/back_of_queue_timestamp
/// ```
/// - Note: the paper trail of timestamps allows backtracking easily for error correction. quick sort to e.g. go-back-five 
fn update_collaborator_sendqueue_timestamp_log(
    team_channel_name: &str,
    collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    let sync_data_dir = PathBuf::from("sync_data")
        .join(team_channel_name)
        .join(collaborator_name);
    fs::create_dir_all(&sync_data_dir)?;

    let mut back_of_queue_timestamp = 0;

    // 3. Crawl through the team channel directory tree
    for entry in WalkDir::new(PathBuf::from("project_graph_data").join(team_channel_name)) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("toml")) {
            // 4. If a .toml file
            let toml_string = fs::read_to_string(entry.path())?;
            let toml_value: Value = toml::from_str(&toml_string)?;

            // 5. If owner = target collaborator
            if toml_value.get("owner").and_then(Value::as_str) == Some(collaborator_name) {
                // 6. If updated_at_timestamp exists
                if let Some(timestamp) = toml_value.get("updated_at_timestamp").and_then(Value::as_integer) {
                    let timestamp = timestamp as u64;

                    // 7. Write stub file
                    let stub_file_path = sync_data_dir.join(timestamp.to_string());
                    fs::File::create(stub_file_path)?;

                    // 8. Update back_of_queue_timestamp
                    if timestamp > back_of_queue_timestamp {
                        back_of_queue_timestamp = timestamp;
                    }
                }
            }
        }
    }

    // 9. Write back_of_queue_timestamp
    let timestamp_file_path = sync_data_dir.join("back_of_queue_timestamp");
    fs::write(timestamp_file_path, back_of_queue_timestamp.to_string())?;

    Ok(back_of_queue_timestamp)
}




// /// Loads CollaboratorData from a TOML file.
// ///
// /// # Arguments
// ///
// /// * `file_path` - The path to the TOML file containing the collaborator data.
// ///
// /// # Returns
// ///
// /// * `Result<CollaboratorData, ThisProjectError>` - `Ok(CollaboratorData)` if the data is 
// ///    successfully loaded, `Err(ThisProjectError)` if an error occurs.
// fn load_collaborator_data_from_toml_file(file_path: &Path) -> Result<CollaboratorData, ThisProjectError> {
//     let toml_string = fs::read_to_string(file_path)?;
//     let collaborator_data: CollaboratorData = toml::from_str(&toml_string)?;
//     Ok(collaborator_data) 
// }

/// Loads a `CoreNode` from a TOML file, handling potential errors.
///
/// # Arguments
///
/// * `file_path` - The path to the TOML file containing the node data.
///
/// # Returns
///
/// * `Result<CoreNode, String>` - `Ok(CoreNode)` if the node is successfully loaded,
///    `Err(String)` containing an error message if an error occurs. 
fn load_core_node_from_toml_file(file_path: &Path) -> Result<CoreNode, String> {
    // 1. Read File Contents 
    let toml_string = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Error reading file: {} in load_core_node_from_toml_file", e)),
    };

    // 2. Parse TOML String 
    let toml_value: Value = match toml_string.parse() {
        Ok(value) => value,
        Err(e) => return Err(format!("Error parsing TOML in load_core_node_from_toml_file: {}", e)),
    };

    // 3. Deserialize into CoreNode Struct (Manually)
    let mut core_node = CoreNode {
        node_name: toml_value.get("node_name").and_then(Value::as_str).unwrap_or("").to_string(),
        description_for_tui: toml_value.get("description_for_tui").and_then(Value::as_str).unwrap_or("").to_string(),
        node_unique_id: toml_value.get("node_unique_id").and_then(Value::as_integer).unwrap_or(0) as u64,
        directory_path: PathBuf::from(toml_value.get("directory_path").and_then(Value::as_str).unwrap_or("")),
        order_number: toml_value.get("order_number").and_then(Value::as_integer).unwrap_or(0) as u32,
        priority: match toml_value.get("priority").and_then(Value::as_str).unwrap_or("Medium") {
            "High" => NodePriority::High,
            "Medium" => NodePriority::Medium,
            "Low" => NodePriority::Low,
            _ => NodePriority::Medium,
        },
        owner: toml_value.get("owner").and_then(Value::as_str).unwrap_or("").to_string(),
        updated_at_timestamp: toml_value.get("updated_at_timestamp").and_then(Value::as_integer).unwrap_or(0) as u64,
        expires_at: toml_value.get("expires_at").and_then(Value::as_integer).unwrap_or(0) as u64,
        children: Vec::new(), // You might need to load children recursively
        teamchannel_collaborators_with_access: toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array).map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
        abstract_collaborator_port_assignments: HashMap::new(),
    };

    // // 4. Handle abstract_collaborator_port_assignments
    // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
    //     for (pair_name, pair_data) in collaborator_assignments_table {
    //         debug_log("Looking for 'collaborator_ports' load_core...");
    //         if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
    //             let mut collaborator_ports = Vec::new();
    //             for port_data in ports_list {
    //                 // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
    //                 let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
    //                 // let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
    //                 let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
    //                 collaborator_ports.push(collaborator_port);
    //             }
    //             core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);
    //             // let mut collaborator_ports = Vec::new();
    //             // for port_data in ports_list {
    //             //     // Deserialize each ReadTeamchannelCollaboratorPortsToml from the array
    //             //     let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
    //             //     let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
    //             //     collaborator_ports.push(collaborator_port);
    //             // }
    //             // // this is doing what?
    //             // core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);

    //         }
    //     }
    // }
    // Inside load_core_node_from_toml_file
    // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
    if let Some(collaborator_assignments_table) = toml_value.get("collaborator_port_assignments").and_then(Value::as_table) {
        for (pair_name, pair_data) in collaborator_assignments_table {
            debug_log("Looking for 'collaborator_ports' load_core...");
            if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
                // Create a vector to hold ReadTeamchannelCollaboratorPortsToml instances for this pair
                let mut ports_for_pair = Vec::new();
    
                for port_data in ports_list {
                    // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
                    let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
                    let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
    
                    // Create ReadTeamchannelCollaboratorPortsToml and add it to the vector
                    let read_teamchannel_collaborator_ports_toml = ReadTeamchannelCollaboratorPortsToml {
                        collaborator_ports: vec![collaborator_port], // Wrap in a vector
                    };
                    ports_for_pair.push(read_teamchannel_collaborator_ports_toml);
                }
    
                // Insert the vector of ReadTeamchannelCollaboratorPortsToml into the HashMap
                core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), ports_for_pair);
            }
        }
    }
    
    Ok(core_node)
}

/*
/// The name of the node. This is used for display and identification.
node_name: String,
/// A description of the node, intended for display in the TUI.
description_for_tui: String,
/// A unique identifier for the node, generated using a timestamp at node creation.
node_unique_id: u64,
/// The path to the directory on the file system where the node's data is stored.
directory_path: PathBuf,
/// An order number used to define the node's position within a list or hierarchy.
order_number: u32,
/// The priority of the node, which can be High, Medium, or Low.
priority: NodePriority,
/// The username of the owner of the node.
owner: String,
/// The Unix timestamp representing when the node was last updated.
updated_at_timestamp: u64,
/// The Unix timestamp representing when the node will expire.
expires_at: u64,
/// A vector of `CoreNode` structs representing the child nodes of this node.
children: Vec<CoreNode>,
/// An ordered vector of collaborator usernames associated with this node.
teamchannel_collaborators_with_access: Vec<String>,
/// A map containing port assignments for each collaborator associated with the node.
abstract_collaborator_port_assignments: HashMap<String, CollaboratorPorts>,
*/
/// Creates a new `CoreNode` instance.
///
/// # Arguments
///
/// * `node_name` - The name of the node.
/// * `description_for_tui` - A description for display in the TUI.
/// * `directory_path` - The path to the node's directory.
/// * `order_number` - The order number for the node.
/// * `priority` - The priority of the node.
/// * `owner` - The username of the node's owner.
/// * `collaborators` - An ordered vector of collaborator usernames.
/// * `abstract_collaborator_port_assignments` - A map of collaborator port assignments.
///
/// # Returns
///
/// * A new `CoreNode` instance with the given attributes.
impl CoreNode {

    fn new(
        node_name: String,
        description_for_tui: String,
        directory_path: PathBuf,
        order_number: u32,
        priority: NodePriority,
        owner: String,
        teamchannel_collaborators_with_access: Vec<String>,
        abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
    ) -> CoreNode {
        let expires_at = get_current_unix_timestamp() + 86400; // Expires in 1 day (for now)
        let updated_at_timestamp = get_current_unix_timestamp();
        let node_unique_id = get_current_unix_timestamp(); 

        CoreNode {
            node_name,
            description_for_tui,
            node_unique_id,
            directory_path,
            // sec_to_next_sync,  // 3-5 seconds per sync is normal, but team can make more or less for traffic/need balance
            order_number,
            priority,
            owner,
            updated_at_timestamp,
            expires_at,
            children: Vec::new(),
            teamchannel_collaborators_with_access,        
            abstract_collaborator_port_assignments, 
        }
    }

    /// Saves the `CoreNode` data to a `node.toml` file.
    ///
    /// This function serializes the `CoreNode` struct into TOML format and writes 
    /// it to a file at the path specified by the `directory_path` field, creating
    /// the directory if it doesn't exist.
    ///
    /// # Error Handling
    /// 
    /// Returns a `Result<(), io::Error>` to handle potential errors during:
    ///  - TOML serialization.
    ///  - Directory creation. 
    ///  - File writing.
    ///
    /// If any error occurs, an `io::Error` is returned, containing information 
    /// about the error. 
    /// 
    fn save_node_to_file(&self) -> Result<(), io::Error> {
        // 1. Serialize the CoreNode struct to a TOML string.
        let toml_string = toml::to_string(&self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("TOML serialization error: {}", e),
            )
        })?;

        // 2. Construct the full file path for the node.toml file.
        let file_path = self.directory_path.join("node.toml");

        // 3. Create the directory if it doesn't exist. 
        if let Some(parent_dir) = file_path.parent() {
            fs::create_dir_all(parent_dir)?;
        }

        // 4. Write the TOML data to the file.
        fs::write(file_path, toml_string)?;

        // 5. Return Ok(()) if the save was successful.
        Ok(()) 
    }
   
    /// Adds a new child node to the current node's `children` vector.
    ///
    /// # Arguments
    ///
    /// * `collaborators` - An ordered vector of usernames for collaborators who have access to this child node.
    /// * `abstract_collaborator_port_assignments` - A HashMap mapping collaborator usernames to their respective `CollaboratorPorts` struct, containing port assignments for synchronization.
    /// * `owner` - The username of the owner of this child node.
    /// * `description_for_tui` - A description of the child node, intended for display in the TUI.
    /// * `directory_path` - The file path where the child node's data will be stored.
    /// * `order_number` - The order number of the child node, determining its position within a list or hierarchy.
    /// * `priority` - The priority level of the child node (High, Medium, or Low).
    fn add_child(
        &mut self,
        teamchannel_collaborators_with_access: Vec<String>, 
        abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
        owner: String,
        description_for_tui: String,
        directory_path: PathBuf,
        order_number: u32,
        priority: NodePriority,
    ) {
        let child = CoreNode::new(
            self.node_name.clone(),
            description_for_tui,
            directory_path,
            order_number,
            priority,
            owner,
            teamchannel_collaborators_with_access,        
            abstract_collaborator_port_assignments,   
        );
        self.children.push(child);
    }
    
    fn update_updated_at_timestamp(&mut self) {
        self.updated_at_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    }

    fn load_node_from_file(path: &Path) -> Result<CoreNode, io::Error> {
        let toml_string = fs::read_to_string(path)?;
        let node: CoreNode = toml::from_str(&toml_string).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e))
        })?; 
        Ok(node)
    }
}

// Generic function to save any serializable data to a TOML file
pub fn save_toml_to_file<T: Serialize>(data: &T, file_path: &Path) -> Result<(), Error> {
    let toml_string = toml::to_string(data).map_err(|e| {
        Error::new(
            std::io::ErrorKind::Other,
            format!("TOML serialization error: {}", e),
        )
    })?;
    fs::write(file_path, toml_string)?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct NodeInstMsgBrowserMetadata {
    // every .toml has these four
    owner: String, // owner of this item
    teamchannel_collaborators_with_access: Vec<String>, 
    updated_at_timestamp: u64, // utc posix timestamp
    expires_at: u64, // utc posix timestamp
    
    node_name: String,
    path_in_node: String,
    expiration_period_days: u64,
    max_message_size_char: u64,
    total_max_size_mb: u64,
}

impl NodeInstMsgBrowserMetadata {
    fn new(
        node_name: &str,
        owner: String
    ) -> NodeInstMsgBrowserMetadata {
        NodeInstMsgBrowserMetadata {
            node_name: node_name.to_string(),
            path_in_node: "/instant_message_browser".to_string(), // TODO
            expiration_period_days: 30, // Default: 7 days
            max_message_size_char: 4096, // Default: 4096 characters
            total_max_size_mb: 512, // Default: 1024 MB
            updated_at_timestamp: get_current_unix_timestamp(),
            expires_at: get_current_unix_timestamp(),  // TODO update this with real something
            teamchannel_collaborators_with_access: Vec::new(), // by default use state-struct node members
            owner: owner,
        }
    }
}

/*
Note: this might get generalized to fit in with vote an other files
but only if that is best
unless there is a clear reason to included created_at, it should not be included
nothing should be included with empirical data in support
*/
#[derive(Debug, Deserialize, Serialize)]
struct InstantMessageFile {
    // every .toml has these four
    owner: String, // owner of this item
    teamchannel_collaborators_with_access: Vec<String>, 
    updated_at_timestamp: u64, // utc posix timestamp
    expires_at: u64, // utc posix timestamp
    
    node_name: String, // Name of the node this message belongs to
    filepath_in_node: String, // Relative path within the node's directory
    text_message: String,
    links: Vec<String>, 
    signature: Option<String>,
}

impl InstantMessageFile {
    fn new(
        owner: &str,
        node_name: &str, // Add node name as a parameter
        filepath_in_node: &str, // Add filepath_in_node as a parameter
        text_message: &str,
        signature: Option<String>,
        graph_navigation_instance_state: &GraphNavigationInstanceState,  // gets uma.toml data
    ) -> InstantMessageFile {
        let timestamp = get_current_unix_timestamp();
        // Calculate expiration date using the value from local_user_metadata
        let expires_at = timestamp + 
            (graph_navigation_instance_state.default_im_messages_expiration_days * 24 * 60 * 60);
        let teamchannel_collaborators_with_access = graph_navigation_instance_state.current_node_teamchannel_collaborators_with_access.clone();

        InstantMessageFile {
            owner: owner.to_string(),
            teamchannel_collaborators_with_access: teamchannel_collaborators_with_access,
            node_name: node_name.to_string(), // Store the node name
            filepath_in_node: filepath_in_node.to_string(), // Store the filepath
            text_message: text_message.to_string(),
            updated_at_timestamp: timestamp, // utc posix timestamp
            expires_at: expires_at, // utc posix timestamp // TODO!! update this
            links: Vec::new(),
            signature,
        }
    }
}

/// Creates a new team-channel directory and its associated metadata.
/// 
/// This function sets up the basic directory structure and files for a new team channel
/// within the UMA project graph. It creates the necessary subdirectories and initializes
/// the `node.toml` file with default values.
///
/// # Arguments
///
/// * `team_channel_name` - The name of the team channel to be created. This name will be used
///   for the directory name and in the `node.toml` metadata.
/// * `owner` - The username of the owner of the team channel.
///
/// TODO: where is the port node system setup here?
fn create_team_channel(team_channel_name: String, owner: String) {
    let team_channels_dir = Path::new("project_graph_data/team_channels");
    let new_channel_path = team_channels_dir.join(&team_channel_name);

    // 1. Create the team channel directory and subdirectories
    if !new_channel_path.exists() {
        fs::create_dir_all(new_channel_path.join("instant_message_browser"))
            .expect("Failed to create team channel and subdirectories");

        // 2. Create 0.toml for instant_message_browser with default metadata
        let metadata_path = new_channel_path.join("instant_message_browser").join("0.toml");
        let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
        save_toml_to_file(&metadata, &metadata_path).expect("Failed to create 0.toml"); 
    }
    //     /*
    //     fn new(
    // TODO update this
    //     ) -> Node {
    //     */
    
    // 3. Create node.toml with initial data for the team channel
    let new_node = CoreNode::new(
        team_channel_name.clone(),
        team_channel_name.clone(),
        new_channel_path.clone(),
        5,
        NodePriority::Medium,
        owner,
        Vec::new(), // Empty collaborators list for a new channel
        HashMap::new(), // Empty collaborator ports map for a new channel
    );

    new_node.save_node_to_file().expect("Failed to save initial node data"); 
}

fn gpg_clearsign_file_to_sendbytes(
    file_path: &Path,
) -> Result<Vec<u8>, ThisProjectError> {
    // 1. Create a unique temporary file path in the OS temp directory.
    let mut temp_dir = std::env::temp_dir();
    let temp_file_name = format!("uma_temp_{}.toml", get_current_unix_timestamp()); // Or use a UUID for stronger uniqueness
    temp_dir.push(temp_file_name);

    // 2. Copy the original file to the temporary location.
    fs::copy(file_path, &temp_dir)?;

    // 3. Clearsign the temporary file, capturing the output.  Redirect stderr for error handling.
    let clearsign_output = Command::new("gpg")
        .arg("--clearsign")
        .arg("--output")
        .arg("-") // Redirect to stdout
        .arg(&temp_dir)
        .stderr(std::process::Stdio::piped())
        .output()?;

    // Handle potential GPG errors.
    if !clearsign_output.status.success() {
        let stderr = String::from_utf8_lossy(&clearsign_output.stderr);
        return Err(ThisProjectError::GpgError(format!(
            "GPG clearsign failed: {}",
            stderr
        )));
    }
    let clearsigned_bytes = clearsign_output.stdout;

    // 4. Clean up the temporary file.
    fs::remove_file(&temp_dir)?; // TODO Handle potential errors if you wish

    debug_log!(
        "(inHRCD)gpg_clearsign_file_to_sendbytes clearsigned_bytes {:?}",
        clearsigned_bytes   
    );

    // 5. Return the encrypted, clearsigned bytes.
    Ok(clearsigned_bytes)
}

fn gpg_encrypt_to_bytes(data: &[u8], recipient_public_key: &str) -> Result<Vec<u8>, ThisProjectError> {
    debug_log!(
        "(inHRCD) STARTING @-|i|- gpg_encrypt_to_bytes() data {:?}",
        data   
    );

    // 1. Create a temporary file for the public key.
    let mut temp_key_file = std::env::temp_dir();
    temp_key_file.push("uma_temp_key.asc");
    let mut file = File::create(&temp_key_file)?;
    file.write_all(recipient_public_key.as_bytes())?;

    debug_log!("(inHRCD) gpg_encrypt_to_bytes() temp_key_file path {:?}", temp_key_file);
    
    // 2. GPG encrypt, reading the recipient key from the temporary file.
    let mut gpg = Command::new("gpg")
        .arg("--encrypt")
        .arg("--recipient-file")
        .arg(&temp_key_file)
        .stdin(Stdio::piped())       // Correct usage for stdin
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;


    // Write data to stdin.
    if let Some(mut stdin) = gpg.stdin.take() {
        stdin.write_all(data)?;
    } else {
        // Consider a better error type...
        return Err(ThisProjectError::GpgError("Failed to open GPG's stdin".into()));
    };

    let output = gpg.wait_with_output()?;

    debug_log!(
        "(inHRCD) gpg_encrypt_to_bytes() output {:?}",
        output   
    );
    
    // 3. Clean up the temporary key file.
    remove_file(temp_key_file)?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ThisProjectError::GpgError(format!("GPG encryption failed: {}", stderr)))
    }
}

/// Decrypts GPG-encrypted data from a byte slice using a provided GPG private key.
///
/// # Purpose
/// This function takes encrypted data as bytes and a GPG private key, and attempts to decrypt 
/// the data using the GPG command-line tool. It handles the decryption process by creating 
/// temporary files and using GPG in a non-interactive, batch mode.
///
/// # Security Considerations
/// - Temporary files are created and immediately deleted after use
/// - Uses batch mode to prevent interactive prompts
/// - Minimizes potential security risks associated with key handling
///
/// # Arguments
/// * `data` - A byte slice containing the encrypted data to be decrypted
/// * `your_gpg_key` - A string containing the GPG private key used for decryption
///
/// # Returns
/// * `Ok(Vec<u8>)` - The decrypted data as a vector of bytes if decryption is successful
/// * `Err(ThisProjectError)` - An error if decryption fails, with details about the failure
///
/// # Errors
/// This function can return errors in several scenarios:
/// - Invalid or incorrect GPG key
/// - Corrupted encrypted data
/// - GPG command-line tool not installed or accessible
/// - Insufficient permissions
/// - Temporary file creation or deletion failures
///
/// # Example
/// ```rust
/// let encrypted_data: &[u8] = // ... some encrypted bytes
/// let private_key: &str = // ... GPG private key
/// match gpg_decrypt_from_bytes(encrypted_data, private_key) {
///     Ok(decrypted_data) => {
///         // Use decrypted data
///         println!("Decryption successful!");
///     },
///     Err(e) => {
///         // Handle decryption error
///         eprintln!("Decryption failed: {:?}", e);
///     }
/// }
/// ```
///
/// # Notes
/// - Requires GPG to be installed on the system
/// - Temporary files are created in the system's temporary directory
/// - The function uses non-interactive GPG mode to prevent hanging on prompts
///
/// # Performance
/// - Creates temporary files for key and encrypted data
/// - Spawns a GPG subprocess for decryption
/// - Recommended for moderate-sized encrypted data
///
/// # Thread Safety
/// - Not guaranteed to be thread-safe due to temporary file creation
/// - Should be used with caution in multi-threaded contexts
fn gpg_decrypt_from_bytes(data: &[u8], your_gpg_key: &str) -> Result<Vec<u8>, ThisProjectError> {
    debug_log("gpg_decrypt_from_bytes()-1. Start! ");

    // 1. Create temporary files
    let mut temp_key_file = std::env::temp_dir();
    temp_key_file.push("uma_temp_privkey.asc");
    fs::write(&temp_key_file, your_gpg_key)?;

    let mut temp_encrypted_file = std::env::temp_dir();
    temp_encrypted_file.push("uma_temp_encrypted.gpg");
    fs::write(&temp_encrypted_file, data)?;

    // 2. Run GPG decryption
    let mut child = Command::new("gpg")
        .arg("--decrypt")
        .arg("--batch")  // Non-interactive mode
        .arg("--yes")    // Assume yes to prompts
        .arg("--quiet")  // Minimal output
        .arg("--no-tty") // No terminal interaction
        .arg("-") // Read from stdin
        .stdin(Stdio::piped())       
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())       
        .spawn()?;
    
    // Write the encrypted data to the child process's standard input
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(data)?;
        stdin.flush()?;
    }
    
    let output = child.wait_with_output()?;

    debug_log!("gpg_decrypt_from_bytes()-4. output {:?}", output);    
    
    // 3. Remove temporary files (important for security)
    fs::remove_file(temp_key_file)?;
    fs::remove_file(temp_encrypted_file)?;

    // 4. Handle output and errors
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ThisProjectError::GpgError(format!("GPG decryption failed: {}", stderr)))
    }
}

// // use std::io::Error;
// fn extract_clearsign_data(clearsigned_data: &[u8]) -> Result<Vec<u8>, ThisProjectError> {
//     let clearsigned_string = String::from_utf8_lossy(clearsigned_data);

//     // 1. Split the clearsigned message into its components (original data and signature).
//     let parts: Vec<&str> = clearsigned_string
//         .split("-----BEGIN PGP SIGNATURE-----")
//         .collect();

//     // 2. Handle cases where the signature is missing or malformed.
//     if parts.len() < 2 {
//         return Err(ThisProjectError::GpgError("Invalid clearsigned data format: Missing signature".into()));
//     }

//     // 3. Extract and return the data from before the signature.
//     let original_data = parts[0].trim().as_bytes().to_vec(); // Convert to Vec<u8>
    
//     debug_log!(
//         "extract_clearsign_data original_data: {:?}",
//         original_data   
//     );

//     Ok(original_data)
// }

// fn extract_clearsign_data(clearsigned_data: &[u8]) -> Result<Vec<u8>, ThisProjectError> {
//     let clearsigned_string = String::from_utf8_lossy(clearsigned_data);

//     // Split at the beginning of the signature
//     let parts: Vec<&str> = clearsigned_string
//         .split("-----BEGIN PGP SIGNATURE-----")
//         .collect();

//     if parts.len() < 2 {
//         return Err(ThisProjectError::GpgError("Invalid clearsigned data: Missing signature".into()));
//     }

//     // Extract the message part (before the signature)
//     let message_part = parts[0];

//     // Find the first non-whitespace character
//     let start_index = message_part
//         .find(|c: char| !c.is_whitespace())
//         .unwrap_or(0); // Default to 0 if no non-whitespace is found

//     // Extract the actual message content
//     let message_content = &message_part[start_index..];
//     // and Trim leading and trailing whitespace from the extracted message:
//     let trimmed_message = message_content.trim();


//     Ok(trimmed_message.as_bytes().to_vec())
// }

// fn extract_clearsign_data(clearsigned_data: &[u8]) -> Result<Vec<u8>, ThisProjectError> {
//     let clearsigned_string = String::from_utf8_lossy(clearsigned_data);

//     // Split at the beginning of the signature
//     let parts: Vec<&str> = clearsigned_string
//         .split("-----BEGIN PGP SIGNATURE-----")
//         .collect();

//     if parts.len() < 2 {
//         return Err(ThisProjectError::GpgError("Invalid clearsigned data: Missing signature".into()));
//     }

//     // Extract the message part (before the signature)
//     let message_part = parts[0];

//     // Split into lines and remove the first 3 lines
//     let message_lines: Vec<&str> = message_part
//         .lines()
//         .skip(3)
//         .collect();

//     // Join the remaining lines
//     let message_content = message_lines.join("\n");

//     Ok(message_content.as_bytes().to_vec())
// }

fn extract_clearsign_data(clearsigned_data: &[u8]) -> Result<Vec<u8>, ThisProjectError> {
    let clearsigned_string = String::from_utf8_lossy(clearsigned_data);

    // Split at the beginning of the signature
    let parts: Vec<&str> = clearsigned_string
        .split("-----BEGIN PGP SIGNATURE-----")
        .collect();

    if parts.len() < 2 {
        return Err(ThisProjectError::GpgError("Invalid clearsigned data: Missing signature".into()));
    }

    // Extract the message part (before the signature)
    let message_part = parts[0];

    // Split the message part by lines and skip the PGP header lines
    let message_lines: Vec<&str> = message_part
        .lines()
        .skip_while(|line| 
            line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") || 
            line.starts_with("Hash:") || 
            line.trim().is_empty()
        )
        .collect();

    // Join the remaining lines
    let message_content = message_lines.join("\n");

    Ok(message_content.as_bytes().to_vec())
}

/// Prepares file contents for secure sending by clearsigning and encrypting them.
///
/// This function reads the contents of the file at the given `file_path`, 
/// clearsigns the content using GPG to ensure integrity and non-repudiation, 
/// and then encrypts the clearsigned content using the provided 
/// `recipient_public_key` for confidentiality.
///
/// # Arguments
///
/// * `file_path`: The path to the file whose contents should be processed.
/// * `recipient_public_key`: The recipient's GPG public key used for encryption.
///
/// # Returns
///
/// * `Ok(Vec<u8>)`: A vector of bytes containing the encrypted, clearsigned file content on success.
/// * `Err(ThisProjectError)`: An error if file reading, clearsigning, or encryption fails.
fn wrapper__path_to_clearsign_to_gpgencrypt_to_send_bytes(
    file_path: &Path, 
    recipient_public_key: &str
) -> Result<Vec<u8>, ThisProjectError> {

    // 1. Clearsign the file contents.
    let clearsigned_content = gpg_clearsign_file_to_sendbytes(file_path)?;

    // 2. Encrypt the clearsigned content.
    let encrypted_content = gpg_encrypt_to_bytes(&clearsigned_content, recipient_public_key)?;

    debug_log!(
        "(in HRCD) wrapper__path_to_clearsign_to_gpgencrypt_to_send_bytes  encrypted_content {:?}",
        &encrypted_content   
    );
    
    Ok(encrypted_content)
}

/// string-mod: remove_non_alphanumeric
/// takes a string slice (&str) as input and returns a new String that 
/// contains only the ASCII alphanumeric characters from the input string. 
/// The original string is not modified. 
///
fn remove_non_alphanumeric(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}


fn add_im_message(
    message_path: &Path,
    owner: &str,
    text: &str,
    signature: Option<String>,
    graph_navigation_instance_state: &GraphNavigationInstanceState, // Pass local_user_metadata here
) -> Result<(), io::Error> {
    // separate name and path
    let parent_dir = if let Some(parent) = message_path.parent() {
        parent
    } else {
        Path::new("")
    };

    // Now you can use `parent_dir` as needed
    // For example, you can check if it's an empty string
    if parent_dir == Path::new("") {
        debug_log("The path has no parent directory.");
    } else {
        debug_log(&format!("parent directory  {:?}", parent_dir)); 
    }

    // Read 0.toml to get this instant messager browser room's settings
    let metadata_path = parent_dir.join("0.toml"); // Assuming path is the instant_message_browser directory
    let metadata_string = fs::read_to_string(metadata_path)?;
    let metadata: NodeInstMsgBrowserMetadata = toml::from_str(&metadata_string)
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e)))?;

    // Extract node name and file path
    let node_name = metadata.node_name;
    let filepath_in_node = metadata.path_in_node;
    let message = InstantMessageFile::new(
        owner, // owner: &str,
        &node_name, // node_name: &str, , // Add node name as a parameter
        &filepath_in_node, // filepath_in_node: &str, , // Add filepath_in_node as a parameter
        text, // text_message: &str,
        signature, // signature: Option<String>,
        graph_navigation_instance_state, // graph_navigation_instance_state: &GraphNavigationInstanceState,  // gets uma.toml data
    );
    let toml_data = toml::to_string(&message).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
    })?; // Wrap TOML error in io::Error
    fs::write(message_path, toml_data)?;
    Ok(())
}

/// ## State, Initialization & Network
/// If as a vignette, let's look at a brief walkthrough of Alice starting up Uma as she embarks on a build with Bob. 
///
/// 1. Alice starts Uma
/// 2. Uma run initialization:
/// Initialization checks:
/// - is this the first time (here we will assume it is not the first setup)
/// (perhaps, is there a hash-salt to check the uma.toml configuration file)
/// - node-graph navigation is set up as starting from square one: location is ~home_square_one=true, because Alice has not yet picked which team_channel she wants to use/sync-with/view/join/enter however said.
/// - a mostly blank ~GraphNavigationState is filled-in (or filled-out)
/// - CWD (current working directory (path)) is set to home_square_one, which is not in any team_channel
/// - a basic home_square_one TUI is displayed showing what team_channels Alice can join/view/enter etc. (ones she has been invited to and has been sent and has loaded the team_channel configuration files for)
/// - Uma listens for Alice's 'command' which can be the number of a listed team_channel (to go to) or options such as log-view, quit, help, make a new team, etc.
/// - Alice picks alice_and_bobs_best_team_ever channel, option: "1"
/// Now Uma needs to do three important things:
/// 1. Uma needs to update graph navigation as with any 'move' within the dungeon-of-rooms of graph nodes.
/// 2. Uma needs change from being at home-base-square-one (no context for 'state') to being in a channel with users and configurations: there is now 'state' to fill-in for the ~graph_navigation_state. 
/// 3. Uma needs to set up the uma_network, which in particular involves:
/// - getting the 'actual list' of collaborators in that team-channel to connect with (which is an intersection of the team-owner's (potential) team-members list and Alice's actual whole 'address-book' of all real contacts on all teams. 
/// - uma_network needs the port-assignments from the team_channel toml (set by the team-owner, so there is no port-collision or source-of-truth mixup) 
/// - uma_network needs the ip (ipv6, ipv4, etc.) for each collaborator, which comes from that collaborator-owned toml (and probably that collaborator's public gpg key)
///
/// Note: If Alice returns to home, all this 'state' is deleted and Uma returns to home-square-one as if she restarted the program. (In fact...it might even be easiest to literally restart to make that process clean.)
fn initialize_uma_application() -> Result<(), Box<dyn std::error::Error>> {
    // Welcome to Uma Land!!
    debug_log("Staring initialize_uma_application()");

    // --- 1. CHECK FOR & SETUP uma.toml ---
    let uma_toml_path = Path::new("uma.toml");
    if !uma_toml_path.exists() {
        /*
        This uses the struct method 'new' to make a standard
        default but name-less file
        then Q&A user into sets that owner-name.
        
        either way, 'owner' needs to be available 
        if a new chanel needs to be created (as the owner)
        */
        // Prompt for owner and create uma.toml
        println!("Welcome to the Uma Collaboration Tools. Please enter your username (this will be the owner for this Uma 'instance'):");
        let mut owner_input = String::new();
        io::stdin().read_line(&mut owner_input).unwrap();
        let owner = owner_input.trim().to_string();

        let local_user_metadata = LocalUserUma::new(owner); // Create LocalUserUma
        
        if let Err(e) = local_user_metadata.save_owner_to_file(&uma_toml_path) { 
            eprintln!("Failed to create uma.toml: {}", e);
            // Handle the error (e.g., exit gracefully) 
            return Ok(()); 
        }
        debug_log!("uma.toml created successfully!"); 
    }
    
    // ... 2. Load user metadata from the now-existing uma.toml
    let user_metadata = match toml::from_str::<LocalUserUma>(&fs::read_to_string(uma_toml_path)?) {
        Ok(metadata) => {
            debug_log!("uma.toml loaded successfully!");
            metadata
        },
        Err(e) => {
            eprintln!("Failed to load or parse uma.toml: {}", e); 
            return Ok(()); 
        }
    };

    // Set the owner from the loaded metadata
    let owner = user_metadata.uma_local_owner_user;

    // ... 2. Load user metadata from the now-existing uma.toml
    let user_metadata = match toml::from_str::<LocalUserUma>(&fs::read_to_string(uma_toml_path)?) {
        Ok(metadata) => {
            debug_log!("uma.toml loaded successfully!");
            metadata
        },
        Err(e) => {
            eprintln!("Failed to load or parse uma.toml: {}", e); 
            return Ok(()); 
        }
    };

    
    // // --- 3. CHECK FOR PORT COLLISIONS ---
    // // You can now safely access user_metadata.uma_local_owner_user if needed
    // if let Err(e) = check_all_ports_in_team_channels() {
    //     eprintln!("Error: {}", e); 
    //     debug_log!("Error: {}", e);
    //     return; 
    // }

    // // ... 4. CREATE DIRECTORIES --- 
    
    
    // Check if the data directory exists
    let project_graph_directory = Path::new("project_graph_data");
    if !project_graph_directory.exists() {
        // If the directory does not exist, create it
        fs::create_dir_all(project_graph_directory).expect("Failed to create project_graph_data directory");
    }


    // Check if the sync_data directory exists,
    // and recursively erase all old files.
    // This is 'session' state for sync which must
    // be new each start-up session.
    // Make a fresh session sync directory
    // note: each 'local instance' should be specific
    // to the location of the uma executable file
    // more than one user may be running on a given computer
    let sync_data_directory = Path::new("sync_data");
    if sync_data_directory.exists() {
        // If the directory exists, remove it recursively
        if let Err(e) = remove_dir_all(sync_data_directory) {
            // Handle the error appropriately, e.g., log it and continue, or return an error if you want to stop initialization
            debug_log!("Error removing sync_data directory: {}", e);
            // Or: return Err(e.into()); // Or handle the error differently
        }
    }
    // Create the directory fresh for the new session.
    fs::create_dir_all(sync_data_directory).expect("Failed to create sync_data directory");
    
    /////////////////////
    // Log Housekeeping
    /////////////////////

    // 1. Create the archive directory if it doesn't exist.
    // saves archives not in the project_graph_data directory, not for sync
    let mut uma_archive_dir = PathBuf::new(); // Start with an empty PathBuf safe path os
    uma_archive_dir.push("uma_archive");    // Push the 'uma_archive' directory
    uma_archive_dir.push("logs");            // Push the 'logs' subdirectory

    if !uma_archive_dir.exists() {
        fs::create_dir_all(&uma_archive_dir).expect("Failed to create uma_archive directory");
    }    

    // 2. Get the current timestamp.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!")
        .as_secs();

    // 3. Construct the new archive file path.
    let archived_log_path = uma_archive_dir.join(format!("uma__{}.log", timestamp));

    // 4. Rename (move) the uma.log file to the archive directory.
    if let Err(e) = fs::rename("uma.log", &archived_log_path) {
        eprintln!("Failed to archive uma.log: {}", e); // Handle the error, but don't stop initialization.
    }


    // Check for port collisions across all team channels
    if let Err(e) = check_all_ports_in_team_channels() {
        eprintln!("Error: {}", e); // Print the error message
        debug_log!("Error: {}", e);
        // Handle the error as needed (e.g., exit UMA)
        return Ok(());
    }
    
    get_local_ip_addresses();
    

    // Ensure project_graph_data/team_channels directory exists
    let team_channels_dir = project_graph_directory.join("team_channels");
    if !team_channels_dir.exists() {
        fs::create_dir_all(&team_channels_dir).expect("Failed to create team_channels directory");
    }

    // Ensure project_graph_data/collaborator_files_address_book directory exists
    let collaborator_files_address_book_dir = project_graph_directory.join("collaborator_files_address_book");
    if !collaborator_files_address_book_dir.exists() {
        fs::create_dir_all(&collaborator_files_address_book_dir).expect("Failed to create collaborator_files_address_book directory");
    }
    
    // Ensure project_graph_data/session_state_items directory exists
    let session_state_dir = project_graph_directory.join("session_state_items");
    if !session_state_dir.exists() {
        fs::create_dir_all(&session_state_dir).expect("Failed to create session_state_items directory");
    }

    // Ensure project_graph_data/sync_state_items directory exists
    let sync_state_dir = project_graph_directory.join("sync_state_items");
    if !sync_state_dir.exists() {
        fs::create_dir_all(&sync_state_dir).expect("Failed to create sync_state_items directory");
    }
    
    // To stop sync from starting before a channel is entered:
    initialize_ok_to_start_sync_flag_to_false();

    // Check if there are any directories in project_graph_data/team_channels
    debug_log("let number_of_team_channels = fs::read_dir(&team_channels_dir)");
    let number_of_team_channels = fs::read_dir(&team_channels_dir)
        .unwrap()
        .filter(|entry| entry.as_ref().unwrap().path().is_dir())
        .count();

    if number_of_team_channels == 0 {
        // If no team channels exist, create the first one
        println!("There are no existing team channels. Let's create one.");
        println!("Enter a name for the team channel:");

        let mut team_channel_name = String::new();
        io::stdin().read_line(&mut team_channel_name).unwrap();
        let team_channel_name = team_channel_name.trim().to_string();


    // TUI Setup, TODO
    /*
    If there is an umi.toml,
    and it has tui_height/tui_height that are not 80/24
    use those new values (from umi.toml) for 
    tui_height = 
    tui_width = 

    or maybe this gets done in the project-manager-thread (not the sink thread)    
    */

    
    
    // // In initialize_uma_application, when creating the first channel:
    // // Get the owner from somewhere (e.g., user input or instance metadata)
    // let owner = "initial_owner".to_string(); // Replace with actual owner

    create_team_channel(team_channel_name, owner);
    }
    

    // if !dir_at_path_is_empty_returns_false("project_graph_data/collaborator_files_address_book") {
    debug_log("if !dir_at_path_is_empty_returns_false(Path::new(project_graph_data/collaborator_files_address_book)) { ");
    if !dir_at_path_is_empty_returns_false(Path::new("project_graph_data/collaborator_files_address_book")) { 
        // If there are no existing users, prompt the user to add a new user
        println!("Welcome to the application!");
        println!("To get started, please add a new user.");

        // Prompt the user to enter a username
        println!("Enter a username:");
        let mut username = String::new();
        io::stdin().read_line(&mut username).unwrap();
        let username = username.trim().to_string();

        // // Prompt the user to enter an IP address
        // println!("Enter an ipv4_address:");
        // let mut ipv4_address = String::new();
        // io::stdin().read_line(&mut ipv4_address).unwrap();
        // let ipv4_address = ipv4_address.trim().parse().unwrap();
        

        // choice...
        // Get IP address input method
        // 3. Auto-detect IP Addresses
        let detected_addresses = get_local_ip_addresses().expect("Failed to auto-detect IP addresses"); 
        let mut ipv4_addresses: Option<Vec<Ipv4Addr>> = None;
        let mut ipv6_addresses: Option<Vec<Ipv6Addr>> = None;

        for addr in detected_addresses {
            match addr {
                IpAddr::V4(v4) => {
                    if ipv4_addresses.is_none() {
                        ipv4_addresses = Some(Vec::new());
                    }
                    ipv4_addresses.as_mut().unwrap().push(v4);
                }
                IpAddr::V6(v6) => {
                    if ipv6_addresses.is_none() {
                        ipv6_addresses = Some(Vec::new());
                    }
                    ipv6_addresses.as_mut().unwrap().push(v6);
                }
            }
        }
                        
        // // Prompt the user to enter an IP address
        // println!("Enter an ipv6_addresses:");
        // let mut ipv6_address = String::new();
        // io::stdin().read_line(&mut ipv6_address).unwrap();
        // let ipv6_address: Ipv6Addr = ipv6_address.trim().parse().unwrap(); // Parse into Ipv6Addr

        // Prompt the user to enter a GPG key
        println!("Enter a gpg_publickey_id:  // Posix? $gpg --list-keys");
        let mut gpg_publickey_id = String::new();
        io::stdin().read_line(&mut gpg_publickey_id).unwrap();
        let gpg_publickey_id = gpg_publickey_id.trim().to_string();
        
        // Prompt the user to enter a GPG key
        println!("Enter an ascii armored public GPG key:  // Posix? $gpg --list-keys");
        let mut gpg_key_public = String::new();
        io::stdin().read_line(&mut gpg_key_public).unwrap();
        let gpg_key_public = gpg_key_public.trim().to_string();

        // // load names of current collaborators to check for collisions: TODO
        // if check_collaborator_name_collision();

        let mut rng = rand::thread_rng(); 
        
        // let updated_at_timestamp = get_current_unix_timestamp()
        

        // Salt List!
        println!("Salt List: Press Enter for random, or type 'manual' for manual input");
        let mut new_usersalt_list_input = String::new();
        io::stdin().read_line(&mut new_usersalt_list_input)?;
        let new_usersalt_list_input = new_usersalt_list_input.trim().to_string();
    
        let new_usersalt_list: Vec<u128> = if new_usersalt_list_input == "manual" {
            let mut salts = Vec::new();
            for i in 1..=4 {
                println!("Enter salt {} (u128):", i);
                let mut salt_input = String::new();
                io::stdin().read_line(&mut salt_input)?;
                let salt: u128 = salt_input.trim().parse().expect("Invalid input, so using u128 input for salt");
                salts.push(salt);
            }
            salts
        } else {
            // Generate 4 random u128 salts
            (0..4)
                .map(|_| rand::thread_rng().gen())
                .collect()
        };
        
        println!("Using salts: {:?}", new_usersalt_list);
        
        
        
        // // Add a new user to Uma file system
        add_collaborator_setup_file(
            username, 
            new_usersalt_list,
            ipv4_addresses, 
            ipv6_addresses,
            gpg_publickey_id,
            gpg_key_public, 
            60,   // Example sync_interval (in seconds)
            get_current_unix_timestamp(),
        );

        // // Save the updated collaborator list to the data directory
        // let toml_data = toml::to_string(&collaborator_list).expect("Failed to serialize collaborator list");
        // fs::write(collaborator_list_file, toml_data).expect("Failed to write collaborator list file");

        println!("User added successfully!");
    }


    Ok(())
}

fn handle_command(
    input: &str, 
    app: &mut App, 
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> Result<bool, io::Error> {
    /*
    For input command mode
    quit
    command-list/legend
    */

    debug_log(&format!("fn handle_command(), input->{:?}", input));
    
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if let Some(command) = parts.first() {
        match command.to_lowercase().as_str() {
            "h" | "help" => {
                debug_log("Help!");
                // Display help information
            }
            
            "bigger" | "big" | "bg" => {
                app.tui_height = (app.tui_height + 1).max(1);  // Height cannot be less than 1
                app.tui_width = (app.tui_width + 1).max(1);  // Width cannot be less than 1
                // ... re-render
            }
    
            "smaller" | "small" | "sm" => {
                app.tui_height = (app.tui_height - 1).max(1);  
                app.tui_width = (app.tui_width - 1).max(1);  
                // ... re-render 
            }
            
            "v" | "vote" => {
                debug_log("Vote!");
                // Display help information
            }
            // "p" | "paralax" => {
            //     debug_log("Vote!");
            //     // Display help information
            // }
            "collaborator" => {
                debug_log("make node!");
                add_collaborator_qa(&graph_navigation_instance_state);
                
            }
            
            // "node" => {
            //     debug_log("Creating a new node...");

            //     // 1. Get input for node name
            //     println!("Enter a name for the new node:");
            //     let mut node_name_input = String::new();
            //     io::stdin().read_line(&mut node_name_input).expect("Failed to read node name input");
            //     let node_name = node_name_input.trim().to_string();

            //     // 2. Get input for description
            //     println!("Enter a description for the new node:");
            //     let mut description_input = String::new();
            //     io::stdin().read_line(&mut description_input).expect("Failed to read description input");
            //     let description_for_tui = description_input.trim().to_string();

            //     // 3. Get input for teamchannel_collaborators_with_access (comma-separated)
            //     println!("Enter teamchannel_collaborators_with_access (comma-separated usernames):");
            //     let mut teamchannel_collaborators_with_access_input = String::new();
            //     io::stdin().read_line(&mut teamchannel_collaborators_with_access_input).expect("Failed to read teamchannel_collaborators_with_access input");
            //     let teamchannel_collaborators_with_access: Vec<String> = teamchannel_collaborators_with_access_input
            //         .trim()
            //         .split(',')
            //         .map(|s| s.trim().to_string())
            //         .collect();

            //     // 4. Construct abstract_collaborator_port_assignments HashMap
            //     let mut abstract_collaborator_port_assignments: HashMap<String, ReadTeamchannelCollaboratorPortsToml> = HashMap::new();
            //     for collaborator_name in &teamchannel_collaborators_with_access { 
            //         // Load collaborator from file
            //         let collaborator = match get_addressbook_file_by_username(collaborator_name) {
            //             Ok(collaborator) => collaborator,
            //             Err(e) => {
            //                 eprintln!("Error loading collaborator {}: {}", collaborator_name, e);
            //                 continue; // Skip to the next collaborator if there's an error
            //             }
            //         };

            //         // Generate random ports for the collaborator 
            //         let mut rng = rand::thread_rng();
            //         let ready_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
            //         let intray_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
            //         let gotit_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
            //         let ready_port__localowneruser: u16 = rng.gen_range(40000..=50000);
            //         let intray_port__localowneruser: u16 = rng.gen_range(40000..=50000);
            //         let gotit_port__localowneruser: u16 = rng.gen_range(40000..=50000);

            //         // Create ReadTeamchannelCollaboratorPortsToml and insert into the HashMap
            //         abstract_collaborator_port_assignments.insert(
            //             collaborator_name.clone(), 
            //             ReadTeamchannelCollaboratorPortsToml {
            //                 ready_port__other_collaborator,
            //                 intray_port__other_collaborator,
            //                 gotit_port__other_collaborator,
            //                 ready_port__localowneruser,
            //                 intray_port__localowneruser,
            //                 gotit_port__localowneruser,
            //             }
            //         );
            //     }

            //     // 5. Get input for order number
            //     // TODO what is this?
            //     println!("Enter the (optional) order number for the new node:");
            //     let mut order_number_input = String::new();
            //     io::stdin().read_line(&mut order_number_input).expect("Failed to read order number input");
            //     let order_number: u32 = order_number_input.trim().parse().expect("Invalid order number");

            //     // 6. Get input for priority
            //     println!("Enter the (optional) priority for the new node (High, Medium, Low):");
            //     let mut priority_input = String::new();
            //     io::stdin().read_line(&mut priority_input).expect("Failed to read priority input");
            //     let priority = match priority_input.trim().to_lowercase().as_str() {
            //         "high" => NodePriority::High,
            //         "medium" => NodePriority::Medium,
            //         "low" => NodePriority::Low,
            //         _ => {
            //             println!("Invalid priority. Defaulting to Medium.");
            //             NodePriority::Medium
            //         }
            //     };

            //     // 7. Create the new node directory
            //     let new_node_path = graph_navigation_instance_state.current_full_file_path.join(&node_name);
            //     fs::create_dir_all(&new_node_path).expect("Failed to create node directory");

            //     // 8. Create the Node instance
            //     let new_node = CoreNode::new(
            //         node_name,
            //         description_for_tui,
            //         new_node_path,
            //         order_number,
            //         priority,
            //         graph_navigation_instance_state.local_owner_user.clone(),
            //         teamchannel_collaborators_with_access, // Pass the collaborators vector
            //         abstract_collaborator_port_assignments, // Pass the abstract_collaborator_port_assignments HashMap
            //     );

            //     // 9. Save the node data to node.toml
            //     if let Err(e) = new_node.save_node_to_file() {
            //         eprintln!("Failed to save node data: {}", e);
            //         // Optionally handle the error more gracefully here
            //     } else {
            //         debug_log!("New node created successfully!"); 
            //     }
            // }, // end of node match arm

            
           "d" | "datalab" | "data" => {
                debug_log("Help!");
                // Display help information
            }

           "l" | "log" | "logmode" | "debug" | "debuglog" | "showlog" => {
            debug_log("Starting log mode...ctrl+c to exit");

                // 1. Read log_mode_refresh DIRECTLY from uma.toml (without loading user data).
                let uma_toml_path = Path::new("uma.toml");
                let toml_data = toml::from_str::<toml::Value>(&fs::read_to_string(uma_toml_path)?)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?; // Convert toml::de::Error 
                
                // Use a default refresh rate if log_mode_refresh is not found or invalid.
                // Use a default refresh rate if log_mode_refresh is not found or invalid.
                // let log_mode_refresh = toml_data
                //     .get("log_mode_refresh")
                //     .and_then(toml::Value::as_float) // Use as_float to get the floating-point value
                //     .map(|v| v as f32) // Convert to f32
                //     .unwrap_or(1.0); // Default refresh rate of 1 second
                let log_mode_refresh = match fs::read_to_string(uma_toml_path) {
                    Ok(toml_string) => {
                        match toml::from_str::<toml::Value>(&toml_string) {
                            Ok(toml_data) => {
                                toml_data
                                    .get("log_mode_refresh")
                                    .and_then(toml::Value::as_float)
                                    .and_then(|v| {
                                        if v >= 0.1 && v <= 10.0 {
                                            Some(v as f32)
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(3.0)
                            }
                            Err(e) => {
                                debug_log!("Error parsing uma.toml: {}", e);
                                3.0 // Default to 3 seconds on parsing error
                            }
                        }
                    }
                    Err(e) => {
                        debug_log!("Error log_mode_refresh reading uma.toml: {}", e);
                        3.0 // Default to 3 seconds on reading error
                    }
                };

                debug_log!("log_mode_refresh: {:?}", log_mode_refresh); 
                
                let mut last_log_file_size = fs::metadata("uma.log")
                    .map(|metadata| metadata.len())
                    .unwrap_or(0); // Get initial size, or 0 if error

                // bootstrap, first print
                // File size has changed, read and display new contents 
                match fs::read_to_string("uma.log") {
                    Ok(log_contents) => {
                        println!("{}", log_contents); // Print to console for now
                    }
                    Err(e) => {
                        eprintln!("Failed to read uma.log: {}", e);
                    }
                }
                        
                loop { // Enter the refresh loop

                    // Check for file size changes 
                    let current_log_file_size = fs::metadata("uma.log") 
                        .map(|metadata| metadata.len())
                        .unwrap_or(0);
                    if current_log_file_size != last_log_file_size {
                        
                        // 1. Read and display the log contents.
                        // File size has changed, read and display new contents 
                        match fs::read_to_string("uma.log") {
                            Ok(log_contents) => { 
                                print!("\x1B[2J\x1B[1;1H"); // Clear the screen 
                                println!("{}", log_contents);
                                // Update the last_log_file_size after reading
                                last_log_file_size = current_log_file_size; 
                            }
                            Err(e) => {
                                eprintln!("Failed to read uma.log: {}", e);
                            }
                        } 
                    } 
                                        
                                                            
                    // // 1. Read and display the log contents.
                    // match fs::read_to_string("uma.log") {
                    //     Ok(log_contents) => {
                    //         println!("{}", log_contents); // Print to console for now
                    //     }
                    //     Err(e) => {
                    //         eprintln!("Failed to read uma.log: {}", e);
                    //     }
                    // }
                    
                    // // 1. Read the log_mode_refresh value from uma.toml.
                    // let uma_toml_path = Path::new("uma.toml");
                    // let user_metadata = match toml::from_str::<LocalUserUma>(&fs::read_to_string(uma_toml_path)?) {
                    //     Ok(metadata) => metadata,
                    //     Err(e) => {
                    //         debug_log!("Error reading or parsing uma.toml: {}", e);
                    //         eprintln!("Error reading or parsing uma.toml: {}", e);
                    //         return Ok(false); // Or handle the error differently (e.g., use a default value)
                    //     }
                    // };
                    


                    // 2. Sleep for a short duration.
                    // thread::sleep(Duration::from_secs(log_mode_refresh)); 
                    thread::sleep(Duration::from_secs_f32(log_mode_refresh)); // Use from_secs_f32

                    // // 3. Check for 'esc' key press to exit.
                    // if let Ok(input) = tiny_tui::get_input() {
                    //     if input == "esc" {
                    //         debug_log("Exiting debug log view.");
                    //         break; // Exit the loop
                    //     }
                    // }
                }
            }

            
           "storyboard" | "mudd" => {
                debug_log("storyboard");
                // Display help information
            }
            // "home" => {
            //     debug_log("home");
                
            //     // // Posix
            //     // app.current_path = PathBuf::from("project_graph_data/team_channels");
                
            //     // any file system compiled, safe path posix or other os
            //     let mut app_data_dir = PathBuf::from("project_graph_data");
            //     app_data_dir.push("team_channels");
            //     app.current_path = app_data_dir;
            //     // Update TUI display
            // }
            "home" => {
                /*
                For a clean reset, 'home' quits and restarts,
                ensuring all processes are clean.
                */
                debug_log("Home command received.");
                
                quit_set_continue_uma_to_false();

                // //////////////////////////
                // // Enable sync flag here!
                // //////////////////////////
                // debug_log("About to set sync flag to true! (handle_command(), home)");
                // initialize_ok_to_start_sync_flag_to_false();  //TODO turn on to use sync !!! (off for testing)
                
                // // 1. Reset the current path
                // let mut app_data_dir = PathBuf::from("project_graph_data");
                // app_data_dir.push("team_channels");
                // app.current_path = app_data_dir;
                // debug_log(&format!("Current path reset to: {:?}", app.current_path)); 

                // // 2. Purge state in GraphNavigationInstanceState
                // app.graph_navigation_instance_state.active_team_channel = String::new();
                // app.graph_navigation_instance_state.current_full_file_path = PathBuf::new();
                // // ... Clear other channel-specific data (e.g., current_node_* fields, collaborator_ports) ...
                // debug_log("GraphNavigationInstanceState - Channel specific data purged."); 

                // // 3. Reset the home_square_one flag
                // app.graph_navigation_instance_state.home_square_one = true;
                // debug_log("home_square_one flag set to true.");

                // // 4.  (Optional) Clear the TUI list to reflect the home screen
                // app.tui_directory_list.clear(); 
                // debug_log("TUI directory list cleared.");

                // 5. (Optional) Trigger a TUI refresh
                // (not needed for default 'current path' print)
                // ... (Your TUI refresh logic) ...
                // debug_log("TUI refresh triggered (if implemented).");
            }
            // "u" | "updated" => {
            //     debug_log("updated selected");
            //     // TODO: update the updated_at_timestamp filed in the node.toml
            // }
            // "m" | "message" => {
                //  debug_log("m selected");
                
                // app.input_mode = InputMode::InsertText;
                // app.current_path = app.current_path.join("instant_message_browser"); // Update path here
                // app.load_im_messages(); // Load messages for the selected channel
                // // Update input box title
            "m" | "message" => {
                debug_log("m selected");
                debug_log(&format!("app.current_path {:?}", app.current_path)); 
                app.input_mode = InputMode::InsertText;

                // TODO Assuming you have a way to get the current node's name:
                let current_node_name = app.current_path.file_name().unwrap().to_string_lossy().to_string();

                app.current_path = app.current_path.join("instant_message_browser");

                debug_log!(
                    "app.current_path after joining 'instant_message_browser': {:?}",
                    app.current_path
                ); 
                
                app.load_im_messages();
            }
            "q" | "quit" | "exit" => {
                debug_log("quit");
                no_restart_set_hard_reset_flag_to_false();
                quit_set_continue_uma_to_false();
                
                return Ok(true); // Signal to exit the loop
            }
            _ => {
                // Display error message (e.g., "Invalid command")
                debug_log(" 'other' commend? _ => {...");
            }
            // ... (handle other commands)
            
        }
    }
    debug_log("end fn handle_command()");
    return Ok(false); // Don't exit by default
}

fn extract_last_section(current_path: &PathBuf) -> Option<String> {
    current_path.file_name().and_then(|os_str| os_str.to_str().map(|s| s.to_string()))
}

// Helper function to determine the next available message file path (e.g., 1.toml, 2.toml, etc.)
fn get_next_message_file_path(current_path: &Path, selected_user_collaborator: &str) -> PathBuf {
    let mut i = 1;
    loop {
        
        let file_path = current_path.join(format!("{}__{}.toml", i, selected_user_collaborator));
        if !file_path.exists() {
            return file_path;
        }
        i += 1;
    }
}

/// Loads collaborator data from a TOML file based on the username.
///
/// This function uses `read_one_collaborator_setup_toml` to deserialize the collaborator data.
///
/// # Arguments
///
/// * `username` - The username of the collaborator whose data needs to be loaded.
///
/// # Errors
///
/// This function returns a `Result<CollaboratorTomlData, ThisProjectError>` to handle potential errors:
///  - `ThisProjectError::IoError`: If the collaborator file is not found or if there is an error reading the file.
///  - `ThisProjectError::TomlDeserializationError`: If there is an error parsing the TOML data.
///
/// # Example
///
/// ```
/// let collaborator = get_addressbook_file_by_username("alice").unwrap(); // Assuming alice's data exists
/// println!("Collaborator: {:?}", collaborator);
/// ```
fn get_addressbook_file_by_username(username: &str) -> Result<CollaboratorTomlData, ThisProjectError> {
    debug_log!("Starting get_addressbook_file_by_username(username),  for -> '{}'", username);

    // Use read_one_collaborator_setup_toml to read and deserialize the data
    match read_one_collaborator_setup_toml(username) {
        Ok(loaded_collaborator) => {
            debug_log!("Collaborator file found ok.");
            Ok(loaded_collaborator)
        }
        Err(e) => {
            debug_log!("Collaborator file not found: {:?}", e);
            Err(e) // Propagate the error from read_one_collaborator_setup_toml
        }
    }
}

/// Used to make a random hex string
/// to store the u128 salt for salted pearson hash
/// in the toml file as hex-string
fn generate_random_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt: u128 = rng.gen(); // Generate a random u128
    format!("0x{:X}", salt) // Convert to hexadecimal string with "0x" prefix
}

/// Loads connection data for members of the currently active team channel.
/// On success, returns a `HashSet` of `MeetingRoomSyncDataset` structs, 
/// each containing connection 
/// data for a collaborator in the current team channel (excluding the current user).
/// As a headline this makes an ip-whitelist or ip-allowlist but the overall process is bigger.
/// This should include 'yourself' so all connection data are there, so you know your ports
///
/// Note: this likely should also include the collabortor's last-recieved-timestamp (and the previous one)
/// this will also need a bootstrap where at first...there is no last timestamp.
///
/// Note: making the allow_lists requires information from more than one source:
/// =uma.toml
/// =project_graph_data/session_items/current_node_teamchannel_collaborators_with_access.toml
/// =/project_graph_data/collaborator_files_address_book/NAME__collaborator.toml
///
/// step 1: get team_channel list of (and data about) all possible team_channel_members
///     from externalized session state item doc @: 
///     project_graph_data/session_items/current_node_teamchannel_collaborators_with_access.toml
///     The 6-port assignments come from this source.
///
/// step 2: get /collaborator_files_address_book data @:
///     .../project_graph_data/collaborator_files_address_book/ directory
///     as: NAME__collaborator.toml
///
/// step 3: Remove any collaborator from that 'possible list' whose information
///     is not in the .../project_graph_data/collaborator_files_address_book directory
///     as: NAME__collaborator.toml
///     The ipv4 and ipv6 lists come from this source.
///
/// step 4: make a session dataset for: teamchannel_connection_data
///     - allowlisted collaborators
///         - names
///         - ip lists
///         - ports
///
/// (note: members should have a list of ipv4, ipv6 addresses, not just one)
///
/// sample: project_graph_data/collaborator_files_address_book/alice__collaborator.toml
/// [[collaborator]]
/// user_name = "alice"
/// ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
/// ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
/// gpg_key_public = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
/// sync_interval = 5000
///
/// Do NOT read all data from all collaborators.      
/// Ethical Data Access: The function only accesses the collaborator data that 
/// is absolutely necessary for building the session_connection_allowlist for the current channel.
///
/// sample node.toml
/// node_name = "teamtest"
/// description_for_tui = "teamtest"
/// node_unique_id = 1728307130
/// directory_path = "project_graph_data/team_channels/teamtest"
/// order_number = 5
/// priority = "Medium"
/// owner = "initial_owner"
/// updated_at_timestamp = 1728307130
/// expires_at = 1728393530
/// children = [] 
/// teamchannel_collaborators_with_access = ["alice", "bob"]
///
/// # abstract_collaborator_port_assignments
/// [abstract_collaborator_port_assignments.alice_bob]
/// collaborator_ports = [
///     { name = "alice", ready_port = 50001, intray_port = 50002, gotit_port = 50003 },
///     { name = "bob", ready_port = 50004, intray_port = 50005, gotit_port = 50006 },
/// ]
///
/// [abstract_collaborator_port_assignments.alice_charlotte]
/// collaborator_ports = [
///     { name = "alice", ready_port = 50007, intray_port = 50008, gotit_port = 50009 },
///     { name = "charlotte", ready_port = 50010, intray_port = 50011, gotit_port = 50012 },
/// ]
///
/// [abstract_collaborator_port_assignments.bob_charlotte]
/// collaborator_ports = [
///     { name = "bob", ready_port = 50013, intray_port = 50014, gotit_port = 50015 },
///     { name = "charlotte", ready_port = 50016, intray_port = 50017, gotit_port = 50018 },
/// ]
///
/// maybe detects any port collisions, 
/// excluding those who collide with senior members
/// or returning an error if found.
fn make_sync_meetingroomconfig_datasets(uma_local_owner_user: &str) -> Result<HashSet<MeetingRoomSyncDataset>, MyCustomError> { 
    debug_log!("Entering the make_sync_meetingroomconfig_datasets() function..."); 

    // --- 1. find node.toml ---
    /*
    1. Find Path to team-channel node.toml, 
    which contains the port assignments 
    and the list of (all possible) team-members 
    (collaborators with access to that channel, 
    though perhaps not shared yet with you)
    */
    // get path, derive name from path
    let channel_dir_path_str = read_state_string("current_node_directory_path.txt")?; // read as string first
    debug_log!("1. Channel directory path (from session state): {}", channel_dir_path_str); 
    
    // use absolute file path
    let channel_dir_path = PathBuf::from(channel_dir_path_str);
    
    // A. Print the absolute path of the channel directory
    match channel_dir_path.canonicalize() {
        Ok(abs_path) => debug_log!("1. Absolute channel directory path: {:?}", abs_path),
        Err(e) => debug_log!("Error 1. getting absolute path of channel directory: {}", e),
    }
    
    // Construct the path to node.toml 
    let channel_node_toml_path = channel_dir_path.join("node.toml");
    debug_log!("1. Channel node.toml path: {:?}", channel_node_toml_path); 

    // B. Print the absolute path of the node.toml file
    match channel_node_toml_path.canonicalize() {
        Ok(abs_path) => debug_log!("1. Absolute channel_dir_path node.toml path: {:?}", abs_path),
        Err(e) => debug_log!("Error 1. getting absolute path of channel_dir_path node.toml: {}", e),
    }

    // --- 2. Load/Read node.toml ---
    // Read that (node toml) data into an organized 'struct' of variables
    // Read node.toml data with fn load_core_node_from_toml_file()
    // loading the fields into an organized struct with datatypes
    let teamchannel_nodetoml_data: CoreNode = match load_core_node_from_toml_file(&channel_node_toml_path) { 
        Ok(node) => {
            debug_log!("2. Successfully read channel node.toml");
            node // ???
        },
        Err(e) => {
            debug_log!("Error 2. reading channel node.toml: {:?}", channel_node_toml_path);
            debug_log!("Error 2. details: {}", e);
            return Err(MyCustomError::from(io::Error::new(io::ErrorKind::Other, e))); // Convert the error
        }
    };
    debug_log!("2. teamchannel_nodetoml_data->{:?}", teamchannel_nodetoml_data);
    
    // --- 3. Empty Table for Later ---
    // Create an (empty) lookup-table (hash-set) to put all the meeting-room-data-sets in.
    // This will contain the local-port-assignments for each desk.
    let mut sync_config_data_set: HashSet<MeetingRoomSyncDataset> = HashSet::new();
    debug_log!("3. sync_config_data_set->{:?} <should be empty, ok>", &sync_config_data_set);
    
    // --- 4. Team-Channel Memebers ---
    // Get team member names from team_channel node
    // (Example of derived-functional definitions: 
    // compile this from the list of port-assignments,
    // rather than having multiple 'sources of truth' for members)
    // let collaborators_names_array = teamchannel_nodetoml_data.teamchannel_collaborators_with_access;
    // derive list functionally from port-assignemnt list
    let collaborators_names_array = match get_collaborator_names_from_node_toml(&channel_node_toml_path) {
        Ok(names) => names,
        Err(e) => {
            debug_log!("Error 4. getting collaborator names: {}", e);
            return Err(MyCustomError::from(io::Error::new(io::ErrorKind::Other, e)));
        }
    };
    debug_log!("4. collaborators_names_array->{:?}", collaborators_names_array);
    
    // --- 5. raw-abstract port-assignments ---
    // Get the raw-abstract port-assignments 
    // from the team_channel node
    // let abstract_collaborator_port_assignments = teamchannel_nodetoml_data.abstract_collaborator_port_assignments;
    // debug_log!(
    //     "5. abstract_collaborator_port_assignments->{:?}", 
    //     &abstract_collaborator_port_assignments
    // );
    let abstract_collaborator_port_assignments = match get_abstract_port_assignments_from_node_toml(&channel_node_toml_path) {
        Ok(names) => names,
        Err(e) => {
            debug_log!("Error 5. getting abstract_collaborator_port_assignments: {}", e);
            return Err(MyCustomError::from(io::Error::new(io::ErrorKind::Other, e)));
        }
    };
    debug_log!(
        "5. abstract_collaborator_port_assignments->{:?}", 
        &abstract_collaborator_port_assignments
    );

    // --- 6. filtered collaborators array ---
    // filter-pass: remove non-contacts from list
    //    - remove self
    //    - remove duplicates
    //    - remove names not in address-book  
    let mut filtered_collaboratorsarray = collaborators_names_array.clone();

    // 6.1  Remove Self (don't try to call yourself on the phone)
    filtered_collaboratorsarray.retain(|name| name != &uma_local_owner_user);

    // 6.2  Remove Duplicates
    filtered_collaboratorsarray.sort();
    filtered_collaboratorsarray.dedup();

    // 6.3  Actual Meeting Contacts
    // Remove Names Not in your Address Book
    // the team-owner invites people to the team
    // each collaborator invites you to connect with them
    filtered_collaboratorsarray.retain(|name| {
        let toml_file_path = Path::new("project_graph_data/collaborator_files_address_book")
            .join(format!("{}__collaborator.toml", name));
        toml_file_path.exists()
    });
    debug_log!(
        "6. filtered_collaboratorsarray->{:?}", 
        &filtered_collaboratorsarray
    );

    // --- Get local user's salt list ---
    let local_user_salt_list = match get_addressbook_file_by_username(uma_local_owner_user) {
        Ok(data) => data.user_salt_list,
        Err(e) => {
            debug_log!("Error loading local user's salt list: {}", e);
            // return Err(e); 
            return Err(e.into()); // Convert ThisProjectError to MyCustomError
        }
    };     
    
    // --- 7. Iterate through the filtered address-book-name-list ---
    // Go through the list make a set of meeting room information for each team-member, 
    // so that you (e.g. Alice) can sync with other team members.
    for collaborator_name in filtered_collaboratorsarray { // collaborator_data is now a String
        debug_log!("7. Processing collaborator: {}", collaborator_name);

        // --- 8. get (that team member's) addressbook file by (their) username ---
        // using get_addressbook_file_by_username()
        // which loads the NAME__collaborator.toml from the collaborator_files_address_books directory 
        // (owned by that collaborator, it is their own gpg signed data)
        let these_collaboratorfiles_toml_data = match get_addressbook_file_by_username(&collaborator_name) {
            Ok(these_collaboratorfiles_toml_data) => these_collaboratorfiles_toml_data,
            Err(e) => {
                // This is where you'll most likely get the "No such file or directory" error
                debug_log!("Error 8. loading collaborator {}. File might be missing. Error: {}", collaborator_name, e); 
                return Err(e.into()); // Convert ThisProjectError to MyCustomError
            }
        };
        debug_log!(
            "8. Collaborator data these_collaboratorfiles_toml_data: {:?}", 
            &these_collaboratorfiles_toml_data
        );

        // --- 9. extract data or drop collaborator from list ---
        // TODO addresses plural?
        /*
        what are all the fields of information to get?
        ipv6
        ipv4
        (is there some other type of address too?)
        gpg
        sync rate?
        */
        // IPvX...what else? 
        // (If not available, drop this person from the list)
        let ipv6_address = match these_collaboratorfiles_toml_data
            .ipv6_addresses.clone()
            .and_then(|v| v.first().cloned()) 
        {
            Some(addr) => {
                debug_log!(
                    "9. IPv6 address for {}: {}", 
                    collaborator_name, addr
                );
                addr // ?
            },
            None => {
                debug_log!("WARNING: 9. No IPv6 address found for {}. Skipping this collaborator.", collaborator_name);
                continue; // Skip to the next collaborator in the loop
            }
        };
        debug_log!(
            "9. ipv6_address {:?}->", 
            &ipv6_address
        );
        
        // TODO Alpha under construction
        // --- 10. Translate abstract port assignments to local role-specific structs ---
        // let role_based_ports = translate_port_assignments()
        /*
        Make local port assignments: Translate abstract port assignments to local role-specific structs
        per real remote collaborator:

        Instance-Role-Specific Local-Meeting-Room-Struct
        This is no longer an abstract set of data that can be used 
        in different ways in different instances, 
        this is now one of those specific instances 
        with local roles and one local way of using those data.
        The abstract port-assignments will be converted 
        into a disambiguated and clarified specific local 
        instance roles set of port assignments, namely, 
        local_user_role, remote_collaborator_role
        */
        debug_log("10. Starting translate_port_assignments()");
        let role_based_ports = translate_port_assignments(
            uma_local_owner_user, 
            &collaborator_name, 
            abstract_collaborator_port_assignments.clone(), // Clone to avoid ownership issues
        )?;
        debug_log!(
            "10. role_based_ports {:?}->", 
            &role_based_ports
        );
        /*
        abstract format is:
        # meeting rooms, abstract_collaborator_port_assignments
        [abstract_collaborator_port_assignments.alice_bob]
        collaborator_ports = [
            { name = "alice", ready_port = 50001, intray_port = 50002, gotit_port = 50003 },
            { name = "bob", ready_port = 50004, intray_port = 50005, gotit_port = 50006 },
        ]
        */

        // --- Get remote collaborator's salt list ---
        // let remote_collaborator_salt_list = match get_addressbook_file_by_username(collaborator_name.clone()) {
        let remote_collaborator_salt_list = match get_addressbook_file_by_username(&collaborator_name.clone()) {
            Ok(data) => data.user_salt_list,
            Err(e) => {
                debug_log!("Error loading remote_collaborator_salt_list user's salt list: {}", e);
                // return Err(e); 
                return Err(e.into()); // Convert ThisProjectError to MyCustomError
            }
        }; 

        // --- 11. Construct MeetingRoomSyncDataset (struct) ---
        // Assemble this one meeting room data-bundle from multiple sources
        // - from node.toml data
        // - from addressbook data
        // - from Instance-Role-Specific Local-Meeting-Room-Struct
        let meeting_room_sync_data = MeetingRoomSyncDataset {
            local_user_name: uma_local_owner_user.to_string(),  // TODO source?
            local_user_salt_list: local_user_salt_list.clone(), // Include the local salt list
            local_user_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.clone().unwrap_or_default(), // Assuming you want to use the first IPv6 address for the local user
            // local_user_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.expect("REASON"), // Assuming you want to use the first IPv6 address for the local user
            local_user_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.clone().unwrap_or_default(), // Get IPv4 addresses or an empty vector
            // local_user_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.expect("REASON"), // Assuming you want to use the first 
            local_user_gpg_publickey_id: these_collaboratorfiles_toml_data.gpg_publickey_id.clone(),
            local_user_public_gpg: these_collaboratorfiles_toml_data.gpg_key_public.clone(),
            local_user_sync_interval: these_collaboratorfiles_toml_data.sync_interval,
            
            local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
            localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: role_based_ports.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip,
            
            remote_collaborator_name: collaborator_name.clone(), // TODO source?
            remote_collaborator_salt_list: remote_collaborator_salt_list,
            remote_collaborator_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.unwrap_or_default(), // Get ip addresses or empty vector
            remote_collaborator_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.unwrap_or_default(), // Get IP addresses or empty vector
            // remote_collaborator_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.expect("REASON"), // Get ip addresses or empty vector
            // remote_collaborator_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.expect("REASON"), // Get IP addresses or empty vector
            remote_collaborator_gpg_publickey_id: these_collaboratorfiles_toml_data.gpg_publickey_id,
            remote_collaborator_public_gpg: these_collaboratorfiles_toml_data.gpg_key_public,
            remote_collaborator_sync_interval: these_collaboratorfiles_toml_data.sync_interval,
            
            remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: role_based_ports.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip,
            remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip,
            remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: role_based_ports.remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip,
        };
                
        // --- 12. add meeting room to set-of-rooms-table ---
        // add this one meeting room data-bundle to the larger set
        sync_config_data_set.insert(meeting_room_sync_data.clone()); 
        debug_log!(
            "12. Created MeetingRoomSyncDataset: {:?}",
            meeting_room_sync_data
        );
        
    } // End of collaborator loop

    debug_log!("12,13: sync_config_data_set created: {:?}", sync_config_data_set);
    
    // 13. after iterating, return full set of meeting-rooms
    Ok(sync_config_data_set) 
}

/// Implementation of the Pearson hashing algorithm
/// 
/// This is a non-cryptographic hash function that produces an 8-bit hash value.
/// It's useful for:
/// - Hash tables
/// - Data integrity checks
/// - Fast execution on 8-bit processors
/// 
/// Features:
/// - Simple implementation
/// - Fast execution
/// - No simple class of inputs that produce collisions
/// - Two strings differing by one character never collide
/// 
/// Reference: Pearson, Peter K. (1990). "Fast Hashing of Variable-Length Text Strings"
///
/// Generate a permutation table using a non-linear transformation
/// This is done at compile time using const fn
const fn generate_pearson_permutation_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        // Non-linear transformation: multiply by prime number 167 and add 13
        // Then mask with 0xFF to keep it within u8 range
        table[i as usize] = ((i * 167 + 13) & 0xFF) as u8;
        i += 1;
    }
    table
}

// The permutation table is computed once at compile time
const PERMUTATION_TABLE: [u8; 256] = generate_pearson_permutation_table();

/// Computes the Pearson hash of the input bytes
/// 
/// # Arguments
/// 
/// * `input` - A slice of bytes to hash
/// 
/// # Returns
/// 
/// * An 8-bit hash value as u8
/// 
/// # Example
/// 
/// ```
/// let text = "Hello, World is the first onasei!";
/// let hash = pearson_hash6(text.as_bytes());
/// println!("Hash: {}", hash);
/// ```
pub fn pearson_hash_base(input: &[u8]) -> Result<u8, std::io::Error> {
    // Check if input is empty
    if input.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input cannot be empty"
        ));
    }

    // Initialize hash to 0
    let mut hash: u8 = 0;
    
    // For each byte in the input
    for &byte in input {
        // XOR the current byte with the hash, use result as index into permutation table
        hash = PERMUTATION_TABLE[(hash ^ byte) as usize];
    }
    
    Ok(hash)
}

/// Calculates Pearson hashes for a ReadySignal struct.
///
/// This function takes a `ReadySignal` and a list of salts (`local_user_salt_list`) as input.
/// It calculates a Pearson hash for the signal's data combined with each salt in the list.
/// The resulting hashes are then stored in the `rh` field of a new `ReadySignal` instance.
///
/// # Arguments
///
/// * `ready_signal`: The `ReadySignal` struct for which to calculate hashes.
/// * `local_user_salt_list`: A slice of `u128` salt values.
///
/// # Returns
///
/// * `Option<ReadySignal>`: A new `ReadySignal` instance with the calculated hashes, or `None` if an error occurred during hash calculation or if required fields of the input signal are missing.
fn add_pearson_hash_to_readysignal_struct(
    ready_signal: &ReadySignal,
    local_user_salt_list: &[u128],
) -> Option<ReadySignal> {
    // debug_log!(
    //     "010101 calculate_and_add_pearson_hashes_to_ready_signal(): Input ReadySignal: {:?}",
    //     &ready_signal
    // );

    if let (Some(ready_timestamp), Some(ready_send_timestamp), Some(is_echo_send)) =
        (ready_signal.rt, ready_signal.rst, ready_signal.re)
    {
        let mut data_to_hash = Vec::new();
        data_to_hash.extend_from_slice(&ready_timestamp.to_be_bytes());
        data_to_hash.extend_from_slice(&ready_send_timestamp.to_be_bytes());
        data_to_hash.push(if is_echo_send { 1 } else { 0 });

        // debug_log!(
        //     "010101 calculate_and_add_pearson_hashes_to_ready_signal(): Data to hash: {:?}",
        //     &data_to_hash
        // );

        let mut ready_signal_hash_list: Vec<u8> = Vec::new();
        for salt in local_user_salt_list {
            let mut salted_data = data_to_hash.clone();
            salted_data.extend_from_slice(&salt.to_be_bytes());

            let hash_result = pearson_hash_base(&salted_data);
            // debug_log!(
            //     "010101 calculate_and_add_pearson_hashes_to_ready_signal(): Hash Result: {:?}",
            //     &hash_result
            // );

            match hash_result {
                Ok(hash) => ready_signal_hash_list.push(hash),
                Err(e) => {
                    debug_log!("Error calculating Pearson hash: {}", e);
                    return None;
                }
            }
        }
        debug_log!(
            "010101 calculate_and_add_pearson_hashes_to_ready_signal(): Calculated Hashes: {:?}",
            &ready_signal_hash_list
        );

        Some(ReadySignal {
            rt: Some(ready_timestamp),
            rst: Some(ready_send_timestamp),
            re: Some(is_echo_send),
            rh: Some(ready_signal_hash_list),
        })
    } else {
        debug_log!("010101 calculate_and_add_pearson_hashes_to_ready_signal(): Missing fields in ReadySignal. Returning None.");
        None
    }
}

/// Retrieves the salt list for a collaborator from their TOML configuration file.
///
/// This function reads the collaborator's TOML file located at
/// `project_graph_data/collaborator_files_address_book/{collaborator_name}__collaborator.toml`,
/// parses the TOML data, and extracts the `user_salt_list`.  It handles potential errors during file
/// reading, TOML parsing, and data extraction.
///
/// # Arguments
///
/// * `collaborator_name`: The name of the collaborator.
///
/// # Returns
///
/// * `Result<Vec<u128>, ThisProjectError>`:  A `Result` containing the collaborator's salt list (`Vec<u128>`) on success, or a `ThisProjectError` if any error occurs.
///
/// use with:let remote_collaborator_salt_list = get_saltlist_for_collaborator(NAME)?; 
///
fn get_saltlist_for_collaborator(collaborator_name: &str) -> Result<Vec<u128>, ThisProjectError> {
    // 1. Construct File Path (using PathBuf)
    let file_path = Path::new("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", collaborator_name));

    // 2. Read File (handling potential errors)
    let toml_string = std::fs::read_to_string(&file_path)?;

    // 3. Parse TOML
    let toml_value: Value = toml::from_str(&toml_string)?;

    // 4. Extract Salt List (handling missing/invalid data)
    let salt_list_result: Result<Vec<u128>, ThisProjectError> = match toml_value.get("user_salt_list") {
        Some(Value::Array(arr)) => {
            arr.iter()
                .map(|val| { // Iterate each item in the array
                    if let Value::String(hex_string) = val {
                        u128::from_str_radix(hex_string.trim_start_matches("0x"), 16)
                            .map_err(|_| ThisProjectError::InvalidData(format!("Invalid salt format in file for: {}", collaborator_name))) // clearer error message
                    } else {
                        Err(ThisProjectError::InvalidData(format!("Invalid salt format in file for: {}", collaborator_name))) // clearer error message
                    }
                }).collect() // Collect results
        },
        _ => Err(ThisProjectError::InvalidData(format!("Missing or invalid 'user_salt_list' in collaborator file for: {}", collaborator_name))), // Handle missing field or type mismatch
    };
    salt_list_result // Return the salt list Result
}


// TODO useful sometime, if not now
/// Calculates a list of Pearson hashes for a given input string using a provided salt list.
///
/// This function takes an input string, converts it to bytes, and calculates a Pearson hash for the
/// byte representation combined with each salt in the provided salt list. The resulting hashes are
/// returned as a `Vec<u8>`.
///
/// # Arguments
///
/// * `input_string`: The string to hash.
/// * `salt_list`: A slice of `u128` salt values.
///
/// # Returns
///
/// * `Result<Vec<u8>, ThisProjectError>`: A `Result` containing the list of calculated Pearson hashes on success,
///   or a `ThisProjectError` if an error occurs during hash calculation.
fn calculate_pearson_hashlist_for_string(
    input_string: &str,
    salt_list: &[u128],
) -> Result<Vec<u8>, ThisProjectError> {
    let input_bytes = input_string.as_bytes();
    let mut hash_list = Vec::new();

    for salt in salt_list {
        let mut salted_data = Vec::new();
        salted_data.extend_from_slice(input_bytes);
        salted_data.extend_from_slice(&salt.to_be_bytes());

        let hash = pearson_hash_base(&salted_data)?;
        hash_list.push(hash);
    }

    Ok(hash_list)
}




/// Verifies the Pearson hashes in a ReadySignal against a provided salt list.
///
/// This function calculates the expected hashes based on the `rt`, `rst`, and `re` fields of the `ReadySignal`
/// and the provided `salt_list`. It then compares the calculated hashes to the `rh` field of the `ReadySignal`.
///
/// # Arguments
///
/// * `ready_signal`: The ReadySignal to verify.
/// * `salt_list`: The list of salts to use for hash calculation.
///
/// # Returns
///
/// * `bool`: `true` if all hashes match, `false` otherwise.
fn verify_readysignal_hashes(
    ready_signal: &ReadySignal, 
    salt_list: &[u128]
) -> bool {
    if let (Some(rt), Some(rst), Some(re), Some(rh)) = 
        (ready_signal.rt, ready_signal.rst, ready_signal.re, &ready_signal.rh) 
    {
        let mut data_to_hash = Vec::new();
        data_to_hash.extend_from_slice(&rt.to_be_bytes());
        data_to_hash.extend_from_slice(&rst.to_be_bytes()); 
        data_to_hash.push(if re { 1 } else { 0 });

        for (i, salt) in salt_list.iter().enumerate() {
            let mut salted_data = data_to_hash.clone();
            salted_data.extend_from_slice(&salt.to_be_bytes());
            match pearson_hash_base(&salted_data) {
                Ok(calculated_hash) => {
                    if calculated_hash != rh[i] { // Compare with the received hash
                        return false; // Hash mismatch
                    }
                }
                Err(e) => {
                    debug_log!("Error calculating Pearson hash: {}", e);
                    return false; // Error during hash calculation
                }
            }
        }

        // All hashes match
        true 
    } else {
        // Missing fields in ReadySignal, consider this a failure 
        false 
    }
}

fn sync_flag_ok_or_wait(wait_this_many_seconds: u64) {
    // check for quit
    loop {
        // 1. Read the 'continue_uma.txt' file 
        let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
            Ok(content) => content,
            Err(_) => {
                debug_log("Error reading 'continue_uma.txt'. Continuing..."); // Handle the error (e.g., log it) but continue for now
                continue; // Skip to the next loop iteration
            }
        };

        // 2. break loop if continue=0
        if file_content.trim() == "0" {
            debug_log("'continue_uma.txt' is 0. sync_flag_ok_or_wait Exiting loop.");
            break; 
        }

        let is_sync_enabled = fs::read_to_string(SYNC_START_OK_FLAG_PATH) 
            .unwrap_or("0".to_string())
            .trim() == "1"; 

        if is_sync_enabled {
            debug_log("Synchronization flag is '1'. Proceeding...");
            break; // Exit the loop
        } else {
            // debug_log("Synchronization flag is '0'. Waiting...");
            thread::sleep(Duration::from_secs(wait_this_many_seconds)); // Wait for 3 seconds
        }
    }
}

/// ### four byte array nearly 30 year timestamp v1
/// ## posix time scale notes
/// ```
/// (u1 to 1; u2 to 2; u4 to 8)
/// 1  1 			= 1 sec
/// 2  10			= 10 sec
/// (u8 to 256)
/// 3  100		= 1.67 min
/// (u16 to 65,536; 256^2)
/// 4  1000		= 16.7 minutes
/// 5  10000		= 2.7 hours
/// (u32 to 16,777,216; 256^3)
/// 6  100000		= 1.157 days / 0.165 weeks
/// 7  1000000 	= 0.381 months / 1.65 Weeks
/// 8  10000000	= 3.81 months / .317 years
/// (u64 to 4,294,967,296; 245^4)
/// 9  100000000	= 3.17 years
/// 10 1000000000	= 31.7 years
/// 11 10000000000	= 317 years
/// 12 100000000000	= 3171 years
/// ```
/// ## Compressed nonce-like timestamp freshness proxy
/// Use a four u8 byte array to get a nearly 31 year nonce timestamp
///
/// You need 8 digits: (skip the seconds digit)
/// ```
/// 10 (10sec) ->  100000000 (3.17 years)
/// +
/// some information about the 10th digit
/// ```
///
/// byte 1:
/// - digit 2 		(in the ones place)
/// - digit 3 		(in the tens place)
/// - fragment-1	(in the hundreds' place), not mod !%2
///
/// byte 2:
/// - digit 4 		(in the ones place)
/// - digit 5 		(in the tens place)
/// - fragment-2	(in the hundreds' place), not mod !%3
///
/// byte 3:
/// - digit 6 		(in the ones place)
/// - digit 7 		(in the tens place)
/// - fragment-3	(in the hundreds' place), not 0 or 4
///
/// byte 4:
/// - digit 8 		(in the ones place)
/// - digit 9 		(in the tens place)
/// - fragment-4	(in the hundreds' place), is prime
///
/// 10th digit fragments:
/// 1. not mod !%2
/// 2. not mod !%3
/// 3. not 0 or 4
/// 4. is prime
///
/// ## One Collision Case
/// The "5" value and "7" value from the compressed 10th-digit(31 year scale) collide, but at least most information from the 10th-digit could be expressed. 
/// - The largest u32 number is: 16,777,216
/// - The largest u64 number is: 4,294,967,296 (Feb 7, year:2106)
/// - With the exception of 5 vs 7 in the last place, this system can mostly reflect posix time up to 9,999,999,999, (or Saturday, November 20, year:2286 5:46:39 PM) which is more than u64 can.
///
/// ### Without Bit Manipulation
/// This works without bitwise operations (fun though those are).
/// There are four u8 (unsigned 8-bit) values,
/// each of which can hold (in decimal terms)
/// up to 0-255
/// including 199
/// The hundres's place can safely be 1 or 0 (though it can be 2 also if we know the whole value is less than 255).
///
/// ## future research
/// For specified time ranges a smaller system should be possible.
/// e.g. if only months and not minutes are needed
fn generate_terse_timestamp_freshness_proxy_v4(posix_timestamp: u64) -> [u8; 4] {

    // 1. Extract relevant digits
    let digit_2 = ((posix_timestamp / 10) % 10) as u8;
    let digit_3 = ((posix_timestamp / 100) % 10) as u8;
    let digit_4 = ((posix_timestamp / 1000) % 10) as u8;
    let digit_5 = ((posix_timestamp / 10000) % 10) as u8;
    let digit_6 = ((posix_timestamp / 100000) % 10) as u8;
    let digit_7 = ((posix_timestamp / 1000000) % 10) as u8;
    let digit_8 = ((posix_timestamp / 10000000) % 10) as u8;
    let digit_9 = ((posix_timestamp / 100000000) % 10) as u8;
    let digit_10 = ((posix_timestamp / 1000000000) % 10) as u8;

    // 2. Determine 10th digit fragments
    let fragment_1 = (digit_10 % 2 != 0) as u8;
    let fragment_2 = (digit_10 % 3 != 0) as u8;
    let fragment_3 = (digit_10 != 0 && digit_10 != 4) as u8;
    let fragment_4 = (is_prime(digit_10)) as u8;

    // 3. Pack into u8 array (4 bytes, fragment in hundreds place)
    //let packed_timestamp = [
    //    (fragment_1 * 100) + (digit_2 * 10) + digit_3, 
    //    (fragment_2 * 100) + (digit_4 * 10) + digit_5,
    //    (fragment_3 * 100) + (digit_6 * 10) + digit_7,
    //    (fragment_4 * 100) + (digit_8 * 10) + digit_9,
    //];

    // For readability, left to right
    let packed_timestamp = [
        (fragment_1 * 100) + (digit_9 * 10) + digit_8, 
        (fragment_2 * 100) + (digit_7 * 10) + digit_6,
        (fragment_3 * 100) + (digit_5 * 10) + digit_4,
        (fragment_4 * 100) + (digit_3 * 10) + digit_2,
    ];

    packed_timestamp
}

fn is_prime(n: u8) -> bool {
    match n {
        2 | 3 | 5 | 7 => true,
        _ => false,
    }
}

/// Sends a byte slice over UDP to the specified address and port.
///
/// # Arguments
///
/// * `data`: The byte slice to send.
/// * `target_addr`: The target IP address.
/// * `port`: The target port.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`:  `Ok(())` if sending was successful, or a `ThisProjectError` if an error occurred.
fn send_data_via_udp(data: &[u8], target_addr: SocketAddr, port: u16) -> Result<(), ThisProjectError> {
    let socket = UdpSocket::bind(":::0")?; // Bind to any available port
    socket.send_to(data, SocketAddr::new(target_addr.ip(), port))?;
    debug_log!("Data sent to {}:{}", target_addr.ip(), port);
    Ok(())
}

/// Sends a `SendFile` struct to a remote collaborator's intray.
/// Now this function *only* handles sending; serialization is done elsewhere. 
///
/// # Arguments
///
/// * `send_file`: The `SendFile` struct to send.
/// * `target_addr`: The target IP address.
/// * `port`: The target port. 
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if the file was sent successfully, `Err(ThisProjectError)` otherwise.
fn sendfile_UDP_to_intray(
    send_file: &SendFile,
    target_addr: SocketAddr,
    port: u16,
) -> Result<(), ThisProjectError> {
    // 1. Serialize the SendFile struct.
    let serialized_data = serialize_send_file(send_file)?;

    // 2. Send the serialized data using UDP.
    send_data_via_udp(&serialized_data, target_addr, port)?;

    Ok(())
}

/// Struct for sending file to in-tray (file sync)
/// Salted-Pearson-Hash-List system for quick verification that packet is intact and sent by owner at timestamp
#[derive(Serialize, Deserialize, Debug)] // Add Serialize/Deserialize for sending/receiving
struct SendFile {
    intray_send_time: Option<u64>, // send-time: generate_terse_timestamp_freshness_proxy(); for replay-attack protection
    gpg_encrypted_intray_file: Option<Vec<u8>>, // Holds the GPG-encrypted file contents
    intray_hash_list: Option<Vec<u8>>, // N hashes of intray_this_send_timestamp + gpg_encrypted_intray_file
}

/// ReadySignal struct
/// - Contents are 'Option<T>' so that assembly and inspection can occur in steps.
/// - Terse names to reduce network traffic, as an exceptional circumstance
/// - Ready-signals are the most commonly sent and most disposable
#[derive(Serialize, Deserialize, Debug)] // Add Serialize/Deserialize for sending/receiving
struct ReadySignal {
    rt: Option<u64>, // ready signal timestamp: last file obtained timestamp
    rst: Option<u64>, // send-time: generate_terse_timestamp_freshness_proxy(); for replay-attack protection
    re: Option<bool>, // echo_send
    rh: Option<Vec<u8>>, // N hashes of rt + re
}

// review use of gpg here
/// GotItSignal struct
/// Terse names to reduce network traffic, as an esceptional circumstatnce
/// Probably does not need a nonce because repeat does nothing...
/// less hash?
#[derive(Serialize, Deserialize, Debug)]
struct GotItSignal {
    gst: Option<u64>, // send-time: generate_terse_timestamp_freshness_proxy(); for replay-attack protection
    di: Option<u64>, // Unique document ID TODO: maybe only this?
    gh: Option<Vec<u8>>, // N hashes of rt + re
}

#[derive(Debug, Clone)] // Add other necessary derives later
struct SendQueue {
    back_of_queue_timestamp: u64,
    // echo_send: bool, //
    items: Vec<PathBuf>,  // ordered list, filepaths
}
impl SendQueue {
    /// Adds a `PathBuf` to the *front* of the `items` vector in the `SendQueue`.
    ///
    /// # Arguments
    ///
    /// * `path`: The `PathBuf` to add to the queue.
    fn add_to_front(&mut self, path: PathBuf) {
        self.items.insert(0, path);
    }
}

/// Retrieves the paths of all send queue update flags for a given collaborator in a team channel.
///
/// This function reads the contents of the directory `sync_data/{team_channel_name}/sendqueue_updates/{collaborator_name}`
/// and returns a vector of `PathBuf` representing the paths to the update flag files.  It also deletes the flag files
/// after reading their contents, ensuring that flags are processed only once.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `collaborator_name`: The name of the collaborator.
///
/// # Returns
///
/// * `Result<Vec<PathBuf>, ThisProjectError>`:  A vector of paths to update flag files on success, or a `ThisProjectError` if an error occurs.
fn get_sendq_update_flag_paths(
    team_channel_name: &str,
    collaborator_name: &str,
) -> Result<Vec<PathBuf>, ThisProjectError> {
    // 1. Construct Directory Path (using PathBuf)
    let mut queue_dir = PathBuf::from("sync_data");
    queue_dir.push(team_channel_name);
    queue_dir.push("sendqueue_updates");
    queue_dir.push(collaborator_name);

    let mut path_list: Vec<PathBuf> = Vec::new(); // Initialize path_list

    // 2. Read Directory and Collect Paths
    match read_dir(&queue_dir) {
        Ok(entries) => {
            for entry_result in entries {
                match entry_result {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_file() {
                            // Read the file path from the queue file and delete.
                            let queue_file_path_str = match std::fs::read_to_string(&path) {
                                Ok(s) => s,
                                Err(e) => {
                                    debug_log!("Error reading queue file: {}", e);
                                    // Handle error appropriately, e.g., continue to the next file or return an error
                                    continue; // Skip this file and continue
                                }
                            };
                            let queue_file_path = PathBuf::from(queue_file_path_str);

                            debug_log!("HRCD: Removing update flag file: {:?}", path);
                            if let Err(e) = remove_file(&path) {
                                debug_log!("Error removing update flag file: {:?} - {}", path, e);
                                // Continue processing other files even if removal fails.
                                continue; // or choose to handle error
                            }

                            // Add the file path from *inside* the queue file to the path_list
                            path_list.push(queue_file_path);

                        }
                    },
                    Err(e) => {
                        debug_log!("Error reading directory entry: {}", e);
                        // Handle error as you see fit
                        return Err(ThisProjectError::IoError(e));
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { 
            // No queue files, return empty list
            debug_log!("get_sendq_update_flag_paths(): Send queue directory not found. Returning empty list.");            
            return Ok(Vec::new());
        }
        Err(e) => return Err(ThisProjectError::IoError(e)),
    };


    Ok(path_list)
}

/// Converts a vector of u8 hash values into a hexadecimal string representation.
///
/// This function takes a slice of `u8` values (typically a hash) and converts it into a hexadecimal string,
/// with each byte represented by two hexadecimal characters.  The resulting string is suitable for use as a filename or identifier.
///
/// # Arguments
///
/// * `hash_array`: A slice of `u8` values representing the hash.
///
/// # Returns
///
/// * `String`: The hexadecimal string representation of the hash.
///
/// # Example
///
/// ```
/// let hash_array = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
/// let hex_string = hash_array_to_hex_string(&hash_array);
/// assert_eq!(hex_string, "123456789abcdef0");
/// ```
/// TODO Does this need error handling?
fn docid__hash_array_to_hex_string(hash_array: &[u8]) -> String {
    hash_array
        .iter()
        .map(|&h| format!("{:02x}", h))
        .collect::<String>()
}

/// Parses a hexadecimal string into a vector of bytes.
///
/// This function takes a hexadecimal string as input and converts it into a `Vec<u8>`.
/// It handles both uppercase and lowercase hexadecimal characters and returns an error
/// if the input string contains invalid characters or has an odd length.
///
/// # Arguments
///
/// * `hex_string`: The hexadecimal string to parse.
///
/// # Returns
///
/// * `Result<Vec<u8>, ThisProjectError>`: A `Result` containing the vector of bytes on success,
///   or a `ThisProjectError` if parsing fails.
fn hex_string_to_bytes(hex_string: &str) -> Result<Vec<u8>, ThisProjectError> {
    // Check for valid length (must be even)
    if hex_string.len() % 2 != 0 {
        return Err(ThisProjectError::InvalidData(
            "Invalid hex string: Odd length".into(),
        ));
    }

    let mut bytes = Vec::with_capacity(hex_string.len() / 2);
    for i in (0..hex_string.len()).step_by(2) {
        let byte_str = &hex_string[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
            ThisProjectError::InvalidData("Invalid hex string: Invalid characters".into())
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Gets a list of active collaborators by reading stub file names in the sync_data directory.
///
/// This function reads the names of files (which are the collaborator names)
/// within the directory:  `sync_data/{team_channel_name}/is_active/`. Each file represents an active collaborator.
/// The function handles directory reading errors and filters out entries that are not files.
///
/// # Arguments
///
/// * None
///
/// # Returns
///
/// * `Result<Vec<String>, ThisProjectError>`:  A `Result` containing a vector of active collaborator names (`Vec<String>`) on success,
///   or a `ThisProjectError` if an error occurs (e.g., during directory reading).
fn get_active_collaborator_names() -> Result<Vec<String>, ThisProjectError> {
    // 1. Get the team channel name
    let team_channel_name = match get_current_team_channel_name() {
        Some(name) => name,
        None => {
            debug_log!("Error: Could not get current channel name in get_active_collaborator_names. Skipping.");
            return Err(ThisProjectError::InvalidData("Could not get team channel name".into()));
        },
    };

    // 2. Construct Path to "is_active" directory
    let is_active_dir = Path::new("sync_data")
        .join(&team_channel_name)
        .join("is_active");

    // 3. Create Vector to Hold Names
    let mut active_collaborators: Vec<String> = Vec::new(); // Initialize an empty vector

    // 4. Read Directory and Collect Names
    match read_dir(&is_active_dir) { // returns Result<ReadDir> so we match on it
        Ok(entries) => {
            // Handle potential errors inside the loop, so not all are lost in case of one error.
            for entry in entries {
                // Handle DirEntry Result
                match entry {
                    Ok(entry) => {
                        // Is it a file?
                        if entry.path().is_file() {
                            // Extract file_name as String
                            let file_name = entry.file_name(); // returns OsString which cannot be string-matched
                            let collaborator_name = file_name.to_string_lossy().into_owned();  // so convert to owned String
                            active_collaborators.push(collaborator_name);
                        }
                    },
                    Err(err) => {
                        debug_log!("Error reading entry: {}", err);
                        // Handle error appropriately.
                        // You might choose to skip the bad entry, log and return an error, or continue
                        // return Err(...); // Example, if you want to stop on first error
                    },
                }
            }
            Ok(active_collaborators) // Return vector of names on success
        }
        Err(err) => Err(ThisProjectError::IoError(err)), // Return error if directory read fails
    }
}

/// Adds a file path to the send queue for all active collaborators in a team channel.
///
/// This function creates a new file containing the file path to be sent. The file is placed in a directory structure under `sync_data`,
/// specifically `sync_data/{team_channel_name}/sendqueue_updates/FILENAME.txt
/// The timestamp is used to ensure unique filenames and can be used for ordering or managing updates.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `collaborator_name`: The name of the collaborator.
/// * `file_path`: The path to the file to be added to the queue.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a `ThisProjectError` if an error occurs.
fn save_updateflag_path_for_sendqueue(
    team_channel_name: &str,
    file_path: &PathBuf, // Take PathBuf directly
) -> Result<(), ThisProjectError> {

    debug_log!(
        "save_updateflag_path_for_sendqueue: team: {:?}, path: {:?}",
        team_channel_name,
        file_path,
    );
    
    // Get active collaborator names
    let active_collaborators = match get_active_collaborator_names() {
        Ok(names) => names,
        Err(e) => {
            debug_log!("Error getting active collaborators: {}", e);
            return Err(e); // Or handle error differently
        }
    };
    
    // 1. Convert hashes to hex string
    // remove_non_alphanumeric
    let filename_for_updateflag = remove_non_alphanumeric(&file_path.to_string_lossy().to_string());    

    // Use the active_collaborators list to determine which queue updates to save
    for this_iter_collaborator_name in active_collaborators {
        // Construct the update flag path for this specific collaborator
        // and save the update flag

        // 2. Construct Directory Path (using PathBuf)
        let mut queue_dir = PathBuf::from("sync_data");
        queue_dir.push(team_channel_name);
        queue_dir.push("sendqueue_updates");
        queue_dir.push(this_iter_collaborator_name);

        // 3. Create Directory (if needed)
        create_dir_all(&queue_dir)?;
    
        // 4. Construct File Path (within directory, with filename_for_updateflag)
        let queue_file = queue_dir.join(format!("{}.txt", filename_for_updateflag));
    
        // 5. Write Filepath to Queue File (convert PathBuf to String, handle potential errors)
        let file_path_string = file_path.to_string_lossy().to_string();
        write(queue_file, file_path_string)?;
    }
    
    debug_log!("File path added to send queue: {:?}", file_path);
    Ok(())
}

// /// Saves data to a file with a filename derived from a hash array.
// ///
// /// This function saves a stub file (named file with no contents) within the specified `directory`.  The filename
// /// is generated by converting the `hash_array` into a hexadecimal string using `hash_array_to_hex_string()`.
// /// if content data are needed that can be added later, but perahps nothing is needed
// ///
// /// # Arguments
// ///
// /// * `hash_array`: A slice of `u8` values used to generate the filename.
// /// * `remote_collarator_name`
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>`: `Ok(())` if the file is successfully saved,
// ///   or a `ThisProjectError` if an error occurs (e.g., during file creation or writing).
// ///
// /// # Example
// ///
// fn set_prefail_flag_via_hash__for_sendfile(
//     hash_array: &[u8],
//     remote_collarator_name: &String,
// ) -> Result<(), ThisProjectError> {
//     let file_name = docid__hash_array_to_hex_string(hash_array);


//     // get team channel from single source of truth
//     let team_channel_name = get_current_team_channel_name();
    
//     // as path
//     // if not exist, make it
//     directory = format..."sync_data/team_channel/fail_flags/{}/DOC-ID", remote_collarator_name, file_name;
    
//     let file_path = directory.join(file_name);
    
//     // Check for and create the directory
//     if let Some(parent_dir) = directory.parent() {
//         std::fs::create_dir_all(parent_dir)?;
//     } else {
//         return Err(ThisProjectError::GpgError("Invalid directory path, no parent".into()))
//     }

//     let mut file = File::create(file_path)?;
//     file.write_all()?;
//     Ok(())
// }


fn hash_sendfile_struct_fields(
    salt_list: &[u128],
    intray_send_time: u64,
    gpg_encrypted_intray_file: &[u8], // Use a slice for efficiency
) -> Result<Vec<u8>, ThisProjectError> {
    let mut calculated_hashes = Vec::with_capacity(salt_list.len());
    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&intray_send_time.to_be_bytes());
    data_to_hash.extend_from_slice(gpg_encrypted_intray_file);
    for salt in salt_list {
        let mut salted_data = data_to_hash.clone();
        salted_data.extend_from_slice(&salt.to_be_bytes());
        match pearson_hash_base(&salted_data) {
            Ok(hash) => calculated_hashes.push(hash),
            Err(e) => {
                debug_log!("hash_sendfile_struct_fields(): Error calculating Pearson hash: {}", e);
                return Err(ThisProjectError::IoError(e));
            }
        }
    }    
    Ok(calculated_hashes)
}

fn hash_checker_for_sendfile_struct(
    salt_list: &[u128],
    intray_send_time: u64,
    gpg_encrypted_intray_file: &[u8], // Use a slice
    compare_to_this_hashvec: &[u8], // Use a slice
) -> bool {
    // 1. Fail by default
    let mut all_hashes_match = false; // Initialize to false (Fail by default)

    debug_log!("hash_checker_for_sendfile_struct(): Starting verification...");

    // 2. Calculate expected hashes
    let calculated_hashes_result = hash_sendfile_struct_fields(salt_list, intray_send_time, gpg_encrypted_intray_file);

    match calculated_hashes_result {
        Ok(calculated_hashes) => {
            // 3. Length Check
            if calculated_hashes.len() != compare_to_this_hashvec.len() {
                debug_log!("hash_checker_for_sendfile_struct(): Hash list length mismatch. Expected: {}, Received: {}", calculated_hashes.len(), compare_to_this_hashvec.len());
            } else {
                // 4. Compare hashes one by one
                all_hashes_match = true; // Assume they match initially
                for (i, &calculated_hash) in calculated_hashes.iter().enumerate() {
                    if calculated_hash != compare_to_this_hashvec[i] {
                        debug_log!("hash_checker_for_sendfile_struct(): Hash mismatch at index {}. Expected: {:02x}, Received: {:02x}", i, calculated_hash, compare_to_this_hashvec[i]);
                        all_hashes_match = false;
                        break;
                    }
                }
                if all_hashes_match {
                    debug_log!("hash_checker_for_sendfile_struct(): All hashes match.");
                }
            }
        },
        Err(e) => {
             debug_log!("hash_checker_for_sendfile_struct():  Error calculating hashes: {:?}. Returning false.", e);
        },
    }
    debug_log!("hash_checker_for_sendfile_struct(): Verification completed. Result: {}", all_hashes_match);
    
    all_hashes_match
}


/// Saves a "pre-fail" flag file (an empty file used as a marker).
///
/// This function creates an empty file within the `sync_data` directory to serve as a "pre-fail"
/// flag.  The file's name is derived from the provided `hash_array`, and its presence indicates
/// that a file send attempt is in progress (and assumed to have failed unless explicitly cleared).
/// The directory structure is as follows:  `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/{doc_id}`
///
/// # Arguments
///
/// * `hash_array`: A slice of `u8` values used to generate the filename (doc_id).
/// * `remote_collaborator_name`: The name of the remote collaborator associated with the flag.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`:  `Ok(())` if the flag file is successfully created, or a `ThisProjectError`
///   if an error occurs (e.g., during file creation or directory creation).
///
fn set_prefail_flag_via_hash__for_sendfile(
    hash_array: &[u8],
    remote_collaborator_name: &str,
) -> Result<(), ThisProjectError> {
    let doc_id = docid__hash_array_to_hex_string(hash_array);

    let team_channel_name = get_current_team_channel_name()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

    let mut directory = PathBuf::from("sync_data"); // Use PathBuf not format!()
    directory.push(&team_channel_name);
    directory.push("fail_retry_flags");
    directory.push(remote_collaborator_name);
    create_dir_all(&directory)?; // Create the directory structure if it doesn't exist

    let file_path = directory.join(&doc_id);  // Use doc_id directly
    File::create(file_path)?; // Create the empty file as a flag
    Ok(())
}


/// Removes a "pre-fail" flag file, indicating successful file transfer.
///
/// This function removes the flag file previously created by `set_prefail_flag_via_hash__for_sendfile`.
/// The file's absence signals that the associated file transfer has completed successfully.
///
/// # Arguments
///
/// * `hash_array`: A slice of `u8` values used to generate the filename (doc_id).
/// * `remote_collaborator_name`: The name of the remote collaborator associated with the flag.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if the file is successfully removed or if it doesn't exist (which
///   is a valid state), or a `ThisProjectError` if another error occurs during file removal.
///
fn remove_prefail_flag__for_sendfile(
    hash_array: &[u8],
    remote_collaborator_name: &str,
) -> Result<(), ThisProjectError> {

    let doc_id = docid__hash_array_to_hex_string(hash_array);


    let team_channel_name = get_current_team_channel_name()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?; // Handle error

    // Use PathBuf and push components, this is clear, safe and cross-platform
    let mut directory = PathBuf::from("sync_data");
    directory.push(&team_channel_name);
    directory.push("fail_retry_flags");
    directory.push(remote_collaborator_name);
    create_dir_all(&directory)?; // Create the directory structure if it doesn't exist
    let file_path = directory.join(&doc_id);

    // Remove the file, but it's ok if it doesn't exist:
    match remove_file(file_path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()), // OK if file not found
        Err(e) => Err(ThisProjectError::IoError(e)),
    }
}

// /// Removes a file in the specified directory with a name based on a hash.
// ///
// /// # Arguments
// ///
// /// * `hash_array`: A slice of `u8` values used to generate the filename.
// /// * `directory`: The path to the directory containing the file to be removed.
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>`: `Ok(())` if the file is successfully removed or if it doesn't exist,
// ///   or a `ThisProjectError` if an error occurs during file removal.
// fn remove_prefail_flag__for_sendfile(
//     hash_array: &[u8],
//     remote_collarator_name: &String,
// ) -> Result<(), ThisProjectError> {
//     let hex_string = docid__hash_array_to_hex_string(hash_array); // Use the helper function
    
//     // get team channel from single source of truth
//     let team_channel_name = get_current_team_channel_name();
    
//     // as path
//     // if not exist, make it
//     directory = format..."sync_data/team_channel/fail_flags/{}/DOC-ID", remote_collarator_name, file_name;
    
//     let file_path = directory.join(hex_string);

//     match remove_file(file_path) {
//         Ok(_) => Ok(()), // File removed successfully
//         Err(e) if e.kind() == ErrorKind::NotFound => Ok(()), // File not found, but that's OK
//         Err(e) => Err(ThisProjectError::IoError(e)), // Other error during file removal
//     }
// }



// let timestamp_request_port = // ... port for sending "ready to receive" to collaborator
// let file_receive_port = // ...  port for receiving files from collaborator 
// let receipt_confirmation_port = // ... port for sending confirmations to collaborator

fn send_data(data: &[u8], target_addr: SocketAddr) -> Result<(), io::Error> { 
    let socket = UdpSocket::bind(":::0")?; 
    socket.send_to(data, target_addr)?;
    Ok(())
}



// use std::path::{Path, PathBuf};
// use std::fs::{read_to_string, write, create_dir_all};


// /// Retrieves or initializes the timestamp of the latest received file from a specific collaborator.
// ///
// /// This function attempts to read the latest received file timestamp from a file at:
// /// `sync_data/{team_channel_name}/latest_receivedfile_timestamps/{remote_collaborator_name}/latest_received_file_timestamp`.
// /// If the file or directory structure doesn't exist, it creates the necessary directories and initializes the timestamp to 0,
// /// effectively treating it as a bootstrap condition.
// ///
// /// # Arguments
// ///
// /// * `team_channel_name`: The name of the team channel.
// /// * `remote_collaborator_name`: The name of the remote collaborator.
// ///
// /// # Returns
// ///
// /// * `u64`: The latest received file timestamp.  Returns 0 if no timestamp file exists or if there was an error reading it (which
// ///   is handled internally by initializing a new timestamp file with 0).
// fn latest_received_file_timestamp_get_or_initialize(
//     remote_collaborator_name: &str,
// ) -> u64 {
    
//     let team_channel_name = get_current_team_channel_name()
//         .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;
    
//     debug_log!("latest_received_file_timestamp_get_or_initialize() called with team_channel_name: {}, remote_collaborator_name: {}", team_channel_name, remote_collaborator_name);
    
//     let mut timestamp_file_path = PathBuf::from("sync_data");
//     timestamp_file_path.push(team_channel_name);
//     timestamp_file_path.push("latest_receivedfile_timestamps");
//     timestamp_file_path.push(remote_collaborator_name);
//     timestamp_file_path.push("latest_received_file_timestamp");

//     // 1. Ensure directory structure exists
//     if let Some(parent) = timestamp_file_path.parent() {
//         if let Err(e) = create_dir_all(parent) {
//             debug_log!("Error creating directory: {}", e); // Log and return
//             return 0;
//         }
//     } else {
//         debug_log!("Invalid timestamp file path: No parent directory");
//         return 0;
//     }

//     // 2. Try to read existing timestamp
//     match read_to_string(×tamp_file_path) {
//         Ok(timestamp_str) => {
//             match timestamp_str.trim().parse() {
//                 Ok(timestamp) => {
//                     debug_log!("Timestamp read from file: {}", timestamp);
//                     return timestamp; 
//                 }
//                 Err(e) => {
//                     debug_log!("Error parsing timestamp from file: {}", e);
//                     // Fall through to initialize with 0 if parsing fails
//                 }
//             }
//         }
//         Err(e) if e.kind() == std::io::ErrorKind::NotFound => { 
//             debug_log!("No timestamp file found. Initializing new file.");
//             // Initialize with 0 if the file doesn't exist
//         }
//         Err(e) => {
//             debug_log!("Error reading timestamp file: {}", e);
//             return 0; // Or handle the error as you see fit (e.g., panic)
//         }
//     }

//     // 3. Initialize with 0 and create/write file if not found or parsing error
//     if let Err(e) = write(×tamp_file_path, "0") { // Returns error or ()
//         debug_log!("Error writing initial timestamp to file: {}", e);
//     } else {
//         debug_log!("Initialized timestamp file with 0");
//     }

//     0 // Return the default
// }




// /// Retrieves or initializes the timestamp of the latest received file from a specific collaborator.
// ///
// /// This function reads the latest received file timestamp from:
// /// `sync_data/{team_channel_name}/latest_receivedfile_timestamps/{remote_collaborator_name}/latest_received_file_timestamp`.
// /// If it doesn't exist, it initializes the timestamp to 0 and creates the necessary directories and file.
// ///
// /// # Arguments
// ///
// /// * `remote_collaborator_name`: The name of the remote collaborator.
// ///
// /// # Returns
// ///
// /// * `Result<u64, ThisProjectError>`: The timestamp on success, or a `ThisProjectError` on failure.
// fn latest_received_file_timestamp_get_or_initialize(
//     remote_collaborator_name: &str,
// ) -> Result<u64, ThisProjectError> { // Correct return type
    
//     let team_channel_name = get_current_team_channel_name()
//         .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?; // Now correctly uses Result

//     debug_log!("latest_received_file_timestamp_get_or_initialize() called with team_channel_name: {}, remote_collaborator_name: {}", team_channel_name, remote_collaborator_name);
    
//     let mut timestamp_file_path = PathBuf::from("sync_data");
//     timestamp_file_path.push(&team_channel_name); // Borrow team_channel_name
//     timestamp_file_path.push("latest_receivedfile_timestamps");
//     timestamp_file_path.push(remote_collaborator_name);
//     timestamp_file_path.push("latest_received_file_timestamp");

//     // 1. Ensure directory structure exists
//     if let Some(parent) = timestamp_file_path.parent() {
//         if let Err(e) = create_dir_all(parent) {
//             debug_log!("Error creating directory: {}", e); // Log and return
//             return Ok(0);
//         }
//     } else {
//         debug_log!("Invalid timestamp file path: No parent directory");
//         return Ok(0);
//     }

//     // 2. Try to read existing timestamp
//     match read_to_string(×tamp_file_path) { // Use & for borrowing
//         Ok(timestamp_str) => {
//             match timestamp_str.trim().parse() {
//                 Ok(timestamp) => {
//                     debug_log!("Timestamp read from file: {}", timestamp);
//                     return Ok(timestamp); // Return Ok(timestamp)
//                 }
//                 Err(e) => {
//                     debug_log!("Error parsing timestamp from file: {}", e);
//                     // Fall through to initialize with 0 if parsing fails
//                 }
//             }
//         }
//         Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
//             debug_log!("No timestamp file found. Initializing new file.");
//         }
//         Err(e) => {
//             debug_log!("Error reading timestamp file: {}", e);
//             return Err(ThisProjectError::IoError(e)); // Correct error return
//         }
//     }

//     // 3. Initialize with 0 and create/write file if not found or parsing error
//     if let Err(e) = write(×tamp_file_path, "0") {
//         debug_log!("Error writing initial timestamp to file: {}", e);
//         return Err(ThisProjectError::IoError(e)); // Correct error handling
//     } else {
//         debug_log!("Initialized timestamp file with 0");
//     }

//     Ok(0) // Return Ok(0)
// }



// /// Retrieves or initializes the timestamp of the latest received file.
// /// Creates the necessary directories and file if they don't exist.
// ///
// /// # Arguments
// ///
// /// * `remote_collaborator_name`: The name of the remote collaborator.
// ///
// /// # Returns
// ///
// /// * `Result<u64, ThisProjectError>`: The latest received file timestamp on success, or a `ThisProjectError` on failure.
// fn latest_received_file_timestamp_get_or_initialize(
//     remote_collaborator_name: &str,
// ) -> Result<u64, ThisProjectError> {
//     let team_channel_name = get_current_team_channel_name()
//         .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

//     let mut timestamp_file_path = PathBuf::from("sync_data");
//     timestamp_file_path.push(&team_channel_name);
//     timestamp_file_path.push("latest_receivedfile_timestamps");
//     timestamp_file_path.push(remote_collaborator_name);
//     timestamp_file_path.push("latest_received_file_timestamp");

//     // Create directories if they don't exist:
//     if let Some(parent) = timestamp_file_path.parent() {
//         create_dir_all(parent)?;
//     }

//     // Attempt to read the timestamp. If the file doesn't exist or parsing fails, initialize it to 0:
//     let timestamp: u64 = match std::fs::read_to_string(×tamp_file_path) // Borrow with &
//         .map_err(|e| ThisProjectError::IoError(e)) // Convert to ThisProjectError if appropriate
//         .and_then(|s| s.trim().parse().map_err(|e| ThisProjectError::ParseIntError(e)))
//     {
//         Ok(ts) => ts,
//         Err(e) => {
//             // Could not read. Initialize with 0 and create the file
//             if let Err(e) = write(×tamp_file_path, "0") { // Must borrow with &
//                 return Err(ThisProjectError::IoError(e)); // And return error
//             }
//             0 // Return default timestamp
//         }
//     };


//     Ok(timestamp)
// }


// use std::fs::{File, create_dir_all, read_to_string};
// use std::io::Write;
// use std::path::PathBuf;

/// Gets the latest received file timestamp for a collaborator in a team channel, using a plain text file.
///
/// This function reads the timestamp from a plain text file at:
/// `sync_data/{team_channel_name}/latest_receivedfile_timestamps/{collaborator_name}/latest_received_file_timestamp.txt`
/// If the file or directory structure doesn't exist, it creates them and initializes the timestamp to 0.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `collaborator_name`: The name of the collaborator.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`:  The latest received timestamp on success, or a `ThisProjectError` if an error occurs.
fn get_latest_received_file_timestamp_plaintext(
    collaborator_name: &str,
    team_channel_name: &str,
) -> Result<u64, ThisProjectError> {
    let mut file_path = PathBuf::from("sync_data");
    file_path.push(team_channel_name);
    file_path.push("latest_receivedfile_timestamps");
    file_path.push(collaborator_name);
    file_path.push("latest_received_file_timestamp.txt");

    
    
    
    // Create directory structure if it doesn't exist
    if let Some(parent) = file_path.parent() {
        create_dir_all(parent)?;
    }

    // Read or initialize the timestamp
    match read_to_string(&file_path) {
        Ok(timestamp_str) => {
            // if let Ok(timestamp) = timestamp_str.trim().parse() {
            // Parse with error handling
            match timestamp_str.trim().parse::<u64>() {
                Ok(timestamp) => Ok(timestamp),
                Err(e) => {
                    debug_log!("Error parsing timestamp from file: {}", e);
                    Err(ThisProjectError::from(e))
                }
            }
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // File not found, initialize to 0
            let mut file = File::create(&file_path)?;
            file.write_all(b"0")?; // Write zero timestamp
            Ok(0)
        }
        Err(e) => Err(ThisProjectError::IoError(e)), // Other IO errors
    }
}


/// Sets the latest received file timestamp for a collaborator in a team channel, using a plain text file.
///
/// This function writes the `timestamp` to a file at the specified path, creating the directory structure if needed.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `collaborator_name`: The name of the collaborator.
/// * `timestamp`: The timestamp to set.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a `ThisProjectError` if an error occurs.
fn set_latest_received_file_timestamp_plaintext(
    team_channel_name: &str,
    collaborator_name: &str,
    timestamp: u64,
) -> Result<(), ThisProjectError> {
    let mut file_path = PathBuf::from("sync_data");
    file_path.push(team_channel_name);
    file_path.push("latest_receivedfile_timestamps");
    file_path.push(collaborator_name);
    file_path.push("latest_received_file_timestamp.txt");

    // Create directory structure if it doesn't exist
    if let Some(parent) = file_path.parent() {
        create_dir_all(parent)?;
    }

    // Write the timestamp to the file, overwriting any previous content
    std::fs::write(file_path, timestamp.to_string())?;
    Ok(())
}



   // // Create the initial ReadySignal (without hashes)
    // let proto_ready_signal = ReadySignal {
    //     rt: Some(last_received_timestamp),
    //     rst: Some(get_current_unix_timestamp()),
    //     re: Some(is_echo_send),
    //     rh: None,
    // };

    // // Calculate and add hashes
    // let ready_signal = add_pearson_hash_to_readysignal_struct(
    //     &proto_ready_signal,
    //     local_user_salt_list,
    // )
    // .ok_or(ThisProjectError::InvalidData("Failed to calculate ReadySignal hashes".into()))?; // Handle potential None
    

    // let serialized_signal = serialize_ready_signal(&ready_signal)?; // Serialize the ReadySignal

    // debug_log!(
    //     "Sending ReadySignal to {}: {:?}\n  (is_echo_send: {})",
    //     target_addr, ready_signal, is_echo_send
    // );

    // // Bind and Send (using existing send_data function)
    // let socket = UdpSocket::bind(":::0")?; // Bind to any available port on any interface.
    // send_data(&serialized_signal, target_addr)?;


    // // 4. Creates a ReadySignal instance to be the ready signal (Corrected)
    // let proto_ready_signal = match get_latest_recieved_from_collaborator_in_teamchannel_file_timestamp(
    //     // Clone the remote_collaborator_name
    //     &local_owner_desk_setup_data_clone.remote_collaborator_name.clone() 
    //     &local_owner_desk_setup_data_clone.local_user_salt_list.clone(), 
    // ) {
    //     Ok(latest_received_file_timestamp) => ReadySignal {
    //         rt: Some(latest_received_file_timestamp), // Correct field name and type
    //         rst: Some(get_current_unix_timestamp()), 
    //         re: Some(false), // Correct field name and type
    //         rh: None, // You'll need to calculate and add the hashes here later
    //     },
    //     Err(e) => {
    //         debug_log!("Error getting last received timestamp: {}", e); 
    //         // Handle the error here. You might want to:
    //         return Ok(()); // Exit the thread

    //         // or
    //         // continue; // Skip to the next iteration of the loop (if this is inside a loop)
    //         // or 
    //         // create a ReadySignal with a default timestamp value:
    //         // ReadySignal {
    //         //     rt: Some(0), // Default timestamp
    //         //     rst: Some(get_current_unix_timestamp()),
    //         //     re: Some(false),
    //         //     rh: None, 
    //         // }
    //     }
    // };
    
/// Sends a ReadySignal to the specified target address.
///
/// This function encapsulates the logic for sending a ReadySignal.  It handles
/// timestamp generation, hash calculation, serialization, and the actual sending
/// of the signal via UDP.
///
/// # Arguments
///
/// * `target_addr`: The `SocketAddr` of the recipient.
/// * `local_user_salt_list`: A slice of `u128` salt values for hash calculation.
/// * `last_received_timestamp`: The timestamp of the last received file.
/// * `is_echo_send`:  A boolean indicating whether this is an echo send.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if the signal was sent successfully, or a `ThisProjectError`
///   if an error occurred.
// fn send_ready_signal(
//     local_user_salt_list: Vec<u128>, 
//     local_user_ipv6_addr_list: Vec<Ipv6Addr>,
//     local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16,
//     last_received_timestamp: u64,
//     is_echo_send: bool,
// ) -> Result<(), ThisProjectError> {
fn send_ready_signal(
    local_user_salt_list: &[u128], 
    local_user_ipv6_address: &Ipv6Addr, 
    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16,
    last_received_timestamp: u64,
    is_echo_send: bool,
) -> Result<(), ThisProjectError> {
 
    // 4.1 Create the initial ReadySignal (without hashes)
    let proto_ready_signal = ReadySignal {
        rt: Some(last_received_timestamp),
        rst: Some(get_current_unix_timestamp()),
        re: Some(is_echo_send),
        rh: None,
    };

    // 4.2 complete ready signal struct with pearson hash
    let ready_signal_to_send_from_this_loop = add_pearson_hash_to_readysignal_struct(
        &proto_ready_signal,
        &local_user_salt_list,
    ).expect("send_ready_signal() Failed to add hash to ReadySignal"); 
    
    // 5. Serialize the ReadySignal
    let serialized_readysignal_data = serialize_ready_signal(
        &ready_signal_to_send_from_this_loop
    ).expect("inHLOD send_ready_signal() err Failed to serialize ReadySignal, ready_signal_to_send_from_this_loop"); 

    // --- Inspect Serialized Data ---
    debug_log!("inHLOD send_ready_signal() inspect Serialized Data: {:?}", ready_signal_to_send_from_this_loop);
    debug_log!("inHLOD send_ready_signal() serialized_readysignal_data: {:?}", serialized_readysignal_data);

    // TODO possibly have some mechanism to try addresses until one works?
    // 6. Send the signal @ 
    //    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
    // TODO figure out way to specify ipv6, 4, prioritizing, trying, etc.
    // (in theory...you could try them all?)
    // Select the first IPv6 address if available



    // Send the readysignal_data to the collaborator's ready_port
    // let target_addr = SocketAddr::new(
    //     IpAddr::V6(ipv6_address_copy), // Use the copied address
    //     local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
    // ); 
    let target_addr = SocketAddr::new(
        IpAddr::V6(*local_user_ipv6_address), // Directly use the provided address
        local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
    );

    // Log before sending
    debug_log!(
        "inHLOD send_ready_signal() Attempting to send ReadySignal to {}: {:?}", 
        target_addr, 
        local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
    );

    // // If sending to the first address succeeds, no need to iterate further

    if send_data(&serialized_readysignal_data, target_addr).is_ok() {
        debug_log("inHLOD send_ready_signal() 6. Successfully sent ReadySignal to {} (first address)");
        return Ok(()); // Exit the thread
    } else {
        debug_log("inHLOD send_ready_signal() err 6. Failed to send ReadySignal to {} (first address)");
        return Err(ThisProjectError::NetworkError("Failed to send ReadySignal".to_string())); // Return an error
    }


        
    Ok(())
}




/// Set up the local owner users in-tray desk
/// requests to recieve are sent from here
/// other people's owned docs are recieved here
/// gpg confirmed
/// save .toml (handle the type: content, node, etc.)
/// and 'gotit' signal sent out from here
///
/// echo_send: if any document comes in
/// automatically send out an echo-type request
/// if you get a file: auto-send an echo-request 
/// a thread per 'sync-event'
///     after entering loop
///     Alice follows these steps...
///     1. Check for halt/quit uma signal
///     2. Make a sync-event thread, enter thread
///     3. set sync_event_id to be unique thread id
///     4. Creates a ReadySignal instance to be the ready signal
///     5. Serialize the ReadySignal 
///     6. Send the signal @ local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip (exact ip choice pending...)
fn handle_local_owner_desk(
    local_owner_desk_setup_data: ForLocalOwnerDeskThread, 
) -> Result<(), ThisProjectError> {
    /*
    TODO:
    I think there is supposed to be a thread per 'sync-event'
    Alice makes an event thread:
    Alice says ready: in the thread
    Alice waits N-miliseconds
    If no reply, kill thread.
    if there is a reply to that event unqiue ID,
    - gpg verify input (if not, kill thread)
    - save .toml etc if ok (if not, kill thread)
    - make another echo-thread (repeat)
    - if ok: send 'gotit!!' signal
    - kill thread
    */
    
    // TODO maybe a flag here to exit the function?
    // let mut exit_hlod = false;
    
    // Clone the values
    let salt_list_1 = local_owner_desk_setup_data.local_user_salt_list.clone();
    let salt_list_2 = local_owner_desk_setup_data.local_user_salt_list.clone();

    let readyport_1 = local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip.clone();
    let readyport_2 = local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip.clone();    

    let remote_collaborator_name = local_owner_desk_setup_data.remote_collaborator_name.clone();
                
    let ipv6_addr_list = local_owner_desk_setup_data.local_user_ipv6_addr_list.clone();

    // Instead of storing Option<&Ipv6Addr>, store the owned Ipv6Addr
    let mut ipv6_addr_1: Option<Ipv6Addr> = None;
    let mut ipv6_addr_2: Option<Ipv6Addr> = None;
    
    // Clone the address when extracting it
    if let Some(addr) = ipv6_addr_list.get(0) {
        ipv6_addr_1 = Some(*addr); // Dereference and clone the IPv6 address
        ipv6_addr_2 = Some(*addr);
    }

    loop { // 1. start overall loop to restart whole desk
        let remote_collaborator_name_for_thread = remote_collaborator_name.clone();
        let salt_list_1_drone_clone = salt_list_1.clone();

        // 1.1 check for halt/quit uma signal
        if should_halt_uma() {
            debug_log!("should_halt_uma(), exiting Uma in handle_local_owner_desk()");
            break Ok(());

        }

        // --- Get team channel name ---
        let team_channel_name = match get_current_team_channel_name() {
            Some(name) => name,
            None => {
                debug_log!("Error: Could not get current channel name. Skipping.");
                continue; // Skip to the next loop iteration
            }
        };

        // wait, if only for testing, so thread debug prints do not ~overlap
        thread::sleep(Duration::from_millis(1000)); // Avoid busy-waiting

        debug_log!("\n (re)Start HLOD handle_local_owner_desk()");
        // Print all sync data for the desk
        debug_log!("
            HLOD handle_local_owner_desk: local_owner_desk_setup_data -> {:?}", 
            &local_owner_desk_setup_data
        );

        /*
        internal "echo":
        To avoid a prolonged delay if there is a backlog of files to recieve,
        but still allow a 3-5 sec pause when there is no backlog, 
        each file-recept will turn off the echo
        */
        // let mut echo_flag = false;

        // Drone Loop in a thread? 
        // --- 1.5 Spawn a thread to handle "Ready" signals & fail-flag removal ---
        let ready_thread = thread::spawn(move || {
            //////////////////////////////////////
            // Listen for 'I got it' GotItSignal
            ////////////////////////////////////
            loop {
                // 1.1 Wait (and check for exit Uma)
                // TODO 
                for i in 0..5 {
                    // break for loop ?
                    if should_halt_uma() {
                        debug_log!("should_halt_uma(), exiting Uma in handle_local_owner_desk()");
                        break;
                    }
                    thread::sleep(Duration::from_millis(1000));
                }
                // break loop loop?
                if should_halt_uma() {
                    debug_log!("HLOD should_halt_uma(), exiting Uma in handle_local_owner_desk()");
                    break;
                }
                
                debug_log!("\nHLOD Drone Loop Start...thanks for coming around!");

                // 1.2 Refresh Timestamp
                // Get/Set latest_received_file_timestamp
                // output  zero and set zero file if no file/path etc.
                /*
                @
                sync_data/{team_channel}/latest_receivedfile_timestamps/bob/latest_received_file_timestamp
                */
                // let mut latest_received_file_timestamp = get_latest_received_file_timestamp_plaintext(
                //     &local_owner_desk_setup_data_clone.remote_collaborator_name,
                //     &team_channel_name,
                // );
                let latest_received_file_timestamp = match get_latest_received_file_timestamp_plaintext(
                    &team_channel_name, // Correct argument order.
                    &remote_collaborator_name_for_thread,
                ) {
                    Ok(ts) => ts, // Correct: Use 'ts' directly.
                    Err(e) => {
                        debug_log!("Error getting timestamp: {}. Using 0.", e);
                        0 // Use a default timestamp (0) if an error occurs.
                    }
                };

                // 1.3 Send Ready Signal (using a function)        
                if let Some(addr_1) = ipv6_addr_1 {
                    // Now addr_1 is a &Ipv6Addr, which matches the function signature
                    send_ready_signal(
                        &salt_list_1_drone_clone,
                        &addr_1,
                        readyport_1,
                        latest_received_file_timestamp,
                        false,
                    );
                }
                debug_log!("\n");
            } // end drone loop (ready-signals)
        }); // end ready_thread

        //////////////////////////////
        // 3. InTrayListerLoop Start
        ////////////////////////////

        // 3.1 hash_set_session_nonce = HashSet::new() as protection against replay attacks Create a HashSet to store received hashes
        let mut hash_set_session_nonce = HashSet::new();  // Create a HashSet to store received hashes

        // --- 2. Enter In-Try-loop ---
        // restarts if crashes
        // enter main loop (to handle in-tray Send-File, gotit signl sending, 'echo' ready-signal sending)
        loop { // 3.2 In-Try-loop

            // --- 3.3 Check for 'should_halt_uma' Signal ---
            if should_halt_uma() {
                debug_log!(
                    "HLOD-InTray 3.3 main loop Check for halt signal. Halting handle_local_owner_desk() for {}", 
                    local_owner_desk_setup_data.remote_collaborator_name
                );
                break;
            }

            // --- 3.4 Create UDP intray socket ---
            debug_log("HLOD Creating intray socket listening UDP...");
            let intray_socket = create_udp_socket(
                &local_owner_desk_setup_data.local_user_ipv6_addr_list,
                local_owner_desk_setup_data.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            )?;
            debug_log!("HLOD: Intray socket created.");

            // --- 3.5 in-tray Send-File Event ---
            // "Listener"?
            // 3.5.1 Receive in-tray Send-File packet
            let mut buf = [0; 65536]; // Maximum UDP datagram size
            loop { // In-Tray-Loop
                // Check for halt signal at the beginning of the loop
                if should_halt_uma() {
                    debug_log!("HLOD-InTray: Halt signal received. Exiting.");
                    break;
                }
            
                match intray_socket.recv_from(&mut buf) {
                    Ok((amt, src)) => {
                    debug_log!(
                        "HLOD-InTray match intray_socket.recv_from(&mut buf) Ok((amt, src)) {:?} {:?}", 
                        amt,
                        src
                    );
                    
                    // Check for exit-signal:
                    if should_halt_uma() {
                        debug_log!(
                            "HLOD-InTray 3.5.2 main loop Check for halt signal. Halting handle_local_owner_desk() for {}", 
                            local_owner_desk_setup_data.remote_collaborator_name
                        );
                        break;
                    }
                    
                    debug_log!(
                        "HLOD-InTray 3.5.2.1 Ok((amt, src)) ready_port Signal Received {} bytes from {}", 
                        amt, 
                        src
                    );

                    // --- Inspect Raw Bytes ---
                    debug_log!(
                        "HLOD-InTray 3.5.2.2 Ready Signal Raw bytes received: {:?}", 
                        &buf[..amt]
                    ); 

                    // --- Inspect Bytes as Hex ---
                    let hex_string = buf[..amt].iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    debug_log!(
                        "HLOD-InTray 3.5.2.3 Ready Signal Raw bytes as hex: {}", 
                        hex_string
                    );

                    // --- 3.5.3 Deserialize the SendFile signal ---
                    // let incoming_intray_file_struct: SendFile = deserialize_intray_send_file_struct(&clearsigned_data)?;  // Deserialize from clearsigned data
                    
                    let mut incoming_intray_file_struct: SendFile = match deserialize_intray_send_file_struct(&buf[..amt]) {
                        Ok(incoming_intray_file_struct) => {

                            debug_log!("HLOD-InTray 2.3 Deserialize Ok(incoming_intray_file_struct) {}: Received SendFile: {:?}",
                                local_owner_desk_setup_data.remote_collaborator_name, 
                                incoming_intray_file_struct
                            ); // Log the signal
                            incoming_intray_file_struct
                        },
                        Err(e) => {
                            debug_log!("HLOD-InTray 2.3 Deserialize Err Receive data Failed to parse ready signal: {}", e);
                            continue; // Continue to the next iteration of the loop
                        }
                    };
                    
                    debug_log("##HLOD-InTray## starting checks(hound's tooth, they say) 2.4");
                    
                    // --- 3.2 timestamp freshness checks ---
                    let current_timestamp = get_current_unix_timestamp();
                    
                    debug_log!(
                        "HLOD 2.4.1 check timestamp freshness checks: current_timestamp -> {:?}",
                        current_timestamp
                    );

                    // 3.2.1 No Future Dated Requests
                    if incoming_intray_file_struct.intray_send_time > Some(current_timestamp + 5) { // Allow for some clock skew (5 seconds)
                        debug_log!("HLOD 2.4.2 check: Received future-dated timestamp. Discarding.");
                        continue;
                    }

                    // 3.2.2 No Requests Older Than ~10 sec
                    if current_timestamp - 10 > incoming_intray_file_struct.intray_send_time.expect("REASON") {
                        debug_log!("HLOD 2.4.3 check: Received outdated timestamp (older than 10 seconds). Discarding.");
                        continue;
                    }

                    // 3.2.3 Check .intray_hash_list hash
                    if incoming_intray_file_struct.intray_hash_list.is_none() {
                        debug_log("HLOD 2.4.4 Check: intray_hash_list hash field is empty. Drop packet and keep going.");
                        continue; // Drop packet: Restart the loop to listen for the next signal
                    }

                    // 3.2.4 Check .intray_send_time timestamp
                    if incoming_intray_file_struct.intray_send_time.is_none() {
                        debug_log("HLOD 2.4.5 Check: intray_send_time ready signal sent-at timestamp field is empty. Drop packet and keep going.");
                        continue; // Drop packet: Restart the loop to listen for the next signal
                    }

                    // --- 4 Check / Add Hash-Nonce for per-session ready-signals ---
                    // ...e.g. guarding against the few seconds of expiration-gap
                    // HLOD 4.1 Hashes
                    let incoming_intray_file_struct_hash_vec = incoming_intray_file_struct.intray_hash_list.clone().expect("intray_hash_list is none");

                    // 4.2
                    if !incoming_intray_file_struct_hash_vec.is_empty() {
                        if hash_set_session_nonce.contains(&incoming_intray_file_struct_hash_vec) {
                            debug_log!("HLOD 4.2 quasi nonce check: Duplicate SendFile received (hash match). Discarding.");
                            continue; // Discard the duplicate signal
                        }
                        hash_set_session_nonce.insert(incoming_intray_file_struct_hash_vec); // Add hash to the set
                    } else {
                        debug_log!("HLOD 4.2 quasi nonce check: SendFile received without hashes. Discarding."); // Or handle differently
                        continue;
                    }

                    // // --- 5 Hash-Check for SendFile Struct ---
                    // // HLOD 5 Drop packet when fail check
                    // if !verify_intray_sendfile_hashes( // make this function TODO
                    //     &incoming_intray_file_struct, 
                    //     &local_owner_desk_setup_data.remote_collaborator_salt_list,
                    // ) {
                    //     debug_log("HLOD 5: SendFile Struct hash verification failed. Discarding signal.");
                    //     continue; // Discard the signal and continue listening
                    // }
                    
                    
                    // --- 5.0 Hash-Check for SendFile Struct ---
                    // HLOD 5.0 Drop packet when fail check
                    // Check the hash of the incoming file against the provided list of salts
                    if !hash_checker_for_sendfile_struct(
                        &local_owner_desk_setup_data.remote_collaborator_salt_list, // Use remote collaborator's salts
                        incoming_intray_file_struct.intray_send_time.expect("Missing intray_send_time"), // Safe unwrap, checked earlier
                        incoming_intray_file_struct.gpg_encrypted_intray_file.as_deref().expect("Missing encrypted file"), // Safe unwrap, checked earlier
                        incoming_intray_file_struct.intray_hash_list.as_deref().expect("Missing hash list")  //Safe unwrap, checked earlier
                    
                    ) {
                        debug_log!("failed HLOD 5.0: SendFile Struct hash verification failed. Discarding signal.");
                        continue; // Discard the signal and continue listening
                    }
                    
                    debug_log!("Passed HLOD 5.0: SendFile Struct hash verified.");

                    // // replace this block
                    // match calculate_and_verify_sendfile_hashes(
                    //     &incoming_intray_file_struct,
                    //     &local_owner_desk_setup_data.remote_collaborator_salt_list,
                    // ) {
                    //     Ok((calculated_hashes, all_hashes_match)) => {
                    //         if !all_hashes_match {
                    //             debug_log("HLOD 5: SendFile Struct hash verification failed. Discarding signal.");
                    //             continue; // Discard the signal and continue listening
                    //         }
                    //         // If all hashes match, you can use the calculated_hashes for further processing if needed
                    //     }
                    //     Err(e) => {
                    //         debug_log(&format!("Error calculating and verifying SendFile hashes: {}", e));
                    //         continue; // Discard the signal and continue listening
                    //     }
                    // }
                    
                    // // replace with this code (incomplete)
                    // // if result is fail
                    // match hash_checker_for_sendfile_struct(
                    //     salt_list: &[u128],
                    //     incoming_intray_file_struct.intray_send_time: u64,
                    //     incoming_intray_file_struct.gpg_encrypted_intray_file: &[u8], // Use a slice
                    //     incoming_intray_file_struct.intray_hash_list// compare_to_this_hashvec: &[u8], // Use a slice
                    // ) {
                    //     Ok(all_hashes_match) => {
                    //         if !all_hashes_match {
                    //             debug_log("HLOD 5: SendFile Struct hash verification failed. Discarding signal.");
                    //             continue; // Discard the signal and continue listening
                    //         }
                    //         // If all hashes match, you can use the calculated_hashes for further processing if needed
                    //     }
                    //     Err(e) => {
                    //         debug_log(&format!("Error calculating and verifying SendFile hashes: {}", e));
                    //         continue; // Discard the signal and continue listening
                    //     }
                    // }
                                        
                    
                    // --- 6. HLOD decypt ---
                    // 6.1  Handle the Option<Vec<u8>> for gpg_encrypted_intray_file
                    let still_encrypted_file_blob = match &incoming_intray_file_struct.gpg_encrypted_intray_file {
                        Some(data) => data,  // Extract the Vec<u8> if Some
                        None => {
                            debug_log!("HLOD 6.1: gpg_encrypted_intray_file is None. Skipping.");
                            continue; // Or handle the None case differently (e.g., return an error)
                        }
                    };
                    debug_log!(
                        "HLOD 6.1 still_encrypted_file_blob -> {:?}",
                        still_encrypted_file_blob
                    );
                    
                    // 6.2 *Now* decrypt the data
                    let decrypted_clearsignfile_data = match gpg_decrypt_from_bytes(
                        still_encrypted_file_blob, 
                        &local_owner_desk_setup_data.local_user_gpg_publickey_id
                    ) { // Pass the extracted data
                        Ok(data) => data,
                        Err(e) => {
                            debug_log!("HLOD 6.2: GPG decryption failed: {}. Skipping.", e);
                            continue; // Skip to the next packet if decryption fails
                        }
                    };
                    debug_log!(
                        "HLOD 6.2 decrypt the data decrypted_clearsignfile_data -> {:?}",
                        decrypted_clearsignfile_data
                    );

                    // 6.3 Extract the clearsigned data
                    let extacted_clearsigned_data = match extract_clearsign_data(&decrypted_clearsignfile_data) {
                        Ok(data) => data,
                        Err(e) => {
                            debug_log!("HLOD 6.3: Clearsign extraction failed: {}. Skipping.", e);
                            continue;
                        }
                    };
                    debug_log!(
                        "HLOD 6.3 extacted_clearsigned_data -> {:?}",
                        extacted_clearsigned_data
                    );
                    
                    // 7 Save File into Uma Folder Structure
                    // let received_toml: Value = toml::from_slice(&extacted_clearsigned_data)?;
                    /*
                    1. if X then save in A place
                    2. if Y then save in B place
                    for a message file, 
                    filepath_in_node = "/instant_message_browser"
                    for MVP: just add it the same way you add any message, next available number.
                    
                    current_path = project_graph_data/team_channels/{}/instant_message_browser/
                    
                    let message_path = get_next_message_file_path(current_path, local_owner_user); 
                    */
                    // 7.1 1. Identifying Instant Message Files
                    let file_str = std::str::from_utf8(&extacted_clearsigned_data).map_err(|_| {
                        ThisProjectError::InvalidData("Invalid UTF-8 in file content".into())
                    })?;
                    
                    if !file_str.contains("filepath_in_node = \"/instant_message_browser\"") {
                        debug_log!("HLOD-InTray: Not an instant message file. Skipping.");
                        continue;
                    }

                    debug_log!(
                        "HLOD 7.1 found message file, file_str -> {:?}",
                        file_str
                    );
                    
                    // 7.2 
                    // 2. Generating File Path
                    let team_channel_name = get_current_team_channel_name()
                        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;
                    let mut current_path = PathBuf::from("project_graph_data/team_channels");
                    current_path.push(&team_channel_name);
                    current_path.push("instant_message_browser");
                    
                    let message_path = get_next_message_file_path(
                        &current_path, 
                        &local_owner_desk_setup_data.remote_collaborator_name // Use local user's name
                    );

                    debug_log!(
                        "HLOD 7.2 got-made message_path -> {:?}",
                        message_path
                    );
                    
                    // 3. Saving the File
                    if let Err(e) = fs::write(&message_path, &extacted_clearsigned_data) {
                        debug_log!("HLOD-InTray: Failed to write message file: {:?}", e);
                        // Consider returning an error here instead of continuing the loop
                        return Err(ThisProjectError::from(e));
                    }

                    debug_log!("7.3 HLOD-InTray: Instant message file saved to: {:?}", message_path);

                    //////////////
                    // Echo Base
                    //////////////
                    
                    // // TODO extract 
                    // let recieved_file_timestamp = ...read updated_at field from .toml (bytes?)

                    // Extract timestamp
                    let recieved_file_timestamp = match extract_updated_at_timestamp(
                        &extacted_clearsigned_data
                    ) {
                        Ok(timestamp) => timestamp,
                        Err(e) => {
                            debug_log!("HLOD-InTray: Error extracting timestamp: {}. Skipping.", e);
                            continue;
                        }
                    };
                    
                    // Now you have the recieved_file_timestamp timestamp
                    debug_log!("Received file updated at: {}", recieved_file_timestamp);
                    // println!("Received file updated at: {}", recieved_file_timestamp);
                    
                    // 1.3 Send Echo Ready Signal (using a function)        
                    if let Some(addr_2) = ipv6_addr_2 {
                        send_ready_signal(
                            &salt_list_2,
                            &addr_2,
                            readyport_2,
                            recieved_file_timestamp,
                            false,
                        );
                    }
                
                // },
                // Err(_) => todo!() // end Ok((amt, src)) => { // end Ok((amt, src)) => {
                    
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available yet.  Don't treat this as an error.
                    debug_log!("HLOD-InTray: No data available yet...WouldBlock");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue; // Continue to the next loop iteration
                }
                Err(e) => {
                    // A real error occurred. Log and handle it.
                    debug_log!("HLOD-InTray: Error receiving data: {}", e);
                    return Err(ThisProjectError::NetworkError(format!(
                        "Error receiving data: {}",
                        e
                    )));  // Or choose another way to handle this
                }
                }
            } // end match ready_socket.recv_from(&mut buf) {
        } // end In-Tray-Loop
        ////////////////////////
        // InTrayListerLoop End
        ////////////////////////
        

    // TESTING ONLY wait, if only for testing, so thread debug prints do not ~overlap
    thread::sleep(Duration::from_millis(100)); // Avoid busy-waiting
    
    debug_log!(
        "HLOD Exiting handle_local_owner_desk() for {}", 
        local_owner_desk_setup_data.local_user_name
    ); // Add collaborator name
}
}


/// Vanilla serialize (no serde!)
/// Due to exceptional priority of minimizing network load:
/// terse key names are used here, these still must not collide
/// though readability is regretibly reduced.
///
/// Use With
/// let socket = UdpSocket::bind(":::0")?; /// Bind to any available IPv6 address
///
/// let ready_signal = ReadySignal {
///     id: 12345,
///     timestamp: 1673276800,
/// };
///
/// Convert the struct data to bytes:
/// let data = serialize_ready_signal(&ready_signal)?; 
///
/// Send the data:
/// socket.send_to(&data, "[::1]:34254")?; /// Replace with your target address and port
/// Ok(())
fn serialize_ready_signal(this_readysignal: &ReadySignal) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();

    // Handle rt (timestamp) -  return an error if None:
    if let Some(rt) = this_readysignal.rt {
        bytes.extend_from_slice(&rt.to_be_bytes()); 
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData, 
            "Missing timestamp (rt) in ReadySignal",
        )); 
    }

    // Handle rst (send timestamp) - return an error if None: 
    if let Some(rst) = this_readysignal.rst {
        bytes.extend_from_slice(&rst.to_be_bytes()); 
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData, 
            "Missing send timestamp (rst) in ReadySignal",
        )); 
    }

    // Handle re (echo_send) -  use a default value (false) if None:
    let re = this_readysignal.re.unwrap_or(false); // Default to false if None
    bytes.push(if re { 1 } else { 0 }); 

    // Handle rh (hash list) - append if Some:
    if let Some(rh) = &this_readysignal.rh {
        bytes.extend_from_slice(rh);
    }
 
    Ok(bytes) 
}

/// Calculates Pearson hashes for a vector of byte slices.
///
/// This function iterates through the input `data_sets` and calculates the Pearson hash for each slice,
/// returning a vector of the calculated hashes.
///
/// # Arguments
///
/// * `data_sets`: A vector of byte slices to hash.
///
/// # Returns
///
/// * `Result<Vec<u8>, ThisProjectError>`: A `Result` containing a vector of the calculated Pearson hashes,
///   or a `ThisProjectError` if an error occurs during hash calculation. 
fn calculate_pearson_hashes(data_sets: &[&[u8]]) -> Result<Vec<u8>, ThisProjectError> {
    let mut hashes = Vec::new();
    for data in data_sets {
        let hash = pearson_hash_base(data)?;
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Vanilla Deserilize json signal
/// The idea of the salt-hash or salt-checksum
/// is that it is a faster and more anonymous way
/// to target the goals of packet-soundness checking
/// and spoof-protection
/// while keeping the computer and network load lite
/// Do not attempt to use Serde crate with this function!!!
fn deserialize_ready_signal(bytes: &[u8]) -> Result<ReadySignal, io::Error> {
    // ... [Your existing code for logging and length checking] ...

    // Extract timestamp (rt):
    let rt = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    debug_log!("DRS: ready_signal_timestamp: {}", rt);

    // Extract send timestamp (rst):
    let rst = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    debug_log!("DRS: ready_signal_send_timestamp: {}", rst);

    // Extract echo_send (re):
    let re = if bytes.len() > 16 { bytes[16] != 0 } else { false };
    debug_log!("DRS: echo_send: {}", re);
    
    // Extract hashes (rh):
    let rh = if bytes.len() > 17 { 
        Some(bytes[17..].to_vec()) 
    } else {
        None
    };
    
    // Correct the return statement to include rst:
    Ok(ReadySignal { 
        rt: Some(rt), 
        rst: Some(rst), // Include rst
        re: Some(re), 
        rh 
    })
}

/// Deserializes a byte slice into a SendFile struct.
///
/// This function performs the reverse operation of serializing a SendFile struct.
/// It takes a byte slice as input and extracts the fields to construct a SendFile instance.
/// It includes error handling for invalid data lengths and returns a Result to indicate success or failure.
///
/// # Arguments
/// * `bytes`: The byte slice containing the serialized SendFile data.
///
/// # Returns
///
/// * `Result<SendFile, ThisProjectError>`:  A Result containing the deserialized SendFile on success, or a ThisProjectError on failure.
fn deserialize_intray_send_file_struct(bytes: &[u8]) -> Result<SendFile, ThisProjectError> {
    // 1. Check Minimum Length
    let timestamp_len = std::mem::size_of::<u64>();
    let min_length = timestamp_len; // Minimum length for just the timestamp

    debug_log!(
        "DISFS Starting deserialize_intray_send_file_struct() bytes {:?}",
        bytes   
    );
    
    if bytes.len() < min_length {
        debug_log!("DISFS bytes.len() < min_length -> returning: Err(ThisProjectError::InvalidData(\"Invalid byte array length for SendFile\".into()))");
        return Err(ThisProjectError::InvalidData("Invalid byte array length for SendFile".into()));
    }

    debug_log!("DISFS bytes.len() >= min_length");
    

    // 2. Extract intray_send_time (as before)
    let intray_send_time = u64::from_be_bytes(bytes[0..timestamp_len].try_into().unwrap());

    // 3. Extract intray_hash_list  (Corrected)
    let hash_list_start = timestamp_len;
    let hash_list_end = hash_list_start + 4; // 4 u8 hashes = 4 bytes

    let intray_hash_list = if bytes.len() >= hash_list_end {
        Some(bytes[hash_list_start..hash_list_end].to_vec()) // Extract and wrap in Some()
    } else {
        None // No hash list present (handle as you see fit)
    };

    // 4. Extract gpg_encrypted_intray_file (Corrected)
    let gpg_encrypted_file_start = hash_list_end;
    let gpg_encrypted_intray_file = if bytes.len() > gpg_encrypted_file_start {
        Some(bytes[gpg_encrypted_file_start..].to_vec()) // Extract and wrap in Some()
    } else {
        None // Or handle the empty case appropriately
    };

    // ... [Construction of SendFile as before, but use Some() wrappers]
    Ok(SendFile {
        intray_send_time: Some(intray_send_time),
        gpg_encrypted_intray_file, // No need for clone, the value is already owned
        intray_hash_list,  // Use the corrected Option<Vec<u8>>
    })
}

/// Serializes a `SendFile` struct into a byte vector.
///
/// # Arguments
/// * `send_file`: The `SendFile` instance to serialize.
///
/// # Returns
///
/// * `Result<Vec<u8>, ThisProjectError>`:  The serialized `SendFile` data as a `Vec<u8>` on success, or a
///   `ThisProjectError` if serialization fails.
fn serialize_send_file(send_file: &SendFile) -> Result<Vec<u8>, ThisProjectError> {
    let mut serialized_data: Vec<u8> = Vec::new();

    // Add intray_send_time
    serialized_data.extend_from_slice(&send_file.intray_send_time.ok_or(ThisProjectError::InvalidData("Missing intray_send_time".into()))?.to_be_bytes());

    // Add intray_hash_list (handle Option)
    if let Some(hash_list) = &send_file.intray_hash_list {
        serialized_data.extend_from_slice(hash_list);
    } else {
        // Handle the None case. Perhaps return an error or use a default/empty hash list.
        return Err(ThisProjectError::InvalidData("intray_hash_list is None".into()));
    }

    // Add gpg_encrypted_file_contents (handle Option)
    if let Some(encrypted_file) = &send_file.gpg_encrypted_intray_file {
        serialized_data.extend_from_slice(encrypted_file);
    } else {
        return Err(ThisProjectError::InvalidData("gpg_encrypted_intray_file is None".into()));
    }

    Ok(serialized_data)
}


//     // 2. Extract intray_send_time
//     let intray_send_time = u64::from_be_bytes(bytes[0..timestamp_len].try_into().unwrap());

//     // 3. Extract intray_hash_list
//     let hash_list_start = timestamp_len;
//     let hash_list_end = hash_list_start + 4; // Assuming 4 salts (4 * u8 hashes)
//     debug_log!(
//         "DISFS hash_list_start {} hash_list_end {}",
//         hash_list_start, hash_list_end   
//     );
    
//     // if bytes.len() < hash_list_end {
//     //     debug_log!("DISFS bytes.len() < hash_list_end -> returning: Err(ThisProjectError::InvalidData(\"Invalid byte array length for SendFile intray_hash_list\".into()))");
//     //     return Err(ThisProjectError::InvalidData("Invalid byte array length for SendFile intray_hash_list".into()));
//     // }
//     debug_log!("DISFS bytes.len() >= hash_list_end {:?}", bytes.len() >= hash_list_end );
    
//     let intray_hash_list = if bytes.len() >= hash_list_end {
//         bytes[hash_list_start..hash_list_end].to_vec() // Extract hashes
//     } else {
//         return Err(ThisProjectError::InvalidData("Invalid byte array length for SendFile".into()));
//     };

//     // 4. Extract gpg_encrypted_intray_file
//     let gpg_encrypted_file_start = hash_list_end;
//     let gpg_encrypted_intray_file = if bytes.len() > gpg_encrypted_file_start {
//         debug_log!("DISFS gpg_encrypted_file_start-> {}", gpg_encrypted_file_start);
//         bytes[gpg_encrypted_file_start..].to_vec() // Extract file content
//     } else {
//         Vec::new() // Or handle the case where there's no file content as needed
//     };


//     // 5. Construct and return the SendFile struct
//     debug_log!("DISFS constructing SendFile struct");
    
//     Ok(SendFile {
//         intray_send_time: Some(intray_send_time),
//         gpg_encrypted_intray_file: Some(gpg_encrypted_intray_file.clone()),
//         intray_hash_list: Some(gpg_encrypted_intray_file),
//     })
// }

fn serialize_gotit_signal(signal: &GotItSignal) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();

    // bytes.extend_from_slice(&signal.gst.to_be_bytes());
    bytes.extend_from_slice(&signal.gst.expect("REASON").to_be_bytes());
    bytes.extend_from_slice(&signal.di.expect("REASON").to_be_bytes()); 
    // bytes.extend_from_slice(signal.gh.as_bytes());
    // Handle the gh Option
    if let Some(hash_list) = &signal.gh { 
        // If gh is Some, extend the bytes vector with the hash_list
        bytes.extend_from_slice(hash_list);
    } else {
        // Handle the None case (e.g., add a placeholder or return an error)
        // bytes.extend_from_slice(&[0u8; 32]); // Example: Add a 32-byte placeholder
    }

    Ok(bytes)
}

fn deserialize_gotit_signal(bytes: &[u8]) -> Result<GotItSignal, io::Error> {
    // Calculate expected lengths (assuming a u64 for both timestamp and ID)
    let timestamp_len = std::mem::size_of::<u64>();
    let id_len = std::mem::size_of::<u64>();
    let expected_min_length = timestamp_len + id_len; // Minimum length for timestamp and ID

    // Check if the byte array has enough data for at least the timestamp and document ID
    if bytes.len() < expected_min_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid byte array length for GotItSignal: too short",
        ));
    }

    // Extract the timestamp
    let gst = u64::from_be_bytes(bytes[0..timestamp_len].try_into().unwrap());

    // Extract the document ID
    let di = u64::from_be_bytes(bytes[timestamp_len..expected_min_length].try_into().unwrap());

    // Extract the hash list (if present)
    let gh = if bytes.len() > expected_min_length {
        Some(bytes[expected_min_length..].to_vec()) // Take the remaining bytes as the hash list
    } else {
        None // No hash list present
    };

    Ok(GotItSignal { 
        gst: Some(gst), 
        di: Some(di), 
        gh: gh, 
    }) 
}

/// File Deserialization (Receiving):
/// Receive Bytes: Receive the byte array from the network using socket.recv_from().
/// Convert to String: Convert the byte array back to a string using String::from_utf8(). This assumes the received bytes are in ASCII encoding.
/// Parse TOML: Parse the TOML string using the toml::from_str() function to create a TOML Value or a custom struct representing the data.
/// Save to File: Write the parsed TOML data to a file using fs::write().
fn receive_toml_file(socket: &UdpSocket) -> Result<(Value, SocketAddr), ThisProjectError> {
    let mut buf = [0; 65536]; // Maximum UDP datagram size
    let (amt, src) = socket.recv_from(&mut buf)?;

    // 2. Convert to string (handling FromUtf8Error)
    let toml_string = String::from_utf8(buf[..amt].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.utf8_error()))?;

    // 3. Parse TOML (handling toml::de::Error)
    let toml_value: Value = toml::from_str(&toml_string)?;

    // 4. Save to file (you'll need to determine the file path)
    // ...

    Ok((toml_value, src))
}

fn get_oldest_retry_timestamp(collaborator_username: &str) -> Result<Option<u64>, io::Error> {
    let retry_flags_dir = Path::new("project_graph_data/sync_state_items")
        .join(&collaborator_username) 
        .join("fail_retry_flags");

    if !retry_flags_dir.exists() {
        return Ok(None); // No retry flags exist
    }

    let mut oldest_timestamp: Option<u64> = None;

    for entry in fs::read_dir(retry_flags_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let file_name = path.file_name().unwrap().to_str().unwrap();
            if let Some((_, timestamp_str)) = file_name.split_once("__") {
                if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                    if oldest_timestamp.is_none() || timestamp < oldest_timestamp.unwrap() {
                        oldest_timestamp = Some(timestamp);
                    }
                }
            }
        }
    }

    Ok(oldest_timestamp)
}

fn create_retry_flag(
    collaborator: &RemoteCollaboratorPortsData, 
    file_path: &PathBuf, 
    timestamp: u64,
) -> Result<PathBuf, io::Error> {
    let retry_flags_dir = Path::new("project_graph_data/sync_state_items")
        .join(&collaborator.remote_collaborator_name)
        .join("fail_retry_flags");

    fs::create_dir_all(&retry_flags_dir)?; 

    // Generate a unique ID (you might use a UUID library for better uniqueness)
    let unique_id: u64 = rand::random();

    let retry_flag_file_name = format!("{}__{}.txt", unique_id, timestamp);
    let retry_flag_path = retry_flags_dir.join(retry_flag_file_name);

    // Create an empty file (the presence of the file acts as the flag)
    File::create(&retry_flag_path)?;

    Ok(retry_flag_path)
}

fn get_absolute_team_channel_path(team_channel_name: &str) -> io::Result<PathBuf> {
    let team_channels_dir = Path::new("project_graph_data/team_channels");
    let channel_path = team_channels_dir.join(team_channel_name);

    channel_path.canonicalize() // Get the absolute path
}


/// Gets existing send-Queue or makes a new one: to send out locally owned files: a queue of paths to those files
/// if back_of_queue_timestamp != 0 and
/// if request-time-stamp = send-q back_of_queue_timestamp -> just return timestamp
/// else: make a new timestamp
///  
/// can Creates a new send queue based on the provided timestamp and collaborator name.
///
/// This function crawls through the team channel directory tree, looking for TOML files owned by the specified local_owner_user(collaborator).
/// So that the local-owner-user can send their owned files to other collaborators.
/// This function adds file paths to the send queue if the file's `updated_at_timestamp` is greater than the provided `back_of_queue_timestamp`.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `localowneruser_name`: The name of the local-owner-usercollaborator.
/// * `back_of_queue_timestamp`: The timestamp to use as the starting point for the queue. If 0, all files are added to the queue.
///
/// # Returns
///
/// * `Result<SendQueue, ThisProjectError>`: A `Result` containing the new `SendQueue` on success, or a `ThisProjectError` on failure.
fn get_or_create_send_queue(
    team_channel_name: &str,
    localowneruser_name: &str,
    mut session_send_queue: SendQueue,
    ready_signal_timestamp: u64,
) -> Result<SendQueue, ThisProjectError> {
    /*
    #[derive(Debug, Clone)]
    struct SendQueue {
        back_of_queue_timestamp: u64,
        // echo_send: bool, //
        items: Vec<PathBuf>,  // ordered list, filepaths
    }
    */
    // let mut back_of_queue_timestamp = session_send_queue.back_of_queue_timestamp.clone();
    debug_log("HRCD->get_or_create_send_queue: start");
    
    // Get update flag paths
    let newpath_list = match get_sendq_update_flag_paths(
        team_channel_name, // No & needed now
        localowneruser_name, // Correct collaborator name
    ) {
        Ok(paths) => paths,
        Err(e) => {
            debug_log!("Error getting update flag paths: {}", e);
            return Err(e); // Or handle as needed
        }
    };

    // Add new paths to the front of the queue
    for this_iter_newpath in newpath_list {
        session_send_queue.add_to_front(this_iter_newpath); // Use the new method
    }
    
    // Note: this will not be true when making a queue, e.g. during first time bootstrapping
    if ready_signal_timestamp == session_send_queue.back_of_queue_timestamp {
        debug_log("HRCD->get_or_create_send_queue: ready_signal_timestamp == back_of_queue_timestamp");
        return Ok(session_send_queue)
    }
    
    // let mut send_queue = SendQueue {
    //     back_of_queue_timestamp,
    //     items: Vec::new(),
    // };

    // 1. Get the path RESULT
    let team_channel_path_result = get_absolute_team_channel_path(team_channel_name);


    // 2. HANDLE the Result from get_absolute_team_channel_path
    let team_channel_path = match team_channel_path_result {
        Ok(path) => path,
        Err(e) => {
            debug_log!("Error getting absolute team channel path: {}", e);
            return Err(e.into());  // Or handle the error differently
        }
    };

    debug_log!("HRCD->Starting crawl of directory: {:?}", team_channel_path);

    // 3. Use the unwrapped PathBuf with WalkDir
    for entry in WalkDir::new(&team_channel_path) { // Note the & for borrowing
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("toml")) {
            debug_log!("HRCD->get_or_create_send_queue: file is toml, entry -> {:?}", entry);
            // If a .toml file
            let toml_string = fs::read_to_string(entry.path())?;
            let toml_value: Value = toml::from_str(&toml_string)?;

            // If owner = target collaborator
            if toml_value.get("owner").and_then(Value::as_str) == Some(localowneruser_name) {
                debug_log("HRCD->get_or_create_send_queue: file owner == colaborator name");
                // If updated_at_timestamp exists
                if let Some(toml_updatedat_timestamp) = toml_value.get("updated_at_timestamp").and_then(Value::as_integer) {
                    debug_log("HRCD->get_or_create_send_queue: updated_at_timestamp field exists in file");
                    let toml_updatedat_timestamp = toml_updatedat_timestamp as u64;

                    // If updated_at_timestamp > back_of_queue_timestamp (or back_of_queue_timestamp is 0)
                    // if timestamp > back_of_queue_timestamp || back_of_queue_timestamp == 0 {
                    if toml_updatedat_timestamp > session_send_queue.back_of_queue_timestamp {
                        debug_log("HRCD->get_or_create_send_queue: timestamp > back_of_queue_timestamp");
                        // Add filepath to send_queue
                        session_send_queue.items.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    }
    
    debug_log("get_or_create_send_queue calling, get_toml_file_timestamp(), Hello?");
    
    // Sort the files in the queue based on their modification time
    session_send_queue.items.sort_by_key(|path| {
        get_toml_file_timestamp(path).unwrap_or(0) // Handle potential errors in timestamp retrieval
    });
    
    debug_log!("HRCD->get_or_create_send_queue: end: Q -> {:?}", session_send_queue);

    Ok(session_send_queue)
}

/// get latest Remote Collaborator file timestamp 
/// for use by handl local owner desk
fn get_latest_recieved_from_collaborator_in_teamchannel_file_timestamp(
    collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    let mut last_timestamp: u64 = 0; // Initialize with 0 (for bootstrap when no files exist)
    debug_log!("get_last_file_timestamp() started"); 

    let channel_dir_path_str = read_state_string("current_node_directory_path.txt")?; // read as string first
    debug_log!("1. Channel directory path (from session state): {}", channel_dir_path_str); 
    // Crawl through the team channel directory
    for entry in WalkDir::new(channel_dir_path_str) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension() == Some(OsStr::new("toml")) {
            let toml_string = fs::read_to_string(path)?;
            let toml_value: Value = toml::from_str(&toml_string)?;

            // Check if the file is owned by the collaborator
            if toml_value.get("owner").and_then(Value::as_str) == Some(collaborator_name) {
                // Get the updated_at_timestamp
                if let Some(timestamp) = toml_value
                    .get("updated_at_timestamp")
                    .and_then(Value::as_integer)
                    .map(|ts| ts as u64) // Convert to u64
                {
                    if timestamp > last_timestamp {
                        last_timestamp = timestamp;
                    }
                }
            }
        }
    }

    debug_log!("get_last_file_timestamp() -> last_timestamp {:?}", last_timestamp); 
    Ok(last_timestamp) // Returns 0 if no matching files are found
}

/// handle_remote_collaborator_meetingroom_desk (send files here)
/// very brief overview:
/// 1. listen for got-it signals and remove fail-flags (yes, their 'last' 3rd step is actually done first)
/// 2. listen for 'ready' signal
/// 3. send one send-queue item at at time & update send-queue (pop item and update back_of_queue_timestamp)
///
/// delete/rewrite:
/// ```path
/// sync_data/team_channel/collaborator_name/back_of_queue_timestamp
/// ```
///
/// Error Handling:
/// 1. Distinguish Between Error Types: Not all errors are equal. Some errors might be transient (e.g., WouldBlock indicating no data is available yet), while others might be fatal (e.g., a socket error).
/// 2. Handle Transient Errors: For transient errors, we can simply continue the loop and try to receive data again.
/// 3. Handle Fatal Errors: For fatal errors, we should log the error, potentially notify the user, and consider exiting the function or the entire sync process.
///
/// TODO add  "workflow" steps: handle_remote_collaborator_meetingroom_desk()
fn handle_remote_collaborator_meetingroom_desk(
    room_sync_input: &ForRemoteCollaboratorDeskThread,
) -> Result<(), ThisProjectError> {
    /*
    future: this should listen at all allowlisted ips for that remote collaborator
    to identify the correct ip for this session.
    e.g. a first setup just to listen to pick the IP
    then enter the real loop and listen for
    
    loop:
    // 2. Create listeners for each IP address
    for ipv6_address in &own_desk_setup_data.local_user_ipv6_addr_list {
        let tx = tx.clone(); // Clone the sender for each thread
        let ready_port = own_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip;

        thread::spawn(move || {...
            
            
    for ipv4_address in &own_desk_setup_data.local_user_ipv6_addr_list {
        let tx = tx.clone(); // Clone the sender for each thread
        let ready_port = own_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip;

        thread::spawn(move || {...
            
            
    future: idea for GPG signed signal
    sender uses your gpg to sign the timestamp
    if you confirm that, then go ahead with that IP and request. 
    this may be equivilent to clearsigning the read signal with less baggage
    
    note: same can be done with gotit signal
    
    Echosend may pre-fail all the send-events (making a fail-flag file)
    then calling a loop to call an eqcho-send function for each echo-event
    if each thread can listen for a got-it and remove the flag
    
    or maybe there is an always running got it listener that removes
    fail flags for any got-it recieved
    */
    loop { // 1. start overall loop to restart whole desk
        // --- 1. overall loop to restard handler in case of failure ---
        //  1.1 Check for halt signal.
        if should_halt_uma() {
            debug_log!(
                "HRCD 1.1 Check for halt signal. Halting handle_remote_collaborator_meetingroom_desk() for {}", 
                room_sync_input.remote_collaborator_name
            );
            break;
        }
    
        
        
        debug_log!(
            "\n Started HRCD the handle_remote_collaborator_meetingroom_desk() for->{}", 
            room_sync_input.remote_collaborator_name
        );
        debug_log!(
            "room_sync_input -> {:?}", 
            room_sync_input
        );

        // --- 1.3 Create two UDP Sockets for Ready and GotIt Signals ---
        debug_log("HRCD Making ready_port listening UDP socket...");
        let ready_socket = create_udp_socket(
            &room_sync_input.remote_collaborator_ipv6_addr_list,
            room_sync_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip,
        )?;
        debug_log("HRCD Making gotit_port listening UDP socket...");
            let gotit_socket = create_udp_socket(
            &room_sync_input.remote_collaborator_ipv6_addr_list,
            room_sync_input.remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip,
        )?;

        // --- 1.4 Initialize (empty for starting) Send Queue ---
        // let mut session_send_queue: Option<SendQueue> = None;
        // 1.4 Initialize Send Queue (empty, with zero timestamp)
        let mut session_send_queue = SendQueue {
            back_of_queue_timestamp: 0,
            items: Vec::new(),
        };

        // let mut last_debug_log_time = Instant::now();
        // let mut last_debug_log_time = Instant::now();
        /*
        I don't think this makes sense here,
        shouldn't this be file-timestamps?
        */


        // --- 1.5 Spawn a thread to handle "Got It" signals & fail-flag removal ---
        let gotit_thread = thread::spawn(move || {
            //////////////////////////////////////
            // Listen for 'I got it' GotItSignal
            ////////////////////////////////////

            loop {
                debug_log(
                    "HRCD Got it loop starting."
                ); 
                // 1.5.1 Check for halt-uma signal
                if should_halt_uma() {
                    debug_log!("HRCD 1.5.1 GotItloop Got It loop: Halt signal received. Exiting. in handle_remote_collaborator_meetingroom_desk");
                    break; // Exit the loop
                }

                // 1.5.2 Receive and handle "Got It" signals // under construction TODO
                let mut buf = [0; 1024];
                match gotit_socket.recv_from(&mut buf) {
                    Ok((amt, src)) => {
                        
                        // Check for exit-signal:
                        if should_halt_uma() {
                            debug_log(
                                "HRCD 1.5.2 should_halt_uma() Halting handle_remote_collaborator_meetingroom_desk",
                            );
                            break;
                        }
                            
                        
                        debug_log!("HRCD 1.5.2 GotItloop Ok((amt, src)) Received {} bytes from {} on gotit port", amt, src);
        
                        // --- Inspect Raw Bytes ---
                        debug_log!(
                            // this does require &
                            "HRCD 1.5.2 GotItloop Raw bytes received: {:?}", 
                            &buf[..amt]
                        ); 
                
                        // --- Inspect Bytes as Hex ---
                        let hex_string = buf[..amt].iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<String>();
                        debug_log!("HRCD 1.5.2 GotItloop Raw bytes as hex: {}", hex_string);
                        
                        // Clone the values you need from room_sync_input
                        // let remote_collaborator_name = room_sync_input.remote_collaborator_name.clone(); 
                        
                        // 1.5.3 Deserialize the GotItSignal
                        let gotit_signal: GotItSignal = match deserialize_gotit_signal(&buf[..amt]) {
                            Ok(gotit_signal) => {
                                debug_log!("HRCD 1.5.3 GotItloop Ok(gotit_signal) : Received GotItSignal: {:?}",
                                    // remote_collaborator_name, 
                                    gotit_signal
                                ); // Log the signal
                                gotit_signal
                            },
                            Err(e) => {
                                debug_log!("HRCD 1.5.3 GotItloop Err Receive data Failed to parse ready signal: {}", e);
                                continue; // Continue to the next iteration of the loop
                            }
                        };
        
                        // 1.5.4  get document_id from signal
                        let document_id = gotit_signal.di;
                        
                        debug_log(
                            "HRCD: Done event of got-it listener."
                        ); 
                            
                        // 1.5.5 check and remove filestubs with name==document_id
                        /*
                        If match
                        Remove From:
                        ```path
                        sync_data/team_channel/fail_flags/NAME-of-COLLABORATOR/DOC-ID
                        ```
                        
                        remove_prefail_flag__for_sendfile(
                            hash_array: &[u8],
                            directory: &Path,
                        )
                        */

                            
                    // // 1.5.6 Sleep for a short duration (e.g., 100ms)
                    // thread::sleep(Duration::from_millis(1000));

                    },
                    Err(e) => {
                        debug_log!("HRCD 1.5 GotItloop Error receiving data on gotit_port: {}", e);
                        // You might want to handle the error more specifically here (e.g., retry, break the loop, etc.)
                        // For now, we'll just log the error and continue listening. 
                        continue;
                    }
                }
            }
        });

        // 1.6.1 zero_timestamp_counter = 0 for ready signal send-at timestamps
        let mut zero_timestamp_counter = 0;
        
        // 1.6.2 hash_set_session_nonce = HashSet::new() as protection against replay attacks Create a HashSet to store received hashes
        let mut hash_set_session_nonce = HashSet::new();  // Create a HashSet to store received hashes
        
        
        let mut rc_set_as_active = false;
        
        
        // --- 2. Enter Main Loop ---
        // enter main loop (to handling signals, sending)
        loop {
            debug_log(
                "HRCD  2.: Starting, restarting Main loop"
            ); 
            // --- 2.1 Check for 'should_halt_uma' Signal ---
            if should_halt_uma() {
                debug_log!(
                    "HRCD 2.1 main loop Check for halt signal. Halting handle_remote_collaborator_meetingroom_desk() for {}", 
                    room_sync_input.remote_collaborator_name
                );
                break;
            }

            // --- 2.2. Handle Ready Signal:  ---
            // "Listener"?
            // 2.2.1 Receive Ready Signal
            let mut buf = [0; 1024]; // TODO size?
            match ready_socket.recv_from(&mut buf) {                
                Ok((amt, src)) => {
                    debug_log!(
                        "HRCD 2.2.1 Ok((amt, src)) ready_port Signal Received {} bytes from {}", 
                        amt, 
                        src
                    );
                    
                    if should_halt_uma() {
                        debug_log!(
                            "HRCD Halting handle_local_owner_desk() for {}", 
                            room_sync_input.remote_collaborator_name
                        );
                        break;
                    }

                    if !rc_set_as_active {
                        if let Err(e) = set_as_active(&room_sync_input.remote_collaborator_name) {
                            debug_log!("Error setting collaborator as active: {}", e);
                            // Handle the error appropriately (e.g., continue or return)
                            continue; // Example: skip to the next iteration
                        }
                
                        rc_set_as_active = true;
                        debug_log("HRCD rc_set_as_active = true")
                    }

                    // --- Inspect Raw Bytes ---
                    debug_log!(
                        "HRCD 2.2.1 Ready Signal Raw bytes received: {:?}", 
                        &buf[..amt]
                    ); 

                    // --- Inspect Bytes as Hex ---
                    let hex_string = buf[..amt].iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    debug_log!(
                        "HRCD 2.2.1 Ready Signal Raw bytes as hex: {}", 
                        hex_string
                    );

                    // --- 2.3 Deserialize the ReadySignal ---
                    // TODO add size check to deserialize function
                    let mut ready_signal: ReadySignal = match deserialize_ready_signal(&buf[..amt]) {
                        Ok(ready_signal) => {
                            // println!("HRCD 2.3 Deserialize Ok(ready_signal) {}: Received ReadySignal: {:?}",
                            //     room_sync_input.remote_collaborator_name, ready_signal
                            // ); // Print to console
                            debug_log!("HRCD 2.3 Deserialize Ok(ready_signal) {}: Received ReadySignal: {:?}",
                                room_sync_input.remote_collaborator_name, 
                                ready_signal
                            ); // Log the signal
                            ready_signal
                        },
                        Err(e) => {
                            debug_log!("HRCD 2.3 Deserialize Err Receive data Failed to parse ready signal: {}", e);
                            continue; // Continue to the next iteration of the loop
                        }
                    };

                    // --- 2.4 Inspect & edge cases ---
                    // - look for missing required fields e.g. timestamp
                    // - only re(is_echo_send_boolean) can be empty, all other cases must drop packet
                    // - handle edge cases such as valid echo-request...with no queue
                    // or maybe there is a queue but empty so just let it do nothing?
                    // maybe ok, make sure this works
                    /*
                        struct ReadySignal {
                            rt: Option<u64>, // ready signal timestamp: last file obtained timestamp
                            rst: Option<u64>, // send-time
                            re: Option<bool>, // echo_send
                            rh: Option<Vec<u8>>, // N hashes of rt + re [can be empty]
                            
                        no echo signal, then re = false
                    */

                    debug_log("\n##HRCD## starting checks(plaid) 2.4");
                    
                    // Check .rh hash
                    if ready_signal.rh.is_none() {
                        debug_log("HRCD 2.4.1 Check: rh hash field is empty. Drop packet and keep going.");
                        continue; // Drop packet: Restart the loop to listen for the next signal
                    }

                    // Check .rt timestamp
                    if ready_signal.rt.is_none() {
                        debug_log("HRCD 2.4.2 Check: rt last-previous-file Timestamp field is empty. Drop packet and keep going.");
                        continue; // Drop packet: Restart the loop to listen for the next signal
                    }

                    // Check .rst timestamp
                    if ready_signal.rst.is_none() {
                        debug_log("HRCD 2.4.3 Check: rst ready signal sent-at timestamp field is empty. Drop packet and keep going.");
                        continue; // Drop packet: Restart the loop to listen for the next signal
                    }

                    // Check .re is_send_echo
                    if ready_signal.re.is_none() {
                        ready_signal.re = Some(false);
                        debug_log("HRCD 2.4.4 Check: echo field is empty, so is_send_echo = false");
                    }

                    // --- 2.5 Hash-Check for ReadySignal ---
                    // Drop packet when fail check
                    if !verify_readysignal_hashes(
                        &ready_signal, 
                        &room_sync_input.remote_collaborator_salt_list,
                    ) {
                        debug_log("HRCD 2.5: ReadySignal hash verification failed. Discarding signal.");
                        continue; // Discard the signal and continue listening
                    }

                    // --- 2.6 Check / Add Hash-Nonce for per-session ready-signals ---
                    // ...e.g. guarding against the few seconds of expiration-gap
                    // After you deserialize the ReadySignal and before the other checks:
                    let ready_signal_hash_vec = ready_signal.rh.clone().expect("rh is none");

                    if !ready_signal_hash_vec.is_empty() {
                        if hash_set_session_nonce.contains(&ready_signal_hash_vec) {
                            debug_log!("HRCD 2.6 quasi nonce check: Duplicate ReadySignal received (hash match). Discarding.");
                            continue; // Discard the duplicate signal
                        }
                        hash_set_session_nonce.insert(ready_signal_hash_vec); // Add hash to the set
                    } else {
                        debug_log!("HRCD 2.6 quasi nonce check: ReadySignal received without hashes. Discarding."); // Or handle differently
                        continue;
                    }

                    // // --- check for edge case: echo without there being a queue item ---      
                    // // Check: Nothing to Echo?
                    // if ready_signal.re.expect("REASON") {
                    //     if let Some(ref mut queue) = session_send_queue {
                    //         if queue.items.is_empty() {
                    //             debug_log!("HRCD: Received echo request but send queue is empty. Dropping request.");
                    //             continue; // Restart the loop to listen for the next signal
                    //         }

                    //     } else {
                    //         debug_log!("HRCD: Received echo request but send queue is not initialized. Dropping request.");
                    //         continue; // Restart the loop
                    //     }
                    // }
                    
                    // TODO add request rules:
                    // no future dated requests
                    // no requests older than ~10 sec
                    // only 3 0=timstamp requests per session (count them!)
                    



                    // --- 3. Get or Create Send Queue ---
                    /* 
                    avoided edge case of echo with no queue:
                    echo_send: if send_que is empty, Uma drops request as usual 
                    */
                    
                    // 3.1 ready_signal_timestamp for send-queue
                    let ready_signal_timestamp = ready_signal.rst.expect("HRCD 3. Missing timestamp in ready signal"); // Unwrap the timestamp outside the match, as it's always required.
                    
                    debug_log!(
                        "HRCD 3.1 check ready_signal_timestamp for send-queue: ready_signal_timestamp -> {:?}", 
                        ready_signal_timestamp
                    );

                    // --- 3.2 timestamp freshness checks ---
                    let current_timestamp = get_current_unix_timestamp();
                    
                    debug_log!(
                        "HRCD 3.2 check timestamp freshness checks: current_timestamp -> {:?}",
                        current_timestamp
                    );

                    // 3.2.1 No Future Dated Requests
                    if ready_signal_timestamp > current_timestamp + 5 { // Allow for some clock skew (5 seconds)
                        debug_log!("HRCD 3.2.1 check: Received future-dated timestamp. Discarding.");
                        continue;
                    }

                    // 3.2.2 No Requests Older Than ~10 sec
                    if current_timestamp - 10 > ready_signal_timestamp {
                        debug_log!("HRCD 3.2.2 check: Received outdated timestamp (older than 10 seconds). Discarding.");
                        continue;
                    }

                    // 3.2.3 only 3 0=timstamp requests per session (count them!)
                    if ready_signal_timestamp == 0 {
                        if zero_timestamp_counter >= 5 {
                            debug_log("HRCD 3.2.3 check: Too many zero-timestamp requests. Discarding.");
                            continue;
                        }
                        zero_timestamp_counter += 1;
                    }

                    debug_log("##HRCD## [Done] checks(plaid) 3.2.3\n");
                    
                    // 3.2.4 look for fail-flags:
                    if !ready_signal.re.unwrap_or(false) {
                        // TODO ... things to do with fail flags?
                        // maybe by default reset the queue
                        let mut session_send_queue = SendQueue {
                            back_of_queue_timestamp: 0,
                            items: Vec::new(),
                        };
                    };

                    // --- 3.3 Get / Make Send-Queue ---
                    let this_team_channelname = match get_current_team_channel_name() {
                        Some(name) => name,
                        None => {
                            debug_log("HRCD 3.3: Error: Could not get current channel name. Skipping send queue creation.");
                            continue; // Skip to the next iteration of the loop
                        }
                    }; 
                    debug_log!("HRCD 3.3 this_team_channelname -> {:?}", this_team_channelname);

                    // if not-echo-send: see if you can or need to make a new queue
                    debug_log!("HRCD 3.3 ?is-echo? ready_signal.re.unwrap_or(false) -> {:?}", ready_signal.re.unwrap_or(false));
                    
                    if !ready_signal.re.unwrap_or(false) {
                        debug_log("HRCD 3.3 get_or_create_send_queue");
                        session_send_queue = match session_send_queue {
                            input_sendqueue => {
                                get_or_create_send_queue(
                                    &this_team_channelname, // for team_channel_name
                                    &room_sync_input.local_user_name, // local owner user name
                                    input_sendqueue, // for session_send_queue
                                    ready_signal_timestamp, // for ready_signal_timestamp
                                )?
                            }
                        };
                    }
                    debug_log!(
                        "HRCD ->[]<- 3.3 Get / Make session_send_queue {:?}",
                        session_send_queue   
                    );

                    // session_send_queue = match session_send_queue {
                    //     Some(queue) => {
                    //         // Update the queue based on the received timestamp if there was a previous queue
                    //         Some(get_or_create_send_queue(
                    //             &this_team_channelname,
                    //             &room_sync_input.remote_collaborator_name,
                    //             queue, // existing queue
                    //             ready_signal_timestamp,
                    //         )?)
                    //     }
                    //     None => {
                    //         // Create a completely fresh queue with the received timestamp 
                    //         Some(get_or_create_send_queue(
                    //             &this_team_channelname,
                    //             &room_sync_input.remote_collaborator_name,
                    //             SendQueue { // a new SendQueue
                    //                 back_of_queue_timestamp: ready_signal_timestamp,
                    //                 items: Vec::new()
                    //             },
                    //             ready_signal_timestamp,
                    //         )?)
                    //     }
                    // };

                    
                    // --- 4. Send File: Send One File from Queue ---
                    // Prset file-send-failed flag
                    // 4.1 preset file_send failed flags file-name == document_id
                    /*
                    Save To:
                    ```path
                    sync_data/team_channel/fail_flags/NAME-of-COLLABORATOR/DOC-ID
                    ```
                    */


                    /*
                    send_file_toml_to_rc_intray(
                        file_path: &PathBuf, 
                        target_addr: SocketAddr, 
                        port: u16,
                        collaborator_salt_list: &[u128], // Pass the salt list here
                    )
                                             
                    # Explaining: 
                    ```             
                    if let Some(ref mut queue) = session_send_queue {
                        while let Some(file_path) = queue.items.pop() {
                    ```
                    
                    That code snippet represents a common pattern in Rust for 
                    iterating over and processing items in a Vec (vector) while
                     also potentially modifying the vector itself (in this case, 
                         by removing elements). Let's break down the logic:

                    if let Some(ref mut queue) = session_send_queue: This is a 
                    conditional statement that uses pattern matching with if 
                    let. session_send_queue is an Option<SendQueue>, meaning 
                    it can either contain a SendQueue or be None.

                    Some(ref mut queue): This part of the pattern attempts
                     to match the Some variant of the Option. If session_send_queue 
                     contains a SendQueue, the code inside the if block will 
                     be executed. The ref mut creates a mutable reference to the
                      inner SendQueue, allowing you to modify it.

                    If session_send_queue is None, the if block is skipped entirely.

                    while let Some(file_path) = queue.items.pop(): This is a 
                    while let loop, another form of pattern matching. queue.items 
                    is a Vec<PathBuf>. pop() removes and returns 
                    the last element of the vector.

                    Some(file_path): This part of the pattern attempts to match
                     the Some variant of the Option returned by pop(). 
                     If queue.items is not empty, pop() will return Some(PathBuf) 
                     where PathBuf is the removed element. The code inside the 
                     while loop will be executed, and file_path will be assigned 
                     the value of the removed PathBuf.

                    Empty Vector: When queue.items becomes empty, pop() will 
                    return None. This will cause the while let loop to terminate.

                    In Summary:

                    The combined if let and while let structure ensures the following:

                    The code inside the while loop only executes 
                    if session_send_queue contains a SendQueue (it's not None).

                    The loop iterates over the items in the SendQueue 
                    from the last element to the first, 
                    removing each item as it's processed.
                    */
                    // 4. while: Send File: Send One File from Queue
                    if let ref mut queue = session_send_queue {
                        while let Some(file_path) = queue.items.pop() {

                            debug_log!(
                                "HRCD 4.2 Send File: if/while let Some(file_path) = queue.items.pop()  file_path {:?}",
                                file_path   
                            );
                            
                            // 4.2.1 Get File Send Time
                            let intray_send_time = get_current_unix_timestamp(); 

                            // TODO maybe store files as the gpg blob
                            // Wrapper of bytes to bytes:
                            // 4.2.2 Read File Contents
                            // 4.3.1 GPG Clearsign the File (with your private key)
                            // 4.3.2 GPG Encrypt File (with their public key)
                            let file_bytes2send = wrapper__path_to_clearsign_to_gpgencrypt_to_send_bytes(
                                &file_path,
                                &room_sync_input.remote_collaborator_public_gpg,
                            )?; 
                            
                            debug_log(
                                "HRCD 4.2, 4.3.1, 4.3.2 done gpg wrapper"
                            );
                            
                            // // 4.4. Calculate SendFile Struct Hashes (Using Collaborator's Salts)
                            // // Change the type to hold Vec<u8>
                            // let mut sendfile_struct_data_to_hash: Vec<Vec<u8>> = Vec::new();
                            // let sendtime_bytes = intray_send_time.to_be_bytes();
                            // sendfile_struct_data_to_hash.push(sendtime_bytes.to_vec()); // Push a Vec<u8>
                            // sendfile_struct_data_to_hash.push(file_bytes2send.clone()); 

                            // for salt in &room_sync_input.local_user_salt_list {
                            //     // Create a new Vec<u8> for each salt
                            //     let salt_bytes = salt.to_be_bytes().to_vec(); 
                            //     sendfile_struct_data_to_hash.push(salt_bytes); // Push the owned Vec<u8>
                            // }

                            // // 4.5. hashing
                            // // Convert to &[u8] slices for the hashing function
                            // let intray_hash_list = calculate_pearson_hashes(
                            //     &sendfile_struct_data_to_hash.iter().map(|v| v.as_slice()).collect::<Vec<&[u8]>>() // Specify type here
                            // )?;
                            
                            
                            // let calculated_hrcd_sendfile_hashes = hash_sendfile_struct_fields(
                            //     &room_sync_input.local_user_salt_list,
                            //     intray_send_time,
                            //     &file_bytes2send.clone(), // Use a slice for efficiency
                            // ); 
                            
                            
                            // // debug_log!(
                            // //     "HRCD 4.5 intray_hash_list {:?}",
                            // //     intray_hash_list   
                            // // );
                            // // 4.6. Create SendFile Struct 
                            // let sendfile_struct = SendFile {
                            //     intray_send_time: Some(intray_send_time),
                            //     gpg_encrypted_intray_file: Some(file_bytes2send.clone()),
                            //     intray_hash_list: Some(calculated_hrcd_sendfile_hashes?),
                            // }; 
                            
                            // // 4.6 set_prefail_flag_via_hash__for_sendfile
                            // set_prefail_flag_via_hash__for_sendfile(
                            //     &calculated_hrcd_sendfile_hashes,
                            //     &room_sync_input.remote_collaborator_name
                            //     );

                            // 4.5 calculate hashes: HRCD
                            let calculated_hrcd_sendfile_hashes = hash_sendfile_struct_fields(
                                &room_sync_input.local_user_salt_list,
                                intray_send_time,
                                &file_bytes2send, 
                            );

                            // Handle the Result from hash_sendfile_struct_fields
                            let calculated_hashes = match calculated_hrcd_sendfile_hashes {
                                Ok(hashes) => hashes,
                                Err(e) => {
                                    debug_log!("HRCD 4.5 Error calculating hashes: {}", e);
                                    continue; // Skip to the next file if hashing fails
                                }
                            };

                            debug_log!(
                                "HRCD 4.5 calculated_hashes {:?}",
                                calculated_hashes   
                            );

                            // 4.6. Create SendFile Struct 
                            let sendfile_struct = SendFile {
                                intray_send_time: Some(intray_send_time),
                                gpg_encrypted_intray_file: Some(file_bytes2send.clone()), // Clone needed here if file_bytes2send is used later
                                intray_hash_list: Some(calculated_hashes.clone()),  // Clone here as well
                            };

                            debug_log!(
                                "HRCD 4.6 Create sendfile_struct {:?}",
                                sendfile_struct   
                            );
                            
                            // 4.7 set_prefail_flag_via_hash__for_sendfile
                            if let Err(e) = set_prefail_flag_via_hash__for_sendfile(
                                &calculated_hashes, // Use the unwrapped hashes
                                &room_sync_input.remote_collaborator_name
                            ) {
                                debug_log!("HRCD 4.7 Error setting pre-fail flag: {}", e);
                                continue; // Handle error as you see fit
                            };
                            // // 4.5. hashing HRCD
                            // let mut calculated_hashes = Vec::new();
                            // match calculate_and_verify_sendfile_hashes(
                            //     &send_file,
                            //     &room_sync_input.local_user_salt_list,
                            // ) {
                            //     Ok((hashes, all_hashes_match)) => {
                            //         if !all_hashes_match {
                            //             debug_log("HLOD 5: SendFile Struct hash verification failed. Discarding signal.");
                            //             continue; // Discard the signal and continue listening
                            //         }
                            //         calculated_hashes = hashes;
                            //     }
                            //     Err(e) => {
                            //         debug_log(&format!("Error calculating and verifying SendFile hashes: {}", e));
                            //         continue; // Discard the signal and continue listening
                            //     }
                            // }

                            // debug_log!(
                            //     "HRCD 4.5. hashing HRCD calculated_hashes {:?}",
                            //     calculated_hashes   
                            // );
                            
                            

                            // // 4.6.2 Create sendfile_struct_final
                            // let sendfile_struct_final = SendFile {
                            //     intray_send_time: Some(intray_send_time),
                            //     gpg_encrypted_intray_file: Some(file_bytes2send),
                            //     intray_hash_list: Some(calculated_hashes),
                            // }; 
                            
                            debug_log!(
                                "HRCD 4.6-7 Create sendfile_struct {:?}",
                                sendfile_struct   
                            );
                            
                            let serialized_file_struct_to_send = serialize_send_file(&sendfile_struct);
                            
                            // --- 4.7 Send serializd-file: send UDP to intray ---
                            // 4.7.1 Send file

                            // 4.7 Send serializd-file Send if serialization was successful (handle Result)
                            match serialized_file_struct_to_send {
                                Ok(extracted_serialized_data) => {  // Serialization OK
                                    match send_data_via_udp(&extracted_serialized_data, src, room_sync_input.remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip) {
                                        Ok(_) => {
                                            debug_log!("HRCD 4.7 File sent successfully");
                                            // ... (Handle successful send, e.g., update timestamp log)
                                            
                                            // --- 4.7.3 Update Timestamp Log ---
                                            debug_log("HRCD calling calling get_toml_file_timestamp(), yes...");
                                            if let Ok(timestamp) = get_toml_file_timestamp(&file_path) {
                                                update_collaborator_sendqueue_timestamp_log(
                                                    // TODO: Replace with the actual team channel name
                                                    "team_channel_name", 
                                                    &room_sync_input.remote_collaborator_name,
                                                )?;
                                                debug_log!("HRCD 4.7.3  Updated timestamp log for {}", room_sync_input.remote_collaborator_name);
                                            }
                                        }
                                        Err(e) => {
                                            debug_log!("Error sending data: {}", e);
                                            // Handle the send error (e.g., log, retry, etc.)
                                        }
                                    }
                                }
                                Err(e) => { // Serialization error
                                    debug_log!("Serialization error: {}", e);
                                    // Handle the serialization error (e.g., log, skip file)
                                }
                            }


                        } // end of while
                    } // end of 4.4: if let Some(ref mut queue) = session_send_queue {
                    debug_log!("\nHRCD: end of inner match.\n");    
                }, // end of the Ok inside the match: Ok((amt, src)) => {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // // --- 3.6 No Ready Signal, Log Periodically ---
                    // terrible idea: most people are simply not online most of the time
                    // this is not an error!!
                    // if last_debug_log_time.elapsed() >= Duration::from_secs(5) {
                    //     debug_log!("HRCD 3.6 {}: Listening for ReadySignal on port {}", 
                    //                room_sync_input.remote_collaborator_name, 
                    //                room_sync_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip);
                    //     last_debug_log_time = Instant::now();
                    // }
                },
                Err(e) => {
                    // --- 3.7 Handle Other Errors ---
                    debug_log!("HRCD #? {}: Error receiving data on ready_port: {} ({:?})", 
                            room_sync_input.remote_collaborator_name, e, e.kind());
                    return Err(ThisProjectError::NetworkError(e.to_string()));
                }
                // }
            // thread::sleep(Duration::from_millis(100));
            } // 6091 match ready_socket.recv_from(&mut buf) { 
        } // 6091... match ready_socket.recv_from(&mut buf) {
        debug_log!("\nHRCD: bottom of main loop.\n");
    } // nothing closes the main loop
    debug_log!("\nending HRCD\n");
    Ok(())
}

// --- Helper Function to Create UDP Socket ---
fn create_udp_socket(ip_addresses: &[Ipv6Addr], port: u16) -> Result<UdpSocket, ThisProjectError> {
    for ip_address in ip_addresses {
        let bind_result = UdpSocket::bind(SocketAddr::new(IpAddr::V6(*ip_address), port));
        match bind_result {
            Ok(socket) => return Ok(socket),
            Err(e) => debug_log!("create_udp_socket() Failed to bind to [{}]:{}: {}", ip_address, port, e),
        }
    }
    Err(ThisProjectError::NetworkError("create_udp_socket() Failed to bind to any IPv6 address".to_string()))
}

// Result enum for the sync operation, allowing communication between threads
enum SyncResult {
    Success(u64), // Contains the new timestamp after successful sync
    Failure(ThisProjectError), // Contains an error if sync failed 
}

/// Extracts the channel name from a team channel directory path. 
/// 
/// This function assumes the path is in the format 
/// "project_graph_data/team_channels/channel_name". 
/// It returns the "channel_name" part of the path.
///
/// # Returns
/// 
/// * `Option<String>`: The channel name if successfully extracted, `None` otherwise.
fn get_current_team_channel_name() -> Option<String> {
    // get path, derive name from path
    let channel_dir_path_str = read_state_string("current_node_directory_path.txt").ok()?; // read as string first
    debug_log!("1. Channel directory path (from session state) [in fn get_current_team_channel_name()] channel_dir_path_str -> {:?}", channel_dir_path_str); 
    
    let path = Path::new(&channel_dir_path_str);
    path.file_name()?.to_str().map(String::from) 
}

/// for normal mode, updates graph-navigation location and graph-state for both
/// 1. the struct
/// 2. the file-set version in .../project_graph_data/session_state_items
/// in both enter-new-node cases, in new-channel, cases, and in other cases
///
/// node.toml toml tables! store the ports: (check they are unique)
/// { collaborator_name = "bob", ready_port = 50001, 
///     intray_port = 50002, gotit_port = 50003, 
///     self_ready_port = 50004, 
///     self_intray_port = 50005, 
///     self_gotit_port = 50006 },
///
/// /// ... other imports ...
/// use std::sync::mpsc; /// For message passing between threads (if needed)
///
/// Version 2:
/// as set by node.toml in the team_channel node
///
/// for every other collaborator, you make:
/// two threds:
///     - your in-tray desk
///     - their in-tray desk
///
/// Each thred has six ports:
///     - three for each 'in-tray desk'
///
/// For each this-session-active-collaborator you keep a send-queue.
/// For one who never requested a file (who isn't online): no need to make a send-queue
///
///  Note current node members are not the same as channel members
///  a node may have narrower scope, but not broader.
///  this may especially apply to tasks only shared to relevant members
fn you_love_the_sync_team_office() -> Result<(), Box<dyn std::error::Error>> {
    /*
    "It's all fun and games until someone syncs a file."
    
    TODO: 
    there needs to be a signal to wait to start
    the home_square_one flag may work
    */
    // --- WAIT FOR CHANNEL SELECTION ---
    sync_flag_ok_or_wait(3); // Wait for the sync flag to become "1"

    // 1.5.1 Check for halt-uma signal
    if should_halt_uma() {
        debug_log!(">*< Halt signal received. Exiting The Uma... in you_love_the_sync_team_office() |o|");
        return Ok(()); // Exit the function
    }
    
    debug_log("starting UMA Sync Team Office...you_love_the_sync_team_office()");
    
    // Read uma_local_owner_user from uma.toml
    // maybe add gpg and make this a separate function TODO
    let uma_toml_path = Path::new("uma.toml");
    let user_metadata = toml::from_str::<toml::Value>(&fs::read_to_string(uma_toml_path)?)?; 
    let uma_local_owner_user = user_metadata["uma_local_owner_user"].as_str().unwrap().to_string();

    debug_log!("\n\nStarting UMA Sync Team Office for (local owner) -> {}", &uma_local_owner_user);

    // let session_connection_allowlists = make_sync_meetingroomconfig_datasets(&uma_local_owner_user)?;
    // debug_log!("session_connection_allowlists -> {:?}", &session_connection_allowlists);
    
    // 1. get sync_meetingroom_config_datasets
    let sync_meetingroom_config_datasets = match make_sync_meetingroomconfig_datasets(&uma_local_owner_user) {
        
        Ok(room_config_datasets) => {
            debug_log!(
                "Successfully generated room_config_datasets: {:?}",
                room_config_datasets
            ); 
            room_config_datasets
        },
        Err(e) => {
            debug_log!("Error creating room_config_datasets: {}", e);
            return Err(Box::new(e)); // Return the error early
        }
    };    
        
    // 2. Create a list for threads for each collaborator on the room_config_datasets: 
    /*
    TODO explain why/how a list:
    to gather for shutdown?
    */
    let mut collaborator_threads = Vec::new();
    
    // 3. get sync_meetingroom_config_dataset 
    // with MeetingRoomSyncDataset, ForLocalOwnerDeskThread, ForRemoteCollaboratorDeskThread
    
    for this_meetingroom_iter in sync_meetingroom_config_datasets { 
        // Extract data from this_meetingroom_iter
        // and place each pile in a nice baggy for each desk.
        debug_log!("Setting up connection with {}", this_meetingroom_iter.remote_collaborator_name);
        
        // Create sub-structs
        let data_baggy_for_owner_desk = ForLocalOwnerDeskThread { 
            local_user_name: this_meetingroom_iter.local_user_name.clone(),
            remote_collaborator_name: this_meetingroom_iter.remote_collaborator_name.clone(),
            local_user_salt_list: this_meetingroom_iter.local_user_salt_list.clone(),
            remote_collaborator_salt_list: this_meetingroom_iter.remote_collaborator_salt_list.clone(),
            local_user_ipv6_addr_list: this_meetingroom_iter.local_user_ipv6_addr_list,
            local_user_ipv4_addr_list: this_meetingroom_iter.local_user_ipv4_addr_list,
            local_user_gpg_publickey_id: this_meetingroom_iter.local_user_gpg_publickey_id.clone(),
            local_user_public_gpg: this_meetingroom_iter.local_user_public_gpg.clone(),
            local_user_sync_interval: this_meetingroom_iter.local_user_sync_interval,
            // ready! (local)
            local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: this_meetingroom_iter.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
            // in-tray (local)
            localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: this_meetingroom_iter.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            // got-it! (local)
            local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: this_meetingroom_iter.local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip,
        };
        let data_baggy_for_collaborator_desk = ForRemoteCollaboratorDeskThread {
            remote_collaborator_name: this_meetingroom_iter.remote_collaborator_name.clone(),
            local_user_name: this_meetingroom_iter.local_user_name.clone(),
            remote_collaborator_salt_list: this_meetingroom_iter.remote_collaborator_salt_list.clone(),
            local_user_salt_list: this_meetingroom_iter.local_user_salt_list.clone(),
            remote_collaborator_ipv6_addr_list: this_meetingroom_iter.remote_collaborator_ipv6_addr_list,
            remote_collaborator_ipv4_addr_list: this_meetingroom_iter.remote_collaborator_ipv4_addr_list,
            remote_collaborator_gpg_publickey_id: this_meetingroom_iter.remote_collaborator_gpg_publickey_id.clone(),
            remote_collaborator_public_gpg: this_meetingroom_iter.remote_collaborator_public_gpg.clone(),
            remote_collaborator_sync_interval: this_meetingroom_iter.remote_collaborator_sync_interval,
            // ready! (remote)
            remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: this_meetingroom_iter.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip,
            // in-tray (remote)
            remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: this_meetingroom_iter.remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip,
            // got-it! (remote)
            remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: this_meetingroom_iter.remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip, 
        };

        // Create the two "meeting room desks" for each collaborator pair:
        // Your Desk
        let owner_desk_thread = thread::spawn(move || {
            handle_local_owner_desk(data_baggy_for_owner_desk); 
            
        });
        // Their Desk
        let collaborator_desk_thread = thread::spawn(move || {
            handle_remote_collaborator_meetingroom_desk(&data_baggy_for_collaborator_desk);
        });
        collaborator_threads.push(owner_desk_thread); 
        collaborator_threads.push(collaborator_desk_thread);
    }    
    
    // ... Handle join logic for your threads... 
    for thread in collaborator_threads {
        thread.join().expect("Failed to join thread.");
    }
    debug_log!("UMA Sync Team Office closed");
    println!("UMA Sync Team Office closed");
    Ok(())
}

// Proverbial Main()
fn we_love_projects_loop() -> Result<(), io::Error> {
    /*
    Modal TUI Project-Graph Browser Loop
    
    user-loop:
    - project_graph user_thread:
    1. initialization of the software and file system (especially first setup bootstrapping)
    - Handle first-time setup and bootstrapping if need be
    - make sure all needed files and directories exist
    
    2 start loop:
    2.1 loading initial instance_graph_navigation_state from files in uma_state_toml_dir
    - inside the app: sometimes variables and state can simply be passed to the next sub-function, but things are not always simple. there may need to be a  repeat of the save-reload-from-files process to get from one sub-function to the next.
    
    2.2 user_app: running one loop-action-set in the user_app()
    
    2.3 saving state in files in uma_state_toml_dir
    (loop again)    
    */

    // Load UMA configuration from uma.toml
    let uma_toml_path = Path::new("uma.toml");

   // TUI Setup, TODO
    /*
    If there is an umi.toml,
    and it has tui_height/tui_height that are not 80/24
    use those new values (from umi.toml) for 
    tui_height = 
    tui_width = 

    or maybe this gets done in the project-manager-thread (not the sink thread)    
    */
    
        
    // let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)?; 
    let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e)))?;

    // setting up absolute file path
    let relative_path = PathBuf::from("project_graph_data/team_channels");
    let abs_current_full_file_path = relative_path.canonicalize().unwrap(); // Handle errors
    
    // node-graph navigation 'state' initial setup
    let mut graph_navigation_instance_state = GraphNavigationInstanceState {
        local_owner_user: user_metadata["uma_local_owner_user"].as_str().unwrap().to_string(),
        active_team_channel: String::new(), // or perhaps "None", or "Default"
        default_im_messages_expiration_days: user_metadata["uma_default_im_messages_expiration_days"].as_integer().unwrap() as u64,
        default_task_nodes_expiration_days: user_metadata["uma_default_task_nodes_expiration_days"].as_integer().unwrap() as u64,
        
        // look into making these smaller for memory use...unless there is a reason
        // this is not pixels, but character-lines on a single screen
        // tui_height: user_metadata["tui_height"].as_integer().unwrap() as u8,
        // tui_width: user_metadata["tui_width"].as_integer().unwrap() as u8,
        
        // Handle missing or invalid values for tui_height and tui_width:
        tui_height: user_metadata.get("tui_height")
            .and_then(Value::as_integer)
            .map(|height| height as u8) // Convert to u8 if valid
            .unwrap_or(24),  // Default to 24 if missing or invalid 
    
        tui_width: user_metadata.get("tui_width")
            .and_then(Value::as_integer) 
            .map(|width| width as u8) // Convert to u8 if valid
            .unwrap_or(80), // Default to 80 if missing or invalid 

        current_full_file_path: abs_current_full_file_path, // Set initial absolute path
        // Initialize other fields of GraphNavigationInstanceState
        current_node_teamchannel_collaborators_with_access: Vec::new(),
        current_node_name: String::new(),
        current_node_owner: String::new(),
        current_node_description_for_tui: String::new(),
        current_node_directory_path: PathBuf::new(),
        current_node_unique_id: 0,
        current_node_members: Vec::new(),
        home_square_one: true,

    };

    // if !verify_gpg_signature(&local_user) {
    //     println!("GPG key verification failed (placeholder)");
    //     return Err(io::Error::new(io::ErrorKind::Other, "GPG Verification Failed"));
    // }
    
    // Create App instance
    let mut app = App::new(graph_navigation_instance_state.clone()); // Pass graph_navigation_instance_state
    
    // -- Start in Command Mode --- 
    app.input_mode = InputMode::Command; // Initialize app in command mode

    // -- Here: save first version of starting 'state'
    
    loop {
        // 1. Read the 'continue_uma.txt' file 
        let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
            Ok(content) => content,
            Err(_) => {
                println!("Error reading 'continue_uma.txt'. Continuing..."); // Handle the error (e.g., log it) but continue for now
                continue; // Skip to the next loop iteration
            }
        };
    
        // 2. break loop if continue=0
        if file_content.trim() == "0" {
            debug_log("'continue_uma.txt' is 0. we_love_projects_loop() Exiting loop.");
            break; 
        }
        
        // Update GraphNavigationInstanceState based on the current path
        debug_log("start loop: we_love_projects_loop()");
        // debug_log(&format!("app.input_mode {:?}", &app.input_mode)); 
  
        // -- Here: this function reads state and adds current graph-node-location data
        // graph_navigation_instance_state.look_read_node_toml();
        
        // --- this is or maybe should be part of the TUI (no state record)
        // Clear the screen
        print!("\x1B[2J\x1B[1;1H");

        // Update the directory list (if in command mode)
        if app.input_mode == InputMode::Command {
             debug_log(" if app.input_mode == InputMode::Command");
            app.update_directory_list()?; 
        }

        // Render the appropriate list based on the mode
        // TODO this 2nd input is a legacy kludge, but is needed to show TUI for now
        // TODO this is most likely VERY wrong and will not work for task-browser
        match app.input_mode {
            InputMode::Command => {
                tiny_tui::render_list(&app.tui_directory_list, &app.current_path);
                debug_log("tiny_tui::render_list(&app.tui_directory_list, &app.current_path)");
                
            }
            // TODO why is theis here? tui_textmessage_list is not the only option
            InputMode::InsertText => {
                tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path);
                debug_log("tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path);");
            }
        }

        // Read user inputs
        let input = tiny_tui::get_input()?;

        // Handle the input based on the mode
        match app.input_mode {
            InputMode::Command => {
                
                // Handle commands (including 'm')
                // if handle_command(&input, &mut app, &mut graph_navigation_instance_state) {
                if handle_command(&input, &mut app, &mut graph_navigation_instance_state)? {
                    debug_log("QUIT");
                    break; // Exit the loop if handle_command returns true (e.g., for "q")
                } else if let Ok(index) = input.parse::<usize>() {
                    let item_index = index - 1; // Adjust for 0-based indexing
                    if item_index < app.tui_directory_list.len() {
                        debug_log("main: if item_index < app.tui_directory_list.len()");
                        debug_log!(
                            "main: app.tui_directory_list: {:?}",
                            app.tui_directory_list
                        );
                        
                        ////////////////////////////
                        // Handle channel selection
                        ////////////////////////////
                        
                        // app.handle_tui_action(); // Remove the extra argument here

                        debug_log("handle_tui_action() started in we_love_projects_loop()");
                        
                        if app.current_path.display().to_string() == "project_graph_data/team_channels".to_string() {
                            debug_log("app.current_path == project_graph_data/team_channels");
                            debug_log(&format!("current_path: {:?}", app.current_path));

                            let input = tiny_tui::get_input()?; // Get input here
                            if let Ok(index) = input.parse::<usize>() { 
                                let item_index = index - 1; // Adjust for 0-based indexing
                                if item_index < app.tui_directory_list.len() {
                                    let selected_channel = &app.tui_directory_list[item_index];
                                    debug_log(&format!("Selected channel: {}", selected_channel)); // Log the selected channel name

                                    
                                    //////////////////////////
                                    // Enable sync flag here!
                                    //////////////////////////
                                    debug_log("About to set sync flag to true!");
                                    set_sync_start_ok_flag_to_true();  //TODO turn on to use sync !!! (off for testing)
                                    
                                    
                                    app.current_path = app.current_path.join(selected_channel);
                                    
                                    debug_log(&format!("New current_path: {:?}", app.current_path)); // Log the updated current path
                                    
                                    app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
                                    
                                    // flag to start sync is set INSIDE look_read_node_toml() if a team_channel is entered
                                    app.graph_navigation_instance_state.look_read_node_toml(); 

                                    // Log the state after loading node.toml
                                    debug_log(&format!("we_love_projects_loop() State after look_read_node_toml: {:?}", app.graph_navigation_instance_state));
                                    
                                    // ... enter IM browser or other features ...
                                } else {
                                    debug_log("Invalid index.");
                                }
                            } 
                        } else if app.is_in_instant_message_browser_directory() {
                            // ... handle other TUI actions ...
                            debug_log("else if self.is_in_instant_message_browser_directory()");
                            
                            
                        }
                        debug_log("end handle_tui_action()");
                    } else {
                        debug_log("Invalid index.");
                    }
                }
            }

            InputMode::InsertText => {
                
                debug_log("handle_insert_text_input");
                // if input == "esc" { 
                if input == "q" {
                    debug_log("esc toggled");
                    app.input_mode = InputMode::Command; // Access input_mode using self
                    app.current_path.pop(); // Go back to the parent directory
                } else if !input.is_empty() {
                    debug_log("!input.is_empty()");

                    let local_owner_user = &app.graph_navigation_instance_state.local_owner_user; // Access using self

                    // 1. final path name (.toml)
                    let message_path = get_next_message_file_path(&app.current_path, local_owner_user); 
                    debug_log(&format!("Next message path: {:?}", message_path)); // Log the calculated message path
                    
                    // 2. make message file
                    add_im_message(
                        &message_path,
                        local_owner_user,
                        input.trim(), 
                        None,
                        &app.graph_navigation_instance_state, // Pass using self
                    ).expect("handle_insert_text_input: Failed to add message");
                    
                    let this_team_channelname = match get_current_team_channel_name() {
                        Some(name) => name,
                        None => "XYZ".to_string(),
                    }; 
                    // save_updateflag_path_for_sendqueue
                    save_updateflag_path_for_sendqueue(
                        &this_team_channelname,
                        &message_path, // Take PathBuf directly
                    );

                    app.load_im_messages(); // Access using self
                }
            }
        }
    }
    debug_log("Finish: we love project loop.");
    Ok(())
}

/// set sync_start_ok_flag to true
/// also use: sync_flag_ok_or_wait(3);
fn set_sync_start_ok_flag_to_true() { 
    if fs::remove_file(SYNC_START_OK_FLAG_PATH).is_ok() {
        debug_log("Old 'ok_to_start_sync_flag.txt' file deleted."); // Optional log.
    }

    let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH)
        .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

    file.write_all(b"1")
        .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
}

/// initialize sync_start_ok_flag
/// also use: sync_flag_ok_or_wait(3);
fn initialize_ok_to_start_sync_flag_to_false() { 
    if fs::remove_file(SYNC_START_OK_FLAG_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH)
        .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

    file.write_all(b"0")
        .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
}

/// Sets a collaborator as "active" by creating a stub file in the sync_data directory.
///
/// This function creates an empty file (a "stub" file) in the directory:
/// `sync_data/{team_channel_name}/is_active/{collaborator_name}`. The presence of this file marks the collaborator as active
/// in the current session for the specified team channel.  The function handles directory creation and any potential errors during
/// file creation.
///
/// This flag signals to other threads and parts of uma that 
/// this (remote collaborator) user is acive.
///
/// # Arguments
///
/// * `collaborator_name`: The name of the collaborator to set as active.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if the stub file was successfully created, or a `ThisProjectError` if an error occurred.
///
/// uses:
/// use std::fs::{create_dir_all, File};
/// use std::path::PathBuf;
fn set_as_active(collaborator_name: &str) -> Result<(), ThisProjectError> {
    // 1. Get team channel name (replace with your actual implementation)
    let team_channel_name = match get_current_team_channel_name() {
        Some(name) => name,
        None => {
            debug_log!("Error: Could not get current channel name. Skipping set_as_active.");
            return Err(ThisProjectError::InvalidData("Could not get team channel name".into()));
        },
    };

    // 2. Construct the directory path using PathBuf
    let mut directory_path = PathBuf::from("sync_data");
    directory_path.push(&team_channel_name);
    directory_path.push("is_active");
    directory_path.push(collaborator_name);

    // 3. Create the directory if it doesn't exist
    create_dir_all(directory_path.parent().unwrap())?;

    // 4. Create the stub file
    // The mere existence of the file (even empty) acts as the flag
    match File::create(&directory_path) {
        Ok(_) => {
            debug_log!("Collaborator '{}' set as active in channel '{}'.", collaborator_name, team_channel_name);
            Ok(())
        },
        Err(e) => {
            debug_log!("Error setting collaborator '{}' as active: {}", collaborator_name, e);
            Err(ThisProjectError::IoError(e))
        },
    }
}


/// signal for continuing or for stoping whole Uma program with all threads
/// Initializes the UMA continue/halt signal by creating or resetting the 
/// `continue_uma.txt` file and setting its value to "1" (continue).
/// set to halt by `quit_set_continue_uma_to_false()`
fn initialize_continue_uma_signal() {
    // 1. Ensure the directory exists
    let directory_path = Path::new(CONTINUE_UMA_PATH).parent().unwrap(); // Get the parent directory
    fs::create_dir_all(directory_path).expect("Failed to create directory for continue_uma.txt");

    // 2. Create or overwrite the file
    if fs::remove_file(CONTINUE_UMA_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(CONTINUE_UMA_PATH)
        .expect("Failed to create 'continue_uma.txt' file.");

    file.write_all(b"1")
        .expect("Failed to write to 'continue_uma.txt' file.");
}

/// signal for continuing or for stoping whole Uma program with all threads
fn initialize_hard_restart_signal() {
    // 1. Ensure the directory exists
    let directory_path = Path::new(HARD_RESTART_FLAG_PATH).parent().unwrap(); // Get the parent directory
    fs::create_dir_all(directory_path).expect("Failed to create directory for yes_hard_restart_flag.txt");

    // 2. Create or overwrite the file
    if fs::remove_file(HARD_RESTART_FLAG_PATH).is_ok() {
        debug_log("Old 'yes_hard_restart_flag.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(HARD_RESTART_FLAG_PATH)
        .expect("Failed to create 'yes_hard_restart_flag.txt' file.");

    file.write_all(b"1")
        .expect("Failed to write to 'yes_hard_restart_flag.txt' file.");
}


/// set signal to stop whole Uma program with all threads
fn quit_set_continue_uma_to_false() { 
    if fs::remove_file(CONTINUE_UMA_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(CONTINUE_UMA_PATH)
        .expect("Failed to create 'continue_uma.txt' file.");

    file.write_all(b"0")
        .expect("Failed to write to 'continue_uma.txt' file.");
}

/// set signal to stop whole Uma program with all threads
fn no_restart_set_hard_reset_flag_to_false() { 
    if fs::remove_file(HARD_RESTART_FLAG_PATH).is_ok() {
        debug_log("Old 'yes_hard_restart_flag.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(HARD_RESTART_FLAG_PATH)
        .expect("Failed to create 'yes_hard_restart_flag.txt' file.");

    file.write_all(b"0")
        .expect("Failed to write to 'yes_hard_restart_flag.txt' file.");
}


/*
An Appropriately Svelt Mainland:
*/
/// Initializes the UMA continue/halt signal by creating or resetting the 
/// `continue_uma.txt` file and setting its value to "1" (continue).
/// set to hault by quit_set_continue_uma_to_false()
///
/// There is NO practical advantage 
/// to using Arc<AtomicBool> over writing a "1" or "0" to a file. 
/// The file method is simpler, more efficient, 
/// and just as reliable in this context.
///
/// This also allows the user to manually set the halt signal.
fn main() {

    // set boolean flag for loops to know when to hault
    initialize_continue_uma_signal();     

    // set boolean flag for uma to know when to restart
    initialize_hard_restart_signal();

    loop {
        // 3. Check for halt signal
        if should_not_hard_restart() {
            debug_log(
                "Halting handle_remote_collaborator_meetingroom_desk()"
            );
            break;
        }

        debug_log("Start!");

        if let Err(e) = initialize_uma_application() { 
                eprintln!("Initialization failed: {}", e);
                // Potentially add more error-specific handling here
                std::process::exit(1); // Exit with a non-zero code to indicate an error
            }

        // Thread 1: Executes the thread1_loop function
        let we_love_projects_loop = thread::spawn(move || {
            we_love_projects_loop();
        });
        // Thread 2: Executes the thread2_loop function
        let you_love_the_sync_team_office = thread::spawn(move || {
            you_love_the_sync_team_office();
        });
        // Keep the main thread alive
        we_love_projects_loop.join().unwrap();
        you_love_the_sync_team_office.join().unwrap();

        println!("All threads completed. The Uma says fare well and strive.");
        debug_log("All threads completed. The Uma says fare well and strive.");
    }
}
