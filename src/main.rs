/*
Uma
2024.09-11
RUST_BACKTRACE=full cargo run

# Uma: Coordination, Productivity, Hygiene
```
4_|
/ \
```
A distributed project graph database MCU (Multipoint Conferencing Unit) with cli TUI, instant messenger, Kanban Task Manager, and other Agile Kahneman-Tversky project, productivity, coordination, collaboration features


Uma Productivity Collaboration Tools for Project-Alignment 
~ "Read the old books."
- MIT license 
- https://github.com/lineality/uma_productivity_collaboration_tool 
- https://github.com/lineality/definition_behavior_studies
- https://github.com/lineality/Online_Voting_Using_One_Time_Pads
- https://github.com/lineality/object_relationship_spaces_ai_ml 
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

// tiny_tui_module.rs

pub mod tiny_tui {
    use std::path::Path;
    use std::time::{
        Duration, 
        UNIX_EPOCH
        };
    use crate::{ // Import from the main module
        DEBUG_FLAG,
        debug_log,
        OpenOptions,
        Write,
        }; 

    pub fn render_list(
        list: &Vec<String>,
        current_path: &Path,
        agenda_process: &str,
        goals_features: &str,
        scope: &str,
        schedule_duration_start_end: &Vec<u64>,
    ) {
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
            println!("Select a Team-Channel (by number):");
        }

        // 2b. Display added core node fields
        println!("Agenda/Process: {}", agenda_process);
        println!("Goals/Features: {}", goals_features);
        println!("Scope: {}", scope);

        if schedule_duration_start_end.len() == 2 {
            let start_time = schedule_duration_start_end[0];
            let end_time = schedule_duration_start_end[1];
            let duration_days = (end_time - start_time) / (60 * 60 * 24); 

            let start_date = format_timestamp_to_date(start_time);
            let end_date = format_timestamp_to_date(end_time);
            println!("Schedule: {} - {} ({} days)", start_date, end_date, duration_days);

        }
        else {
            println!("Schedule: (no schedule)");
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }    
        
    pub fn simple_render_list(list: &Vec<String>, current_path: &Path) {
            
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
            println!("Select a Team-Channel (by number):"); 
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }    
    
    

/// Converts a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to a YYYY-MM-DD formatted date string
///
/// # Arguments
/// * `timestamp` - Unix timestamp in seconds
///
/// # Returns
/// * `String` - Date in "YYYY-MM-DD" format, or "Invalid Date" if the timestamp cannot be converted
///
/// # Examples
/// ```
/// let timestamp = 1672531200; // 2023-01-01 00:00:00 UTC
/// assert_eq!(format_timestamp_to_date(timestamp), "2023-01-01");
/// ```
/// use -> use std::time::{Duration, UNIX_EPOCH};
fn format_timestamp_to_date(timestamp: u64) -> String {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp))
        .and_then(|datetime| datetime.duration_since(UNIX_EPOCH).ok())
        .map(|duration| {
            let secs = duration.as_secs();
            let year = 1970 + (secs / 31_557_600); // Approximate years (365.25 days)
            let remaining_secs = secs % 31_557_600;
            let month = 1 + (remaining_secs / 2_629_800); // Approximate months (30.44 days)
            let day = 1 + ((remaining_secs % 2_629_800) / 86_400); // Days (24 hours)
            
            format!("{:04}-{:02}-{:02}", year, month, day)
        })
        .unwrap_or_else(|| "Invalid Date".to_string())
}
    
        
    pub fn render_tasks_list(headers: &[String], data: &[Vec<String>], current_path: &Path) {
        debug_log("starting: render_tasks_list");
        // 1. Display Current Path
        print!("\x1B[2J\x1B[1;1H"); // Clear the screen
        println!("Current Path: {}", current_path.display());
    
        // 2. Display Table (reuse display_table from tiny_tui_module)
        display_table(headers, data);
    
        // 3. (Optional) Display any other task-specific information or instructions.
        println!("Select a Task (by number):"); 
    }
        
    
    
    // pub fn render_list(list: &Vec<String>, current_path: &Path) {
    //     println!("Current Path: {}", current_path.display());
    //     for (i, item) in list.iter().enumerate() {
    //         println!("{}. {}", i + 1, item);
    //     }
    // }

    pub fn get_input() -> Result<String, std::io::Error> {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
    
    pub fn display_table(headers: &[String], data: &[Vec<String>]) {  // Changed header type
        debug_log("tui module: task-mode: start: display_table()");
        debug_log!(
            "tui module: display_table(): headers -> {:?} data -> {:?}",
            headers,
            data,
        );
        
        // Print headers
        for header in headers {
            print!("{:<15} ", header);
        }
        println!();

        // Print separator (optional)
        println!("{}", "-".repeat(headers.len() * 15));


        // Print rows:  Handle potentially uneven row lengths
        // Find the maximum number of columns for formatting:
        let max_columns = headers.len();

        for row in data {
            for (i, item) in row.iter().enumerate() {
                if i < max_columns { // Ensure we don't exceed the header count.
                    print!("{:<15} ", item); 
                }
            }
            println!();
        }
    }
    
    // pub fn display_table(headers: &[&str], data: &[Vec<&str>]) {
    //     // Print headers
    //     for header in headers {
    //         print!("{:<15} ", header); // Left-align with padding
    //     }
    //     println!();
    
    //     // Print separator
    //     println!("{}", "-".repeat(headers.len() * 15));
    
    //     // Print data rows
    //     for row in data {
    //         for item in row {
    //             print!("{:<15} ", item);
    //         }
    //         println!();
    //     }
    // }
    // // fn main() {
    // //     let headers = vec!["Column 1", "Column 2", "Column 3"];
    // //     let data = vec![
    // //         vec!["Data A", "Data B", "Data C"],
    // //         vec!["Data D", "Data E", "Data F"],
    // //     ];
    // //     display_table(&headers, &data);
    // // }
    
    // Helper function to transpose the table data
    pub fn transpose_table_data(data: &[Vec<String>]) -> Vec<Vec<String>> {
        debug_log("tui module: task-mode: start: transpose_table_data()");
        if data.is_empty() {
            return Vec::new();
        }
    
        let num_rows = data.iter().map(|col| col.len()).max().unwrap_or(0);  // Or 0 for an empty table
        let num_cols = data.len();
        let mut transposed_data = vec![vec![String::new(); num_cols]; num_rows];
    
        for (j, col) in data.iter().enumerate() {
            for (i, item) in col.iter().enumerate() {
                transposed_data[i][j] = item.clone();
            }
        }
    
        transposed_data
    }

}




*/

// Set debug flag (future: add time stamp with 24 check)
const DEBUG_FLAG: bool = true;
const MAX_NETWORK_TYPE_LENGTH: usize = 1024; // Example: 1KB limit

const EMPTY_IPV_4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1); // == = 127.0.0.1
const EMPTY_IPV_6: Ipv6Addr = Ipv6Addr::UNSPECIFIED; // Correct way to represent an unspecified IPv6 address

// use std::sync::mpsc;
// use std::fmt::Write as StdFmtWrite;

use std::io;
use std::io::{
    Error,
    ErrorKind,
    Write,
    // Read,
};
// use std::str::FromStr; 
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
    // DirEntry,
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

use std::process::Command as StdCommand;
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
#[macro_use]
mod tiny_tui_module;
use tiny_tui_module::tiny_tui;

const FILE_READWRITE_N_RETRIES: u64 = 5;
const FILE_READWRITE_RETRY_SEC_PAUSE: u64 = 2;
const FILE_READWRITE_RETRY_SEC_PAUSE_MIN: u64 = 1;
const FILE_READWRITE_RETRY_SEC_PAUSE_MAX: u64 = 6;
const CONTINUE_UMA_PATH: &str = "project_graph_data/session_state_items/continue_uma.txt";
const HARD_RESTART_FLAG_PATH: &str = "project_graph_data/session_state_items/yes_hard_restart_flag.txt";
const SYNC_START_OK_FLAG_PATH: &str = "project_graph_data/session_state_items/ok_to_start_sync_flag.txt";


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
    InvalidInput(String),
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
            ThisProjectError::InvalidInput(ref msg) => write!(f, "Invalid Input: {}", msg), 
            ThisProjectError::PortCollision(ref msg) => write!(f, "Port Collision: {}", msg),
            ThisProjectError::NetworkError(ref msg) => write!(f, "Network Error: {}", msg),
            ThisProjectError::WalkDirError(ref err) => write!(f, "WalkDir Error: {}", err),
            ThisProjectError::ParseIntError(ref err) => write!(f, "ParseInt Error: {}", err),
            ThisProjectError::ParseIntError(ref err) => write!(f, "ParseInt Error: {}", err),
            ThisProjectError::GpgError(ref err) => write!(f, "GPG Error: {}", err), // Add this arm
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
            ThisProjectError::InvalidInput(msg) => MyCustomError::InvalidData(msg), 
            ThisProjectError::PortCollision(msg) => MyCustomError::PortCollision(msg),
            // ... add other conversions for your variants ...
            _ => MyCustomError::InvalidData("Unknown error".to_string()), // Default case
        }
    }
}

fn remove_duplicates_from_path_array(vec: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut unique_vec = Vec::new();

    for item in vec {
        if seen.insert(item.clone()) {
            unique_vec.push(item);
        }
    }

    unique_vec
}

// Implement the From trait to easily convert from other error types into ThisProjectError
impl From<io::Error> for ThisProjectError {
    fn from(err: io::Error) -> ThisProjectError {
        ThisProjectError::IoError(err)
    }
}

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

// /*
// TODO:
// in the nearterm and long term
// there needs to be a way of selecting and coordinating about working ip addresses
// e.g. once an address works, the number of that address in the shared list may be 
// transmitted in the ReadySignal to say which ip is being used (e.g. when 
//     there are several possible 'campuses' that might be used)
    
// The primary task is testing what local IP for the local owner user out of the list
// in their file works (and which listen item that is).

// another later task may be using a intranet mode.
// */

/// Get Band: Network config data
/// The function is called during initialization bootstrapping
/// so there are few pre-existing values to put in,
/// this function must bootstrap itself.
/// Note: this is before any team_channel has been entered
/// 
/// Get Band: Network config data
/// Returns the first valid IP address and its type ("ipv6" or "ipv4") found for the local user, 
/// along with its index in the respective list.
///
/// This function is called during initialization bootstrapping to determine a valid network configuration
/// before any team channel is entered. It reads the local user's IP address lists from their collaborator
/// TOML file and attempts to bind a UDP socket to each address to verify its validity.
///
/// Args:
///     uma_local_owner_user: The username of the local UMA user.
///
/// Returns:
///     (String, u8): A tuple containing the network type ("ipv6" or "ipv4") and the index of the valid IP address. 
///     Returns ("none", 0) if no valid IP address is found.
fn get_band__find_valid_network_index_and_type(
    uma_local_owner_user: &str,
) -> (
    bool, // network_found_ok flag
    String, // network_type
    u8, // network_index
    Ipv4Addr, 
    Ipv6Addr,
    ) {
    /*
    General Steps
    1. get name of local owner
        paremeter
    2. get local owner file (or fields)
    "/project_graph_data/collaborator_files_address_book/{}__collaborator.toml", uma_local_owner_user
    3. look for valid ipv6
        find_valid_local_owner_ipv6_address
    4. (if not found) look for valid ivp4
        find_valid_local_owner_ipv4_address
    5. (pending) look for other network band types e.g. CB radio, optical, audio, etc.
    6. return (network_type, network_index) tuple (e.g. ('ipv6', 0)
    */

    // 2. Load IP lists from the collaborator file
    let (ipv4_addresses, ipv6_addresses) = match load_local_ip_lists(uma_local_owner_user) {
        Ok(lists) => lists,
        Err(e) => {
            debug_log!("Error loading IP lists: {}. Returning filler values.", e);
            return (
                false,
                "none".to_string(),
                0,
                EMPTY_IPV_4,  // Filler value
                EMPTY_IPV_6,  // Filler value
            );
        }
    };

    let (ipv4_addresses_string, ipv6_addresses_string) = match load_local_iplists_as_stringtype(uma_local_owner_user) {
        Ok(lists) => lists,
        Err(e) => {
            debug_log!("Error loading IP lists as strings: {}", e);
            // Return "none" with default IP addresses
            return (false, "none".to_string(), 0, Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED); 
        }
    };

    // 3. Try IPv6 addresses first
    if let Some(valid_ipv6) = find_valid_local_owner_ipv6_address(&ipv6_addresses) {
        // Get index
        debug_log!("Found valid ipv6 address: {:?}", valid_ipv6);
        
        if let Some(index) = get_index_byof_ip(
            &ipv4_addresses_string,
            &ipv6_addresses_string,
            &valid_ipv6.to_string()
        ) {
            return (true, "ipv6".to_string(), index, EMPTY_IPV_4, valid_ipv6);
        } else {
            debug_log!("Valid IPv6 address not found in the list.");
        }
    }

    // 4. If no valid IPv6, then try IPv4
    if let Some(valid_ipv4) = find_valid_local_owner_ipv4_address(&ipv4_addresses) {
        if let Some(index) = get_index_byof_ip(
            &ipv4_addresses_string,
            &ipv6_addresses_string,
            &valid_ipv4.to_string()
        ) {
            return (true, "ipv4".to_string(), index, valid_ipv4, EMPTY_IPV_6);
        } else {
            debug_log!("Valid IPv4 address not found in the list.");
        }
    }

    // 5. No valid IP found
    debug_log!("No valid IPv4 or IPv6 address found.");
    (false, "none".to_string(), 0, EMPTY_IPV_4, EMPTY_IPV_6) // Return a default value
}

/// Attempts to bind a UDP socket to each address in the provided list.
/// 
/// This function iterates through the `ip_addresses` slice. For each address, it attempts to bind a UDP
/// socket to the address on a designated test port (55555). If successful, the function immediately
/// returns the bindable address. If binding fails for all addresses in the list, the function returns `None`.
///
/// This function is used during initialization to determine a valid local IP address that UMA can use
/// for communication.
///
/// Args:
///     ip_addresses (&[Ipv6Addr]): A slice of IPv6 addresses to test.
///
/// Returns:
///     Option<Ipv6Addr>: The first IPv6 address in the list to which a UDP socket can be successfully bound, or `None` if no address is bindable.
///
fn find_valid_local_owner_ipv6_address(ipv6_addresses: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    for &address in ipv6_addresses {
        if !address.is_loopback() && !address.is_unspecified() { // Use short-circuit &&
            let test_port = 55555;
            let socket_addr = SocketAddr::new(IpAddr::V6(address), test_port);
            if UdpSocket::bind(socket_addr).is_ok() { // Simplified check
                return Some(address);
            } else {
                debug_log!("Could not bind to {:?}. Trying next address...", socket_addr);
            }
        }
    }
    None
}

// Analogous function for IPv4
fn find_valid_local_owner_ipv4_address(ipv4_addresses: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    // ... (Implementation is analogous to the IPv6 version)
    for &address in ipv4_addresses {
        if !address.is_loopback() && !address.is_unspecified() {
            let test_port = 55555;
            let socket_addr = SocketAddr::new(IpAddr::V4(address), test_port);
            if UdpSocket::bind(socket_addr).is_ok() {
                return Some(address);
            } else {
                debug_log!("Could not bind to {:?}. Trying next address...", socket_addr);
            }
        }
    }
    None
}

/// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
///
/// This function reads the collaborator file for the given `owner` and extracts the
/// `ipv4_addresses` and `ipv6_addresses` fields. It handles missing fields by returning empty vectors.
///
/// # Arguments
///
/// * `owner`: The username of the local user.
///
/// # Returns
///
/// * `Result<(Vec<String>, Vec<String>), ThisProjectError>`: A tuple containing the IPv4 and IPv6 address lists as strings, or a `ThisProjectError` if an error occurs.
fn load_local_iplists_as_stringtype(owner: &str) -> Result<(Vec<String>, Vec<String>), ThisProjectError> {
    let toml_path = format!("project_graph_data/collaborator_files_address_book/{}__collaborator.toml", owner);
    let toml_string = std::fs::read_to_string(toml_path)?;
    let toml_value: toml::Value = toml::from_str(&toml_string)?;

    // Extract IPv4 addresses (handling missing/invalid data):
    let ipv4_addresses: Vec<String> = match toml_value.get("ipv4_addresses") {
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|val| val.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(), // Return empty if no IP list found.
    };

    // Extract IPv6 addresses:
    let ipv6_addresses: Vec<String> = match toml_value.get("ipv6_addresses") {
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|val| val.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(), // Return empty on error.
    };

    Ok((ipv4_addresses, ipv6_addresses))
}

/// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
///
/// This function reads the collaborator file for the given `owner` and extracts the
/// `ipv4_addresses` and `ipv6_addresses` fields. It handles missing fields by returning empty vectors.
///
/// # Arguments
///
/// * `owner`: The username of the local user.
///
/// # Returns
///
/// * `Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError>`: A tuple containing the IPv4 and IPv6 address lists, or a `ThisProjectError` if an error occurs.
fn load_local_ip_lists(owner: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError> {
    let toml_path = format!("project_graph_data/collaborator_files_address_book/{}__collaborator.toml", owner);
    let toml_string = std::fs::read_to_string(toml_path)?;
    let toml_value: toml::Value = toml::from_str(&toml_string)?;

    // Extract IPv4 addresses (handling missing/invalid data):
    let ipv4_addresses: Vec<Ipv4Addr> = match toml_value.get("ipv4_addresses") {
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|val| val.as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()))
            .collect(),
        _ => Vec::new(), // Return empty if no IP list found.
    };

    // Extract IPv6 addresses:
    let ipv6_addresses: Vec<Ipv6Addr> = match toml_value.get("ipv6_addresses") {
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|val| val.as_str().and_then(|s| s.parse::<Ipv6Addr>().ok()))
            .collect(),
        _ => Vec::new(), // Return empty on error.
    };

    Ok((ipv4_addresses, ipv6_addresses))
}

/// This converts between the u8 sent by uma over network and usize that Rust uses for array-indices.
fn get_ip_by_index(
    index: u8,
    ipv4_list: &[Ipv4Addr],
    ipv6_list: &[Ipv6Addr],
) -> Option<(IpAddr, u8)> {
    if index < ipv4_list.len() as u8 {
        Some((IpAddr::V4(ipv4_list[index as usize]), index))
    } else if index < (ipv4_list.len() + ipv6_list.len()) as u8 {
        let ipv6_index = index - ipv4_list.len() as u8;
        Some((IpAddr::V6(ipv6_list[ipv6_index as usize]), index))
    } else {
        None
    }
}

/// Saves the combined network option index to a file.
/// @ /sync_data/network_option_index.txt
/// This function saves the given `combined_index` to "sync_data/{team_channel_name}/network_option_index.txt".
/// It creates the necessary directories if they don't exist and handles file I/O errors.
///
/// # Arguments
///
/// * `combined_index`: The combined network option index.
/// * `team_channel_name`: The name of the team channel.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`:  `Ok(())` on success, or an error if an I/O operation fails.
fn save_network_option_index_statefile(
    combined_index: u8,
) -> Result<(), ThisProjectError> {
    let mut file_path = PathBuf::from("sync_data");
    file_path.push("network_option_index.txt");

    if let Some(parent_dir) = file_path.parent() {
        create_dir_all(parent_dir)?;
    }

    let mut file = File::create(&file_path)?;
    write!(file, "{}", combined_index)?;
    Ok(())
}

/// Finds the the index in either along, not combined.
/// This converts between the u8 sent by uma over network and usize that Rust uses for array-indices.
///
/// This function searches for the given `ip_address` 
/// each list alone.
/// It returns the index found.
///
/// # Arguments
///
/// * `ipv4_list`: The list of IPv4 addresses as strings.
/// * `ipv6_list`: The list of IPv6 addresses as strings.
/// * `ip_address`: The IP address to search for as a string.
///
/// # Returns
///
/// * `Option<u8>`:  The combined index, or `None` if the IP address is not found.
fn get_index_byof_ip(
    ipv4_list: &[String],
    ipv6_list: &[String],
    ip_address: &str,
) -> Option<u8> {
    let ip_addr: IpAddr = ip_address.parse().ok()?;

    debug_log!("get_index_byof_ip ipv4_list{:?}",ipv4_list);
    debug_log!("get_index_byof_ip ipv6_list{:?}",ipv6_list);
    debug_log!("get_index_byof_ip ip_address{:?}",ip_address);
    debug_log!("get_index_byof_ip ip_addr{:?}",ip_addr);

    let result = match ip_addr {
        IpAddr::V4(ipv4) => {
            ipv4_list.iter().position(|ip| ip == &ipv4.to_string()).map(|index| index as u8)
        }
        IpAddr::V6(ipv6) => {
            ipv6_list.iter().position(|ip| ip == &ipv6.to_string()).map(|index| index as u8)
        }
    };

    debug_log!("get_index_byof_ip result {:?}", result);

    result

}

/// Saves the local user's network band config data
/// to sync_data text files
/// As this is done only once during startup, retry is likely not needed 
///
fn write_local_band__save_network_band__type_index(
    network_type: String,
    network_index: u8,
    this_ipv4: Ipv4Addr,
    this_ipv6: Ipv6Addr,
) -> Result<(), ThisProjectError> {
    // 1. Construct Path:
    let base_path = PathBuf::from("sync_data");

    // 2. Create Directory (if doesn't exist)
    create_dir_all(&base_path)?;

    // 3. Construct Absolute File Paths
    let type_path = base_path.join("network_type.txt");
    let index_path = base_path.join("network_index.txt");
    let ipv4_path = base_path.join("ipv4.txt");
    let ipv6_path = base_path.join("ipv6.txt");

    // 4. Write to Files (handling potential errors):
    let mut type_file = File::create(&type_path)?; // Note the & for borrowing
    writeln!(type_file, "{}", network_type)?;

    let mut index_file = File::create(&index_path)?;
    writeln!(index_file, "{}", network_index)?;

     // 4. Write to Files (handling potential errors):
     // TODO this is not working, it is writing "sync_data/ipv6.txt" as the file text
     // the path to the file should not be the file content...
    let mut ip4_file = File::create(&ipv4_path)?; // Note the & for borrowing
    writeln!(ip4_file, "{}", this_ipv4.to_string())?;  // Write IP string

    let mut ip6_file = File::create(&ipv6_path)?;
    writeln!(ip6_file, "{}", this_ipv6.to_string())?;  // Write IP string
    
    Ok(())
}

/// Saves the local user's network band config data
/// to sync_data text files
/// as this is done only once during startup, retry is likely not needed
/// 
fn write_save_rc_bandnetwork_type_index(
    remote_collaborator_name: String,
    team_channel_name: String,
    network_type: String,
    network_index: u8,
    this_ipv4: Ipv4Addr,
    this_ipv6: Ipv6Addr,
) -> Result<(), ThisProjectError> {
    /* ?
    Wait random time in A to B range, N times
    FILE_READWRITE_N_RETRIES
    FILE_READWRITE_RETRY_SEC_PAUSE_MIN
    FILE_READWRITE_RETRY_SEC_PAUSE_max
    */

    
    debug_log("write_save_rc_bandnetwork_type_index(), starting");

    // 1. Construct Path:
    let mut base_path = PathBuf::from("sync_data");
    base_path.push(team_channel_name);
    base_path.push("network_band");
    base_path.push(remote_collaborator_name);

    // Create directory structure if it doesn't exist
    create_dir_all(&base_path)?;
    
    debug_log!("write_save_rc_bandnetwork_type_index(), base_path {:?}", base_path);

    // 3. Construct Absolute File Paths
    let type_path = base_path.join("network_type.txt");
    let index_path = base_path.join("network_index.txt");
    let ipv4_path = base_path.join("ipv4.txt");
    let ipv6_path = base_path.join("ipv6.txt");
    
    debug_log!("write_save_rc_bandnetwork_type_index(), type_path {:?}", type_path);
    debug_log!("write_save_rc_bandnetwork_type_index(), index_path {:?}", index_path);
    debug_log!("write_save_rc_bandnetwork_type_index(), ipv4_path {:?}", ipv4_path);
    debug_log!("write_save_rc_bandnetwork_type_index(), ipv6_path {:?}", ipv6_path);

    // 4.1 Write to Files (handling potential errors):
    let mut type_file = File::create(&type_path)?; // Note the & for borrowing
    writeln!(type_file, "{}", network_type)?;
    
    debug_log!("write_save_rc_bandnetwork_type_index(), type_file {:?}", type_file);

    let mut index_file = File::create(&index_path)?;
    writeln!(index_file, "{}", network_index)?;
    
    debug_log!("write_save_rc_bandnetwork_type_index(), index_file {:?}", index_file);

    // 4.2 Write to Files (handling potential errors):
    let mut ip4_file = File::create(&ipv4_path)?; // Note the & for borrowing
    writeln!(ip4_file, "{}", this_ipv4.to_string())?;  // Write IP string
    debug_log!("write_save_rc_bandnetwork_type_index(), ip4_file {:?}", ip4_file);

    let mut ip6_file = File::create(&ipv6_path)?;
    writeln!(ip6_file, "{}", this_ipv6.to_string())?;  // Write IP string
    debug_log!("write_save_rc_bandnetwork_type_index(), ip6_file {:?}", ip6_file);
    
    Ok(())
}

// TODO: maybe use a parameter in team-channel instead of hard-coding ~10 sec
/// hlod_udp_handshake__rc_network_type_rc_ip_addr(): returns (rc_network_type, rc_ip_addr) as (String, String) loop until satisfied:
/// every 10-60 sec: (lite-weight is the goal, not expensive-brute-force)
/// 1. check for hault-uma (if not more often check somehow)
/// 2. check for received ready-signal in /sync_data/ (if so, exit handshake) see below: with this you can get the rc_ip-data read_rc_bandnetwork_type_index()
/// 3. if not the above options: send a ready signal (iterating) to each listed collaborator ip 
///   ipv4 and ipv6 (until (step 2) there has been logged a ready-signal from one of them)
///
fn hlod_udp_handshake__rc_network_type_rc_ip_addr(
    local_owner_desk_setup_data: &ForLocalOwnerDeskThread,
    band_local_network_type: &str,
    band_local_user_ipv4_address: &Ipv4Addr,
    band_local_user_ipv6_address: &Ipv6Addr,
    band_local_network_index: u8,
) -> Result<(String, String), ThisProjectError> {
    debug_log("inHLOD: Start hlod_udp_handshake__rc_network_type_rc_ip_addr()");
    
    // --- 1. Extract Data from Setup Data ---
    let local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip = local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip;


    // --- Select IP Address and Create SocketAddr for Local Listening ---
    let listen_ip_addr = match band_local_network_type {
        "ipv6" => IpAddr::V6(*band_local_user_ipv6_address),
        "ipv4" => IpAddr::V4(*band_local_user_ipv4_address),
        _ => return Err(ThisProjectError::NetworkError(
            "Invalid network type in hlod_udp_handshake__rc_network_type_rc_ip_addr".into()
            )
        ),
    };

    let local_listen_addr = SocketAddr::new(
        listen_ip_addr, 
        local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
    );

    // --- Prepare ReadySignal ---
    let timestamp_for_rt = match get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl(
        &local_owner_desk_setup_data.remote_collaborator_name,
    ) {
        Ok(timestamp) => timestamp,
        Err(e) => {
            debug_log!("hlod_udp_handshake__rc_network_type_rc_ip_addr(): Error getting timestamp: {}", e);
            0
        }
    };
    debug_log!(
        "hlod_udp_handshake: .rt, timestamp_for_rt, from get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl -> {:?}", 
        timestamp_for_rt,
    );
    

    // setup: Get Team Channel Name
    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

    // setup: Construct Path to check for a ready signal received from the rc (remote collaborator)
    let mut got_signal_check_base_path = PathBuf::from("sync_data");
    got_signal_check_base_path.push(team_channel_name.clone());
    got_signal_check_base_path.push("network_band");
    got_signal_check_base_path.push(&local_owner_desk_setup_data.remote_collaborator_name);        

    loop { // hlod_udp_handshake__rc_network_type_rc_ip_addr() Main loop starts here
        debug_log("hlod_udp_handshake__rc_network_type_rc_ip_addr() main loop (re)starting from the top...");
        
        // 1. Check for Halt Signal and Team Channel Name (as before)
        if should_halt_uma() { // 1. check for halt-uma
            return Err(ThisProjectError::NetworkError("UMA halt signal received (not an error)".into())); // or log the exit?
        }

        // --- 2. Check for Received Ready Signal ---
        // hlod_udp_handshake__rc_network_type_rc_ip_addr() Main loop starts here
        if got_signal_check_base_path.exists() {
            // The path exists...

            // --- The purpose of this block is to use existing band data if it exists in sync_data
            if let Ok(Some((rc_network_type, _, rc_ip_addr_string))) = read_rc_bandnetwork_type_index(
                &local_owner_desk_setup_data.remote_collaborator_name, // Correct collaborator name
                &team_channel_name, // Use correctly retrieved team channel name
            ) {
                debug_log!(
                    "hlod_udp_handshake__rc_network_type_rc_ip_addr(): Ready signal information found in sync_data for {}. rc_network_type: {}, rc_ip: {:?}",
                    local_owner_desk_setup_data.remote_collaborator_name,
                    rc_network_type, 
                    rc_ip_addr_string, 
                );
                
                return Ok((rc_network_type, rc_ip_addr_string)); // Return address, breaking loop
            } else {
                // ... (No ready signal yet, continue sending your own)
                debug_log("hlod_udp_handshake path but no files");
            }
        } else { 
                // ... (No ready signal yet, continue sending your own)
                debug_log("hlod_udp_handshake no path yet");
        } // End of if got_signal_check_base_path.exists()

        // --- 3. Send Ready Signal ---
        // ... [Iterate remote IP addresses *only* if no ReadySignal received]

        // Send to each IPv6 address in rc_ipv6_list
        debug_log("hlod_udp_handshake__rc_network_type_rc_ip_addr() Sending Handshake ready signals!");
        for ipv6_addr_string in &local_owner_desk_setup_data.remote_collaborator_ipv6_addr_list {
            send_ready_signal(
                &local_owner_desk_setup_data.local_user_salt_list,
                "ipv6".to_string(),                            // Correct: Always "ipv6" here
                ipv6_addr_string.to_string(),                  //Correct: Use remote IPv6 address
                local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,  // Use provided port
                timestamp_for_rt,                              // Use calculated timestamp
                band_local_network_type,                       // band_local_network_type
                band_local_network_index,                      // Use band index
            )?;
            debug_log!(
                "ReadySignal sent to IPv6: {}:{}",
                ipv6_addr_string, 
                local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
            );
        }

        // Send to each IPv4 address in rc_ipv4_list
        for ipv4_addr_string in &local_owner_desk_setup_data.remote_collaborator_ipv4_addr_list {  // Iterate IPv4 list
            send_ready_signal( 
                &local_owner_desk_setup_data.local_user_salt_list,
                "ipv4".to_string(),                           // Correct: Always "ipv4" here
                ipv4_addr_string.to_string(),                   // Correct: Use remote IPv4 address
                local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip, // Use port number
                timestamp_for_rt,                           // Use calculated timestamp // Correct: Consistent order
                band_local_network_type,
                band_local_network_index,                           // Use consistent type for band index. // Correct: Consistent order
            )?;
            debug_log!(
                "ReadySignal sent to IPv4: {}:{}",
                ipv4_addr_string, 
                local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
            );            
        }

        // 1.1 Wait (and check for exit Uma)  this waits and checks N times: for i in 0..N {
        for i in 0..5 {
            // break for loop ?
            if should_halt_uma() {
                debug_log!("hold_udp_handshake: should_halt_uma(), exiting Uma in handle_local_owner_desk()");
                break; // break this for-loop
            }
            thread::sleep(Duration::from_secs(3));
        }
        // Then break out of this function main loop
        if should_halt_uma() {
            debug_log!("hold_udp_handshake: should_halt_uma(). Exiting hlod_upd_handshake()");
            break Ok((Default::default(), Default::default()));
        }

    } // loop end
}


// HEREHERE todo TODO fix this, not checking for likely duely noneexistant files
/// Reads the remote collaborator's band data (network type, index, IP address). -> (network_type, network_index, rc_ip)
///
/// This function reads the remote collaborator's network band information, which was previously
/// saved by the `write_save_rc_bandnetwork_type_index` function. The data is read from files
/// within the following directory structure:
/// sync_data/{team_channel_name}/network_band/{remote_collaborator_name}/
///
/// It returns a tuple containing the remote collaborator's network type (e.g., "ipv4" or "ipv6"),
/// network index (as a u8), and IP address (as an IpAddr).
///
/// # Arguments
///
/// * `remote_collaborator_name`: The remote collaborator's username.
/// * `team_channel_name`: The name of the active team channel.
///
/// # Returns
///
/// * `Result<(String, u8, IpAddr), ThisProjectError>`: A tuple containing the network type,
///   network index, and IP address on success, or a `ThisProjectError` if reading or parsing fails.
///
fn read_rc_bandnetwork_type_index(
    remote_collaborator_name: &str,
    team_channel_name: &str,
) -> Result<Option<(String, u8, String)>, ThisProjectError> { // Returns Option

    let mut base_path = PathBuf::from("sync_data");
    base_path.push(team_channel_name);
    base_path.push("network_band");
    base_path.push(remote_collaborator_name);

    // Check if the directory for the collaborator's band data exists
    if !base_path.exists() {
        debug_log!("read_rc_bandnetwork_type_index: Directory for collaborator '{}' not found.  No ready signal received yet.", remote_collaborator_name);
        return Ok(None); // Return None, not an error
    }


    let network_type_path = base_path.join("network_type.txt");
    let network_index_path = base_path.join("network_index.txt");
    let ipv4_path = base_path.join("ipv4.txt");
    let ipv6_path = base_path.join("ipv6.txt");

    // Use a match statement to handle potential file not found errors
    let network_type = match fs::read_to_string(&network_type_path) {
        Ok(content) => content.trim().to_string(),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            debug_log!("read_rc_bandnetwork_type_index: network_type.txt not found for collaborator '{}'.", remote_collaborator_name);
            return Ok(None); // Return None
        }
        Err(e) => return Err(ThisProjectError::IoError(e)), // Return other IO errors
    };

    let network_index: u8 = match fs::read_to_string(&network_index_path) {  //Similar handling
        Ok(content) => content.trim().parse().map_err(ThisProjectError::ParseIntError)?,
        Err(e) if e.kind() == ErrorKind::NotFound => {
             debug_log!("read_rc_bandnetwork_type_index:  network_index.txt not found for collaborator '{}'.", remote_collaborator_name);
            return Ok(None);
        }
        Err(e) => return Err(ThisProjectError::IoError(e)),
    };


    let ip_address_string = match network_type.as_str() { // ... (as before)
        "ipv4" => match fs::read_to_string(&ipv4_path) { //Handle potential file not found error here as well:
                Ok(s) => s.trim().to_string(),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    debug_log!("read_rc_bandnetwork_type_index: ipv4.txt not found for collaborator '{}'.", remote_collaborator_name);
                    return Ok(None);
                }                
                Err(e) => return Err(ThisProjectError::IoError(e)),
            },
        "ipv6" => match fs::read_to_string(&ipv6_path) {  // And here.
                Ok(s) => s.trim().to_string(),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                     debug_log!("read_rc_bandnetwork_type_index: ipv6.txt not found for collaborator '{}'.", remote_collaborator_name);
                    return Ok(None);
                }                
                Err(e) => return Err(ThisProjectError::IoError(e)),
            },
        _ => return Err(ThisProjectError::NetworkError("Invalid network type".into())),
    };

    Ok(Some((network_type, network_index, ip_address_string)))  // Wrap the result in Some()
}

/// Reads the local user's network band configuration data from files in the sync_data directory.
/// Uses absolute paths and handles file I/O and parsing errors.
///
/// Returns:
///     Result<(String, u8, Ipv4Addr, Ipv6Addr), ThisProjectError>: A tuple containing the network type, index, IPv4 address, and IPv6 address on success, or a ThisProjectError on failure.
fn read_band__network_config_type_index_specs() -> Result<(String, u8, Ipv4Addr, Ipv6Addr), ThisProjectError> {
    // 1. Construct Absolute Paths (get current absolute working directory)
    let mut base_path = std::env::current_dir()?; // Start with absolute current directory. Handle potential errors.
    base_path.push("sync_data");
    let type_path = base_path.join("network_type.txt");
    let index_path = base_path.join("network_index.txt");
    let ipv4_path = base_path.join("ipv4.txt");
    let ipv6_path = base_path.join("ipv6.txt");

    // 2. Read Values From Files
    let network_type_result = read_to_string(&type_path);
    let network_index_result = read_to_string(&index_path);
    let ipv4_result = read_to_string(&ipv4_path);
    let ipv6_result = read_to_string(&ipv6_path);

    // 3. Handle File Reading Errors: Return early if *any* file read fails
    let network_type = network_type_result?.trim().to_string();
    let network_index_str = network_index_result?.trim().to_string();
    let ipv4_str = ipv4_result?.trim().to_string();
    let ipv6_str = ipv6_result?.trim().to_string();


    // 4. Parse network_index (u8), Handling Errors
    let network_index: u8 = network_index_str
        .parse()
        .map_err(|e| ThisProjectError::InvalidData(format!("Invalid network index: {}", e)))?;


    // 5. Parse IPv4 and IPv6, Handling Errors
    let ipv4: Ipv4Addr = ipv4_str
        .parse()
        .map_err(|e| ThisProjectError::InvalidData(format!("Invalid IPv4 address: {}", e)))?;
    let ipv6: Ipv6Addr = ipv6_str
        .parse()
        .map_err(|e| ThisProjectError::InvalidData(format!("Invalid IPv6 address: {}", e)))?;


    Ok((network_type, network_index, ipv4, ipv6))
}


enum IpAddrKind { V4, V6 }

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
    toml_string.push_str(&format!("gpg_key_public = \"\"\"{}\"\"\"\n", collaborator.gpg_key_public));

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
    /* ?
    Wait random time in A to B range, N times
    FILE_READWRITE_N_RETRIES
    FILE_READWRITE_RETRY_SEC_PAUSE_MIN
    FILE_READWRITE_RETRY_SEC_PAUSE_max
    */

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
/// gpg_key_public = """-----BEGIN PGP PUBLIC KEY BLOCK----- ..."""
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
    debug_log("Starting read_one_collaborator_setup_toml()");

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
//     let output = MainStdCommand::new("gpg")
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
    let output = StdCommand::new("gpg") 
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

fn debugpause(n: u64) {
    debug_log("DebugPause Time!");
    let wait_until = SystemTime::now() + Duration::from_secs(n);
    loop {
        if SystemTime::now() >= wait_until {
            break;
        }
        thread::sleep(Duration::from_millis(2000));
    }
    debug_log("...ok");
}

/// read timestamps from .toml files, like you were born to do just that...on Mars!!
fn get_toml_file_updated_at_timestamp(file_path: &Path) -> Result<u64, ThisProjectError> {
    debug_log!(
        "Starting get_toml_file_updated_at_timestamp, file_path -> {:?}",
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
        "[Done] get_toml_file_updated_at_timestamp, timestamp -> {:?}",
        timestamp   
    );
    
    Ok(timestamp)
}

// debug_log! macro for f-string printing variables
// #[macro_use]
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
    remote_collaborator_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    remote_collaborator_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
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
    local_user_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    local_user_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
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
    let mut child = StdCommand::new("gpg")
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
#[derive(PartialEq, Clone, Debug)]
enum InputMode {
    /// MainCommand Mode:  The default mode. The user can type commands (e.g., "help", "quit", "m") 
    /// to navigate the project graph or interact with UMA features.
    MainCommand,
    /// Insert Text Mode:  Used for entering text, such as instant messages. In this mode, 
    /// user input is treated as text to be added to the current context.
    InsertText,
    TaskCommand,
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
    
    // For Task Display
    next_path_lookup_table: HashMap<usize, PathBuf>,
    ordered_task_column_list: Vec<String>,
    task_display_table: Vec<String>, // ?
    
}


impl App {
    /*

    
    */
    fn update_next_path_lookup_table(&mut self) {

        debug_log("Starting update_next_path_lookup_table ");
        
        // Clear previous entries.
        self.next_path_lookup_table.clear();

        match self.input_mode {
            InputMode::MainCommand => {
                for (i, item) in self.tui_directory_list.iter().enumerate() {
                    let next_path = self.current_path.join(item);
                    self.next_path_lookup_table.insert(i + 1, next_path);
                }
                }
            InputMode::TaskCommand => {
                if self.is_at_task_browser_root() { // COLUMN Navigation (if at root)
                    for (i, column) in self.tui_directory_list.iter().enumerate() {
                        let next_path = self.current_path.join(column);
                        self.next_path_lookup_table.insert(i + 1, next_path);
                    }
                } else { //TASK Navigation if within a column
                    for (i, item) in self.tui_file_list.iter().enumerate() {
                        if let Some(task_path) = self.get_full_task_path(i){
                        self.next_path_lookup_table.insert(i + 1, task_path);
                        }
                    }
                }
            }
            InputMode::InsertText => {
                // Do nothing, as no file-system based paths are used for inputting messages.
            }
            }
    }

    
    fn new(graph_navigation_instance_state: GraphNavigationInstanceState) -> App {
        App {
            tui_focus: 0,
            current_path: PathBuf::from("project_graph_data/team_channels"),
            input_mode: InputMode::MainCommand, 
            tui_file_list: Vec::new(), // Initialize files
            tui_directory_list: Vec::new(), // Initialize files
            tui_textmessage_list: Vec::new(), // Initialize files
            tui_width: 80, // default posix terminal size
            tui_height: 42, // default posix terminal size
            command_input_integer: None,
            current_command_input: None,
            current_text_input: None,
            graph_navigation_instance_state, // Initialize the field
            
            next_path_lookup_table: HashMap::new(),
            ordered_task_column_list: Vec::new(),
            task_display_table: Vec::new(),
        }
    }
    /*

    ## Task Display

    struct GraphNavigationInstanceState {
        local_owner_user: String, // Store the local user data here
        // local_owner_hash_list: Vec<u8>,
        active_team_channel: String, 
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
        current_node_unique_id: Vec<u8>,
        current_node_members: Vec<String>,
        home_square_one: bool,
        
        next_path_lookup_table: HashMap<usize, PathBuf>,
        ordered_task_column_list: Vec<String>, // not needed here?
        task_display_table: Vec<String>, // ?
        }

    impl GraphNavigationInstanceState {
        maybe populate the next_path_lookup_table and task_display_table
        using functions here
    }

    note: columns are (node) directories with a formatted directory name:
    int underscore string: sequence number left to right, underscore, and display name
    to be systematically processed.

    note: the TUI display table should have int space string for the columns and for the tasks

    ### Task Display Parts:
    1. a sequence counter (to mostly increment)
    2. an ordered list of column paths
    3. display table: maybe array of strings (for the TUI to show as a simple table)
    4. path lookup dictionary: a {int:path} path lookup dictionary (for the user-interface to select next path)

    ### Column-item Steps: columns are (node) directories
    1. Preset/Reset the Task Display Parts (see above)
    2. read the "#_str" column names, start the sequence counter after the highest
    3. add column names and numbers (from #_str") to the path lookup dict (these are the column headers)
    4. add column numbers and names to display table (maybe truncate list name depending on display size if name is too long)
    5. add column path to ordered column path list

    ### Task-item Steps: tasks are (node) directories
    1. tasks: iterate through the ordered column path list (in order), for each column:
    2. simple sort the tasks (directories) in the column (directory), alphanumeric
    3. use and increment sequence counter. use the current sequence int and when done increment
    4. add task names and numbers (from #_str") to the path lookup dict: add as rows in the current column
    5. add task number and name to path lookup dictionary


    // example
    let mut graph_state = GraphNavigationInstanceState { /* initialize fields */ };
    graph_state.update_task_display()?;
    graph_state.print_task_display(); // For debugging
    
    */

    // /// Updates the task display components based on the current directory
    // pub fn update_task_display(&mut self) -> std::io::Result<()> {
    //     // Reset display components
    //     self.next_path_lookup_table.clear();
    //     self.ordered_task_column_list.clear();
    //     self.task_display_table.clear();

    //     let mut sequence_counter: usize = 1;
        
    //     // Clone the PathBuf to avoid borrowing issues
    //     // Get absolute path from current directory
    //     let channel_dir_path = self.current_path.clone();
    //     debug_log!(
    //         "update_task_display, channel_dir_path -> {:?}",
    //         channel_dir_path
    //     );
        
        
    //     // // A. Print the absolute path of the channel directory
    //     // match channel_dir_path.canonicalize() {
    //     //     Ok(abs_path) => debug_log!("update_task_display. Absolute channel directory path: {:?}", abs_path),
    //     //     Err(e) => debug_log!("Error update_task_display. getting absolute path of channel directory: {}", e),
    //     // }

    //     // Process columns
    //     self.process_columns(&channel_dir_path, &mut sequence_counter)?;
        
    //     // Process tasks in each column
    //     self.process_tasks(&mut sequence_counter)?;

    //     Ok(())
    // }

    //     /// Process column directories and create headers
    //     fn process_columns(&mut self, channel_dir_path: &Path, sequence_counter: &mut usize) -> std::io::Result<()> {
    //         let mut columns: Vec<(usize, String, PathBuf)> = Vec::new();

    //         // Collect and parse column directories
    //         for entry in fs::read_dir(channel_dir_path)? {
    //             let entry = entry?;
    //             let path = entry.path();
    //             if path.is_dir() {
    //                 if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
    //                     if let Some((seq, display_name)) = parse_directory_name(name) {
    //                         columns.push((seq, display_name.to_string(), path));
    //                         *sequence_counter = (*sequence_counter).max(seq + 1);
    //                     }
    //                 }
    //             }
    //         }

    //         // Sort columns by sequence number
    //         columns.sort_by_key(|(seq, _, _)| *seq);

    //         // Create header row
    //         let mut header_row = String::new();
    //         for (seq, display_name, path) in &columns {
    //             // Add to path lookup
    //         self.next_path_lookup_table.insert(*seq, path.clone());
                
                
    //             // Add to ordered column list
    //             self.ordered_task_column_list.push(path.to_string_lossy().to_string());
                
    //             // Add to display table header
    //             let truncated_name = truncate_string(&display_name, 
    //                 (self.tui_width as usize / columns.len()).saturating_sub(5));
    //             header_row.push_str(&format!("{:3} {:<20} ", seq, truncated_name));
    //         }

    //         self.task_display_table.push(header_row);
    //         Ok(())
    //     }

    //     /// Process tasks within each column
    //     fn process_tasks(&mut self, sequence_counter: &mut usize) -> std::io::Result<()> {
    //         let max_rows = self.get_max_tasks_count()?;
    //         let column_count = self.ordered_task_column_list.len();

    //         // Initialize rows
    //         for _ in 0..max_rows {
    //             let mut row = String::new();
    //             for _ in 0..column_count {
    //                 row.push_str(&" ".repeat(25)); // Adjust spacing based on your needs
    //             }
    //             self.task_display_table.push(row);
    //         }

    //         // Process each column
    //         for (col_idx, column_path_str) in self.ordered_task_column_list.iter().enumerate() {
    //             let column_path = Path::new(column_path_str);
    //             let mut tasks: Vec<(String, PathBuf)> = Vec::new();

    //             // Collect tasks in current column
    //             for entry in fs::read_dir(column_path)? {
    //                 let entry = entry?;
    //                 let path = entry.path();
    //                 if path.is_dir() {
    //                     if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
    //                         tasks.push((name.to_string(), path));
    //                     }
    //                 }
    //             }

    //             // Sort tasks
    //             tasks.sort_by(|(a, _), (b, _)| a.cmp(b));

    //             // Process each task
    //             for (row_idx, (task_name, task_path)) in tasks.iter().enumerate() {
    //                 if row_idx + 1 >= self.task_display_table.len() {
    //                     break;
    //                 }

    //                 // Add to path lookup
    //                 self.next_path_lookup_table.insert(*sequence_counter, task_path.clone());

    //                 // Update display table
    //                 let display_text = format!("{:3} {}", sequence_counter, 
    //                     truncate_string(task_name, 20));
                    
    //                 // Update the specific position in the row
    //                 let row = &mut self.task_display_table[row_idx + 1];
    //                 let start_pos = col_idx * 25;
    //                 let end_pos = start_pos + display_text.len().min(25);
    //                 if start_pos < row.len() {
    //                     let mut new_row = row[..start_pos].to_string();
    //                     new_row.push_str(&display_text);
    //                     new_row.push_str(&row[end_pos..]);
    //                     self.task_display_table[row_idx + 1] = new_row;
    //                 }

    //                 *sequence_counter += 1;
    //             }
    //         }

    //         Ok(())
    //     }

    /// Updates the task display components and returns formatted headers and data
    pub fn update_task_display(&mut self) -> std::io::Result<(Vec<String>, Vec<Vec<String>>)> {
        // Reset display components
        self.next_path_lookup_table.clear();
        self.ordered_task_column_list.clear();
        self.task_display_table.clear();

        let mut sequence_counter: usize = 1;
        // Clone the PathBuf to avoid borrowing issues
        // Get absolute path from current directory
        let channel_dir_path = self.current_path.clone();
        debug_log!(
            "update_task_display, channel_dir_path -> {:?}",
            channel_dir_path
        );

        // Initialize vectors for headers and data
        let mut headers: Vec<String> = Vec::new();
        let mut data: Vec<Vec<String>> = Vec::new();

        // Process columns and collect headers
        self.process_columns(&channel_dir_path, &mut sequence_counter, &mut headers)?;
        
        // Process tasks and collect data
        self.process_tasks(&mut sequence_counter, &headers, &mut data)?;

        Ok((headers, data))
    }

    fn process_columns(
        &mut self, 
        current_dir: &Path, 
        sequence_counter: &mut usize,
        headers: &mut Vec<String>
    ) -> std::io::Result<()> {
        let mut columns: Vec<(usize, String, PathBuf)> = Vec::new();

        // Collect and parse column directories
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some((seq, display_name)) = parse_directory_name(name) {
                        columns.push((seq, display_name.to_string(), path));
                        *sequence_counter = (*sequence_counter).max(seq + 1);
                    }
                }
            }
        }

        // Sort columns by sequence number
        columns.sort_by_key(|(seq, _, _)| *seq);

        // Process columns
        for (seq, display_name, path) in columns {
            // Add to path lookup
            self.next_path_lookup_table.insert(seq, path.clone());
            
            // Add to ordered column list
            self.ordered_task_column_list.push(path.to_string_lossy().to_string());
            
            // Add to headers
            let truncated_name = truncate_string(&display_name, 12);
            headers.push(format!("{:3} {}", seq, truncated_name));
        }

        Ok(())
    }

    fn process_tasks(
        &mut self, 
        sequence_counter: &mut usize,
        headers: &[String],
        data: &mut Vec<Vec<String>>
    ) -> std::io::Result<()> {
        let max_rows = self.get_max_tasks_count()?;
        
        // Initialize data rows
        for _ in 0..max_rows {
            data.push(vec![String::new(); headers.len()]);
        }

        // Process each column
        for (col_idx, column_path_str) in self.ordered_task_column_list.iter().enumerate() {
            let column_path = Path::new(column_path_str);
            let mut tasks: Vec<(String, PathBuf)> = Vec::new();

            // Collect tasks in current column
            for entry in fs::read_dir(column_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        tasks.push((name.to_string(), path));
                    }
                }
            }

            // Sort tasks
            tasks.sort_by(|(a, _), (b, _)| a.cmp(b));

            // Process each task
            for (row_idx, (task_name, task_path)) in tasks.iter().enumerate() {
                if row_idx >= data.len() {
                    break;
                }

                // Add to path lookup
                self.next_path_lookup_table.insert(*sequence_counter, task_path.clone());

                // Add to data matrix
                let display_text = format!("{:3} {}", 
                    sequence_counter,
                    truncate_string(task_name, 12)
                );
                
                data[row_idx][col_idx] = display_text;

                *sequence_counter += 1;
            }
        }

        Ok(())
    }

    
    /// Gets the maximum number of tasks across all columns
    fn get_max_tasks_count(&self) -> std::io::Result<usize> {
        let mut max_count = 0;
        for column_path_str in &self.ordered_task_column_list {
            let count = fs::read_dir(column_path_str)?
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().is_dir())
                .count();
            max_count = max_count.max(count);
        }
        Ok(max_count)
    }

    /// Prints the current task display (for debugging)
    pub fn print_task_display(&self) {
        for row in &self.task_display_table {
            println!("{}", row);
        }
    }


    fn handle_tui_action(&mut self) -> Result<(), io::Error> { // Now returns Result
        debug_log("app fn handle_tui_action() started");
        
        // self.update_next_path_lookup_table();
                                      
        if self.is_in_team_channel_list() {
            debug_log("is_in_team_channel_list");
            debug_log(&format!("handle_tui_action() current_path: {:?}", self.current_path));
            
            let input = tiny_tui::get_input()?; // Get input here
            if let Ok(index) = input.parse::<usize>() { 
                let item_index = index - 1; // Adjust for 0-based indexing
                if item_index < self.tui_directory_list.len() {
                    let selected_channel = &self.tui_directory_list[item_index];
                    debug_log(&format!("Selected channel: {}", selected_channel)); // Log the selected channel name
                    
                    self.current_path = self.current_path.join(selected_channel);
                    
                    debug_log(&format!("handle_tui_action() New current_path: {:?}", self.current_path)); // Log the updated current path
                    
                    self.graph_navigation_instance_state.current_full_file_path = self.current_path.clone();
                    self.graph_navigation_instance_state.nav_graph_look_read_node_toml(); 

                    // Log the state after loading node.toml
                    debug_log(&format!("handle_tui_action() State after nav_graph_look_read_node_toml: {:?}", self.graph_navigation_instance_state));
                    
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
        debug_log("starting: load_im_messages called"); 
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
                let last_section = extract_last_path_section(&self.current_path);

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

        // Render the message list
        tiny_tui::render_list(
            &self.tui_textmessage_list, 
            &self.current_path,
            &self.graph_navigation_instance_state.agenda_process,
            &self.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
            &self.graph_navigation_instance_state.scope,
            &self.graph_navigation_instance_state.schedule_duration_start_end,
        ); 
    } 
   
    
    fn enter_task_browser(&mut self) {
        debug_log!("task-mode: starting: enter_task_browser");
        if self.current_path.exists() {
            self.load_tasks();
            self.input_mode = InputMode::TaskCommand;
        } else {
            debug_log!("'task_browser' directory not found in current node.");

        }
    }
    // fn handle_task_action(&mut self, input: &str) -> bool { // Return true to exit, false to continue
    //     if input == "q" || input == "quit" {
    //         return true; // Exit task mode
    //     } else if let Ok(selection) = input.parse::<usize>() {
    //         if self.is_at_task_browser_root() { // COLUMN Navigation
    //             // ... (Handle column selection as before)
    //         } else { // TASK Navigation (within a column)
    //             // ... (Handle task selection logic)
    //         }

    //     }
    //     // ... handle other task-related commands
    //     false  // Don't exit task mode by default

    // }
    // fn handle_task_action(&mut self, input: &str) -> bool { // Return true to exit, false to continue
    //     if input == "q" || input == "quit" {
    //         return true; // Exit task mode
    //     } else if let Ok(selection) = input.parse::<usize>() {

    //         if self.is_at_task_browser_root() { // COLUMN Navigation (if at root)
    //             if selection > 0 && selection <= self.tui_directory_list.len() {
    //                 let column_index = selection - 1;
    //                 let column_name = &self.tui_directory_list[column_index];
    //                 self.current_path.push(column_name); // Navigate INTO column directory.
    //                 self.load_tasks(); // Refresh to show tasks within column
    //                 return false; // Stay in task mode, now within a column

    //             } else {
    //                debug_log!("Invalid column selection."); 
    //                return false; // Stay in task mode (invalid input)
    //             }
    //         } else { // TASK Navigation (if within a column)
    //             if selection > 0 && selection <= self.tui_file_list.len() {  //Task selection
    //                 // Get full task path (within current column)
    //                 let task_index = selection - 1; //0-indexed

    //                 //More robust task name extraction:
    //                 let task_name = if let Some(task_entry) = self.tui_file_list.get(task_index) {
    //                     task_entry[3..].trim().to_string() // Extract name, handling potential panics.
    //                 } else {
    //                     String::new() // Handle invalid index gracefully
    //                 };
                    
    //                 if !task_name.is_empty() { // Only proceed if task_name is valid
    //                     let task_path = self.current_path.join(&task_name); 
    //                     self.current_path = task_path; // Set as the new current path

    //                     let node_toml_path = self.current_path.join("node.toml"); //For viewing task details:
    //                     if let Ok(toml_string) = fs::read_to_string(node_toml_path) {
    //                         if let Ok(toml_value) = toml::from_str::<Value>(&toml_string) {
    //                             debug_log!("Task Details:\n{:#?}", toml_value);
    //                         }
    //                     }
    //                     return true; // Exit task mode to view selected task.
    //                 } else {
    //                      debug_log!("Invalid task index or name.");
    //                     return false; // Stay in task mode.
    //                 }
    //             } else {
    //                 debug_log!("Invalid task selection.");
    //                 return false; // Stay in task mode.
    //             }
    //         } // End of TASK Navigation Block (added)
    //     } else if input.starts_with('m') {  // ...  (Message Owner Logic)
    //         // ... (your existing message owner logic)
    //     }
    //     false // Stay in task mode (no recognized input)
    // } // End of handle_task_action (added)
    
    
    fn is_at_task_browser_root(&self) -> bool {
        self.current_path.ends_with("task_browser") && self.tui_file_list.is_empty()
    }

    fn get_current_column_name(&self) -> Option<String> {
        let last_section = extract_last_path_section(&self.current_path);
        if let Some(name) = last_section {
            if name.starts_with('#') {
                Some(name)
            } else { None }
        } else { None }
    }
    
    // fn handle_task_action(&mut self, input: &str) -> bool {  //Returns true to exit Task Mode
    //     if input == "q" || input == "quit" {
    //         return true; //Exit task mode
    //     } else if let Ok(selection) = input.parse::<usize>() {
    //         if selection > 0 && selection <= self.tui_file_list.len() { // Use file_list for tasks now:
    //             let task_index = selection - 1;
    //             let full_task_path = self.get_full_task_path(task_index);
    //             if let Some(path) = full_task_path {
    //                 // Go to selected task node:  Update current_path
    //                 // Note: you'll likely need to update GraphNavigationInstanceState as well to reflect this navigation change.
    //                 // For simplicity here, we'll just print task details.
    //                 self.current_path = path.clone();
    //                 let node_toml_path = path.join("node.toml");
    //                 if let Ok(toml_string) = fs::read_to_string(node_toml_path) {
    //                     if let Ok(toml_value) = toml::from_str::<Value>(&toml_string) {
    //                         debug_log!("Task Details:\n{:#?}", toml_value); //View task details for now.
    //                         // TODO: Actual node navigation and state update here. 
    //                     }
    //                 }
    //                 return true; // Exit task mode to view the task node. 
    //             }
    //         } else {
    //             debug_log!("Invalid task number selection."); // Stay in task mode
    //         }

    //     }  else if input.starts_with('m') {
    //         // Message owner, etc... (other task actions)
    //         if let Some(task_number_str) = input.get(1..) {
    //             if let Ok(task_number) = task_number_str.parse::<usize>() {
    //                 // TODO: Implement message owner logic here (using task_number)
    //                 debug_log!("Message owner of task {} (not implemented yet).", task_number);
    //             } else {
    //                  debug_log!("Invalid task number for message command.");
    //             }
    //         } else {
    //              debug_log!("Invalid message command format.");
    //         }            
    //     }

    //     false // Stay in task mode by default
    // }


    fn get_full_task_path(&self, task_index: usize) -> Option<PathBuf> {
        debug_log("starting get_full_task_path()");
        // Extract data to form a path:
        if let Some(task_entry) = self.tui_file_list.get(task_index) {
            let parts: Vec<&str> = task_entry.split('.').collect(); // Corrected split and collect
            let task_name = parts.last().unwrap_or(&"").trim(); // Ensure this handles empty/invalid input
            let column_index_parts: Vec<&str> = parts[0].split(' ').collect();
            if column_index_parts.len() >= 1 {
                let column_name = column_index_parts[0]; // Ensure this handles empty/invalid input

                let task_path = self.current_path.join(column_name).join(task_name); // Ensure this handles potential path errors
                Some(task_path)
            } else { None }

        } else { None }

    }

fn handle_task_action(&mut self, input: &str) -> bool { // Return true to exit task mode
        // TODO handle 'b' back
        
        if input == "q" || input == "quit" {
            self.input_mode = InputMode::MainCommand; //Switch back to MainCommand mode
            self.current_path.pop(); // Go back to parent directory ("task_browser")
            self.load_tasks();        //Refresh task view at the previous parent level.
            return false;             // Stay in the main loop (don't exit Uma)

        } else if let Ok(selection) = input.parse::<usize>() {
            // ... (Logic for task number handling - See detailed code below)
        } else {
            debug_log!("Invalid task command.");
            // (Optional) Display error message in TUI
        }
        false // Don't exit task mode by default for other commands
    }

    // // still under construction
    // fn handle_task_number_selection(&mut self, selection: usize) -> bool {
    //         if selection > 0 && selection <= self.tui_file_list.len() {
    //             let task_index = selection - 1;
    //             if let Some(task_name) = self.tui_file_list.get(task_index) {
    //                 let task_path = self.current_path.join(task_name);
    //                 self.current_path = task_path;
    
    //                 if self.current_path.join("node.toml").exists() {
    //                     // Correctly handle the Result from load_core_node_from_toml_file:
    //                     match load_core_node_from_toml_file(&self.current_path.join("node.toml")) {
    //                         Ok(this_node_data) => {
    //                             debug_log!("Node data loaded:\n{:#?}", this_node_data); // Or display in TUI
    //                             // ... (Code to display node data in a dedicated view)...
    //                         }
    //                         Err(e) => {
    //                             debug_log!("Error loading node data: {}", e);
    //                             // ... (Error handling, e.g., display error message in TUI) ...
    //                         }
    //                     }
    //                 }
    //                 return true; // Exit task mode to view/edit task
    //             } else {
    //                 debug_log!("Invalid task number.");
    //             }
    //         }
    //         false // Stay in task mode if invalid input
    //     }
    
    
    
    /// headers/columns = directories with names starting with int and underscore such as 1_plan 2_started 3_done
    /// the number and underscore should be removed
    /// the number should be used as the header/column number
    /// for MVP each directory-name in side each column-directory becomes a row-item in that column
    /// e.g. if 1_plan contains a directory called "report" then given report a sequential number
    /// and list it under the header "plan" 
    /// results sent to display_table() as function or as method
    fn load_tasks(&mut self) {
        debug_log!("task-mode: starting: tasks app: load_tasks");
        self.tui_directory_list.clear(); // Clear directories
        self.tui_file_list.clear();  // Clear files

        let task_browser_dir = &self.current_path;

        if self.is_at_task_browser_root() {
            

            // // app.update_task_display()?;
            // let (headers, data) = self.update_task_display()?;
            // debug_log!(
            //     "headers -> {:?} data -> {:?}", 
            //      headers,
            //      data,
            // );
            // tiny_tui::display_table(&headers, &data);
            
            
            // // Column display at root (corrected logic)
            // let mut column_names = Vec::new();
            // let mut column_data = Vec::new();

            // // read and use dir, not make new dir
            // if let Ok(entries) = fs::read_dir(task_browser_dir) {
            //     let mut numbered_entries = Vec::new();  //Corrected type
            //     // Find numbered task directories first:
            //     for entry in entries.flatten() {
            //         if entry.path().is_dir() && entry.file_name().to_string_lossy().starts_with(|c: char| c.is_ascii_digit()) {  // Numbered directories
            //             numbered_entries.push(entry);
            //         }
            //     }

            //     // Sort the directory entries by their leading number to ensure they are processed in the correct order
            //     numbered_entries.sort_by_key(|entry| {
            //         // Attempt to parse the filename as an integer, or use 0 if the filename cannot be parsed correctly.
            //         entry.file_name().to_string_lossy().chars().next().and_then(|c| c.to_digit(10)).unwrap_or(0) as u32
            //     });
                
            //     for entry in numbered_entries {
            //         let column_name = entry.file_name().to_string_lossy().to_string();  // Keep the full column name
            //         debug_log!(
            //             "task-mode: starting: tasks app: load_tasks: this_col_name -> {:?}", 
            //             column_name
            //         );                    
            //         column_names.push(column_name.clone());  //Corrected to push strings

            //         let mut column_tasks = Vec::new();                    
            //         if let Ok(tasks) = fs::read_dir(entry.path()) {
            //             for task in tasks.flatten() {
            //                 if task.path().is_dir() { // Tasks are directories inside columns
            //                     debug_log!(
            //                         "task-mode: starting: tasks app: load_tasks: load_tasks this_task_name -> {:?}", 
            //                         task.file_name().to_string_lossy(),
            //                     );                    
            //                     column_tasks.push(task.file_name().to_string_lossy().to_string()); //Correct type here
            //                 }
            //             }
            //         }
            //         column_data.push(column_tasks); 
            //     }                
            // } else {
            //      debug_log!("'task_browser' directory not found."); // Add a more specific debug log message.
            // }
            // // Transpose the data for display_table:
            // debug_log!(
            //     "task-mode: starting: tasks app: load_tasks: column_data -> {:?}", 
            //     column_data
            // );            
            // debug_log!("task-mode: starting: tasks app: load_tasks: column_names -> {:?}", column_names);
            // let transposed_data = tiny_tui::transpose_table_data(&column_data);

            // debug_log!("task-mode: starting: tasks app: load_tasks: column_names -> {:?}", column_names);

            // // tiny_tui::display_table(
            // //     &column_names, // Now pushing correct String values
            // //     &transposed_data,
            // // );
            
            

            // Version 2: More detailed error handling
            match self.update_task_display() {
                Ok((headers, data)) => {
                    if headers.is_empty() {
                        debug_log("Warning: No headers found in task display");
                        tiny_tui::render_tasks_list(
                            &["No Tasks".to_string()], 
                            &Vec::new(),
                            &self.current_path,
                        );
                    } else {
                        // pub fn render_tasks_list(headers: &[String], data: &[Vec<String>], current_path: &Path) {
                        tiny_tui::render_tasks_list(
                            &headers, 
                            &data, 
                            &self.current_path,
                        );
                        
                        
                    }
                },
                Err(e) => {
                    debug_log(&format!("Error updating task display: {}", e));
                    // Show error message in table format
                    tiny_tui::render_tasks_list(
                        &["Error".to_string()],
                        &vec![vec![format!("Failed to load tasks: {}", e)]],
                        &self.current_path
                    );
                }
            }

        } else { // Inside a column
             // ... (task display within a column remains the same)
            let mut file_list = Vec::new();

            //Iterate through tasks and add to file_list (no column header)
            if let Ok(entries) = read_dir(task_browser_dir) {
                for (i, entry) in entries.flatten().enumerate() {
                    if entry.file_type().unwrap().is_dir() {  // Check for directories
                        file_list.push(format!("{}. {}", i + 1, entry.file_name().to_string_lossy().to_string())); //Corrected type here
                    }
                }
            } else {
                // ... handle errors
            }

            // Render the list using the correct parameters:
            tiny_tui::render_list(
                &file_list,      // Pass the file list
                &self.current_path, //Pass the current path
                &self.graph_navigation_instance_state.agenda_process,
                &self.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                &self.graph_navigation_instance_state.scope,
                &self.graph_navigation_instance_state.schedule_duration_start_end,
            );
        }
    }
    

    // fn load_tasks(&mut self) {
    //     debug_log("task-mode: starting: tasks app: load_tasks");
    //     self.tui_directory_list.clear();
    //     self.tui_file_list.clear();

    //     let task_browser_dir = &self.current_path;

    //     if self.is_at_task_browser_root() {
    //         // Column display at root
    //         let mut column_names = Vec::new();
    //         let mut column_data = Vec::new();

    //         if let Ok(entries) = fs::read_dir(task_browser_dir) {
    //             for entry in entries.flatten() {
    //                 if entry.path().is_dir() && entry.file_name().to_string_lossy().starts_with("#_") {
    //                     let column_name = entry.file_name().to_string_lossy()[2..].to_string();
    //                     column_names.push(column_name.clone());

    //                     let mut column_tasks = Vec::new();
    //                     if let Ok(tasks) = fs::read_dir(entry.path()) {
    //                         for task in tasks.flatten() { // No need for enumerate here
    //                             if task.path().is_dir() {
    //                                 column_tasks.push(task.file_name().to_string_lossy().to_string());
    //                             }
    //                         }
    //                     }
    //                     column_data.push(column_tasks);
    //                 }
    //             }
    //         }
    //         // Transpose the data for display_table:
    //         debug_log!(
    //             "task-mode: starting: tasks app: load_tasks: column_data -> {:?}", 
    //             column_data
    //         );
    //         let transposed_data = tiny_tui::transpose_table_data(&column_data);

    //         tiny_tui::display_table(
    //             &column_names, // No need for iter().map()... here
    //             &transposed_data,
    //         );
    //     } else {
    //         // ... (task display within a column remains the same)
    //     }
    // }
    
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



// /// Serializes collaborator data to a TOML string, handling the `user_salt_list` manually.
// ///
// /// This function serializes a `CollaboratorTomlData` instance to a TOML-formatted string.
// /// It handles the `user_salt_list` field manually to ensure the correct hexadecimal string
// /// representation with "0x" prefixes and enclosing double quotes.  It uses the `toml` crate
// /// for serializing other fields.
// ///
// /// # Arguments
// ///
// /// * `collaborator`: A reference to the `CollaboratorTomlData` instance to serialize.
// ///
// /// # Returns
// ///
// /// * `Result<String, ThisProjectError>`:  The serialized TOML string on success, or a
// ///    `ThisProjectError` if an error occurs (e.g., during formatting or TOML serialization
// ///     of other fields).
// ///
// fn serialize_collaborator_to_toml(collaborator: &CollaboratorTomlData) -> Result<String, ThisProjectError> {
//     let mut toml_string = String::new();

//     // Manually serialize user_name:
//     toml_string.push_str(&format!("user_name = \"{}\"\n", collaborator.user_name));

//     // Custom serialization for user_salt_list:
//     toml_string.push_str("user_salt_list = [\n");
//     for salt in &collaborator.user_salt_list {
//         StdFmtWrite!(toml_string, "    \"0x{:x}\",\n", salt).map_err(|_| ThisProjectError::InvalidData("Formatting error".into()))?;
//     }
//     toml_string.push_str("]\n");

//     // Use toml crate for other fields (assuming they serialize correctly):
//     // ipv4_addresses and ipv6_addresses need special handling within the toml crate.
//     serialize_ip_addresses(&mut toml_string, "ipv4_addresses", &collaborator.ipv4_addresses)?;
//     serialize_ip_addresses(&mut toml_string, "ipv6_addresses", &collaborator.ipv6_addresses)?;
//     toml_string.push_str(&format!("gpg_publickey_id = \"{}\"\n", collaborator.gpg_publickey_id));
//     toml_string.push_str(&format!("gpg_key_public = \"{}\"\n", collaborator.gpg_key_public));
//     toml_string.push_str(&format!("sync_interval = {}\n", collaborator.sync_interval));
//     toml_string.push_str(&format!("updated_at_timestamp = {}\n", collaborator.updated_at_timestamp));

//     Ok(toml_string)
// }

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

impl CollaboratorTomlData {
    fn new(
        user_name: String, 
        user_salt_list: Vec<u128>, // Take ownership of user_salt_list
        ipv4_addresses: Option<Vec<Ipv4Addr>>,
        ipv6_addresses: Option<Vec<Ipv6Addr>>,
        gpg_publickey_id: String,
        gpg_key_public: String, 
        sync_interval: u64,
        updated_at_timestamp: u64,
    ) -> CollaboratorTomlData {
        debug_log!("CollaboratorTomlData.new: user_salt_list {:?}", user_salt_list);
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
    
    debug_log!("user_name {:?}", user_name);
    debug_log!("user_salt_list {:?}", &user_salt_list);
    debug_log!("ipv4_addresses {:?}", ipv4_addresses);
    debug_log!("ipv6_addresses {:?}", ipv6_addresses);
    debug_log!("gpg_publickey_id {:?}", &gpg_publickey_id);
    debug_log!("gpg_key_public {:?}", &gpg_key_public);
    debug_log!("sync_interval {:?}", sync_interval);   
    debug_log!("updated_at_timestamp {:?}", updated_at_timestamp); 
    
    // print-log stops here.
    // so maybe let collaborator = CollaboratorTomlData::new( is failing
    
    // likely failing
    // Create the CollaboratorTomlData instance using the existing new() method:
    
    // let collaborator = CollaboratorTomlData::new(
    //     user_name, 
    //     user_salt_list,          // Empty vector for user_salt_list
    //     ipv4_addresses,                // None for ipv4_addresses
    //     None,                // None for ipv6_addresses
    //     "".to_string(),      // Empty string for gpg_publickey_id
    //     "".to_string(),      // Empty String for gpg_key_public
    //     sync_interval,                   // 0 for sync_interval
    //     updated_at_timestamp,                   // 0 for updated_at_timestamp
    // );
    // debug_log!("printing collaborator: {:?}", collaborator);
    
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
    
    debug_log!("collaborator {:?}", collaborator);

    // Serialize the data:
    // let toml_string = toml::to_string(&collaborator).map_err(|e| {
    //     std::io::Error::new(
    //         std::io::ErrorKind::Other,
    //         format!("TOML serialization error: {}", e),
    //     )
    // })?;
    
    
    
    match serialize_collaborator_to_toml(&collaborator) {
        Ok(toml_string) => {
            println!("Serialized TOML:\n{}", toml_string);

            // Write the TOML string to a file (example file path)
            // match write_toml_to_file("collaborator_data.toml", &toml_string) {
            //     Ok(_) => println!("TOML data written to file successfully."),
            //     Err(e) => println!("Error writing to file: {}", e),
            // }
            debug_log!("toml_string {:?}", toml_string);
        
            // Construct the file path:
            let file_path = Path::new("project_graph_data/collaborator_files_address_book")
                .join(format!("{}__collaborator.toml", collaborator.user_name));
        
            // Log the constructed file path:
            debug_log!("Attempting to write collaborator file to: {:?}", file_path); 
            
            // Create the file and write the data:
            let mut file = File::create(file_path.clone())?;
            file.write_all(toml_string.as_bytes())?;

        }
        Err(e) => println!("Error serializing to TOML: {}", e),
    }
    
     // // Check for potential errors during file creation:
     // match File::create(&file_path) {
     //     Ok(mut file) => {
     //         debug_log!("File creation succeeded.");

     //         // Check for errors while writing to the file: 
     //         match file.write_all(toml_string.as_bytes()) {
     //             Ok(_) => { 
     //                 debug_log!("Collaborator file written successfully."); 
     //             },
     //             Err(err) => {
     //                 debug_log!("Error writing data to collaborator file: {:?}", err);
     //                 // Consider returning the error here for more explicit error handling
     //                 // return Err(err);
     //             }
     //         } 
     //     },
     //     Err(err) => {
     //         debug_log!("Error creating collaborator file: {:?}", err);
     //         // Return the error here to propagate it
     //         return Err(err); 
     //     }
     // } 
    
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
    active_team_channel: String, 
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
    current_node_unique_id: Vec<u8>,
    current_node_members: Vec<String>,
    home_square_one: bool,
    // from task fields:
    // project module items as task-ish thing
    agenda_process: String,
    goals_features_subfeatures_tools_targets: String,
    scope: String,
    schedule_duration_start_end: Vec<u64>, // Vec<u64>,?

    

    
    
    // app.&App,  // TODO really?
}

impl GraphNavigationInstanceState {
    
    /// To read a node toml: See if you want to use load_core_node_from_toml_file() instead.
    ///
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
    fn nav_graph_look_read_node_toml(&mut self) {
        debug_log!(
            "starting nav_graph_look_read_node_toml() self.current_full_file_path -> {:?}, self.active_team_channel.clone() -> {:?}", 
            
            self.current_full_file_path.clone(),
            self.active_team_channel.clone(),
        );

        let node_toml_path = self.current_full_file_path.join("node.toml");
        
        debug_log!(
            "nav_graph_look_read_node_toml() node_toml_path -> {:?}",
            node_toml_path.clone()
        );

        debug_log!(
            "nav_graph_look_read_node_toml() node_toml_path -> {:?}",
            node_toml_path.clone()
        );
        
        // Add more detailed existence checking
        debug_log!("Checking if path exists: {:?}", node_toml_path.exists());
        debug_log!("Checking if path is file: {:?}", node_toml_path.is_file());
        
        // Try to read the file metadata
        match fs::metadata(&node_toml_path) {
            Ok(metadata) => {
                debug_log!("File metadata found: is_file={}, size={}", metadata.is_file(), metadata.len());
            },
            Err(e) => {
                debug_log!("Error reading file metadata: {}", e);
            }
        }

        // Try to open and read the file
        match fs::read_to_string(&node_toml_path) {
            Ok(contents) => {
                debug_log!("Successfully read file, content length: {}", contents.len());
                
                // Load and parse the node.toml file
                let this_node = match load_core_node_from_toml_file(&node_toml_path) { 
                    Ok(node) => node,
                    Err(e) => {
                        debug_log!("ERROR: nav_graph_look_read_node_toml() Failed to load node.toml: {}", e); 
                        return; 
                    }
                };
                
                debug_log!("nav_graph_look_read_node_toml(), this_node -> {:?}", this_node);

                // Check if this is a Team Channel Node using path components
                let is_team_channel = self.current_full_file_path
                    .components()
                    .any(|component| component.as_os_str() == "team_channels");

                if is_team_channel {
                    // Update state for team channel node
                    self.active_team_channel = this_node.node_name.clone();
                    self.current_node_teamchannel_collaborators_with_access = this_node.teamchannel_collaborators_with_access.clone();
                    self.current_node_name = this_node.node_name.clone();
                    self.current_node_owner = this_node.owner.clone();
                    self.current_node_description_for_tui = this_node.description_for_tui.clone();
                    self.current_node_directory_path = this_node.directory_path.clone();
                    self.current_node_unique_id = this_node.node_unique_id;
                    self.home_square_one = false;
                    self.agenda_process = this_node.agenda_process;
                    self.goals_features_subfeatures_tools_targets = this_node.goals_features_subfeatures_tools_targets;
                    self.scope = this_node.scope;
                    self.schedule_duration_start_end = this_node.schedule_duration_start_end;
                } else {
                    debug_log!("nav_graph_look_read_node_toml(), not a team channel node");
                }
            },
            Err(e) => {
                debug_log!("Error reading file: {}", e);
                debug_log!("This directory is not a node. nav_graph_look_read_node_toml() node.toml not found at {:?}. ", node_toml_path);
                return;
            }
        }

        debug_log!("ending: nav_graph_look_read_node_toml()");
}    
    
    // fn nav_graph_look_read_node_toml(&mut self) {
    // debug_log!(
    //     "starting nav_graph_look_read_node_toml() self.current_full_file_path -> {:?}, self.active_team_channel.clone() -> {:?}", 
    //     self.current_full_file_path.clone(),
    //     self.active_team_channel.clone(),
    // );

    // let node_toml_path = self.current_full_file_path.join("node.toml");
    // debug_log!("nav_graph_look_read_node_toml() node_toml_path -> {:?}", node_toml_path.clone());

    // // Check if node.toml exists (do this check only once)
    // if !node_toml_path.exists() {
    //     debug_log!("This directory is not a node. nav_graph_look_read_node_toml() node.toml not found at {:?}. ", node_toml_path);
    //     return;
    // }

    // debug_log!("nav_graph_look_read_node_toml() node.toml found at: {:?}", node_toml_path);

    // // Load and parse the node.toml file
    // let this_node = match load_core_node_from_toml_file(&node_toml_path) { 
    //     Ok(node) => node,
    //     Err(e) => {
    //         debug_log!("ERROR: nav_graph_look_read_node_toml() Failed to load node.toml: {}", e); 
    //         return; 
    //     }
    // };
    
    // debug_log!("nav_graph_look_read_node_toml(), this_node -> {:?}", this_node);

    // // Update current_node_directory_path.txt
    // if let Err(e) = fs::write(
    //     "project_graph_data/session_state_items/current_node_directory_path.txt", 
    //     self.current_full_file_path.to_string_lossy().as_bytes(),
    // ) {
    //     debug_log!("Error nav_graph_look_read_node_toml() writing team channel directory path to file: {}", e);
    // }

    // // Check if this is a Team Channel Node using path components
    // let is_team_channel = self.current_full_file_path
    //     .components()
    //     .any(|component| component.as_os_str() == "team_channels");

    // if is_team_channel {
    //     // Update state for team channel node
    //     self.active_team_channel = this_node.node_name.clone();
    //     self.current_node_teamchannel_collaborators_with_access = this_node.teamchannel_collaborators_with_access.clone();
    //     self.current_node_name = this_node.node_name.clone();
    //     self.current_node_owner = this_node.owner.clone();
    //     self.current_node_description_for_tui = this_node.description_for_tui.clone();
    //     self.current_node_directory_path = this_node.directory_path.clone();
    //     self.current_node_unique_id = this_node.node_unique_id;
    //     self.home_square_one = false;
    //     self.agenda_process = this_node.agenda_process;
    //     self.goals_features_subfeatures_tools_targets = this_node.goals_features_subfeatures_tools_targets;
    //     self.scope = this_node.scope;
    //     self.schedule_duration_start_end = this_node.schedule_duration_start_end;
    // } else {
    //     debug_log!("nav_graph_look_read_node_toml(), not a team channel node");
    // }

    // debug_log!("ending: nav_graph_look_read_node_toml()");
    // }
        
//     fn nav_graph_look_read_node_toml(&mut self) {
        
//         debug_log!(
//             "starting nav_graph_look_read_node_toml() self.current_full_file_path -> {:?}, self.active_team_channel.clone() -> {:?}", 
//             self.current_full_file_path.clone(),
//             self.active_team_channel.clone(),
//         );

//         let node_toml_path = self.current_full_file_path.join("node.toml");
//         debug_log!("nav_graph_look_read_node_toml() node_toml_path -> {:?}", node_toml_path.clone());

//         // 2. Check if node.toml exists 
//         if node_toml_path.exists() { 
//             debug_log!("nav_graph_look_read_node_toml() node.toml found at: {:?}", node_toml_path);

//             // --- UPDATE current_node_directory_path.txt HERE ---
//             let team_channel_dir_path = self.current_full_file_path.clone(); 
//             if let Err(e) = fs::write(
//                 "project_graph_data/session_state_items/current_node_directory_path.txt", 
//                 team_channel_dir_path.to_string_lossy().as_bytes(), // Convert to byte slice
//             ) {
//                 debug_log!("Error nav_graph_look_read_node_toml() writing team channel directory path to file: {}", e);
//                 // Handle the error appropriately (e.g., display an error message)
//             }

//             // 1. Handle File Existence Error
//             if !node_toml_path.exists() {
//                 debug_log!("This directory is not a node. nav_graph_look_read_node_toml() node.toml not found at {:?}. ", node_toml_path);
//                 return; 
//             }

//             // 2. Handle TOML Parsing Error
//             let this_node = match load_core_node_from_toml_file(&node_toml_path) { 
//                 Ok(node) => node,
//                 Err(e) => {
//                     debug_log!("ERROR: nav_graph_look_read_node_toml() Failed to load node.toml: {}", e); 
//                     return; 
//                 }
//             };
            
//             debug_log!("nav_graph_look_read_node_toml(), this_node -> {:?}", this_node);

//             // 3. Check if this is a Team Channel Node 
//             // TODO maybe also check for a node.toml file
//             let path_components: Vec<_> = self.current_full_file_path.components().collect();

//             if path_components.len() >= 2 
//                 && path_components[path_components.len() - 2].as_os_str() == "team_channels" 
//             {
//                 self.active_team_channel = this_node.node_name.clone();

//                 //maybe also check for a node.toml file
                
//                 // 5. Update GraphNavigationInstanceState with node.toml data (for Team Channel Nodes)
//                 self.current_node_teamchannel_collaborators_with_access = this_node.teamchannel_collaborators_with_access.clone();
//                 self.current_node_name = this_node.node_name.clone();
//                 self.current_node_owner = this_node.owner.clone();
//                 self.current_node_description_for_tui = this_node.description_for_tui.clone();
//                 self.current_node_directory_path = this_node.directory_path.clone();
//                 self.current_node_unique_id = this_node.node_unique_id;
//                 self.home_square_one = false;
//                 // Note: `current_node_members` appears to be unused, consider removing it
//                 self.agenda_process = this_node.agenda_process;
//                 self.goals_features_subfeatures_tools_targets = this_node.goals_features_subfeatures_tools_targets;
//                 self.scope = this_node.scope;
//                 self.schedule_duration_start_end = this_node.schedule_duration_start_end;
//             } // end of if path_components.len() >= 2 
        
//         } else {
//             debug_log("nav_graph_look_read_node_toml(), not a node, no updates");
//         } // End of Team Channel Node Handling
        
//         debug_log!(
//             "ending: nav_graph_look_read_node_toml()");
//     }    

//     fn save_to_session_items(&self) -> Result<(), io::Error> {
//             let session_items_path = Path::new("project_graph_data/session_state_items");

//             // 1. Save simple string values as plain text:
//             fs::write(session_items_path.join("local_owner_user.txt"), &self.local_owner_user)?;
//             fs::write(session_items_path.join("active_team_channel.txt"), &self.active_team_channel)?;
//             // ... (save other simple string values)

//             // 2. Save u64 values as plain text:
//             fs::write(session_items_path.join("default_im_messages_expiration_days.txt"), self.default_im_messages_expiration_days.to_string())?;
//             fs::write(session_items_path.join("default_task_nodes_expiration_days.txt"), self.default_task_nodes_expiration_days.to_string())?;
//             fs::write(session_items_path.join("current_node_unique_id.txt"), pearson_hash_to_hex_string(&self.current_node_unique_id))?;

//             // 3. Save PathBuf as plain text:
//             // fs::write(session_items_path.join("current_full_file_path.txt"), self.current_full_file_path.to_string_lossy())?;
//             // fs::write(session_items_path.join("current_node_directory_path.txt"), self.current_node_directory_path.to_string_lossy())?;
//             fs::write(
//                 session_items_path.join("current_full_file_path.txt"), 
//                 self.current_full_file_path.as_os_str().to_string_lossy().as_bytes(), 
//             )?;
        
//             fs::write(
//                 session_items_path.join("current_node_directory_path.txt"), 
//                 self.current_node_directory_path.as_os_str().to_string_lossy().as_bytes(), 
//             )?; 
            
//             // 4. Save Vec<String> as TOML:
//             let collaborators_toml = toml::to_string(&self.current_node_teamchannel_collaborators_with_access).map_err(|e| {
//                 io::Error::new(
//                     io::ErrorKind::Other,
//                     format!("Failed to serialize collaborators to TOML: {}", e),
//                 )
//             })?;
//             fs::write(session_items_path.join("current_node_teamchannel_collaborators_with_access.toml"), collaborators_toml)?;
            
//             // ... (save other Vec<String> values similarly)

//             Ok(())
//     }

}  // end of impl GraphNav... 

/// Helper function to parse directory name in format "number_name"
fn parse_directory_name(name: &str) -> Option<(usize, &str)> {
    let parts: Vec<&str> = name.splitn(2, '_').collect();
    if parts.len() == 2 {
        if let Ok(num) = parts[0].parse::<usize>() {
            return Some((num, parts[1]));
        }
    }
    None
}

/// Helper function to truncate string to specified length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
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
    /// A unique identifier for the node, generated using pearson hashes of the other fields
    node_unique_id: Vec<u8>,
    /// The path to the directory on the file system where the node's data is stored.
    directory_path: PathBuf,
    /// An order number used to define the node's position within a list or hierarchy.
    // order_number: u32,
    /// The priority of the node, which can be High, Medium, or Low.
    // priority: NodePriority,
    /// The username of the owner of the node.
    owner: String,
    /// The Unix timestamp representing when the node was last updated.
    updated_at_timestamp: u64,
    /// The Unix timestamp representing when the node will expire.
    expires_at: u64,
    /// A vector of `CoreNode` structs representing the child nodes of this node.
    // children: Vec<CoreNode>,
    /// An ordered vector of collaborator usernames associated with this node.
    teamchannel_collaborators_with_access: Vec<String>,
    /// A map containing port assignments for each collaborator associated with the node.
    abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
    
    // project module items as task-ish thing
    agenda_process: String,
    goals_features_subfeatures_tools_targets: String,
    scope: String,
    schedule_duration_start_end: Vec<u64>, 
}



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
///
/// The name of the node. This is used for display and identification.
/// node_name: String,
/// A description of the node, intended for display in the TUI.
/// description_for_tui: String,
/// A unique identifier for the node, generated using a timestamp at node creation.
/// node_unique_id: u64,
/// The path to the directory on the file system where the node's data is stored.
/// directory_path: PathBuf,
/// An order number used to define the node's position within a list or hierarchy.
/// order_number: u32,
/// The priority of the node, which can be High, Medium, or Low.
/// priority: NodePriority,
/// The username of the owner of the node.
/// owner: String,
/// The Unix timestamp representing when the node was last updated.
/// updated_at_timestamp: u64,
/// The Unix timestamp representing when the node will expire.
/// expires_at: u64,
/// A vector of `CoreNode` structs representing the child nodes of this node.
/// children: Vec<CoreNode>,
/// An ordered vector of collaborator usernames associated with this node.
/// teamchannel_collaborators_with_access: Vec<String>,
/// A map containing port assignments for each collaborator associated with the node.
/// abstract_collaborator_port_assignments: HashMap<String, CollaboratorPorts>,
///
impl CoreNode {
    fn new(
        node_name: String,
        description_for_tui: String,
        directory_path: PathBuf,
        owner: String,
        teamchannel_collaborators_with_access: Vec<String>,
        abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
        agenda_process: String,
        goals_features_subfeatures_tools_targets: String,
        scope: String,
        schedule_duration_start_end: Vec<u64>, 
    ) -> Result<CoreNode, ThisProjectError> {
        debug_log!("Starting CoreNode::new");
        debug_log!("Directory path received: {:?}", directory_path);
        debug_log!("Checking if directory exists: {}", directory_path.exists());
        debug_log!("Absolute path: {:?}", directory_path.canonicalize().unwrap_or(directory_path.clone()));

        debug_log!("About to get current timestamp");
        let expires_at = get_current_unix_timestamp() + 11111111111;
        let updated_at_timestamp = get_current_unix_timestamp();
        debug_log!("Got timestamps");

        // 1. Get the salt list using the correct function
        debug_log!("About to get address book data for owner: {}", owner);
        let owner_data = match get_addressbook_file_by_username(&owner) {
            Ok(data) => {
                debug_log!("Successfully got address book data");
                data
            },
            Err(e) => {
                debug_log!("Error getting address book data: {:?}", e);
                return Err(e);
            }
        };
        let salt_list = owner_data.user_salt_list;

        debug_log!("About to calculate node_unique_id");
        // 2. Calculate the hash
        // TODO add new fields
        let node_unique_id = match calculate_corenode_hashes(
            &node_name,
            &description_for_tui,
            updated_at_timestamp,
            &salt_list,
        ) {
            Ok(id) => {
                debug_log!("Successfully calculated node_unique_id");
                id
            },
            Err(e) => {
                debug_log!("Error calculating node_unique_id: {:?}", e);
                return Err(e);
            }
        };
        
        debug_log!("About to create CoreNode instance");
        // 3. Create the CoreNode instance
        let node = CoreNode {
            node_name,
            description_for_tui,
            node_unique_id,
            directory_path,
            owner,
            updated_at_timestamp,
            expires_at,
            teamchannel_collaborators_with_access,        
            abstract_collaborator_port_assignments,
            agenda_process,
            goals_features_subfeatures_tools_targets,
            scope,
            schedule_duration_start_end,
        };
        debug_log!("Successfully created CoreNode instance");

        Ok(node)
    }
// }
    
    // fn new(
    //     node_name: String,
    //     description_for_tui: String,
    //     directory_path: PathBuf,
    //     owner: String,
    //     teamchannel_collaborators_with_access: Vec<String>,
    //     abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
    //     agenda_process: String,
    //     goals_features_subfeatures_tools_targets: String,
    //     scope: String,
    //     schedule_duration_start_end: Vec<u64>, 
    // ) -> Result<CoreNode, ThisProjectError> {
    //     debug_log!("Starting CoreNode::new");
    //     debug_log!("Directory path received: {:?}", directory_path);
    //     debug_log!("Checking if directory exists: {}", directory_path.exists());
    //     debug_log!("Absolute path: {:?}", directory_path.canonicalize().unwrap_or(directory_path.clone()));

    //     // Log all input parameters
    //     debug_log!("input dump: {:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
    //         node_name,
    //         description_for_tui,
    //         directory_path,
    //         owner,
    //         teamchannel_collaborators_with_access,
    //         abstract_collaborator_port_assignments,
    //         agenda_process,
    //         goals_features_subfeatures_tools_targets,
    //         scope,
    //         schedule_duration_start_end
    //     );

    //     debug_log!("About to get current timestamp");
    //     let expires_at = get_current_unix_timestamp() + 11111111111; // Expires in 352 years
    //     let updated_at_timestamp = get_current_unix_timestamp();
    //     debug_log!("Got timestamps");

    //     // 1. Get the salt list, handling potential errors:
    //     debug_log!("About to get salt list for owner: {}", owner);
    //     let salt_list = match get_saltlist_for_collaborator(&owner) {
    //         Ok(list) => {
    //             debug_log!("Successfully got salt list");
    //             list
    //         },
    //         Err(e) => {
    //             debug_log!("Error getting salt list: {:?}", e);
    //             return Err(ThisProjectError::IoError(
    //                 std::io::Error::new(std::io::ErrorKind::NotFound, "Failed to get salt list")
    //             ));
    //         }
    //     };

    //     debug_log!("About to calculate node_unique_id");
    //     // 2. Calculate the hash, using the retrieved salt list:
    //     let node_unique_id = match calculate_corenode_hashes(
    //         &node_name,
    //         &description_for_tui,
    //         updated_at_timestamp,
    //         &salt_list,
    //     ) {
    //         Ok(id) => {
    //             debug_log!("Successfully calculated node_unique_id");
    //             id
    //         },
    //         Err(e) => {
    //             debug_log!("Error calculating node_unique_id: {:?}", e);
    //             return Err(e);
    //         }
    //     };
        
    //     debug_log!("About to create CoreNode instance");
    //     // 3. Create the CoreNode instance:
    //     let node = CoreNode {
    //         node_name,
    //         description_for_tui,
    //         node_unique_id,
    //         directory_path,
    //         owner,
    //         updated_at_timestamp,
    //         expires_at,
    //         teamchannel_collaborators_with_access,        
    //         abstract_collaborator_port_assignments,
    //         agenda_process,
    //         goals_features_subfeatures_tools_targets,
    //         scope,
    //         schedule_duration_start_end,
    //     };
    //     debug_log!("Successfully created CoreNode instance");

    //     Ok(node)
    //     }
    
    // fn new(
    //     node_name: String,
    //     description_for_tui: String,
    //     directory_path: PathBuf,
    //     owner: String,
    //     teamchannel_collaborators_with_access: Vec<String>,
    //     abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
    //     // project state task items
    //     agenda_process: String,
    //     goals_features_subfeatures_tools_targets: String,
    //     scope: String,
    //     schedule_duration_start_end: Vec<u64>, 
    // ) -> Result<CoreNode, ThisProjectError> {
    //     debug_log("Starting CoreNode::new");
    //     debug_log!("Directory path received: {:?}", directory_path);
    //     debug_log!("Checking if directory exists: {}", directory_path.exists());
    //     debug_log!("Absolute path: {:?}", directory_path.canonicalize().unwrap_or(directory_path.clone()));
        
        
    //     debug_log!(
    //         "input dump: {:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
    //         node_name,
    //         description_for_tui,
    //         directory_path,
    //         owner,
    //         teamchannel_collaborators_with_access,
    //         abstract_collaborator_port_assignments,
    //         agenda_process,
    //         goals_features_subfeatures_tools_targets,
    //         scope,
    //         schedule_duration_start_end
    //         );
    //     let expires_at = get_current_unix_timestamp() + 11111111111; // Expires in 352 years
    //     let updated_at_timestamp = get_current_unix_timestamp();

    //     // 1. Get the salt list, handling potential errors:
    //     let salt_list = get_saltlist_for_collaborator(&owner)?; // Use the ? operator to propagate errors

    //     debug_log("starting make node-unique-id");
    //     // 2. *Now* calculate the hash, using the retrieved salt list:
    //     let node_unique_id = calculate_corenode_hashes(
    //         &node_name,            // &str
    //         &description_for_tui,  // &str
    //         updated_at_timestamp,  // u64
    //         &salt_list,            // &[u128]
    //     )?;
        
    //     debug_log!(
    //         "CoreNode::new, node_unique_id{:?}",
    //         node_unique_id
    //     );
        
    //     // // Project State
    //     // let agenda_process: String = "".to_string();
    //     // let goals_features_subfeatures_tools_targets: String = "".to_string();
    //     // let scope: String = "".to_string();
    //     // let schedule_duration_start_end: Vec<u64> = [].to_vec();

    //     // 3. Create the CoreNode instance (all fields now available):
    //     Ok(CoreNode {
    //         node_name,
    //         description_for_tui,
    //         node_unique_id,
    //         directory_path,
    //         owner,
    //         updated_at_timestamp,
    //         expires_at,
    //         teamchannel_collaborators_with_access,        
    //         abstract_collaborator_port_assignments,
    //         agenda_process,
    //         goals_features_subfeatures_tools_targets,
    //         scope,
    //         schedule_duration_start_end,
    //     })
    // }
    
    /// Saves the `CoreNode` data to a `node.toml` file.
    ///
    /// This function serializes the `CoreNode` struct into TOML format and writes 
    /// it to a file at the path specified by the `directory_path` field, creating
    /// the directory if it doesn't exist.
    ///
    /// # Error Handling
    /// 
    /// Returns a `Result<(), io::Error>` to handle potential errors during:
    ///  - TOML serialization
    ///  - Directory creation
    ///  - File writing
    fn save_node_to_file(&self) -> Result<(), io::Error> {
        // Debug logging for initial state
        debug_log!("Starting save_node_to_file");
        debug_log!("Current working directory: {:?}", std::env::current_dir()?);
        debug_log!("Target directory path: {:?}", self.directory_path);
        
        // 1. Verify and create directory structure
        if !self.directory_path.exists() {
            debug_log!("Directory doesn't exist, creating it");
            fs::create_dir_all(&self.directory_path)?;
        }
        debug_log!("Directory now exists: {}", self.directory_path.exists());
        
        // 2. Verify directory is actually a directory
        if !self.directory_path.is_dir() {
            debug_log!("Path exists but is not a directory!");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Path exists but is not a directory"
            ));
        }
        
        // 3. Serialize the CoreNode struct to a TOML string
        let toml_string = toml::to_string(&self).map_err(|e| {
            debug_log!("TOML serialization error: {}", e);
            io::Error::new(
                io::ErrorKind::Other,
                format!("TOML serialization error: {}", e),
            )
        })?;
        debug_log!("Successfully serialized CoreNode to TOML");

        // 4. Construct and verify the file path
        let file_path = self.directory_path.join("node.toml");
        debug_log!("Full file path for node.toml: {:?}", file_path);
        
        // 5. Verify parent directory one more time
        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                debug_log!("Parent directory missing, creating: {:?}", parent);
                fs::create_dir_all(parent)?;
            }
        }

        // 6. Write the TOML data to the file
        debug_log!("Writing TOML data to file...");
        fs::write(&file_path, &toml_string)?;
        
        // 7. Verify the file was created
        if file_path.exists() {
            debug_log!("Successfully created node.toml at: {:?}", file_path);
        } else {
            debug_log!("Warning: File write succeeded but file doesn't exist!");
        }

        Ok(())
    }
        
    // /// Saves the `CoreNode` data to a `node.toml` file.
    // ///
    // /// This function serializes the `CoreNode` struct into TOML format and writes 
    // /// it to a file at the path specified by the `directory_path` field, creating
    // /// the directory if it doesn't exist.
    // ///
    // /// # Error Handling
    // /// 
    // /// Returns a `Result<(), io::Error>` to handle potential errors during:
    // ///  - TOML serialization
    // ///  - Directory creation
    // ///  - File writing
    // fn save_node_to_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_file");
    //     debug_log!("Current directory: {:?}", std::env::current_dir()?);
    //     debug_log!("Target directory path: {:?}", self.directory_path);
    //     debug_log!("Directory exists: {}", self.directory_path.exists());

    //     // 1. Ensure the directory exists first
    //     // Create all parent directories first
    //     fs::create_dir_all(&self.directory_path)?;
    //     debug_log!("Created directory structure: {:?}", self.directory_path);


    //     // 2. Serialize the CoreNode struct to a TOML string
    //     let toml_string = toml::to_string(&self).map_err(|e| {
    //         io::Error::new(
    //             io::ErrorKind::Other,
    //             format!("TOML serialization error: {}", e),
    //         )
    //     })?;

    //     // 3. Construct the full file path for the node.toml file
    //     let file_path = self.directory_path.join("node.toml");
    //     debug_log!("Attempting to save to file path: {:?}", file_path);

    //     // 4. Write the TOML data to the file
    //     fs::write(&file_path, toml_string)?;

    //     debug_log!("Successfully saved node.toml file");
    //     Ok(())
    // }

    // /// Saves the `CoreNode` data to a `node.toml` file.
    // ///
    // /// This function serializes the `CoreNode` struct into TOML format and writes 
    // /// it to a file at the path specified by the `directory_path` field, creating
    // /// the directory if it doesn't exist.
    // ///
    // /// # Error Handling
    // /// 
    // /// Returns a `Result<(), io::Error>` to handle potential errors during:
    // ///  - TOML serialization
    // ///  - Directory creation
    // ///  - File writing
    // fn save_node_to_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_file");
    //     debug_log!("Directory path: {:?}", self.directory_path);

    //     // 1. Ensure the directory exists first
    //     fs::create_dir_all(&self.directory_path).map_err(|e| {
    //         debug_log!("Failed to create directory: {:?}", e);
    //         e
    //     })?;

    //     // 2. Serialize the CoreNode struct to a TOML string
    //     let toml_string = toml::to_string(&self).map_err(|e| {
    //         debug_log!("TOML serialization error: {}", e);
    //         io::Error::new(
    //             io::ErrorKind::Other,
    //             format!("TOML serialization error: {}", e),
    //         )
    //     })?;

    //     // 3. Construct the full file path for the node.toml file
    //     let file_path = self.directory_path.join("node.toml");
    //     debug_log!("Attempting to save to file path: {:?}", file_path);

    //     // 4. Write the TOML data to the file
    //     fs::write(&file_path, toml_string).map_err(|e| {
    //         debug_log!("Failed to write file: {:?}", e);
    //         e
    //     })?;

    //     debug_log!("Successfully saved node.toml file");
    //     Ok(())
    // }
        
        
        
        
    // /// Saves the `CoreNode` data to a `node.toml` file.
    // ///
    // /// This function serializes the `CoreNode` struct into TOML format and writes 
    // /// it to a file at the path specified by the `directory_path` field, creating
    // /// the directory if it doesn't exist.
    // ///
    // /// # Error Handling
    // /// 
    // /// Returns a `Result<(), io::Error>` to handle potential errors during:
    // ///  - TOML serialization.
    // ///  - Directory creation. 
    // ///  - File writing.
    // ///
    // /// If any error occurs, an `io::Error` is returned, containing information 
    // /// about the error. 
    // /// 
    // fn save_node_to_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_file()");

    //     debug_log!("save_node_to_file(), Directory path: {:?}", self.directory_path);
    //     // 1. Serialize the CoreNode struct to a TOML string.
    //     let toml_string = toml::to_string(&self).map_err(|e| {
    //         io::Error::new(
    //             io::ErrorKind::Other,
    //             format!("TOML serialization error: {}", e),
    //         )
    //     })?;

    //     // 2. Construct the full file path for the node.toml file.
    //     let file_path = self.directory_path.join("node.toml");
        
    //     debug_log!("save_node_to_file(), file_path in save_node_to_file {:?}",
    //         file_path,
    //     );

    //     // 3. Create the directory if it doesn't exist. 
    //     if let Some(parent_dir) = file_path.parent() {
    //         fs::create_dir_all(parent_dir)?;
    //     }

    //     // 4. Write the TOML data to the file.
    //     fs::write(&file_path, toml_string).map_err(|e| {
    //         debug_log!("Failed to write file: {:?}", e);
    //         e
    //     })?;

    //     // 5. Return Ok(()) if the save was successful.
    //     debug_log!("Successfully saved node.toml file");
    //     Ok(()) 
    // }
   
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
    // TODO maybe use for something else
    // fn add_child(
    //     &mut self,
    //     teamchannel_collaborators_with_access: Vec<String>, 
    //     abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
    //     owner: String,
    //     description_for_tui: String,
    //     directory_path: PathBuf,
    // ) {
    //     let child = CoreNode::new(
    //         self.node_name.clone(),
    //         description_for_tui,
    //         directory_path,
    //         owner,
    //         teamchannel_collaborators_with_access,        
    //         abstract_collaborator_port_assignments,   
    //     );

    // }
    
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


/// Calculates Pearson hashes for the provided CoreNode fields and salts.
/// This function is now external to CoreNode, taking individual fields as arguments.
///
/// Args:
///     node_name: The node's name.
///     description: The node's description.
///     timestamp: The node's timestamp.
///     salt_list: The list of salts for hashing.
///
/// Returns:
///     Result<Vec<u8>, ThisProjectError>: A vector of calculated hashes, or an error.
fn calculate_corenode_hashes(
    node_name: &str,
    description: &str,
    updated_at_timestamp: u64,
    salt_list: &[u128],
) -> Result<Vec<u8>, ThisProjectError> {
    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(node_name.as_bytes());
    data_to_hash.extend_from_slice(description.as_bytes());
    data_to_hash.extend_from_slice(&updated_at_timestamp.to_be_bytes());

    let mut hash_list = Vec::new();
    for salt in salt_list {
        let mut salted_data = data_to_hash.clone();
        salted_data.extend_from_slice(&salt.to_be_bytes());
        match pearson_hash_base(&salted_data) {
            Ok(hash) => hash_list.push(hash),
            Err(e) => return Err(e.into()),  // Return the error.
        }
    }
    Ok(hash_list)
}



/*
let node_unique_id_str_result = extract_string_from_toml_bytes(received_file_bytes, "node_unique_id");

// Then handle the result...
match node_unique_id_str_result {
    Ok(node_unique_id_str) => {
        // Use the node_unique_id_str
    }
    Err(e) => {
        // Handle error
    }
}
*/
/// Extracts a string value associated with a given key from a TOML-formatted byte slice.
///
/// This function manually parses the byte slice, looking for a line that matches the
/// format `key = "value"`.  It handles cases where the key is not found or the value is
/// not enclosed in double quotes. It does NOT handle TOML arrays or tables.
/// It does NOT depend on the serde or toml crate.
///
/// # Arguments
///
/// * `toml_bytes`: The TOML data as a byte slice.
/// * `key`: The key to search for.
///
/// # Returns
///
/// * `Result<String, ThisProjectError>`: The extracted value or an error.
fn extract_string_from_toml_bytes(toml_bytes: &[u8], key: &str) -> Result<String, ThisProjectError> {
    let toml_str = std::str::from_utf8(toml_bytes).map_err(|_| ThisProjectError::InvalidData("Invalid UTF-8".into()))?;

    for line in toml_str.lines() {
        let line = line.trim();
        if line.starts_with(key) && line.contains('=') {
            let parts: Vec<&str> = line.split('=').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let value = parts[1];
                if value.starts_with('"') && value.ends_with('"') {
                    return Ok(value[1..value.len() - 1].to_string());
                } else {
                    return Err(ThisProjectError::InvalidData("Value not in quotes".into()));
                }
            }
        }
    }
    Err(ThisProjectError::InvalidData(format!("Key '{}' not found", key).into()))
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

    // // 1. Read team channel name using correct function
    // let this_teamchannel_name = match get_current_team_channel_name_from_cwd() { 
    //     Some(name) => name,
    //     None => {
    //         debug_log!("Error: Could not get current channel name in update_collaborator_sendqueue_timestamp_log(). Returning early. Skipping."); // Add log
    //         return Err(ThisProjectError::InvalidData("Could not get team channel name".into())); // Return Error not Ok(0)
    //     }
    // }; 
    // debug_log!(
    //     "update_collaborator_sendqueue_timestamp_log(): team_channel_name ->{}", 
    //     this_teamchannel_name
    // );    

    // let sync_data_dir = PathBuf::from("sync_data")
    //     .join(&this_teamchannel_name)  // Use the read name
    //     .join(collaborator_name);
    
    // // Handle directory creation result:
    // if let Err(e) = fs::create_dir_all(&sync_data_dir) { 
    //     debug_log!("Error creating directories: {}", e);
    //     return Err(e.into()); // Return the error
    // };

    let mut back_of_queue_timestamp = 0;
    let team_channel_path = PathBuf::from("project_graph_data").join(team_channel_name);  // Use the read name

    // 3. Crawl through the team channel directory tree
    for entry in WalkDir::new(team_channel_path) {
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

                    // // 7. Write stub file
                    // let stub_file_path = sync_data_dir.join(timestamp.to_string());
                    // fs::File::create(stub_file_path)?;

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
    
    debug_log!(
        "End of update_collaborator_sendqueue_timestamp_log, back_of_queue_timestamp -> {:?}",
        back_of_queue_timestamp   
    );

    Ok(back_of_queue_timestamp)
}

fn display_simple_tui_table(headers: &[&str], data: &[Vec<&str>]) {
    // Print headers
    for header in headers {
        print!("{:<15} ", header); // Left-align with padding
    }
    println!();

    // Print separator
    println!("{}", "-".repeat(headers.len() * 15));

    // Print data rows
    for row in data {
        for item in row {
            print!("{:<15} ", item);
        }
        println!();
    }
}
// fn main() {
//     let headers = vec!["Column 1", "Column 2", "Column 3"];
//     let data = vec![
//         vec!["Data A", "Data B", "Data C"],
//         vec!["Data D", "Data E", "Data F"],
//     ];
//     display_table(&headers, &data);
// }

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
    
    debug_log!(
        "Starting: load_core_node_from_toml_file(), file_path -> {:?}",
        file_path,
        );
    // 1. Read File Contents 
    let toml_string = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Error lcnftf reading file: {} in load_core_node_from_toml_file", e)),
    };

    // 2. Parse TOML String 
    let toml_value: Value = match toml_string.parse() {
        Ok(value) => value,
        Err(e) => return Err(format!("Error lcnftf parsing TOML in load_core_node_from_toml_file: {}", e)),
    };

    // 3. Extract node_unique_id as hex string and decode using your function:
    // let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_str) {
    //     Some(hex_string) => hex_string_to_pearson_hash(hex_string)?, // Use your function. Propagate error with ?.
    //     None => return Err("error: load_core_node_from_toml_file(), Missing node_unique_id".to_string()),
    // };
    
    // 3. Extract node_unique_id as array
    let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_array) {
        Some(array) => {
            let mut vec = Vec::new();
            for value in array {
                if let Some(num) = value.as_integer() {
                    if num >= 0 && num <= 255 {
                        vec.push(num as u8);
                    } else {
                        return Err("Invalid byte value in node_unique_id".to_string());
                    }
                } else {
                    return Err("Invalid value in node_unique_id array".to_string());
                }
            }
            vec
        },
        None => return Err("Missing or invalid node_unique_id".to_string()),
    };
    
    // 4. Task Items
    let agenda_process = toml_value
        .get("agenda_process")
        .and_then(Value::as_str)
        .ok_or("Missing or invalid agenda_process")?
        .to_string();

    let goals_features = toml_value
        .get("goals_features_subfeatures_tools_targets")
        .and_then(Value::as_str)
        .ok_or("Missing or invalid goals_features_subfeatures_tools_targets")?
        .to_string();

    let scope = toml_value
        .get("scope")
        .and_then(Value::as_str)
        .ok_or("Missing or invalid scope")?
        .to_string();

    let schedule_duration = toml_value
        .get("schedule_duration_start_end")
        .and_then(Value::as_array)
        .ok_or("Missing or invalid schedule_duration_start_end")?
        .iter()
        .map(|v| v.as_integer().ok_or("Invalid integer in schedule_duration"))
        .collect::<Result<Vec<i64>, &str>>()?
        .into_iter()
        .map(|i| i as u64)
        .collect();
    
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

    // 5. Deserialize into CoreNode Struct (Manually)
    let mut core_node = CoreNode {
        node_name: toml_value.get("node_name").and_then(Value::as_str).unwrap_or("").to_string(),
        description_for_tui: toml_value.get("description_for_tui").and_then(Value::as_str).unwrap_or("").to_string(),
        node_unique_id: node_unique_id,
        directory_path: PathBuf::from(toml_value.get("directory_path").and_then(Value::as_str).unwrap_or("")),
        // order_number: toml_value.get("order_number").and_then(Value::as_integer).unwrap_or(0) as u32,
        // priority: match toml_value.get("priority").and_then(Value::as_str).unwrap_or("Medium") {
        //     "High" => NodePriority::High,
        //     "Medium" => NodePriority::Medium,
        //     "Low" => NodePriority::Low,
        //     _ => NodePriority::Medium,
        // },
        owner: toml_value.get("owner").and_then(Value::as_str).unwrap_or("").to_string(),
        updated_at_timestamp: toml_value.get("updated_at_timestamp").and_then(Value::as_integer).unwrap_or(0) as u64,
        expires_at: toml_value.get("expires_at").and_then(Value::as_integer).unwrap_or(0) as u64,
        // children: Vec::new(), // You might need to load children recursively
        teamchannel_collaborators_with_access: toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array).map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
        abstract_collaborator_port_assignments: HashMap::new(),
        agenda_process,
        goals_features_subfeatures_tools_targets: goals_features,
        scope,
        schedule_duration_start_end: schedule_duration,
    };
    
    
    
    // 6. collaborators
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
        recipients_list: Vec<String>,
    ) -> InstantMessageFile {
        let timestamp = get_current_unix_timestamp();
        // Calculate expiration date using the value from local_user_metadata
        let expires_at = timestamp + 
            (graph_navigation_instance_state.default_im_messages_expiration_days * 24 * 60 * 60);
        // let teamchannel_collaborators_with_access = graph_navigation_instance_state.current_node_teamchannel_collaborators_with_access.clone();

        InstantMessageFile {
            owner: owner.to_string(),
            teamchannel_collaborators_with_access: recipients_list,
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

// /// Broken
// /// Creates a new team-channel directory and its associated metadata.
// /// 
// /// This function sets up the basic directory structure and files for a new team channel
// /// within the UMA project graph. It creates the necessary subdirectories and initializes
// /// the `node.toml` file with default values.
// ///
// /// # Arguments
// ///
// /// * `team_channel_name` - The name of the team channel to be created. This name will be used
// ///   for the directory name and in the `node.toml` metadata.
// /// * `owner` - The username of the owner of the team channel.
// ///
// /// TODO: where is the port node system setup here?
// fn create_team_channel(team_channel_name: String, owner: String) {
//     let team_channels_dir = Path::new("project_graph_data/team_channels");
//     let new_channel_path = team_channels_dir.join(&team_channel_name);

//     // 1. Create the team channel directory and subdirectories
//     if !new_channel_path.exists() {
//         fs::create_dir_all(new_channel_path.join("instant_message_browser"))
//             .expect("Failed to create team channel and subdirectories");

//         // 2. Create 0.toml for instant_message_browser with default metadata
//         let metadata_path = new_channel_path.join("instant_message_browser").join("0.toml");
//         let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
//         save_toml_to_file(&metadata, &metadata_path).expect("Failed to create 0.toml"); 
//     }
//     //     /*
//     //     fn new(
//     // TODO update this
//     //     ) -> Node {
//     //     */
    
    
//     // thread 'main' panicked at src/main.rs:4341:14:
//     // REASON: IoError(Os { code: 2, kind: NotFound, message: "No such file or directory" })
//     // 
//     // 3. Create node.toml with initial data for the team channel
//     let new_node = CoreNode::new(
//         team_channel_name.clone(),
//         team_channel_name.clone(),
//         new_channel_path.clone(),
//         // 5,  // depricated
//         // NodePriority::Medium,  // depricated
//         owner,
//         Vec::new(), // Empty collaborators list for a new channel
//         HashMap::new(), // Empty collaborator ports map for a new channel
//     );

//     // new_node.save_node_to_file().expect("Failed to save initial node data"); 
//     new_node.expect("REASON").save_node_to_file().expect("Failed to save initial node data"); 
    
// }


/// Creates a new team-channel directory, subdirectories, and metadata files.
/// Handles errors and returns a Result to indicate success or failure.
///
/// # Arguments
///
/// * `team_channel_name` - The name of the new team channel.
/// * `owner` - The username of the channel owner.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>` - `Ok(())` on success, or a `ThisProjectError`
///   describing the error.
fn create_team_channel(team_channel_name: String, owner: String) -> Result<(), ThisProjectError> {
    debug_log("starting create_team_channel()");
    let team_channels_dir = Path::new("project_graph_data/team_channels");
    let new_channel_path = team_channels_dir.join(&team_channel_name);

    // 1. Create Directory Structure (with error handling)
    fs::create_dir_all(new_channel_path.join("instant_message_browser"))?; // Propagate errors with ?
    fs::create_dir_all(new_channel_path.join("task_browser"))?; // task browser directory
    // for i in 1..=3 { // Using numbers
    //     let col_name = format!("{}_col{}", i, i);
    //     let col_path = new_channel_path.join("task_browser").join(col_name);
    //     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel
    // }    
    let col_name = "1_planning";
    let col_path = new_channel_path.join("task_browser").join(col_name);
    fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

    let col_name = "2_started";
    let col_path = new_channel_path.join("task_browser").join(col_name);
    fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

    let col_name = "3_done";
    let col_path = new_channel_path.join("task_browser").join(col_name);
    fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

    
    // 2. Create and Save 0.toml Metadata (with error handling)
    let metadata_path = new_channel_path.join("instant_message_browser/0.toml"); // Simplified path
    let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
    save_toml_to_file(&metadata, &metadata_path)?; // Use ? for error propagation

    // Generate collaborator port assignments (simplified):
    let mut abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();    

    // Add owner to collaborators list and port assignments:
    // This makes it possible to create CoreNode and ensures the owner has port assignments
    let mut collaborators = Vec::new();
    collaborators.push(owner.clone());
    debug_log!(
        "create_team_channel(): owner 'added' to collaborators {:?}",
        collaborators,
        );

    // let mut rng = rand::thread_rng(); // Move RNG outside the loop for fewer calls

    // Load the owner's data
    // let owner_data = read_one_collaborator_setup_toml(&owner)?;

    // Simplified port generation (move rng outside loop):
    // Assign random ports to owner:  Only owner for new channel.
    let mut rng = rand::thread_rng(); // Move RNG instantiation outside the loop
    let ready_port = rng.gen_range(40000..60000) as u16; // Adjust range if needed
    let tray_port = rng.gen_range(40000..60000) as u16; // Random u16 port number
    let gotit_port = rng.gen_range(40000..60000) as u16; // Random u16 port number
    let abstract_ports_data = AbstractTeamchannelNodeTomlPortsData {
        user_name: owner.clone(), 
        ready_port,
        intray_port: tray_port,
        gotit_port,
    };    
    debug_log!(
        "create_team_channel(): owner's abstract_ports_data created {:?}",
        abstract_ports_data
        );

    // Store in the HashMap with "owner_owner" key. If more than one user this key can become unique.
    // abstract_collaborator_port_assignments.insert(
    //     format!("{}_{}", owner.clone(), owner), // Key derived from collaborator names
    //     vec![ReadTeamchannelCollaboratorPortsToml { collaborator_ports: vec![abstract_ports_data] }],
    // );
    // debug_log!("create_team_channel(): owner 'added' to abstract_collaborator_port_assignments");

    // // // Project State
    // let agenda_process = get_agenda_process()?;
    // let features = get_features_and_goals()?;
    // let scope = get_project_scope()?;
    // let schedule = get_schedule_info()?;
            
// Store in the HashMap with "owner_owner" key. If more than one user this key can become unique.
    abstract_collaborator_port_assignments.insert(
        format!("{}_{}", owner.clone(), owner), // Key derived from collaborator names
        vec![ReadTeamchannelCollaboratorPortsToml { collaborator_ports: vec![abstract_ports_data] }],
    );
    debug_log!("create_team_channel(): owner 'added' to abstract_collaborator_port_assignments");

    // Add debug logs for Project State retrieval
    debug_log!("create_team_channel(): About to get agenda_process");
    let agenda_process = get_agenda_process()?;
    debug_log!("create_team_channel(): Got agenda_process");

    debug_log!("create_team_channel(): About to get features_and_goals");
    let features = get_features_and_goals()?;
    debug_log!("create_team_channel(): Got features_and_goals");

    debug_log!("create_team_channel(): About to get project_scope");
    let scope = get_project_scope()?;
    debug_log!("create_team_channel(): Got project_scope");

    debug_log!("create_team_channel(): About to get schedule_info");
    let schedule = get_schedule_info()?;
    debug_log!("create_team_channel(): Got schedule_info");

    debug_log!("create_team_channel(): About to create CoreNode");
            
    // 3. Create and Save CoreNode (handling Result)
    // node.toml file should be created after the directory structure is in place
    // This is done during first-time initialization so there should be salt list for the owner user (if not exit!)
    debug_log("create_team_channel(): Next is let new_node_result = CoreNode::new");
    
    
    // let new_node_result = CoreNode::new(
    //     team_channel_name.clone(),         // node_name
    //     team_channel_name,                 // description_for_tui
    //     new_channel_path.clone(),          // directory_path
    //     owner,                             // owner
    //     collaborators,                     // teamchannel_collaborators_with_access
    //     abstract_collaborator_port_assignments, // ports
    //     // project state task items
    //     agenda_process,                    // new field: agenda process
    //     features,                          // new field: features and goals
    //     scope,                             // new field: project scope
    //     schedule,                          // new field: schedule 
    // );
    

    // 3. Create and Save CoreNode (handling Result)
    let new_node_result = CoreNode::new(
        team_channel_name.clone(),
        team_channel_name,
        new_channel_path.clone(),
        owner,
        collaborators,
        abstract_collaborator_port_assignments,
        agenda_process,
        features,
        scope,
        schedule,
    );
    
    debug_log!(
        "create_team_channel(): next trying save_node_to_file with new_node_result -> {:?}",
        new_node_result);
    
    // Handle the result
    match new_node_result {
        Ok(new_node) => {
            debug_log!("CoreNode created successfully, attempting to save...");
            new_node.save_node_to_file().map_err(|e| ThisProjectError::IoError(e))?;
            debug_log!("Node saved successfully");
            Ok(())
        }
        Err(e) => {
            debug_log!("Error creating CoreNode: {}", e);
            Err(e)
        }
    }
    

        
        
    // match new_node_result {  // Handle result of CoreNode::new
    //     Ok(new_node) => {
    //         new_node.save_node_to_file()?; // Then save the node
    //         Ok(()) // Return Ok(()) to indicate success
    //     }
    //     Err(e) => {
    //          debug_log!("Error creating CoreNode: {}", e);
    //         Err(e) // Return the error if CoreNode creation fails
    //     }
    // }

}

/// Creates a new (core)Node directory, subdirectories, and metadata files.
/// Handles errors and returns a Result to indicate success or failure.
///
/// # Arguments 
///
/// * `path_to_node` - Base path where the node will be created
/// * `teamchannel_collaborators_with_access` - List of collaborators
/// * `team_channel_name` - Name of the team channel
///
/// # Returns
///
/// * `Result<(), ThisProjectError>` - `Ok(())` on success, or a `ThisProjectError`
fn create_core_node(
    node_path: PathBuf,
    teamchannel_collaborators_with_access: Vec<String>,
    team_channel_name: String,
) -> Result<(), ThisProjectError> {
    debug_log!("start create_core_node(), node_path -> {:?}", node_path);
    
    // Get user input for node name
    println!("Enter node name:");
    let mut node_name = String::new();
    io::stdin().read_line(&mut node_name)?;
    let node_name = node_name.trim().to_string();

    // Get user input for description
    println!("Enter project description:");
    let mut description = String::new();
    io::stdin().read_line(&mut description)?;
    let description = description.trim().to_string();    
    
    // Create the specific node directory path
    let node_specific_path = node_path.join(&node_name);
    debug_log!("Creating node at specific path: {:?}", node_specific_path);

    // Create the main node directory
    fs::create_dir_all(&node_specific_path)?;

    // Get user input for planning fields
    let agenda_process = get_agenda_process()?;
    let features = get_features_and_goals()?;
    let scope = get_project_scope()?;
    let schedule = get_schedule_info()?;
    let owner = get_local_owner_username();

    // Create subdirectories within the node directory
    let message_dir = node_specific_path.join("instant_message_browser");
    let task_browser_dir = node_specific_path.join("task_browser");
    
    fs::create_dir_all(&message_dir)?;
    fs::create_dir_all(&task_browser_dir)?;

    // Create task browser columns
    for col_name in ["1_planning", "2_started", "3_done"].iter() {
        let col_path = task_browser_dir.join(col_name);
        fs::create_dir_all(&col_path)?;
        // TODO: Create column nodes (recursive call for later)
        // create_core_node(col_path, teamchannel_collaborators_with_access.clone(), format!("{}_{}", node_name, col_name))?;
    }

    // Create and Save metadata
    let metadata_path = message_dir.join("0.toml");
    let metadata = NodeInstMsgBrowserMetadata::new(&node_name, owner.clone());
    save_toml_to_file(&metadata, &metadata_path)?;

    // Create CoreNode instance
    let new_node_result = CoreNode::new(
        node_name.clone(),                 // node_name
        description,                       // description_for_tui
        node_specific_path.clone(),        // directory_path
        owner,                             // owner
        teamchannel_collaborators_with_access, 
        HashMap::new(),                    // for ports
        agenda_process,                    // agenda process
        features,                          // features and goals
        scope,                             // project scope
        schedule,                          // schedule information
    );
    
    match new_node_result {
        Ok(new_node) => {
            // Save node.toml in the specific node directory
            new_node.save_node_to_file()?;
            debug_log!("Successfully created node: {:?}", node_specific_path);
            Ok(())
        }
        Err(e) => {
            debug_log!("Error creating CoreNode: {}", e);
            Err(e)
        }
    }
}

// /// Creates a new (core)Node directory, subdirectories, and metadata files.
// /// Handles errors and returns a Result to indicate success or failure.
// ///
// /// # Arguments 
// ///
// /// * `path_to_node` 
// /// * 'teamchannel_collaborators_with_access' from Graph nav struct
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>` - `Ok(())` on success, or a `ThisProjectError`
// fn create_core_node(
//     node_path: PathBuf,
//     teamchannel_collaborators_with_access: Vec<String>,
//     team_channel_name: String,
// ) -> Result<(), ThisProjectError> {
//     debug_log!("start create_core_node(), node_path -> {:?}", node_path);
    
//     // Get user input for planning fields
//     let agenda_process = get_agenda_process()?;
//     let features = get_features_and_goals()?;
//     let scope = get_project_scope()?;
//     let schedule = get_schedule_info()?;
//     let owner = get_local_owner_username();
    
//     // Get user input for description and planning fields
//     println!("Enter project description:");
//     let mut description = String::new();
//     io::stdin().read_line(&mut description)?;
//     let description = description.trim().to_string();    
    
//     // TODO not working, gets uma root only
//     // let team_channel_name = match get_current_team_channel_name_from_cwd() {
//     //     Some(name) => name,
//     //     None => {
//     //         debug_log!("Error: create_core_node(), Could not get current channel name. Skipping.");
//     //         return Err(ThisProjectError::InvalidData("Error: create_core_node(), Could not get team channel name".into()));
//     //     },
//     // };

//     // Create directory structure at the specified path
//     fs::create_dir_all(&node_path.join("instant_message_browser"))?;
//     fs::create_dir_all(&node_path.join("task_browser"))?;

//     let col_name = "1_planning";
//     let col_path = node_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?;

//     let col_name = "2_started";
//     let col_path = node_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?;

//     let col_name = "3_done";
//     let col_path = node_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?;

//     // 2. Create and Save 0.toml Metadata (with error handling)
//     let metadata_path = node_path.join("instant_message_browser/0.toml");
//     let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
//     save_toml_to_file(&metadata, &metadata_path)?;

//     // empty array
//     let abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();

//     // Load the owner's data
//     let owner_data = read_one_collaborator_setup_toml(&owner)?;

//     let mut rng = rand::thread_rng();

//     // 3. Create and Save CoreNode (handling Result)
//     let new_node_result = CoreNode::new(
//         team_channel_name.clone(),         // node_name
//         team_channel_name,                 // description_for_tui
//         node_path.clone(),                 // directory_path
//         owner,                             // owner
//         teamchannel_collaborators_with_access, 
//         HashMap::new(),                    // for ports
//         // project state task items
//         agenda_process,                    // new field: agenda process
//         features,                          // new field: features and goals
//         scope,                             // new field: project scope
//         schedule,                          // new field: schedule information
//     );
    
//     match new_node_result {
//         Ok(new_node) => {
//             new_node.save_node_to_file()?;
//             Ok(())
//         }
//         Err(e) => {
//             debug_log!("Error creating CoreNode: {}", e);
//             Err(e)
//         }
//     }
// }

/// Gets user input for agenda process selection of create_core_node()
fn get_agenda_process() -> Result<String, ThisProjectError> {
    println!("Enter agenda process (default option: Agile, Kahneman-Tversky, Definition-Studies):");
    let mut input = String::new();
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    
    let input = input.trim();
    if input.is_empty() {
        let input: String = "Agile, Kahneman-Tversky, Definition-Studies".to_string();
    }
    
    
    Ok(input.to_string())
}

/// Gets user input for features and goals of create_core_node()
fn get_features_and_goals() -> Result<String, ThisProjectError> {
    println!("Enter project features (comma-separated):");
    let mut features = String::new();
    io::stdin().read_line(&mut features)?;

    println!("Enter user tools needed:");
    let mut tools = String::new();
    io::stdin().read_line(&mut tools)?;

    println!("Enter sub-feature goals:");
    let mut goals = String::new();
    io::stdin().read_line(&mut goals)?;

    Ok(format!("Features: {}\nTools: {}\nGoals: {}", 
        features.trim(), tools.trim(), goals.trim()))
}

/// Gets project scope information of create_core_node()
fn get_project_scope() -> Result<String, ThisProjectError> {
    println!("Is this a stand-alone project or part of larger project? (S/L):");
    let mut project_type = String::new();
    io::stdin().read_line(&mut project_type)?;

    println!("Enter MVP goals:");
    let mut mvp_goals = String::new();
    io::stdin().read_line(&mut mvp_goals)?;

    Ok(format!("Project Type: {}\nMVP Goals: {}", 
        project_type.trim(), mvp_goals.trim()))
}

// /// Gets schedule information and converts 
// /// to required format of create_core_node()
// fn get_schedule_info() -> Result<Vec<u64>, ThisProjectError> {
//     debug_log("starting get_schedule_info()")
//     println!("Enter project duration in days:");
//     let mut days = String::new();
//     io::stdin().read_line(&mut days)?;
//     let days: u64 = days.trim().parse().map_err(|_| 
//         ThisProjectError::InvalidInput("Invalid number of days".into()))?;

//     println!("Enter start year (YYYY):");
//     let mut year = String::new();
//     io::stdin().read_line(&mut year)?;
//     let year: u64 = year.trim().parse().map_err(|_| 
//         ThisProjectError::InvalidInput("Invalid year".into()))?;

//     println!("Enter start month (1-12):");
//     let mut month = String::new();
//     io::stdin().read_line(&mut month)?;
//     let month: u64 = month.trim().parse().map_err(|_| 
//         ThisProjectError::InvalidInput("Invalid month".into()))?;

//     println!("Enter start day (1-31):");
//     let mut day = String::new();
//     io::stdin().read_line(&mut day)?;
//     let day: u64 = day.trim().parse().map_err(|_| 
//         ThisProjectError::InvalidInput("Invalid day".into()))?;

//     let seconds_per_day: u64 = 24 * 60 * 60;
//     let days_since_epoch = (year - 1970) * 365 + ((month - 1) * 30) + (day - 1);
//     let start_timestamp = days_since_epoch * seconds_per_day;
    
//     let duration_seconds = days * seconds_per_day;
//     let end_timestamp = start_timestamp + duration_seconds;

//     Ok(vec![
//         start_timestamp,
//         end_timestamp,
//         duration_seconds
//     ])
// }

/// Gets schedule information and converts 
/// to required format of create_core_node()
fn get_schedule_info() -> Result<Vec<u64>, ThisProjectError> {
    debug_log("starting get_schedule_info()");

    // Duration input and validation
    println!("Enter project duration in days:");
    let mut days = String::new();
    io::stdin().read_line(&mut days)?;
    let days: u64 = days.trim().parse().map_err(|_| 
        ThisProjectError::InvalidInput("Invalid number of days".into()))?;
    debug_log!("Parsed days: {}", days);
    
    if days == 0 || days > 3650 { // 10 years max
        return Err(ThisProjectError::InvalidInput("Duration must be between 1 and 3650 days".into()));
    }

    // Year input and validation
    println!("Enter start year (YYYY):");
    let mut year = String::new();
    io::stdin().read_line(&mut year)?;
    let year: u64 = year.trim().parse().map_err(|_| 
        ThisProjectError::InvalidInput("Invalid year".into()))?;
    debug_log!("Parsed year: {}", year);

    if year < 2023 || year > 2100 {
        return Err(ThisProjectError::InvalidInput("Year must be between 2023 and 2100".into()));
    }

    // Month input and validation
    println!("Enter start month (1-12):");
    let mut month = String::new();
    io::stdin().read_line(&mut month)?;
    let month: u64 = month.trim().parse().map_err(|_| 
        ThisProjectError::InvalidInput("Invalid month".into()))?;
    debug_log!("Parsed month: {}", month);

    if month < 1 || month > 12 {
        return Err(ThisProjectError::InvalidInput("Month must be between 1 and 12".into()));
    }

    // Day input and validation
    println!("Enter start day (1-31):");
    let mut day = String::new();
    io::stdin().read_line(&mut day)?;
    let day: u64 = day.trim().parse().map_err(|_| 
        ThisProjectError::InvalidInput("Invalid day".into()))?;
    debug_log!("Parsed day: {}", day);

    if day < 1 || day > 31 {
        return Err(ThisProjectError::InvalidInput("Day must be between 1 and 31".into()));
    }

    // Time calculations
    let seconds_per_day: u64 = 24 * 60 * 60;
    let days_since_epoch = (year - 1970) * 365 + ((month - 1) * 30) + (day - 1);
    debug_log!("Calculated days since epoch: {}", days_since_epoch);

    let start_timestamp = days_since_epoch * seconds_per_day;
    debug_log!("Calculated start timestamp: {}", start_timestamp);
    
    let duration_seconds = days * seconds_per_day;
    debug_log!("Calculated duration in seconds: {}", duration_seconds);

    let end_timestamp = start_timestamp + duration_seconds;
    debug_log!("Calculated end timestamp: {}", end_timestamp);

    // Final validation
    if end_timestamp < start_timestamp {
        return Err(ThisProjectError::InvalidInput("End time cannot be before start time".into()));
    }

    let result = vec![
        start_timestamp,
        end_timestamp,
        duration_seconds
    ];
    debug_log!("Returning schedule info: {:?}", result);

    Ok(result)
}

// // TODO Under Construction
// /// Creates a new (core)Node directory, subdirectories, and metadata files.
// /// Handles errors and returns a Result to indicate success or failure.
// ///
// /// # Arguments 
// ///
// /// * `team_channel_name` - The name of the new team channel.
// /// * `owner` - The username of the channel owner.
// /// * 'path_to_node' - ?
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>` - `Ok(())` on success, or a `ThisProjectError`
// ///   describing the error.
// fn create_core_node(
//     team_channel_name: String, 
//     owner: String, 
//     // nodepath: PathBuff,
// ) -> Result<(), ThisProjectError> {
//     /*
//     TODO
//     1. integrate path
//     2. 
//     3. Q&A for the planning fields
//     - allow default agenda-process-policy to be:
//     "Agile, Kahneman-Tversky, Definiition-Studies"
//     - ask for user-features, speicifc user-tools,
//     and sub-feature goals
//     - scope...
//     1. stand-alone or part of larger project
//     2. MVP goals
//     3. 
//     - ask person for 'days' convert that duration
//     to seconds 
//     - ask person for start perhaps year month day
//     (could be three questions) convert that
//     to posix time and use duration to get the
//     finish-date
//     4. add planning fields to corenode new impl fn
//         impl CoreNode {
        
//             fn new(
            
            
//     // project module items as task-ish thing
//     agenda_process: String,
//     goals_features_subfeatures_tools_targets: String,
//     scope: String,
//     schedule_duration_start_end: Vec<u64>, // Vec<u64>,?
    
//     */
//     let team_channels_dir = Path::new("project_graph_data/team_channels");
//     let new_channel_path = team_channels_dir.join(&team_channel_name);

//     // 1. Create Directory Structure (with error handling)
//     fs::create_dir_all(new_channel_path.join("instant_message_browser"))?; // Propagate errors with ?
//     fs::create_dir_all(new_channel_path.join("task_browser"))?; // task browser directory
//     // for i in 1..=3 { // Using numbers
//     //     let col_name = format!("{}_col{}", i, i);
//     //     let col_path = new_channel_path.join("task_browser").join(col_name);
//     //     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel
//     // }

//     let col_name = "1_planning";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

//     let col_name = "1_started";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

//     let col_name = "3_done";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

    
//     // 2. Create and Save 0.toml Metadata (with error handling)
//     let metadata_path = new_channel_path.join("instant_message_browser/0.toml"); // Simplified path
//     let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
//     save_toml_to_file(&metadata, &metadata_path)?; // Use ? for error propagation

//     // Generate collaborator port assignments (simplified):
//     let mut abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();    

//     // Add owner to collaborators list and port assignments:
//     // This makes it possible to create CoreNode and ensures the owner has port assignments
//     let mut collaborators = Vec::new();
//     collaborators.push(owner.clone());
//     debug_log!("create_team_channel(): owner 'added' to collaborators");

//     // let mut rng = rand::thread_rng(); // Move RNG outside the loop for fewer calls

//     // Load the owner's data
//     let owner_data = read_one_collaborator_setup_toml(&owner)?;

//     // Simplified port generation (move rng outside loop):
//     // Assign random ports to owner:  Only owner for new channel.
//     let mut rng = rand::thread_rng(); // Move RNG instantiation outside the loop
    
//     // let ready_port = rng.gen_range(40000..60000) as u16; // Adjust range if needed
//     // let tray_port = rng.gen_range(40000..60000) as u16; // Random u16 port number
//     // let gotit_port = rng.gen_range(40000..60000) as u16; // Random u16 port number
//     // let abstract_ports_data = AbstractTeamchannelNodeTomlPortsData {
//     //     user_name: owner.clone(), 
//     //     ready_port,
//     //     intray_port: tray_port,
//     //     gotit_port,
//     // };    
//     // debug_log!("create_team_channel(): owner's abstract_ports_data created");


//     // // Store in the HashMap with "owner_owner" key. If more than one user this key can become unique.
//     // abstract_collaborator_port_assignments.insert(
//     //     format!("{}_{}", owner.clone(), owner), // Key derived from collaborator names
//     //     vec![ReadTeamchannelCollaboratorPortsToml { collaborator_ports: vec![abstract_ports_data] }],
//     // );
//     // debug_log!("create_team_channel(): owner 'added' to abstract_collaborator_port_assignments");


//     // 3. Create and Save CoreNode (handling Result)
//     // node.toml file should be created after the directory structure is in place
//     // This is done during first-time initialization so there should be salt list for the owner user (if not exit!)
//     let new_node_result = CoreNode::new(
//         team_channel_name.clone(),         // node_name
//         team_channel_name,                 // description_for_tui
//         new_channel_path.clone(),          // directory_path
//         owner,                             // owner
//         collaborators,                    // teamchannel_collaborators_with_access
//         HashMap::new(), // for ports
//     );
    
//     match new_node_result {  // Handle result of CoreNode::new
//         Ok(new_node) => {
//             new_node.save_node_to_file()?; // Then save the node
//             Ok(()) // Return Ok(()) to indicate success
//         }
//         Err(e) => {
//              debug_log!("Error creating CoreNode: {}", e);
//             Err(e) // Return the error if CoreNode creation fails
//         }
//     }

// }


/// Recursively moves all contents from the source directory to the destination directory.
/// Deletes the source directory if it is empty after moving all its contents.
/// use std::fs;
/// use std::path::Path;
///
/// e.g. 
/// // Call the function to move the directory
/// if let Err(error) = move_directory__from_path_to_path("path/to/old/directory", "path/to/new/directory") {
///     eprintln!("An error occurred: {}", error);
/// }
fn move_directory__from_path_to_path<SourceDirectory: AsRef<Path>, DestinationDirectory: AsRef<Path>>(
    source_directory: SourceDirectory,
    destination_directory: DestinationDirectory,
) -> std::io::Result<()> {
    let source_path = source_directory.as_ref();
    let destination_path = destination_directory.as_ref();

    // Iterate through all entries in the source directory
    for entry_result in fs::read_dir(source_path)? {
        let entry = entry_result?;
        let file_type = entry.file_type()?;

        // If the entry is a directory, create it in the destination directory and move its contents
        if file_type.is_dir() {
            fs::create_dir_all(destination_path.join(entry.file_name()))?;
            move_directory__from_path_to_path(entry.path(), destination_path.join(entry.file_name()))?;
        }
        // If the entry is a file, move it to the destination directory
        else {
            fs::rename(entry.path(), destination_path.join(entry.file_name()))?;
        }
    }

    // Remove the source directory if it is empty
    fs::remove_dir(source_path)?;
    Ok(())
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
    let clearsign_output = StdCommand::new("gpg")
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
    let mut gpg = StdCommand::new("gpg")
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
    let mut child = StdCommand::new("gpg")
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

// /// save for every member with access in channel...
// fn write_newfile_sendq_flag(
//     recipients_list: Vec<String>,
//     file_path: Path,
// ) {
//     team_channel_name = get_current_team_channel_name_from_cwd();
//     // e.g. sync_data/teamtest/new_file_path_flags/bob}
    
//     // // maybe iterate through recipients_list

//     // 1. make paths (for each participant in list)
//     // make parent path if not yet exists
    
//     // 2. save files to paths

// }



/// Writes a new file send queue flag for each recipient in the given list.
///
/// Creates a flag file for each recipient in the `recipients_list` under the directory:
/// `sync_data/{team_channel_name}/sendqueue_updates/{recipient_name}/{timestamp_flagfile_name}.txt`,
/// where `filename` is the sanitized filename of `file_path`.
///
/// # Arguments
///
/// * `recipients_list`: A vector of recipient usernames.
/// * `file_path`: The path to the file to be added to the send queue.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a `ThisProjectError` if an error occurs during directory or file creation.
fn write_newfile_sendq_flag(
    recipients_list: &[String], // Use a slice for efficiency
    file_path: &Path, // Use a reference to avoid unnecessary cloning
) -> Result<(), ThisProjectError> {
    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

    let timestamp_flagfile_name = get_current_unix_timestamp();

    for recipient in recipients_list {
        let mut flag_path = PathBuf::from("sync_data");
        flag_path.push(&team_channel_name);
        flag_path.push("sendqueue_updates");
        flag_path.push(recipient);
        flag_path.push(format!("{}.txt", timestamp_flagfile_name));

        if let Some(parent_dir) = flag_path.parent() {
            create_dir_all(parent_dir)?;
        }

        let file_path_string = file_path.to_string_lossy(); // For writing to the flag file

        // Create flag file (empty file acts as a flag). Handle potential errors.
        match File::create(&flag_path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(file_path_string.as_bytes()) {
                    debug_log!(
                        "write_newfile_sendq_flag(): Error writing file path to flag file: {}",
                        e
                    );
                    return Err(e.into());  // Or handle error appropriately
                } else {
                    debug_log!("write_newfile_sendq_flag(): Flag file created: {:?} contents: {:?}", flag_path, file_path_string);
                    
                }
            },
            Err(e) => {
                debug_log!(
                    "write_newfile_sendq_flag(): Error creating flag file: {}",
                    e
                );
                return Err(e.into());
            }
        }                
    }
    Ok(())
}

/// Reads all new file send queue flags and cleans up the flag files.
///
/// This function reads all flag files in the directory
/// `sync_data/{team_channel_name}/sendqueue_updates/{remote_collaborator_name}/`
/// and returns the file paths contained within those flags as a vector.
/// After reading, it deletes all flag files to ensure they are processed only once.
///
/// # Arguments
///
/// * `remote_collaborator_name`: The name of the remote collaborator.
/// * `team_channel_name`: The name of the team channel.
///
/// # Returns
///
/// * `Result<Vec<PathBuf>, ThisProjectError>`: A vector of file paths on success, or a `ThisProjectError` if an error occurs during directory access or file operations.
fn read_all_newfile_sendq_flags_w_cleanup(
    remote_collaborator_name: &str,
    team_channel_name: &str,
) -> Result<Vec<PathBuf>, ThisProjectError> {
    let mut flag_dir = PathBuf::from("sync_data");
    flag_dir.push(team_channel_name);
    flag_dir.push("sendqueue_updates");
    flag_dir.push(remote_collaborator_name);

    let mut file_paths = Vec::new();

    // 1. Read all flag files and collect paths: Check if directory exists
    if flag_dir.exists() { // Only proceed if the directory exists
        match fs::read_dir(&flag_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {  // Flatten to handle potential errors directly
                    let flag_file_path = entry.path();
                    if flag_file_path.is_file() {
                        match fs::read_to_string(&flag_file_path) {
                            Ok(file_path_str) => {
                                let file_path = PathBuf::from(file_path_str.trim()); //Important: trim whitespace!
                                file_paths.push(file_path);
                            }
                            Err(e) => {
                                debug_log!("Error reading flag file: {} - {}", flag_file_path.display(), e);
                                // Choose whether to continue or return an error:
                                return Err(e.into()); // Or continue;
                            }
                        }

                        // 2. Delete the flag file immediately after reading (cleanup): Handle errors
                        if let Err(e) = fs::remove_file(&flag_file_path) {
                            debug_log!("Error removing flag file: {} - {}", flag_file_path.display(), e);
                            // Handle the remove error if needed
                            // return Err(e.into()); // Or continue;
                        }
                    }
                }
            }
            Err(e) => {
                debug_log!(
                    "read_all_newfile_sendq_flags_w_cleanup: Error reading directory: {}",
                    e
                );
                return Err(e.into());
            }
        }


        // // 3. Remove directory if empty:  Handle errors
        // if fs::read_dir(&flag_dir)?.next().is_none() { // Directory is now empty
        //     if let Err(e) = fs::remove_dir(&flag_dir) { // Just remove the directory, not recursively
        //         debug_log!(
        //             "read_all_newfile_sendq_flags_w_cleanup: Error removing empty directory: {}",
        //             e
        //         );
        //         // Handle error, e.g., continue or return
        //         return Err(e.into());  // Or continue;
        //     }
        // }
    }
    

    Ok(file_paths)  // Return Ok with file paths or handle not existing as needed
}


/// Add New Message File
/// 1. create message .toml
/// 2. save .toml to team-channel messages path
/// 3. save that path as 
///
fn add_im_message(
    incoming_file_path: &Path,
    owner: &str,
    text: &str,
    signature: Option<String>,
    graph_navigation_instance_state: &GraphNavigationInstanceState, // Pass local_user_metadata here
) -> Result<(), io::Error> {
    
    // 1. Parse for {to:user} syntax
    let mut recipients_list = graph_navigation_instance_state.current_node_teamchannel_collaborators_with_access.clone();
    if let Some(to_clause) = text.find("{to:") {
        if let Some(end_brace) = text[to_clause..].find('}') {
            let recipient_name = text[to_clause + 4..to_clause + end_brace].trim();
            recipients_list.clear(); // Clear default list: restrict to listed recipient only

            // 2. Check if recipient in team channel list and is not sender.
            if graph_navigation_instance_state.current_node_teamchannel_collaborators_with_access.contains(&recipient_name.to_string()) && recipient_name != owner {
                recipients_list.push(recipient_name.to_string()); // Add only the specified recipient
            } else {
                // Log if user not found
                debug_log!("'to:' but Recipient '{}' not found in channel or is sender.", recipient_name);                
            }
        }
    }

    // separate name and path
    let parent_dir = if let Some(parent) = incoming_file_path.parent() {
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
        recipients_list.clone(),
    );
    let toml_data = toml::to_string(&message).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
    })?; // Wrap TOML error in io::Error
    fs::write(incoming_file_path, toml_data)?;
    
    
    // Write update flag for each possible remote collaborator
    // sync_data/teamtest/new_file_path_flags/bob
    // sync_data/teamtest/new_file_path_flags/charlotte
    // etc.
    write_newfile_sendq_flag(
        &recipients_list,
        &incoming_file_path,
    );
    
    Ok(())
}


/*

// Example usage (in file receiving):

// ... after receiving and decrypting a node file ...

// 1. Create lookup table:
let node_id_to_path = create_node_id_to_path_lookup(&team_channel_path)?;


// 2. Access node data (must match `node_unique_id_str` from `create_node_id_to_path_lookup`):
let node_unique_id_str = received_toml.get("node_unique_id").and_then(Value::as_str).map(|s| s.to_owned()).unwrap_or_default();
if let Some(existing_path) = node_id_to_path.get(&node_unique_id_str) {
    // Node exists, handle move/replace:

    // 3. Remove old node directory
    std::fs::remove_dir_all(existing_path)?;

    // ... (your node saving logic)
} else {
    // Node is new, save it:
    // ... (your node saving logic)

}
*/
/// Creates a lookup table of node unique IDs to their full file paths.
///
/// This function iterates through the team channel directory, identifies node directories (those containing a `node.toml` file),
/// extracts the node's unique ID from the `node.toml`, and stores the ID and full file path in a HashMap.
///
/// # Arguments
///
/// * `team_channel_path`: The path to the team channel directory.
///
/// # Returns
///
/// * `Result<HashMap<String, PathBuf>, ThisProjectError>`:  A HashMap mapping node unique IDs to their paths, or a `ThisProjectError` if an error occurs.
fn create_node_id_to_path_lookup(
    team_channel_path: &Path,
) -> Result<HashMap<String, PathBuf>, ThisProjectError> {
    let mut node_lookup: HashMap<String, PathBuf> = HashMap::new();

    for entry in WalkDir::new(team_channel_path) {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() { // A. Nodes only (directories)
            let node_toml_path = path.join("node.toml");
            if node_toml_path.exists() {
                // Found a node directory
                let toml_string = std::fs::read_to_string(&node_toml_path)?;
                let toml_value: Value = toml::from_str(&toml_string)?;

                // B. Extract node unique ID
                // let node_unique_id = toml_value.get("node_unique_id").and_then(Value::as_integer).unwrap_or(0) as u64;
                
                // Updated to get unique_id as hex_string:
                let node_unique_id_str = toml_value.get("node_unique_id").and_then(Value::as_str).map(|s| s.to_owned()).unwrap_or_default();
                if node_unique_id_str.is_empty() {
                    continue; // Skip this node if no valid ID
                }


                // C. Get full file path
                let full_path = path.to_path_buf();

                // Add to lookup table:
                node_lookup.insert(node_unique_id_str, full_path);
            }
        }
    }

    Ok(node_lookup)
}


// // early alpha, maybe entirely wrong!
// // use std::collections::HashMap;
// // use std::fs::{self, DirEntry, File};  // Import DirEntry and File
// // use std::io;
// // use std::path::{Path, PathBuf};
// // use toml::Value; // Import the Value type
// // // ... other imports (e.g., for your tiny_tui)
// /// t is for task
// fn display_task_browser(current_node_path: &Path) -> bool {
//     let task_browser_dir = current_node_path.join("task_browser");

//     let mut columns: HashMap<String, HashMap<u32, PathBuf>> = HashMap::new();
//     let mut column_entries: Vec<DirEntry> = Vec::new(); // Correct type

//     // 1. Column Discovery and Default Creation
//     if let Ok(entries) = fs::read_dir(&task_browser_dir) {
//         for entry in entries.flatten() {
//             if entry.path().is_dir() && entry.file_name().to_string_lossy().starts_with("#_") {
//                 column_entries.push(entry);
//             }
//         }
//     }


//     // Create default columns if none exist:  Create DirEntry objects
//     if column_entries.is_empty() {
//         for default_col in ["#_plan", "#_started", "#_done"] {
//             let path = task_browser_dir.join(default_col);
//             fs::create_dir_all(&path).expect("Failed to create default column directory");

//             // Manually create DirEntry (workaround for read_dir not returning defaults immediately after creation):
//             let entry = fs::read_dir(&task_browser_dir).unwrap().find(|entry| {
//                 entry.as_ref().unwrap().file_name().to_string_lossy() == default_col
//             }).unwrap(); // safe unwrap inside this specific context.

//             // column_entries.push(entry);
//             column_entries.push(entry.expect("REASON"));
            
//         }
//     }

//     column_entries.sort_by_key(|entry| entry.file_name());

//     // Create HashMap and populate task data
//     for entry in column_entries {
//         let column_name = entry.file_name().to_string_lossy()[2..].to_string(); // Remove "#_"
//         let column_dir = task_browser_dir.join(entry.file_name()); // For task iteration inside this column
//         let mut task_map: HashMap<u32, PathBuf> = HashMap::new();
//         let mut task_counter = 1;

//         // Load tasks for this column:
//         if let Ok(task_entries) = fs::read_dir(column_dir) { 
//             for task_entry in task_entries.flatten() {
//                 if task_entry.path().is_dir() { // tasks are directories, not files
//                     let task_path = task_entry.path(); 
//                     task_map.insert(task_counter, task_path);
//                     task_counter += 1;
//                 }
//             }
//         }

//         columns.insert(column_name, task_map);
//     }

//     // 3. Display and Interaction
//     // ... (Use tiny_tui or other method to display columns and tasks)

//     loop {
//         // ... (Display the task browser TUI using the 'columns' HashMap) ...
//         let input = tiny_tui::get_input().expect("Failed to get input");

//         if let Ok(task_number) = input.parse::<u32>() {
//             // Find the task based on number:
//             for (column_name, task_map) in &columns {
//                 if let Some(task_path) = task_map.get(&task_number) {

//                     //Example: View Task Details
//                     let node_toml_path = task_path.join("node.toml");
//                     let toml_string = fs::read_to_string(node_toml_path).expect("Failed to read TOML");
//                     let toml_value: Value = toml::from_str(&toml_string).expect("Failed to parse TOML");
//                     println!("Task Details:\n{:#?}", toml_value);  //Use {:#?} for pretty print                    
                    
//                     // ... (Handle other task interactions: edit, move, etc.)...
//                     break; // Task found, exit inner loop
//                 }
//             }


//         } else if input.to_lowercase() == "q" || input.to_lowercase() == "quit" {
//              break; //Exit the task browser loop
//         } else {
//             // Handle other commands or invalid input
//              println!("Invalid command or task number.");
//         }
//     }
//     return false;
// }

/// Finds the path to a GPG public key file (`.asc` extension) in the specified directory.
///
/// Returns `Ok(Some(path))` if a `.asc` file is found, `Ok(None)` if no `.asc` file is found,
/// and `Err(_)` if there's an error reading the directory.
fn find_gpg_public_key_file(directory: &Path) -> Result<Option<PathBuf>, ThisProjectError> {
    let entries = fs::read_dir(directory)?;

    for entry in entries {
        let entry = entry?; // Handle potential errors during directory iteration
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "asc") {
            return Ok(Some(path));
        }
    }

    Ok(None) // No .asc file found
}

// fn get_local_owner_user_name() -> String {
//     let uma_toml_path = Path::new("uma.toml");
//     // let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)?; 
//     let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)
//     .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e)))?;
//     let local_owner_username = user_metadata["uma_local_owner_user"].as_str().unwrap().to_string();
    
//     local_owner_username
// }
fn get_local_owner_username() -> String {  // Returns String directly
    debug_log("starting get_local_owner_username()");
    let uma_toml_path = Path::new("uma.toml");

    let toml_string = read_to_string(uma_toml_path).unwrap_or_else(|e| {
        eprintln!("Error reading uma.toml: {}", e); // Log the error
        std::process::exit(1); // Or handle differently, but exit if no config is a show stopper.
    });

    let toml_value: toml::Value = toml::from_str(&toml_string).unwrap_or_else(|e| {
        eprintln!("Error parsing uma.toml: {}", e);
        std::process::exit(1);  // If your application cannot continue without a username...
    });

    toml_value["uma_local_owner_user"]
        .as_str()
        .unwrap_or_else(|| {
            eprintln!("'uma_local_owner_user' not found in uma.toml"); // Handle the error
            std::process::exit(1);
        })
        .to_string()
}

fn export_addressbook() -> Result<(), ThisProjectError> {
    debug_log("start export_addressbook()");

    // 1. Get local owner's username
    // 1. Get local owner's username
    // Read uma_local_owner_user from uma.toml
    // maybe add gpg and make this a separate function TODO
    // Load UMA configuration from uma.toml
    let uma_toml_path = Path::new("uma.toml");
    // let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)?; 
    let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e)))?;
    let local_owner_username = user_metadata["uma_local_owner_user"].as_str().unwrap().to_string();

    // 2. Construct paths
    let address_book_export_dir = PathBuf::from("import_export_invites/addressbook_invite/export");
    let key_file_path = address_book_export_dir.join("key.asc");
    let collaborator_file_path = PathBuf::from("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", local_owner_username));

    // 3. Read public key (early return on error).  Handles NotFound.
    let public_key_string = match read_to_string(&key_file_path) {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug_log!("Public key file ('key.asc') not found. Skipping address book export.");
            return Ok(()); // Return Ok if the file isn't found, not continuing.
        },
        Err(e) => return Err(ThisProjectError::IoError(e)),
    };

    // 4. Clearsign collaborator file
    let clearsign_output = StdCommand::new("gpg")
        .arg("--sign")
        .arg(&collaborator_file_path)
        .output()?;


    // Error handling: (exit early on error)
    if !clearsign_output.status.success() {
        let stderr = String::from_utf8_lossy(&clearsign_output.stderr);
        return Err(ThisProjectError::GpgError(format!("GPG clearsign failed: {}", stderr)));
    }
    let clearsigned_data = clearsign_output.stdout;

    // 5. Encrypt clearsigned data
    let encrypted_data = encrypt_with_gpg(&clearsigned_data, &public_key_string)?;

    // 6. Create export directory if it doesn't exist
    let export_dir = PathBuf::from("import_export_invites/addressbook_invite/export");
    create_dir_all(&export_dir)?;

    // 7. Write encrypted data to file. Use a timestamp to avoid overwriting.
    let export_file_path = export_dir.join(format!(
        "{}_addressbook_{}.gpg",
        local_owner_username,
        get_current_unix_timestamp() // Or use a UUID
    ));
    let mut file = File::create(&export_file_path)?;
    file.write_all(&encrypted_data)?;
    
    debug_log("export complete");

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
/// 
/// ip availability is also read and recorded in sync-state stored
/// as a combined-index that included type data (hopefully works with other signal types too)
/// return true for online, false for offline
fn initialize_uma_application() -> Result<bool, Box<dyn std::error::Error>> {
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
        // remove this unwrap
        
        let owner = owner_input.trim().to_string();

        let local_user_metadata = LocalUserUma::new(owner); // Create LocalUserUma
        
        if let Err(e) = local_user_metadata.save_owner_to_file(&uma_toml_path) { 
            eprintln!("Failed to create uma.toml: {}", e);
            // Handle the error (e.g., exit gracefully) 
            return Ok(false); 
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
            return Ok(false); 
        }
    };

    // Set the uma_local_owner_user from the loaded metadata
    let uma_local_owner_user = user_metadata.uma_local_owner_user;

    // ... 2. Load user metadata from the now-existing uma.toml
    let user_metadata = match toml::from_str::<LocalUserUma>(&fs::read_to_string(uma_toml_path)?) {
        Ok(metadata) => {
            debug_log!("uma.toml loaded successfully!");
            metadata
        },
        Err(e) => {
            eprintln!("Failed to load or parse uma.toml: {}", e); 
            return Ok(false); 
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


    // // Check if the data directory exists
    // let invite_parent_folder = Path::new("import_export_invites");
    // if !invite_parent_folder.exists() {
    //     // If the directory does not exist, create it
    //     fs::create_dir_all(invite_parent_folder).expect("Failed to create import_export_invites directory");
    // }

    // Check if the data directory exists
    let addressbook_invite = Path::new("import_export_invites/addressbook_invite/import");
    if !addressbook_invite.exists() {
        // If the directory does not exist, create it
        fs::create_dir_all(addressbook_invite).expect("Failed to create addressbook_invite directory");
    }

    // Check if the data directory exists
    let addressbook_invite = Path::new("import_export_invites/addressbook_invite/export");
    if !addressbook_invite.exists() {
        // If the directory does not exist, create it
        fs::create_dir_all(addressbook_invite).expect("Failed to create addressbook_invite directory");
    }
    
    // Check if the data directory exists
    let teamchannel_invites = Path::new("import_export_invites/teamchannel_invites/import");
    if !teamchannel_invites.exists() {
        // If the directory does not exist, create it
        fs::create_dir_all(teamchannel_invites).expect("Failed to create teamchannel_invites directory");
    }
    
    // Check if the data directory exists
    let teamchannel_invites = Path::new("import_export_invites/teamchannel_invites/export");
    if !teamchannel_invites.exists() {
        // If the directory does not exist, create it
        fs::create_dir_all(teamchannel_invites).expect("Failed to create teamchannel_invites directory");
    }
    
    // not yet working
    // export_addressbook()?;
    
    
    // TODO
    // look for a file in import_export_invites/addressbook_invite/export
    // try to read it as a gpg key
    // export your addressbook file clearsigned by you and encrypted with the public gpg key in that file
    
    
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
        return Ok(false);
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
        println!("Enter your ascii-armored public GPG key line by line.");
        println!("Then Type 'END'+Enter/Return when finished:");
        println!("get with -> Posix: $ gpg --armor --export YOURKEYID");
        let mut gpg_key_public = String::new();
        loop {
            let mut line = String::new();
            io::stdin().read_line(&mut line).expect("Failed to read line");
            let line = line.trim();
    
            if line == "END" {
                break;
            }
            gpg_key_public.push_str(line);
            gpg_key_public.push('\n'); // Add newline character back
        }
    
        // Remove the trailing newline if it exists
        if gpg_key_public.ends_with('\n') {
            gpg_key_public.pop();
        }
    
        println!("GPG key entered:\n{}", gpg_key_public); // Confirmation (remove in production)
        debug_log("GPG key entered");
        
        // let mut gpg_key_public = String::new();
        // io::stdin().read_line(&mut gpg_key_public).unwrap();
        // let gpg_key_public = gpg_key_public.trim().to_string();

        // // load names of current collaborators to check for collisions: TODO
        // if check_collaborator_name_collision();

        // let mut rng = rand::thread_rng(); 
        
        // let updated_at_timestamp = get_current_unix_timestamp()
        

        // // Salt List!
        debug_log("Salt List");
        // Generate salt list (4 random u128 values)
        let new_usersalt_list: Vec<u128> = (0..4)
            .map(|_| rand::thread_rng().gen())
            .collect();
        
        // println!("Salt List: Press Enter for random, or type 'manual' for manual input");
        // let mut new_usersalt_list_input = String::new();
        // io::stdin().read_line(&mut new_usersalt_list_input)?;
        // let new_usersalt_list_input = new_usersalt_list_input.trim().to_string();
    
        

            
        // let new_usersalt_list: Vec<u128> = if new_usersalt_list_input == "manual" {
        //     let mut salts = Vec::new();
        //     for i in 1..=4 {
        //         println!("Enter salt {} (u128):", i);
        //         let mut salt_input = String::new();
        //         io::stdin().read_line(&mut salt_input)?;
        //         let salt: u128 = salt_input.trim().parse().expect("Invalid input, so using u128 input for salt");
        //         salts.push(salt);
        //     }
        //     salts
        // } else {
        //     // Generate 4 random u128 salts
        //     (0..4)
        //         .map(|_| rand::thread_rng().gen())
        //         .collect()
        // };

        println!("Using salts: {:?}", new_usersalt_list);
        debug_log!("Using salts: {:?}", new_usersalt_list);

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

        debug_log("User added successfully!");
        println!("User added successfully!");
    }

    /////////////////////////////
    // Check & Make Team Channel
    /////////////////////////////
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

        create_team_channel(team_channel_name, uma_local_owner_user.clone());
        }
        
        // TODO
        // maybe check for node file made?

        debug_log("after create_team_channel()");

    
    ////////////////////////////////////////////////////////////////////////// 
    // --- Band: Network Band Finder: IP Validity Check and Flag Setting ---
    /////////////////////////////////////////////////////////////////////////  
    
    // let (ipv4_list, ipv6_list) = load_local_ip_lists(&user_metadata.uma_local_owner_user)?;
    // let (str_ipv4list, str_ipv6list) = load_local_iplists_as_stringtype(&user_metadata.uma_local_owner_user)?;
    
    // // currently only using ipv6
    // let local_user_ipv6_address = find_valid_local_owner_ip_address(
    //     &ipv6_list
    // )
    //     .ok_or(ThisProjectError::NetworkError("No valid local IPv6 address found".to_string()))?;

    // // // Instead of cloning the first address, use the result of the selector:
    // // ipv6_addr_1 = Some(local_user_ipv6_address); // No need to clone or dereference as the variable now directly holds the Ipv6Addr
    // // ipv6_addr_2 = ipv6_addr_1.clone(); // Clone the selected address for ipv6_addr_2 if needed

    // // get index of valid IP v6
    // let ip_index = get_index_byof_ip(
    //     &str_ipv4list,
    //     &str_ipv6list,
    //     &local_user_ipv6_address.to_string(), // as ip_address
    // );

    // debug_log!(
    //     "Found IP/index <{:?} {:?}>", 
    //     local_user_ipv6_address, 
    //     ip_index
    // );
    
    
    // Network Detection or Work Offline?

    

    // Call get_band__find_valid_network_index_and_type to retrieve band info and online status
    let (
        network_found_ok,
        network_type,
        network_index,
        this_ipv4,
        this_ipv6,
    ) = get_band__find_valid_network_index_and_type(&uma_local_owner_user);


    // Handle offline mode if no network connection is found
    if !network_found_ok {  // Check the flag *before* writing/saving values to prevent corrupting or creating bad data from invalid inputs.
        debug_log!("No valid network connection found. Entering offline mode.");
        return Ok(false); // Return false to signal offline mode; do not initialize sync, do not continue processing those invalid or undefined network type and IP values. Halt immediately in this specific scenario and set `network_found_ok` boolean flag to `false` consistent with best practice for what you stated was the desired and specified handling for this exact use-case: halt Uma.
    }


    // set network data state-file(s) in sync_data/ directory:
    if let Err(e) = write_local_band__save_network_band__type_index( // Check if writing to sync data state files fails
        network_type, // network type, as String
        network_index, // network index, as u8
        this_ipv4,  //ipv4, as std::net::Ipv4Addr
        this_ipv6, // ipv6, as std::net::Ipv6Addr
    ) { // then handle that error: do not allow bad values to propagate to other parts of the system, halt uma and or handle in other specified way if this error can occur for other reasons not related to invalid IP retrieval. 
        // Handle error, halt uma or do something else as per your specs if failure to save band configuration is an error distinct from failure to find a valid IP address.
        // e.g. debug_log("Error saving network configuration: {}", e);
        return Err(Box::new(e)); // Or handle the error as needed, including halting Uma with an informative message
    };



    Ok(true) // Indicate online mode only when valid IP data has been obtained, parsed, converted, and written to sync data state files correctly
}

// fn handle_numeric_input(
//     input: &str,
//     app: &mut App,
//     graph_navigation_instance_state: &GraphNavigationInstanceState,
// ) -> Result<bool, Box<dyn std::error::Error>> {
//     if let Ok(index) = input.parse::<usize>() {
//         let item_index = index - 1; // Adjust for 0-based indexing
//         if item_index < app.tui_directory_list.len() {
//             // Special handling for team channels directory
//             if app.current_path.display().to_string() == "project_graph_data/team_channels".to_string() {
//                 let selected_channel = &app.tui_directory_list[item_index];
//                 debug_log(&format!("Selected channel: {}", selected_channel));
                
//                 // Enable sync flag
//                 set_sync_start_ok_flag_to_true();
                
//                 // Update paths
//                 app.current_path = app.current_path.join(selected_channel);
//                 app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
                
//                 // Update navigation state
//                 app.graph_navigation_instance_state.nav_graph_look_read_node_toml();
//             }
//             // Handle regular directory navigation
//             else {
//                 app.current_path = app.current_path.join(&app.tui_directory_list[item_index]);
//             }
//             return Ok(true);
//         }
//     }
//     Ok(false)
// }


fn handle_main_command_mode(
    input: &str, 
    app: &mut App, 
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> Result<bool, io::Error> {
    /*
    For input command mode
    quit
    command-list/legend
    */

    debug_log(&format!("fn handle_main_command_mode(), input->{:?}", input));
    // First, try to handle numeric input
    if let Ok(index) = input.trim().parse::<usize>() {
        let item_index = index - 1; // Adjust for 0-based indexing
        if item_index < app.tui_directory_list.len() {
            // Special handling for team channels directory
            if app.current_path.display().to_string() == "project_graph_data/team_channels".to_string() {
                let selected_channel = app.tui_directory_list[item_index].clone();
                debug_log(&format!("Selected channel: {}", selected_channel));
                
                set_sync_start_ok_flag_to_true();
                
                app.current_path = app.current_path.join(&selected_channel);
                app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
                
                // Simply call the method without trying to handle its result
                app.graph_navigation_instance_state.nav_graph_look_read_node_toml();
            } else {
                // Regular directory navigation
                app.current_path = app.current_path.join(&app.tui_directory_list[item_index]);
            }
            return Ok(false);  // Continue main loop
        }
    }
    // Then handle text commands:
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if let Some(command) = parts.first() {

        match command.to_lowercase().as_str() {
            "h" | "help" => {
                debug_log("Help!");
                // Display help information
            }
            
            "addnode" | "add_node" | "newnode" | "new" | "node" | "task" | "addtask" | "add_task" => {
                debug_log("Command: Add Node");
                
                debug_log!("app.current_path {:?}", app.current_path);
                
                create_core_node(
                    app.current_path.clone(), // node_path: PathBuf,
                    app.graph_navigation_instance_state.current_node_teamchannel_collaborators_with_access.clone(),  // teamchannel_collaborators_with_access: Vec<String>,
                    app.graph_navigation_instance_state.active_team_channel.clone(),
                );
                
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
            "b" | "back" => {
                debug_log("back mode started");
                app.input_mode = InputMode::MainCommand;
                debug_log("changed to command mode");
                
                if app.current_path != PathBuf::from("project_graph_data/team_channels") {
                     // Only move back if not at the root of project_graph_data/team_channels
                    app.current_path.pop();
                    app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone(); // Update full path after popping.
                    app.graph_navigation_instance_state.nav_graph_look_read_node_toml(); // Update internal state too.
                    tiny_tui::render_list(
                        &app.tui_directory_list, 
                        &app.current_path,
                        &app.graph_navigation_instance_state.agenda_process,
                        &app.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                        &app.graph_navigation_instance_state.scope,
                        &app.graph_navigation_instance_state.schedule_duration_start_end,
                        );
                    app.update_directory_list()?;
                   
                } else {
                  debug_log("back, but at root!");
                }
            }
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
                // debug_log("About to set sync flag to true! (handle_main_command_mode(), home)");
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
            // "u" | "manually_updated" => {
            //     debug_log("updated selected");
            //     // TODO: update the updated_at_timestamp filed in the node.toml
            // }
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
                
                // Enter Browser of Messages
                app.load_im_messages();
            }
            "t" | "task" | "tasks" => {
                debug_log("t selected: task browser launching");
                debug_log(&format!("app.current_path {:?}", app.current_path)); 
                app.input_mode = InputMode::InsertText;

                // TODO Assuming you have a way to get the current node's name:
                let current_node_name = app.current_path.file_name().unwrap().to_string_lossy().to_string();

                app.current_path = app.current_path.join("task_browser");

                debug_log!(
                    "app.current_path after joining 'task_browser': {:?}",
                    app.current_path
                ); 

                // Enter Browser of Tasks
                app.enter_task_browser();
                
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
                // if app.is_in_task_browser_directory() {
                if app.is_in_instant_message_browser_directory() {
                
                    if app.handle_task_action(input) { // Exit if handle_task_action returns true.
                        app.current_path.pop(); // Leave task browser directory
                    }; 
                // Stay within the task browser function and mode otherwise.
                } else {
                // ... Handle other command input as usual ...
                }
            }
            // ... (handle other commands)
            
        }
    }
    debug_log("end fn handle_main_command_mode()");
    return Ok(false); // Don't exit by default
}


fn task_mode_handle__commands(
    input: &str, 
    app: &mut App, 
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> Result<bool, io::Error> {
    /*
    For input command mode
    quit
    command-list/legend
    */

    debug_log(&format!("fn task_mode_handle__commands(), input->{:?}", input));
    
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
            
            "home" => {
                /*
                For a clean reset, 'home' quits and restarts,
                ensuring all processes are clean.
                */
                debug_log("Home command received.");
                quit_set_continue_uma_to_false();
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
    debug_log("end fn task_mode_handle__commands()");
    return Ok(false); // Don't exit by default
}


fn extract_last_path_section(current_path: &PathBuf) -> Option<String> {
    current_path.file_name().and_then(|os_str| os_str.to_str().map(|s| s.to_string()))
}

/// Determines the next available message file path.
///
/// Finds the highest existing message number in the given directory,
/// *ignoring usernames*, and returns a `PathBuf` for the next available file,
/// formatted as `{next_number}__{username}.toml`.
///
/// Handles empty directories and non-message files by starting from 1.
///
/// # Arguments
///
/// * `current_path`: The directory containing message files.
/// * `username`: The username for the *new* file.
///
/// # Returns
///
/// * `PathBuf`: Path to the next available message file.
fn get_next_message_file_path(current_path: &Path, username: &str) -> PathBuf {
    let mut max_number = 0;

    debug_log!(
        "get_next_message_file_path(): Starting. current_path: {:?}, username: {}",
        current_path, username
    );


    if let Ok(entries) = fs::read_dir(current_path) {
        for entry in entries.flatten() {
            if let Some(file_name) = entry.file_name().to_str() {
                if let Some((number_str, _rest)) = file_name.split_once("__") { // Ignore the rest of the filename
                    if let Ok(number) = number_str.parse::<u32>() {
                        max_number = max_number.max(number);
                    }
                }
            }
        }
    }

    let next_number = max_number + 1;
    let file_name = format!("{}__{}.toml", next_number, username);
    let file_path = current_path.join(file_name);


    debug_log!(
        "get_next_message_file_path(): Returning file_path: {:?}",
        file_path
    );    
    file_path
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
    // debug_log!("Starting get_addressbook_file_by_username(username),  for -> '{}'", username);
    
    // Debug the directory structure
    let base_dir = Path::new("project_graph_data/collaborator_files_address_book");
    debug_log!("Base directory path: {:?}", base_dir);
    debug_log!("Base directory exists: {}", base_dir.exists());
    
    // Check current working directory
    debug_log!("Current working directory: {:?}", std::env::current_dir()?);
    
    // Construct and check the specific file path
    let file_path = base_dir.join(format!("{}__collaborator.toml", username));
    debug_log!("Looking for file at: {:?}", file_path);
    debug_log!("File exists: {}", file_path.exists());

    // Try to list files in the directory if it exists
    if base_dir.exists() {
        debug_log!("Contents of collaborator_files_address_book directory:");
        match std::fs::read_dir(base_dir) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        debug_log!("Found file: {:?}", entry.path());
                    }
                }
            },
            Err(e) => debug_log!("Could not read directory contents: {}", e),
        }
    }
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

/// Moves a task (node) from one column to another in the task browser.
/// Updates all relevant paths in node.toml files.
///
/// # Arguments
///
/// * `path_lookup_table` - HashMap containing path lookups by number
///
/// # Returns
///
/// * `Result<(), ThisProjectError>` - Success or error status
fn move_task(
    next_path_lookup_table: &HashMap<usize, PathBuf>
) -> Result<(), ThisProjectError> {
    debug_log("starting move_task()");
    // 1. Get source task number
    println!("Enter task number to move:");
    let task_num = get_user_input_number()?;
    
    // Get source path from lookup
    let source_path = match next_path_lookup_table.get(&task_num) {
        Some(path) => path.clone(),
        None => return Err(ThisProjectError::InvalidData(
            format!("Task number {} not found", task_num)
        )),
    };
    debug_log!("move_task(), Source path: {:?}", source_path);

    // 2. Get destination column number
    println!("Enter destination column number:");
    let dest_num = get_user_input_number()?;
    
    // Get destination path from lookup
    let dest_path = match next_path_lookup_table.get(&dest_num) {
        Some(path) => path.clone(),
        None => return Err(ThisProjectError::InvalidData(
            format!("Destination column {} not found", dest_num)
        )),
    };
    debug_log!("move_task(), Destination path: {:?}", dest_path);

    // 3. Perform the move operation
    move_node_directory(source_path, dest_path)?;
    debug_log!(
        "ending move_task()"
        );
    Ok(())
}

/// Helper function to get numeric input from user
fn get_user_input_number() -> Result<usize, ThisProjectError> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input.trim().parse::<usize>().map_err(|_| 
        ThisProjectError::InvalidData("Invalid number".into())
    )
}

// /*
// This may be garbage:
// For Task Mode:
// 1. Link to tasks: view node 2nd layer deep using links in graph nav struct

// 2. Move task(node) to new directory
// Maybe use the lookup-number directory to get the path of the item to move.

// - command "move"
// - a Q&A interface:
// Q: Move what task?
// A: int
// (maybe get path from next-path lookup dict)

// Q: move to what column?
// A: int
// (this can also be from the lookup path dict)


// Moving a task involves:
// 1. move_from_path = (from next path lookup table)
// 2. move_to_directory_path = (from next path lookup table)
// 3. in move_from_path directory, change "directory_path" node.toml field to be move_to_directory_path 
// 4. recursively move the whole directory to the new location...
// (note: internal nodes? local path? full path?)
// 5. resetting the file paths of all nested nodes (unless those are relative...)
// - iterate through new directory path recursively
// - look for node.toml files
// - set node_path to that absolute path

// why is this reading the file BEFORE the move?

// Why is the using path recorded IN the file,
// instead of the literal path to that file?

// Why is there no doc-string?
// */
// /// Moves a node directory and updates all internal paths
// fn move_node_directory(
//     source_path: PathBuf,
//     dest_path: PathBuf
// ) -> Result<(), ThisProjectError> {
//     debug_log("Starting move_node_directory()");
    
//     debug_log!("Moving node from {:?} to {:?}", source_path, dest_path);

//     // 1. Read the source node.toml
//     let node_toml_path = source_path.join("node.toml");
//     let mut node = load_core_node_from_toml_file(&node_toml_path)
//         .map_err(|e| ThisProjectError::InvalidData(e))?;

//     // 2. Update the node's directory path
//     node.directory_path = dest_path.clone();

//     // 3. Create the new directory
//     let new_node_path = dest_path.join(source_path.file_name().unwrap());
//     fs::create_dir_all(&new_node_path)?;

//     // 4. Move the directory contents
//     move_directory_contents(&source_path, &new_node_path)?;

//     // 5. Update paths in all nested node.toml files
//     update_nested_node_paths(&new_node_path)?;

//     // 6. Remove the old directory
//     fs::remove_dir_all(source_path)?;

//     Ok(())
// }

// /// Updates paths in all nested node.toml files
// fn update_nested_node_paths(
//     dir_path: &Path
// ) -> Result<(), ThisProjectError> {
//     debug_log("starting update_nested_node_paths()");
//     for entry in fs::read_dir(dir_path)? {
//         let entry = entry?;
//         let path = entry.path();

//         if path.is_dir() {
//             update_nested_node_paths(&path)?;
//         } else if path.file_name().unwrap() == "node.toml" {
//             let mut node = load_core_node_from_toml_file(&path)
//                 .map_err(|e| ThisProjectError::InvalidData(e))?;
//             node.directory_path = path.parent().unwrap().to_path_buf();
//             save_toml_to_file(&node, &path)?;
//         }
//     }
//     Ok(())
// }

// /// Recursively moves directory contents
// fn move_directory_contents(
//     from: &Path,
//     to: &Path
// ) -> Result<(), ThisProjectError> {
//     debug_log("starting move_directory_contents()");
//     for entry in fs::read_dir(from)? {
//         let entry = entry?;
//         let path = entry.path();
//         let destination = to.join(path.file_name().unwrap());

//         if path.is_dir() {
//             fs::create_dir_all(&destination)?;
//             move_directory_contents(&path, &destination)?;
//         } else {
//             fs::copy(&path, &destination)?;
//         }
//     }
//     Ok(())
// }

// /// Moves a node directory and updates its metadata.
// ///
// /// This function moves a node's directory from the `source_path` to the `dest_path`.
// /// It updates the `directory_path` field in the node's `node.toml` file to reflect
// /// the new location. The function uses the `source_path`, not path within the struct.
// /// It handles directory creation, moving, and file updates efficiently.
// ///
// /// # Arguments
// ///
// /// * `source_path`: The current path to the node's directory.
// /// * `dest_path`: The intended path for the moved node's directory.
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>`: `Ok(())` if the move is successful; otherwise, a `ThisProjectError` is returned.
// fn move_node_directory(
//     source_path: PathBuf,
//     dest_path: PathBuf,
// ) -> Result<(), ThisProjectError> {
//     debug_log!("Starting move_node_directory()");
//     debug_log!("Moving node from {:?} to {:?}", source_path, dest_path);

//     // 1. Construct the new node path (where the moved node will be located).
//     let new_node_path = dest_path.join(source_path.file_name().unwrap());
//     debug_log!("move_node_directory: new_node_path is: {:?}", new_node_path);

//     // 2. Create the new directory, including all parents.
//     fs::create_dir_all(&new_node_path)?;
//     debug_log!("move_node_directory: created new_node_path: {:?}", new_node_path);

//     // 3. Recursively move the source directory's contents to the new directory.
//     move_directory_contents(&source_path, &new_node_path)?;
//     debug_log!("move_node_directory: contents moved to: {:?}", new_node_path);

//     // 4. Update node.toml (use full path)
//     // (The old path is already deleted by move_directory_contents)
//     update_node_path_in_toml(&new_node_path)?;
//     debug_log!("move_node_directory: updated node.toml paths");
    
//     // 5. Remove the old directory.
//     fs::remove_dir_all(source_path.clone())?;
//     // fs::remove_dir_all(source_path)?;
//     debug_log!("move_node_directory: removed source_path at : {:?}", source_path);
    
//     Ok(())
// }


// /// Updates the directory_path in node.toml
// /// Does NOT attempt to move anything
// fn update_node_path_in_toml(new_node_path: &Path) -> Result<(), ThisProjectError> {
//     debug_log!("starting update_node_path_in_toml(), for path: {:?}", new_node_path);

//     let node_toml_path = new_node_path.join("node.toml");

//     // 1. Read node.toml file:
//     let mut node = load_core_node_from_toml_file(&node_toml_path)
//         .map_err(|e| ThisProjectError::InvalidData(e))?;
    
//     // 2. Check if directory path is already the new path:
//     if node.directory_path == new_node_path {
//         debug_log!(
//             "skipping: update_node_path_in_toml(): node_toml.directory_path is already = {:?}, so no change required",
//             node.directory_path
//         );
//         return Ok(());
//     }
    
//     debug_log!("update_node_path_in_toml: old-node.directory_path: {:?}", node.directory_path);

//     // 3. Set new node.directory_path:
//     node.directory_path = new_node_path.to_path_buf();
//     debug_log!("update_node_path_in_toml: new-node.directory_path: {:?}", node.directory_path);
        
//     // 4. Write node.toml file:
//     save_toml_to_file(&node, &node_toml_path)?; // No need to use new_node_path again

//     debug_log!("Successfully updated node.toml directory path.");
//     Ok(())
// }

// /// Recursively moves directory contents
// fn move_directory_contents(
//     from: &Path,
//     to: &Path
// ) -> Result<(), ThisProjectError> {
//     debug_log("starting move_directory_contents()");
//     for entry in fs::read_dir(from)? {
//         let entry = entry?;
//         let path = entry.path();
//         let destination = to.join(path.file_name().unwrap());

//         if path.is_dir() {
//             fs::create_dir_all(&destination)?;
//             move_directory_contents(&path, &destination)?;
//         } else {
//             fs::copy(&path, &destination)?;
//         }
//     }
//     Ok(())
// }

/// Moves a node directory and updates its metadata.
///
/// This function moves a node's directory from the `source_path` to the `dest_path`.
/// It updates the `directory_path` field in the node's `node.toml` file to reflect
/// the new location. The function uses the `source_path`, not path within the struct.
/// It handles directory creation, moving, and file updates efficiently.
///
/// # Arguments
///
/// * `source_path`: The current path to the node's directory.
/// * `dest_path`: The intended path for the moved node's directory.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if the move is successful; otherwise, a `ThisProjectError` is returned.
fn move_node_directory(
    source_path: PathBuf,
    dest_path: PathBuf,
) -> Result<(), ThisProjectError> {
    debug_log!("Starting move_node_directory()");
    debug_log!("Moving node from {:?} to {:?}", source_path, dest_path);

    // 1. Construct the new node path (where the moved node will be located).
    let new_node_path = dest_path.join(source_path.file_name().unwrap());
    debug_log!("move_node_directory: new_node_path is: {:?}", new_node_path);

    // 2. Create the new directory, including all parents.
    fs::create_dir_all(&new_node_path)?;
    debug_log!("move_node_directory: created new_node_path: {:?}", new_node_path);


    // let original_node_toml_path = new_node_path.push("node.toml");
    let mut original_node_toml_path = source_path.clone();
    original_node_toml_path.push("node.toml");
    
    // 3. Update node.toml (use full path)
    // Option 1: Using to_string_lossy() (safest for paths that might contain non-UTF-8 characters)    
    let mut new_node_path_string = dest_path.to_string_lossy().into_owned();    
    
    debug_log!(
        "next: match safe_update_toml_field(\n{:?},\n{:?},\n{:?},\n)",
        &original_node_toml_path,   // path to .toml
        &new_node_path_string, // new value
        "directory_path",      // name of field
    );

    match safe_update_toml_field(
        &original_node_toml_path,        // path to .toml
        &new_node_path_string, // new value
        "directory_path",     // name of field
    ) {
        Ok(_) => println!("Successfully updated TOML file"),
        Err(e) => eprintln!("Error: {}", e)
    }    
    
    
    // 4. Recursively move the source directory's contents to the new directory.
    move_directory_contents(&source_path, &new_node_path)?;
    debug_log!("move_node_directory: contents moved to: {:?}", new_node_path);



    
    debug_log!("move_node_directory: updated node.toml paths");
    
    // 5. Remove the old directory.
    fs::remove_dir_all(source_path.clone())?;
    debug_log!("move_node_directory: removed source_path at : {:?}", source_path);
    
    Ok(())
}

/// Updates the directory_path in node.toml
/// Does NOT attempt to move anything
fn update_node_path_in_toml(new_node_path: &Path) -> Result<(), ThisProjectError> {
    debug_log!("starting update_node_path_in_toml(), for path: {:?}", new_node_path);

    let node_toml_path = new_node_path.join("node.toml");

    // 1. Read node.toml file:
    let mut node = load_core_node_from_toml_file(&node_toml_path)
        .map_err(|e| ThisProjectError::InvalidData(e))?;
    
    // 2. Check if directory path is already the new path:
    if node.directory_path == new_node_path {
        debug_log!(
            "skipping: update_node_path_in_toml(): node_toml.directory_path is already = {:?}, so no change required",
            node.directory_path
        );
        return Ok(());
    }
    
    debug_log!("update_node_path_in_toml: old-node.directory_path: {:?}", node.directory_path);

    // 3. Set new node.directory_path:
    node.directory_path = new_node_path.to_path_buf();
    debug_log!("update_node_path_in_toml: new-node.directory_path: {:?}", node.directory_path);
        
    // 4. Write node.toml file:
    save_toml_to_file(&node, &node_toml_path)?; // No need to use new_node_path again

    debug_log!("Successfully updated node.toml directory path.");
    Ok(())
}


/// Updates a specified field in a TOML file with a new value.
/// 
/// # Arguments
/// 
/// * `path` - A PathBuf containing the path to the TOML file
/// * `new_string` - A string slice containing the new value to be set
/// * `field` - A string slice containing the name of the field to update
/// 
/// # Returns
/// 
/// * `io::Result<()>` - Ok(()) on success, or an error if the operation fails
/// 
/// # Example
/// 
/// ```
/// # use std::fs;
/// # use std::path::PathBuf;
/// # fs::write("example.toml", "field = \"old_value\"").unwrap();
/// let path = PathBuf::from("example.toml");
/// let result = update_toml_field(&path, "new_value", "field");
/// # fs::remove_file("example.toml").unwrap();
/// ```
pub fn update_toml_field(
    path: &PathBuf, 
    new_string: &str, 
    field: &str
) -> io::Result<()> {
    // Read the entire file content using PathBuf's as_path() method
    let content = fs::read_to_string(path.as_path())?;
    
    // Create a temporary file with the same name plus .tmp
    let temp_path = path.with_extension("tmp");
    let mut temp_file = File::create(&temp_path)?;
    
    let mut field_found = false;
    
    // Process each line
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(field) && trimmed.contains('=') {
            // Write the new line for the matching field
            writeln!(temp_file, "{} = \"{}\"", field, new_string)?;
            field_found = true;
        } else {
            // Write the original line
            writeln!(temp_file, "{}", line)?;
        }
    }
    
    // If field wasn't found, append it
    if !field_found {
        writeln!(temp_file, "{} = \"{}\"", field, new_string)?;
    }
    
    // Ensure all data is written
    temp_file.flush()?;
    
    // Replace the original file with the temporary file
    fs::rename(temp_path, path)?;
    
    Ok(())
}

/// A safer wrapper function that includes additional error checking.
/// 
/// # Arguments
/// 
/// * `path` - A PathBuf containing the path to the TOML file
/// * `new_string` - A string slice containing the new value to be set
/// * `field` - A string slice containing the name of the field to update
/// 
/// # Returns
/// 
/// * `Result<(), String>` - Ok(()) on success, or an error message if the operation fails
///
/// Example Use:
/// ```
/// use std::path::PathBuf;
/// let config_path = PathBuf::from("config.toml");
/// match safe_update_toml_field(&config_path, "alice", "user_name") {
///     Ok(_) => println!("Successfully updated TOML file"),
///     Err(e) => eprintln!("Error: {}", e)
/// }
/// ```
pub fn safe_update_toml_field(
    path: &PathBuf, 
    new_string: &str, 
    field: &str
) -> Result<(), String> {
    
    debug_log("starting safe_update_toml_field()");

    debug_log!(
        "in safe_update_toml_field(\n{:?},\n{:?},\n{:?},\n)",
        &path,   // path to .toml
        &new_string, // new value
        "field",      // name of field
    );    
    
    // Validate inputs
    if field.is_empty() {
        return Err("Error: safe_update_toml_field() Field name cannot be empty".to_string());
    }
    
    if !path.exists() {
        return Err(format!("Error: safe_update_toml_field() File not found: {}", path.display()));
    }
    
    update_toml_field(path, new_string, field)
        .map_err(|e| format!("Error: safe_update_toml_field() Failed to update TOML file: {}", e))
}

/// Recursively moves directory contents
fn move_directory_contents(
    from: &Path,
    to: &Path
) -> Result<(), ThisProjectError> {
    debug_log("starting move_directory_contents()");
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        let destination = to.join(path.file_name().unwrap());

        if path.is_dir() {
            fs::create_dir_all(&destination)?;
            move_directory_contents(&path, &destination)?;
        } else {
            // Now, move the file instead of copying it
            fs::rename(&path, &destination)?;
        }
    }
    Ok(())
}

/// Loads connection data for members of the currently active team channel.
/// On success, returns a `HashSet` of `MeetingRoomSyncDataset` structs, 
/// each containing connection 
/// data for a collaborator in the current team channel (excluding the current user).
/// As a headline this makes an ip-whitelist or ip-allowlist but the overall process is bigger.
/// This should include 'yourself' so all connection data are there, so you know your ports
///
/// Note: this likely should also include the collabortor's last-received-timestamp (and the previous one)
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

/// Converts a Pearson hash (Vec<u8>) to a hexadecimal string.
///
/// # Arguments
///
/// * `hash`: The Pearson hash as a `Vec<u8>`.
///
/// # Returns
///
/// * `String`: The hexadecimal representation of the hash.
fn pearson_hash_to_hex_string(hash: &[u8]) -> String {
    hash.iter()
        .map(|&byte| format!("{:02x}", byte)) // Format each byte as two hex digits
        .collect()
}

/// Converts a hexadecimal string to a Pearson hash (Vec<u8>).
///
/// Returns an error if the input string is not a valid hexadecimal representation.
///
/// # Arguments
///
/// * `hex_string`: The hexadecimal string.
///
/// # Returns
///
/// * `Result<Vec<u8>, String>`: The Pearson hash as a `Vec<u8>`, or an error message.
fn hex_string_to_pearson_hash(hex_string: &str) -> Result<Vec<u8>, String> {
    debug_log("starting hex_string_to_pearson_hash()");
    
    if hex_string.len() % 2 != 0 {
        return Err("Invalid hex string: Length must be even".to_string());
    }

    let mut hash = Vec::with_capacity(hex_string.len() / 2);
    for i in (0..hex_string.len()).step_by(2) {
        let hex_byte = &hex_string[i..i + 2];
        match u8::from_str_radix(hex_byte, 16) {
            Ok(byte) => hash.push(byte),
            Err(_) => return Err(format!("Invalid hex string: Invalid byte: {}", hex_byte)),
        }
    }
    debug_log("end of hex_string_to_pearson_hash");
    Ok(hash)
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
///
/// In this version of the function, the match expression for the 
/// pearson_hash_base call returns false by default in the case 
/// of an error. Additionally, the function checks if the index i 
/// is within the bounds of the rh field before accessing it. If 
/// the index is out-of-bounds, the function returns false.
///
/// By returning false by default in the case of any errors, the 
/// function ensures that the caller can easily determine whether 
/// the hashes are valid or not.
fn verify_readysignal_hashes(
    ready_signal: &ReadySignal,
    salt_list: &[u128]
) -> bool {
    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&ready_signal.rt.to_be_bytes());
    data_to_hash.extend_from_slice(&ready_signal.rst.to_be_bytes());
    data_to_hash.extend_from_slice(&ready_signal.b.to_be_bytes());

    for (i, salt) in salt_list.iter().enumerate() {
        let mut salted_data = data_to_hash.clone();
        salted_data.extend_from_slice(&salt.to_be_bytes());
        let calculated_hash = match pearson_hash_base(&salted_data) {
            Ok(hash) => hash,
            Err(e) => {
                debug_log!("verify_readysignal_hashes(), Error calculating Pearson hash: {}", e);
                return false; // Error during hash calculation
            }
        };

        if i >= ready_signal.rh.len() {
            debug_log!("verify_readysignal_hashes(),  Out-of-bounds index error when accessing rh field");
            return false; // Out-of-bounds index error
        }

        // comparing each index to each index: fail-checking step-wise
        if calculated_hash != ready_signal.rh[i] { // Compare with the received hash
            debug_log!(
                "failed in verify_readysignal_hashes(), hash != hash: ready_signal.rh->{:?} != calculated_hash->{:?}, all ready_signal.rh->{:?}", 
                ready_signal.rh[i],
                calculated_hash,
                ready_signal.rh,
            );
            return false; // Hash mismatch
        }
    }

    // All hashes match
    true
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
    rt: u64, // ready signal timestamp: last file obtained timestamp
    rst: u64, // send-time: generate_terse_timestamp_freshness_proxy(); for replay-attack protection
    b: u8, // Network Index (e.g. which ipv6 in the list)
    rh: Vec<u8>, // N hashes of rt + re
}

/// Serializes a ReadySignal into a byte vector
/// Does NOT use serde.
fn serialize_ready_signal(ready_signal: &ReadySignal) -> Result<Vec<u8>, ThisProjectError> {
    let mut bytes = Vec::new();

    // Add timestamps (rt and rst)
    bytes.extend_from_slice(&ready_signal.rt.to_be_bytes());
    bytes.extend_from_slice(&ready_signal.rst.to_be_bytes());

    // Add Network band byte as u8 bytes
    bytes.extend_from_slice(&ready_signal.b.to_be_bytes());

    // Add hash list
    bytes.extend_from_slice(&ready_signal.rh);

    Ok(bytes)
}

// TODO max size check?
/// Calculates Pearson hashes for a ReadySignal's fields. Hashes `rt`, `rst`, `nt`, `ni`, and salts.
///
/// Args:
///     rt: The `rt` timestamp.
///     rst: The `rst` timestamp.
///     nt: The network type string.
///     ni: The network index.
///     local_user_salt_list: The list of salts for hashing.
///
/// Returns:
///     Result<Vec<u8>, ThisProjectError>: The calculated hash list, or an error if hashing fails.
fn calculate_ready_signal_hashes(
    rt: u64,
    rst: u64,
    band: u8,
    local_user_salt_list: &[u128],
) -> Result<Vec<u8>, ThisProjectError> {
    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&rt.to_be_bytes());
    data_to_hash.extend_from_slice(&rst.to_be_bytes());
    data_to_hash.extend_from_slice(&band.to_be_bytes());

    let mut ready_signal_hash_list: Vec<u8> = Vec::new();
    for salt in local_user_salt_list {
        let mut salted_data = data_to_hash.clone();
        salted_data.extend_from_slice(&salt.to_be_bytes());

        match pearson_hash_base(&salted_data) {
            Ok(hash) => ready_signal_hash_list.push(hash),
            Err(e) => return Err(ThisProjectError::IoError(e)), // Directly return the error
        }
    }

    Ok(ready_signal_hash_list)
}

// Define enums for each field you want to validate
#[derive(Debug, PartialEq)]
enum Timestamp {
    Valid(u64),
    Invalid,
}

#[derive(Debug, PartialEq)]
enum DocumentId {
    Valid(u64),
    Invalid,
}

// Proto struct with Option<T> for initial deserialization
#[derive(Debug)]
struct PrototGotitSignal {
    gst: Option<Timestamp>,
    di: Option<DocumentId>,
    gh: Option<Vec<u8>>,
}

/// GotItSignal struct
/// Terse names to reduce network traffic, as an esceptional circumstatnce
/// Probably does not need a nonce because repeat does nothing...
///
/// Final struct with validated data
/// use proto-struct PrototGotitSignal for loading possibly corrupted data
#[derive(Debug)]
struct GotItSignal {
    gst: u64,
    di: u64,
    gh: Vec<u8>,
}

// Converts a byte slice to a u64, handling potential errors.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.len() != 8 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid byte length for u64"));
    }
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

/// Calculates Pearson hash list for a GotItSignal.
/// Hashes the `gst` (send time), `di` (document ID/received timestamp), and salts.
///
/// # Arguments
///
/// * `gst`: The `gst` timestamp.
/// * `di`: The `di` timestamp (received file's timestamp).
/// * `local_user_salt_list`:  The list of salts for hashing.
///
/// # Returns
///
/// * `Result<Vec<u8>, ThisProjectError>`: The calculated hash list or an error.
fn calculate_gotitsignal_hashlist(
    timestamp_for_gst: u64,
    timestamp_for_di: u64,
    local_user_salt_list: &[u128],
) -> Result<Vec<u8>, ThisProjectError> {

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&timestamp_for_gst.to_be_bytes());
    data_to_hash.extend_from_slice(&timestamp_for_di.to_be_bytes());

    debug_log!(
        "calculate_gotitsignal_hashlist(): Data to hash: {:?}",
        &data_to_hash
    );

    let mut gotit_signal_hash_list: Vec<u8> = Vec::new();
    for salt in local_user_salt_list {
        let mut salted_data = data_to_hash.clone();
        salted_data.extend_from_slice(&salt.to_be_bytes());

        match pearson_hash_base(&salted_data) {
            Ok(hash) => gotit_signal_hash_list.push(hash),
            Err(e) => {
                return Err(ThisProjectError::IoError(e));  // Return the error
            }
        }
    }
    debug_log!(
        "calculate_gotitsignal_hashlist(): Calculated Hashes: {:?}",
        &gotit_signal_hash_list
    );

    Ok(gotit_signal_hash_list)
}


/// Deserializes a byte slice into a `PrototGotitSignal`, manually handling the byte extraction.
///
/// Arguments:
///     bytes: The byte slice containing the serialized data.
///
/// Returns:
///     Result<PrototGotitSignal, Error>: A `Result` containing the `PrototGotitSignal` on success, or an `Error` if deserialization fails.
fn deserialize_proto_gotit_signal(bytes: &[u8]) -> Result<PrototGotitSignal, Error> {

    // Calculate expected lengths (assuming a u64 for both timestamp and ID)
    let timestamp_len = std::mem::size_of::<u64>();
    let id_len = std::mem::size_of::<u64>();
    let expected_min_length = timestamp_len + id_len; // Minimum length for timestamp and ID

    // Check if the byte array has enough data for at least the timestamp and document ID
    if bytes.len() < expected_min_length {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid byte array length for PrototGotitSignal: too short",
        ));
    }

    // Extract timestamp
    let gst_bytes = &bytes[0..timestamp_len];
    let gst = match bytes_to_u64(gst_bytes) {
        Ok(ts) => Some(Timestamp::Valid(ts)),
        Err(_) => Some(Timestamp::Invalid),  // Or handle differently
    };

    // Extract document ID
    let di_bytes = &bytes[timestamp_len..expected_min_length];
    let di = match bytes_to_u64(di_bytes) {
        Ok(id) => Some(DocumentId::Valid(id)),
        Err(_) => Some(DocumentId::Invalid),
    };

    // Extract hash list (if any)
    let gh = if bytes.len() > expected_min_length {
        Some(bytes[expected_min_length..].to_vec())
    } else {
        None
    };

    Ok(PrototGotitSignal { gst, di, gh })
}


fn validate_and_convert_gotit_signal(proto_signal: PrototGotitSignal) -> Result<GotItSignal, String> {
    let gst = match proto_signal.gst {
        Some(Timestamp::Valid(ts)) => ts,
        _ => return Err("Invalid or missing gst".into()),
    };

    let di = match proto_signal.di {
        Some(DocumentId::Valid(id)) => id,
        _ => return Err("Invalid or missing di".into()),
    };

    // Default to an empty vector if the hash list is missing
    let gh = proto_signal.gh.unwrap_or_default();

    Ok(GotItSignal { gst, di, gh })
}

fn process_incoming_gotit_signal_bytes(bytes: &[u8]) -> Result<GotItSignal, String> {
    let proto_signal = deserialize_proto_gotit_signal(bytes)
        .map_err(|e| format!("Deserialization failed: {}", e))?; // Handle deserialization error

    validate_and_convert_gotit_signal(proto_signal)
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
    fn add_to_front_of_sendq(&mut self, path: PathBuf) {
        self.items.insert(0, path);
    }
}

/// unpack new node
/// saves new node.toml file, ensuring path and feature directories
/// Unpacks and saves a new node from received data.
///
/// This function takes the raw bytes of a clearsigned and decrypted `node.toml` file
/// and saves it to the specified path. It also creates the standard UMA node
/// subdirectories: "instant_message_browser" and "task_browser".
///
/// This function is used during file synchronization to create or update nodes
/// on the local file system based on data received from a remote collaborator.
/// It assumes the `extracted_clearsigned_file_data` contains valid TOML data
/// for a `CoreNode` struct.
///
/// # Arguments
///
/// * `extracted_clearsigned_file_data`: The raw bytes of the decrypted and
///   clearsigned `node.toml` file.
/// * `new_full_abs_node_directory_path`: The *full absolute path* to the
///   directory where the node should be saved. This path should *include* the
///   node directory name itself (e.g.,
///   `"project_graph_data/team_channels/my_team/my_node"`).
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a
///   `ThisProjectError` if an error occurs during file or directory creation.
///
/// # Example
///
/// ```
/// // ... (assuming you have extracted_clearsigned_file_data and new_full_abs_node_directory_path)
///
/// match unpack_new_node_save_toml_and_create_dir(&extracted_clearsigned_file_data, &new_full_abs_node_directory_path) {
///     Ok(_) => println!("Node unpacked and saved successfully."),
///     Err(e) => eprintln!("Error unpacking node: {}", e),
/// }
/// ```
fn unpack_new_node_save_toml_and_create_dir(
    extracted_clearsigned_file_data: &Vec<u8>, 
    new_full_abs_node_directory_path: &Path,
) -> Result<(), ThisProjectError> {
    
    // 1. Make full file path
    let new_node_toml_file_path = new_full_abs_node_directory_path.join("node.toml"); // Path to the new node.toml

    // 2. Create directory if it doesn't exist
    fs::create_dir_all(new_full_abs_node_directory_path)?;
    
    // 3. write file from GPG clearsign extracted data as node.toml
    if let Err(e) = fs::write(
        &new_node_toml_file_path, 
        &extracted_clearsigned_file_data
    ) {
        debug_log!("HLOD-InTray: Unpack Node: Failed to write message file: {:?}", e);
        // Consider returning an error here instead of continuing the loop
        return Err(ThisProjectError::from(e));
    }
    
    // 4. Add IM-Browser directory
    let im_browser_path = new_full_abs_node_directory_path.join("instant_message_browser");  // Construct path correctly
    create_dir_all(&im_browser_path)?;

    // 5. Add Task-Browser directory
    let task_browser_path = new_full_abs_node_directory_path.join("task_browser");  // Construct path correctly
    create_dir_all(&task_browser_path)?;

    Ok(())
}

// /// unpack new node
// /// saves new node.toml file, ensuring path and IM directory
// fn unpack_new_node_save_toml_and_create_dir(
//     toml_string: &str,
//     path: &Path,
//     dir_name: &str,  // Now this is the general name
// ) -> Result<(), std::io::Error> {
//     // 1. Create parent directories.
//     create_dir_all(path)?;

//     // 2. Create and write to node.toml.
//     let toml_path = path.join("node.toml");
//     let mut toml_file = File::create(&toml_path)?;
//     toml_file.write_all(toml_string.as_bytes())?;

//     // 3. Create associated directory.  (This is the only change)
//     let dir_path = path.join(dir_name); // No longer specifically "instant_message_browser"
//     create_dir_all(&dir_path)?;


//     // Add this to create "instant_message_browser/" next to node.toml:
//     let im_browser_path = path.join("instant_message_browser");
//     create_dir_all(&im_browser_path)?;    

//     Ok(())
// }

/// Retrieves the paths of all send queue update flags for a given collaborator in a team channel.
///
/// This function reads the contents of the directory `sync_data/{team_channel_name}/sendqueue_updates/{collaborator_name}`
/// and returns a vector of `PathBuf` representing the paths to the update flag files.  It also deletes the flag files
/// after reading their contents, ensuring that flags are processed only once.
///
/// Note: each potential participant must have a separate flag.
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
    let team_channel_name = match get_current_team_channel_name_from_cwd() {
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

/// depricated...this saves a name...
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


// /// Saves a "pre-fail" flag file (an empty file used as a marker).
// ///
// /// This function creates an empty file within the `sync_data` directory to serve as a "pre-fail"
// /// flag.  The file's name is derived from the provided `hash_array`, and its presence indicates
// /// that a file send attempt is in progress (and assumed to have failed unless explicitly cleared).
// /// The directory structure is as follows:  `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/{doc_id}`
// ///
// /// # Arguments
// ///
// /// * `hash_array`: A slice of `u8` values used to generate the filename (doc_id).
// /// * `remote_collaborator_name`: The name of the remote collaborator associated with the flag.
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>`:  `Ok(())` if the flag file is successfully created, or a `ThisProjectError`
// ///   if an error occurs (e.g., during file creation or directory creation).
// ///
// fn set_prefail_flag_rt_timestamp__for_sendfile(
//     rt_timestamp: u64,
//     remote_collaborator_name: &str,
// ) -> Result<(), ThisProjectError> {
//     // let doc_id = docid__hash_array_to_hex_string(hash_array);
    
//     let team_channel_name = get_current_team_channel_name_from_cwd()
//         .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

//     let mut file_path = PathBuf::from("sync_data"); // Use PathBuf not format!()
//     file_path.push(&team_channel_name);
//     file_path.push("fail_retry_flags");
//     file_path.push(remote_collaborator_name);
//     create_dir_all(&file_path)?; // Create the directory structure if it doesn't exist
    
//     // TODO string of u64
//     let string_of_rt = rt_timestamp.to_string();
    
//     file_path.push(string_of_rt);
//     File::create(file_path)?; // Create the empty file as a flag
//     Ok(())
// }



/// Extracts the `updated_at_timestamp` field from a TOML file.
///
/// This function reads the TOML file at the specified path, parses it, and extracts the
/// `updated_at_timestamp` field.  It handles potential errors during file reading, TOML
/// parsing, and missing or invalid timestamp fields.
///
/// # Arguments
///
/// * `file_path`: The path to the TOML file.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`: The `updated_at_timestamp` value on success, or a
///   `ThisProjectError` if an error occurs.
fn get_updated_at_timestamp_from_toml_file(file_path: &Path) -> Result<u64, ThisProjectError> {
    // 1. Read the TOML file: Handle file read errors
    let toml_string = match std::fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            debug_log!("Error reading TOML file {:?}: {}", file_path, e);
            return Err(ThisProjectError::from(e));
        }
    };
    debug_log!("Read TOML file: {:?}", file_path);
    

    // 2. Parse the TOML string: Handle TOML parsing errors
    let toml_value: Value = match toml::from_str(&toml_string) {
        Ok(value) => value,
        Err(e) => {
            debug_log!("Error parsing TOML string: {}", e);
            return Err(ThisProjectError::from(e)); // Or handle error differently
        }
    };
    debug_log!("Parsed TOML value.");

    // 3. Extract updated_at_timestamp:  Handle missing/invalid timestamp
    let updated_at_timestamp = match toml_value.get("updated_at_timestamp") {
        Some(Value::Integer(ts)) => *ts as u64, // Convert to u64, handle overflow
        Some(_) => {
            debug_log!("'updated_at_timestamp' has invalid type");
            return Err(ThisProjectError::InvalidData(
                "'updated_at_timestamp' has invalid type".into(),
            ));
        }
        None => {
            debug_log!("'updated_at_timestamp' field not found in TOML file");
            return Err(ThisProjectError::InvalidData(
                "'updated_at_timestamp' field not found in TOML file".into(),
            ));
        }
    };
    debug_log!("Extracted timestamp: {}", updated_at_timestamp);

    Ok(updated_at_timestamp) // Return the timestamp if successful
}

/// Sets a "pre-fail" flag file.  The filename is the file's `updated_at` timestamp.
/// The file content is the ReadySignal's `.rt` timestamp.
///
/// Directory structure: `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/{file_updated_at_timestamp}`.
///
/// # Arguments
///
/// * `file_updated_at_time`: The file's `updated_at_timestamp`.
/// * `rt_timestamp`: The `.rt` timestamp from the ReadySignal.
/// * `remote_collaborator_name`: Remote collaborator's name.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a `ThisProjectError`.
fn set_prefail_flag_rt_timestamp__for_sendfile(
    file_updated_at_time: u64,
    mut rt_timestamp: u64,
    remote_collaborator_name: &str,
) -> Result<(), ThisProjectError> {
    
    /*
    edge case: if there are no files, the timestamp will be zero
    if the rt_timestamp is zero: set the flag for 1 (not zero)
    zero-return means there are no flags
    */
    if rt_timestamp == 0 {
        rt_timestamp = 1;
    }

    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

    let mut flag_file_path = PathBuf::from("sync_data")
        .join(&team_channel_name)
        .join("fail_retry_flags")
        .join(remote_collaborator_name)
        .join(file_updated_at_time.to_string());  // Filename is the file's updated_at timestamp

    // Create directory structure if it doesn't exist
    if let Some(parent) = flag_file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write the .rt timestamp to the file
    fs::write(flag_file_path, rt_timestamp.to_string())?;

    debug_log!(
        "Set pre-fail flag for file updated at {} with ReadySignal timestamp {}.",
        file_updated_at_time, rt_timestamp
    );
    Ok(())
}

/// Retrieves the .rt timestamp from the oldest pre-fail flag file.
///
/// Iterates through the `fail_retry_flags` directory, finds the oldest file (based on filename, which is the `updated_at` timestamp),
/// reads the `.rt` timestamp (the file content) from that oldest file, and returns it.
/// Deletes all flag files after reading the oldest timestamp, ensuring flags are processed only once.
/// Returns 0 if no flags are found or if an error occurs during file operations.
///
/// Directory structure: `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/{file_updated_at_timestamp}`
///
/// # Arguments
///
/// * `remote_collaborator_name`: The name of the remote collaborator.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`: The `.rt` timestamp from the oldest flag file (or 0) on success, or a `ThisProjectError`.
fn get_oldest_sendfile_prefailflag_rt_timestamp_or_0_w_cleanup(
    remote_collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    debug_log("get_oldest prefail: starting get_oldest_sendfile_prefailflag_rt_timestamp_or_0_w_cleanup()");
    let mut oldest_timestamp = 0u64;
    let mut oldest_file_path: Option<PathBuf> = None; // Store path to the oldest file

    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("get_oldest prefail... Unable to get team channel name".into()))?;

    let prefail_directory = PathBuf::from("sync_data")
        .join(&team_channel_name)
        .join("fail_retry_flags")
        .join(remote_collaborator_name);

    if !prefail_directory.exists() {
        debug_log!(
            "get_oldest...: Directory {:?} not found. Returning 0.",
            prefail_directory
        );
        return Ok(0);
    }

    // 1. Find the oldest file:
    for entry in fs::read_dir(&prefail_directory)? {
        let entry = entry?;
        let path = entry.path();
        
        debug_log!(
            "get_oldest prefail... path -> {:?}",
            path
        );
        
        if path.is_file() {
            let file_name = path.file_name().and_then(|n| n.to_str()).ok_or(ThisProjectError::InvalidData("Invalid flag file name".into()))?;
            let file_updated_at: u64 = file_name.parse().map_err(|_| ThisProjectError::InvalidData("Invalid timestamp in flag file name".into()))?;

            if oldest_file_path.is_none() || file_updated_at < oldest_timestamp {
                oldest_timestamp = file_updated_at;
                oldest_file_path = Some(path.clone()); //Store the path
            }
        }
    }

    // 2. Read .rt timestamp from the oldest file (if found):
    if let Some(path) = oldest_file_path {
        match fs::read_to_string(&path) { // Read content (rt timestamp)
            Ok(content) => {
                oldest_timestamp = content.trim().parse().map_err(|_| ThisProjectError::InvalidData("Invalid .rt timestamp in flag file".into()))?;
                debug_log!("get_oldest prefail: Oldest .rt timestamp found: {}", oldest_timestamp);
            },
            Err(e) => {
                debug_log!("get_oldest prefail: Error reading .rt timestamp from file {:?}: {}", path, e);
                return Err(ThisProjectError::from(e));
            }
        }
        // 3. Delete oldest flag
        // TODO alpha version: remove only oldest flag
        match fs::read_to_string(&path) { // Read content (rt timestamp)
            Ok(pathtemp) => {
                if let Err(e) = fs::remove_file(pathtemp) { // Use &path
                    debug_log!(
                        "get_oldest prefail: Error removing oldest_file_path flag file {:?}: {}",
                        path,
                        e);
                    return Err(ThisProjectError::from(e)); // Or handle error as needed
                }
            },
            Err(e) => {
                debug_log!("get_oldest prefail: Error in remove_file {:?}: {}", path, e);
                return Err(ThisProjectError::from(e));
            }
        }

        // for entry in fs::read_dir(&prefail_directory)? {
        //     let entry = entry?;
        //     let path = entry.path();
        //     if path.is_file() {
        //         if let Err(e) = fs::remove_file(&path) { // Use &path
        //             debug_log!("get_oldest prefail: Error removing flag file {:?}: {}", path, e);
        //             return Err(ThisProjectError::from(e)); // Or handle error as needed
        //         }
        //     }
    
    }

    Ok(oldest_timestamp)
}

/// Removes a specific pre-fail flag file based on its ID (timestamp).
/// currently gotit sign di (doc id) is the updated-at time of the file
///
/// This function attempts to remove the flag file located at:
/// `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/{di_flag_id}`.
/// It returns an `Ok(())` if the file is successfully removed or if the file
/// doesn't exist (which isn't considered an error in this context, as the goal is
/// simply to ensure the flag is *not* present). It returns an error only if a file
/// operation other than `NotFound` occurs.
///
/// # Arguments
///
/// * `di_flag_id`: The document ID (timestamp) used as the flag file name.
/// * `remote_collaborator_name`: The remote collaborator's name.
/// * `team_channel_name`: The team channel name.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on successful removal or if the
/// file doesn't exist, or a `ThisProjectError` on other file operation errors.
fn remove_one_prefail_flag__for_sendfile(
    di_flag_id: u64,         // Use u64 directly, as the flag ID comes from a u64 timestamp.
    remote_collaborator_name: &str, // Use &str for efficiency
    team_channel_name: &str,   // Use &str for efficiency
) -> Result<(), ThisProjectError> {

    let mut flag_file_path = PathBuf::from("sync_data")
        .join(team_channel_name)
        .join("fail_retry_flags")
        .join(remote_collaborator_name);

    if !flag_file_path.exists() { // Check for existance
        return Ok(()); //
    }
    
    flag_file_path.push(di_flag_id.to_string());  // Use di_flag_id directly

    match remove_file(flag_file_path) {
        Ok(_) => {
            debug_log!(
                "remove_one_prefail_flag__for_sendfile(): Successfully removed flag with id: {}",
                di_flag_id
            );
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            debug_log!("remove_one_prefail_flag__for_sendfile(): Flag file not found: {}", di_flag_id);
            Ok(()) // Not an error if the file isn't found.
        }
        Err(e) => {
            debug_log!("remove_one_prefail_flag__for_sendfile(): Error removing flag file: {}", e);
            Err(ThisProjectError::IoError(e))  // Return other errors
        }
    }
}




/// Removes all pre-fail flag files for a remote collaborator.
///
/// This function removes all files within the fail_retry_flags directory for the
/// given team channel and remote collaborator. The directory structure is as
/// follows:  `sync_data/{team_channel_name}/fail_retry_flags/{remote_collaborator_name}/`.
///
/// # Arguments
///
/// * `remote_collaborator_name`: The name of the remote collaborator.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` if all files were removed
///   successfully (or if the directory doesn't exist), or a
///   `ThisProjectError` if an error occurs during directory access or file
///   removal.
fn remove_prefail_flags__for_sendfile(
    remote_collaborator_name: &str,
) -> Result<(), ThisProjectError> {
    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;

    let directory = PathBuf::from("sync_data")
        .join(&team_channel_name)
        .join("fail_retry_flags")
        .join(remote_collaborator_name);

    if !directory.exists() { // Check for existance
        return Ok(()); // Or log a message: debug_log!("Directory not found: {:?}", directory);
    }

    for entry in fs::read_dir(&directory)? {  // Iterate through directory contents
        let entry = entry?;
        let path = entry.path();
        if path.is_file() { // Only remove files
            match fs::remove_file(&path) { // Use remove_file, not remove_dir_all
                Ok(_) => debug_log!("Removed flag file: {:?}", path),
                Err(e) => {
                    debug_log!("Error removing flag file: {:?} - {}", path, e);
                    // Either continue or return the error if you want to stop on the first error.
                    return Err(ThisProjectError::IoError(e)); 
                }
            }
        }
    }
    Ok(())
}

// let timestamp_request_port = // ... port for sending "ready to receive" to collaborator
// let file_receive_port = // ...  port for receiving files from collaborator 
// let receipt_confirmation_port = // ... port for sending confirmations to collaborator
fn send_data(data: &[u8], target_addr: SocketAddr) -> Result<(), io::Error> { 
    let socket = UdpSocket::bind(":::0")?; 
    socket.send_to(data, target_addr)?;
    Ok(())
}

/// Gets the latest received file timestamp for a collaborator in a team channel, using a plain text file.
///
/// This function reads the timestamp from a plain text file at:
/// `sync_data/{team_channel_name}/latest_receivedfile_timestamps/{collaborator_name}/latest_receivedfromme_file_timestamp.txt`
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
///
/// This is one of those values and functions that can be confusing
/// because both you and your remote collaborator have quasi-mirror-image sync systems
/// with reversed roles. Both of you are making 'latest_received' timestamps
/// and both of you are using your and their 'latest_received' timestamps,
/// which are simultanously 'the same' abstract value but very different local-context-role-specific values
///
/// the complimentary function is: get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl()
/// 
/// example location of use:
/// Drone Loop to Send ReadySignals  (hlod)
/// 1.2 Refresh Timestamp
fn read_latestreceivedfromme_file_timestamp_plaintextstatefile(
    collaborator_name: &str,
    team_channel_name: &str,
) -> Result<u64, ThisProjectError> {
    /*
    Wait random time in A to B range, N times
    FILE_READWRITE_N_RETRIES
    FILE_READWRITE_RETRY_SEC_PAUSE_MIN
    FILE_READWRITE_RETRY_SEC_PAUSE_max
    */
    
    let mut file_path = PathBuf::from("sync_data");
    file_path.push(team_channel_name);
    file_path.push("latest_receivedfile_timestamps");
    file_path.push(collaborator_name);
    file_path.push("latest_receivedfromme_file_timestamp.txt");

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
            debug_log!(
                "Error: glrfftptsf() getting timestamp: e'{}'e. Using0 inside read_latestreceivedfromme_file_timestamp_plaintextstatefile()",
                e,
            );
            // File not found, initialize to 0
            let mut file = File::create(&file_path)?;
            file.write_all(b"0")?; // Write zero timestamp
            Ok(0)
        }
        Err(e) => Err(ThisProjectError::IoError(e)), // Other IO errors
    }
}

/// Gets the latest received file timestamp for a collaborator in a team channel, using a plain text file.
///
/// As another thread may be reading/writing the file, there 
/// is a random-wait retry system
///
/// This function reads the timestamp from a plain text file at:
/// `sync_data/{team_channel_name}/latest_receivedfile_timestamps/
/// {collaborator_name}/latest_received_from_rc_filetimestamp.txt`
/// If the file or directory structure doesn't exist, 
/// it creates them and initializes the timestamp to 0.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `collaborator_name`: The name of the collaborator.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`:  The latest received timestamp on success, or a `ThisProjectError` if an error occurs.
///
/// This is one of those values and functions that can be confusing
/// because both you and your remote collaborator have quasi-mirror-image sync systems
/// with reversed roles. Both of you are making 'latest_received' timestamps
/// and both of you are using your and their 'latest_received' timestamps,
/// which are simultanously 'the same' abstract value but very different local-context-role-specific values
///
/// the complimentary function is: read_latestreceivedfromme_file_timestamp_plaintextstatefile()
/// 
/// example location of use:
/// Drone Loop to Send ReadySignals  (hlod)
/// 1.2 Refresh Timestamp
///
/// If the system is busy and needs to wait, just wait and retry
/// retry-wait must not be considered an 'error' to 'handled'
/// to collapse the entire system.
///
/// the complimentary function is: read_latestreceivedfromme_file_timestamp_plaintextstatefile()
fn read_rc_latest_received_from_rc_filetimestamp_plaintextstatefile(
    team_channel_name: &str,
    collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    let mut file_path = PathBuf::from("sync_data");
    file_path.push(team_channel_name);
    file_path.push("latest_receivedfile_timestamps");
    file_path.push(collaborator_name);
    file_path.push("latest_received_from_rc_filetimestamp.txt");

    let mut retries = FILE_READWRITE_N_RETRIES;

    // Retry loop
    loop { 
        // Generate a random pause duration within the specified range
        let pause_duration = Duration::from_secs(rand::thread_rng().gen_range(FILE_READWRITE_RETRY_SEC_PAUSE_MIN..=FILE_READWRITE_RETRY_SEC_PAUSE_MAX));

        match read_to_string(&file_path) {
            Ok(timestamp_str) => {
                match timestamp_str.trim().parse::<u64>() {
                    Ok(timestamp) => return Ok(timestamp), // Success!
                    Err(e) => {
                        debug_log!("Error parsing timestamp from file: {}. Retrying...", e);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Create directories and file if not found (only on first attempt)
                if retries == FILE_READWRITE_N_RETRIES { // Only create on the first try:
                    if let Some(parent) = file_path.parent() {
                        create_dir_all(parent)?;
                    }
                    let mut file = File::create(&file_path)?;
                    file.write_all(b"0")?;
                    return Ok(0);
                } else {
                    debug_log!("File not found. Retrying...");
                }
            }
            Err(e) => {
                debug_log!("IO error reading timestamp file: {}. Retrying...", e);
            }
        }

        if retries == 0 {
            debug_log!("Failed to read timestamp after multiple retries. Using default value 0.");
            return Ok(0); // Or return an appropriate error
        }

        retries -= 1;
        thread::sleep(pause_duration);  // Pause before retrying
    }
}

/// Gets the latest received file's `updated_at_timestamp` for a collaborator.
///
/// Crawls the team channel directory, finds TOML files owned by the collaborator,
/// extracts their `updated_at_timestamp`, and returns the latest one.  Returns 0 if no such files are found.
///
/// # Arguments
///
/// * `team_channel_name`: The team channel name.
/// * `collaborator_name`: The collaborator's name.
///
/// # Returns
///
/// * `Result<u64, ThisProjectError>`: The latest `updated_at_timestamp` or an error.
fn actual_latest_received_from_rc_file_timestamp(
    team_channel_name: &str,
    collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    let mut latest_timestamp = 0;
    let team_channel_path = PathBuf::from("project_graph_data/team_channels").join(team_channel_name);

    debug_log!(
        "read_latestreceivedfromme_file_timestamp_plaintextstatefile(): Starting GLRFRCFT team_channel_path: {:?}, collaborator_name: {}",
        team_channel_path, collaborator_name
    );

    // 1. Crawl the team channel directory:
    for entry in walkdir::WalkDir::new(team_channel_path) { // Use walkdir to traverse subdirectories
        let entry = entry?;
        let path = entry.path();

        // 2. Check for TOML files:
        if path.is_file() && path.extension().map_or(false, |ext| ext == "toml") {
            debug_log!("GLRFRCFT(): Found TOML file: {:?}", path);

            // 3. Read and parse the TOML file:
            match fs::read_to_string(path).and_then(|content| Ok(toml::from_str::<Value>(&content))) {
                Ok(toml_data) => {
                    debug_log!("GLRFRCFT(): Successfully parsed TOML file.");

                    // 4. Check file ownership:
                    if toml_data.clone()?.get("owner").and_then(Value::as_str) == Some(collaborator_name) {
                        debug_log!("GLRFRCFT(): File owned by collaborator.");

                        // 5. Extract and update latest_timestamp:
                        if let Some(timestamp) = toml_data?
                            .get("updated_at_timestamp")
                            .and_then(Value::as_integer)
                            .map(|ts| ts as u64)
                        {
                            debug_log!("GLRFRCFT(): Found updated_at_timestamp: {}", timestamp);

                            latest_timestamp = latest_timestamp.max(timestamp); // Keep the latest
                        } else {
                            debug_log!("GLRFRCFT(): 'updated_at_timestamp' field not found or invalid in TOML file: {:?}", path);
                        }
                    }
                }
                Err(e) => {
                    debug_log!("GLRFRCFT(): Error reading or parsing TOML file: {:?} - {}", path, e);
                    // Handle error as needed (e.g., log and continue, or return an error)
                    // return Err(ThisProjectError::from(e)); //Example: Return the error.
                    continue; // Or continue to the next file.
                }
            }
        }
    }

    debug_log!("GLRFRCFT(): End Returning latest timestamp: {}", latest_timestamp);

    Ok(latest_timestamp)
}

/// Sets the latest received file timestamp for a collaborator in a team channel, using a plain text file.
///
/// As another thread may be reading/writing the file, there 
/// is a random-wait retry system
///
/// This function writes the `timestamp` to a file at the specified path, creating the directory structure if needed.
///
/// # Arguments
///
/// * `team_channel_name`: The name of the team channel.
/// * `remote_collaborator_name`: The name of the collaborator.
/// * `timestamp`: The timestamp to set.
///
/// # Returns
///
/// * `Result<(), ThisProjectError>`: `Ok(())` on success, or a `ThisProjectError` if an error occurs.
fn write_save_latest_received_from_rc_file_timestamp_plaintext(
    team_channel_name: &str,
    remote_collaborator_name: &str,
    timestamp: u64,
) -> Result<(), ThisProjectError> {
    let mut file_path = PathBuf::from("sync_data");
    file_path.push(team_channel_name);
    file_path.push("latest_receivedfile_timestamps");
    file_path.push(remote_collaborator_name);
    file_path.push("latest_received_from_rc_filetimestamp.txt");

    // Create directory structure if it doesn't exist
    if let Some(parent) = file_path.parent() {
        create_dir_all(parent)?;
    }
    
    let mut retries = FILE_READWRITE_N_RETRIES;

    loop {
        // Random pause duration
        let pause_duration = Duration::from_secs(rand::thread_rng().gen_range(FILE_READWRITE_RETRY_SEC_PAUSE_MIN..=FILE_READWRITE_RETRY_SEC_PAUSE_MAX));
        
        // Attempt to write to the file
        match std::fs::write(&file_path, timestamp.to_string()) { // Note the &
            Ok(_) => return Ok(()), // Success! Exit the loop.
            Err(e) => {
                // Check if the directory structure exists and create it if it doesn't.
                // Create the directory *only* if the file write fails *and* it's due to a missing directory:
                if e.kind() == ErrorKind::NotFound && retries == FILE_READWRITE_N_RETRIES {
                    if let Some(parent) = file_path.parent() {
                        if let Err(dir_err) = create_dir_all(parent) {
                            debug_log!(
                                "Error creating directory: {}", 
                                dir_err
                            ); // Log and return the error if the directory can't be created.
                            return Err(ThisProjectError::IoError(dir_err)); // Return appropriate error
                        }
                    }

                }
                                                
                // Log the error before retrying
                debug_log!(
                    "Error writing timestamp to file: {}. Retrying... in write_save_latest_received_from_rc_file_timestamp_plaintext()", 
                    e
                );
            }
        }
        

        if retries == 0 { // Maximum retries reached. Return an error or use a default value as needed.
            debug_log!("Failed to write timestamp to file after multiple retries.");
            return Err(ThisProjectError::NetworkError("Failed to write timestamp after retries".into())); // Or return a more appropriate error
        }

        retries -= 1;
        thread::sleep(pause_duration); // Pause before the next retry
    }
}

#[derive(Debug)]
enum CompressionError {
    InvalidNetworkType,
    NetworkIndexOutOfRange,
}

/// Compresses network type and index into a single u8, strictly using 3 digits.
/// Hundreds digit: 0 for IPv4, 1 for IPv6.
/// Remaining digits (0-99): Network index.
///
/// # Arguments
///
/// * `network_type`: "ipv4" or "ipv6".
/// * `network_index`: The network index (0-99).
///
/// # Returns
///
/// * `Result<u8, CompressionError>`: The compressed byte (0-199), or an error if input is invalid.
fn compress_band_data_byte(
    network_type: &str,
    network_index: u8,
) -> Result<u8, CompressionError> {

    if network_index > 99 {
        return Err(CompressionError::NetworkIndexOutOfRange);
    }

    let hundreds_digit = match network_type {
        "ipv4" => 0,
        "ipv6" => 1,
        _ => return Err(CompressionError::InvalidNetworkType),
    };

    let band_byte = (hundreds_digit * 100) + network_index; // Combine using decimal places, not bitwise

    debug_log!("compress_band_data_byte(), band_byte: {}, (network_type, network_index) ({}, {})", band_byte, network_type, network_index);
    Ok(band_byte)
}

#[derive(Debug)]
enum DecompressionError {
    InvalidBandByte,
    InvalidIndex,
}

// Implement Display for DecompressionError to improve debug output:
impl std::fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressionError::InvalidBandByte => write!(f, "Invalid band byte value (must be 0-199)"),
            DecompressionError::InvalidIndex => write!(f, "Invalid network index (must be 0-99)"),
        }
    }
}
// Implement Error for DecompressionError for compatibility:
impl std::error::Error for DecompressionError {}

/// Decompresses network type and index from a u8 byte.
///
/// Hundreds digit: 0 for IPv4, 1 for IPv6.
/// Remaining digits (0-99):  Network index.
/// Returns an error for invalid input.  Handles errors explicitly with Result.
///
/// # Arguments
///
/// * `band_byte`: The compressed byte.
///
/// # Returns
///
/// * `Result<(String, u8), DecompressionError>`:  The network type and index, or a DecompressionError.
fn decompress_banddata_byte(band_byte: u8) -> Result<(String, u8), DecompressionError> {
    if band_byte >= 200 {
        debug_log!("decompress_banddata_byte(): Invalid band_byte: {} (must be 0-199).", band_byte);
        return Err(DecompressionError::InvalidBandByte);
    }

    let hundreds_digit = band_byte / 100;
    let network_index = band_byte % 100;

    if network_index > 99 { // Strict check as per the specification.
        debug_log!("decompress_banddata_byte(): Invalid index: {} (must be from 0-99).", network_index);
        return Err(DecompressionError::InvalidIndex); // Specific error for easier handling
    }

    let network_type = if hundreds_digit == 1 {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    };

    debug_log!("decompress_banddata_byte(), band_byte: {}: (network_type, network_index) ({}, {})", band_byte, network_type, network_index);
    Ok((network_type, network_index)) // Valid data: return Ok(data)
}

/// Sends a ReadySignal to the specified target address, selecting the IP address based on the network type.
/// goes to: their_rmtclb_ip
///     i.e. local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
///
/// Handles hash calculation, serialization, and sending the signal via UDP.
///
/// Args:
///     local_user_salt_list: A slice of `u128` salt values for hash calculation.
///     local_user_ipv4_address: The local user's IPv4 address.
///     local_user_ipv6_address: The local user's IPv6 address.
///     target_port: The target port on the remote machine.
///     last_received_timestamp: The timestamp of the last received file.
///     network_type: A string slice representing the network type ("ipv6" or "ipv4").
///     network_index: The index of the valid IP address in the local user's IP list (included in ReadySignal, but not used for IP selection).
///
/// Returns:
///     Result<(), ThisProjectError>: `Ok(())` on success, or a `ThisProjectError` if an error occurred.
fn send_ready_signal(
    local_user_salt_list: &[u128], // to make hash
    rc_network_type_string: String, // Remote collaborator's network type (ipv4, ipv6, etc.)
    rc_ip_addr_string: String, // Remote collaborator's IP string
    target_port: u16, // local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
    last_received_timestamp: u64, // last_received_timestamp
    local_user_network_type: &str, // LOU needed for .b section
    local_user_network_index: u8,  // LOU needed for .b section
) -> Result<(), ThisProjectError> {
    debug_log!("send_ready_signal()1: Starting...");

    // for ready_signal.b
    let b_band_data = match compress_band_data_byte(
        local_user_network_type, 
        local_user_network_index,
    ) {
        Ok(data) => data,
        Err(e) => {
            // Handle the error here. You could print an error message, return from the function,
            // or do something else depending on your specific needs.
            eprintln!("send_ready_signal()2: Error compressing band data: {:?}", e);
            return Ok(());
        }
    };
    
    // 1. Calculate hashes
    let current_timestamp = get_current_unix_timestamp();
    let hashes_result = calculate_ready_signal_hashes(
        last_received_timestamp,
        current_timestamp,
        b_band_data,
        local_user_salt_list,
    );
    let hashes = match hashes_result {
        Ok(h) => h,
        Err(e) => return Err(e),
    };

    // 2. Create ReadySignal 
    let ready_signal = ReadySignal {
        rt: last_received_timestamp,
        rst: current_timestamp,
        b: b_band_data,
        rh: hashes,
    };
    debug_log!("send_ready_signal()3: ReadySignal created: {:?}", ready_signal);

    // 3. Serialize
    let serialized_signal = serialize_ready_signal(&ready_signal)?;
    debug_log!("send_ready_signal()4: ReadySignal serialized.");

    // 4. Determine target IP based on network_type:
    let send_readysignal_ip_addr = match rc_network_type_string {
        value if value == "ipv6".to_string() => {
            let ipv6_addr: Ipv6Addr = rc_ip_addr_string.parse().map_err(|_| ThisProjectError::NetworkError("Invalid IPv6 address".into()))?; // Corrected: .parse()
            IpAddr::V6(ipv6_addr)
        },
        value if value == "ipv4".to_string() => {
            let ipv4_addr: Ipv4Addr = rc_ip_addr_string.parse().map_err(|_| ThisProjectError::NetworkError("Invalid IPv4 address".into()))?; // Corrected: .parse()
            IpAddr::V4(ipv4_addr)
        },
        _ => return Err(ThisProjectError::NetworkError("send_ready_signal() error Invalid network type".into())),
    };
    
    let target_addr = SocketAddr::new(send_readysignal_ip_addr, target_port);

    // 5. Send the signal
    debug_log!("send_ready_signal()4: Sending ReadySignal to: {:?}", target_addr);
    send_data(&serialized_signal, target_addr)?;
    debug_log!("send_ready_signal()5: ReadySignal sent successfully.");

    Ok(())
}

// draft based on 'send ready signal' function
/// Sends a Gotit to the specified target address.
fn send_gotit_signal(
    local_user_salt_list: &[u128], 
    local_user_ipv4_address: &Ipv4Addr,
    local_user_ipv6_address: &Ipv6Addr,
    network_type: &str,  // Add network type
    local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16,
    received_file_updatedat_timestamp: u64,
) -> Result<(), ThisProjectError> {
    /*
    struct GotItSignal {
        gst: Option<u64>, // send-time: 
            generate_terse_timestamp_freshness_proxy(); for replay-attack protection
        di: Option<u64>, // the 'id' is updated_at file timestamp 
            (because context= filesync timeline ID)
        gh: Option<Vec<u8>>, // N hashes of rt + re
    */
    
    let timestamp_for_gst = get_current_unix_timestamp();
    
    // Make hashes of gotit_signal fields:
    let gh_hashes = calculate_gotitsignal_hashlist(
        timestamp_for_gst, 
        received_file_updatedat_timestamp, // as di
        local_user_salt_list,
    );
    
    // Create the GotItSignal struct:
    let gotit_struct = GotItSignal {
        gst: timestamp_for_gst,
        di: received_file_updatedat_timestamp,
        gh: gh_hashes?, // Include calculated hashes
    };
    
    // 5. Serialize the ReadySignal
    let serialized_gotitsignal_data = serialize_gotit_signal(
        &gotit_struct
    ).expect("inHLOD send_gotit_signal() err Failed to serialize ReadySignal, gotit_signal_to_send_from_this_loop"); 

    // --- Inspect Serialized Data ---
    debug_log!("inHLOD send_gotit_signal() serialized_gotitsignal_data: {:?}", serialized_gotitsignal_data);

    // Determine target IP based on network_type
    let detected_lou_ip_addr = match network_type {
        "ipv6" => IpAddr::V6(*local_user_ipv6_address),
        "ipv4" => IpAddr::V4(*local_user_ipv4_address),
        _ => return Err(ThisProjectError::NetworkError("Invalid network type in send_gotit_signal".into())),
    };

    let target_addr = SocketAddr::new(
        detected_lou_ip_addr,
        local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip,
    );

    // Log before sending
    debug_log!(
        "inHLOD send_gotit_signal() Attempting to send ReadySignal to {}: {:?}", 
        target_addr, 
        local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip
    );

    // // If sending to the first address succeeds, no need to iterate further

    if send_data(&serialized_gotitsignal_data, target_addr).is_ok() {
        debug_log("inHLOD send_gotit_signal() 6. Successfully sent GotIt to {} (first address)");
        return Ok(()); // Exit the thread
    } else {
        debug_log("inHLOD send_gotit_signal() err 6. Failed to send GotIt to {} (first address)");
        return Err(ThisProjectError::NetworkError("Failed to send ReadySignal".to_string())); // Return an error
    }

    Ok(())
}

/// Set up the local owner users in-tray desk
/// requests to recieve are sent from here
/// other people's owned docs are received here
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
    
    // find a valid local owner ip address
    // e.g. to pass a single ip to later functions
    // set empty and fill later or exit
    // let local_user_ipv6_address: Option<Ipv6Addr> = find_valid_local_owner_ip_address(
    //     &local_owner_desk_setup_data.local_user_ipv6_addr_list,
    //     );

    // let local_user_ipv6_address = local_user_ipv6_address.ok_or(
    //     ThisProjectError::NetworkError("No valid local IPv6 address found".to_string()),
    // )?;
    // // set empty and fill later or exit
    // let mut local_user_ipv6_address: Ipv6Addr;
    
    // let option_localuseripv6address = find_valid_local_owner_ip_address(
    //     &local_owner_desk_setup_data.local_user_ipv6_addr_list,
    // );
    
    // if let Some(option_fill) = option_localuseripv6address {
    //     // Use the valid IPv6 address
    //     local_user_ipv6_address = option_fill;

    // } else {
    //     // Handle the case where no valid IPv6 address was found
    //     return Err(ThisProjectError::NetworkError("No valid local IPv6 address found".to_string()));  // Or another appropriate error
        
    //     // TODO: maybe signal uma to hault
    // }
    
    debug_log("HLOD Starting the handle_local_owner_desk()");
    
    
    // Clone the values
    let salt_list_1 = local_owner_desk_setup_data.local_user_salt_list.clone();
    let salt_list_2 = local_owner_desk_setup_data.local_user_salt_list.clone();

    let readyport_1 = local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip.clone();
    let readyport_2 = local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip.clone();    
    let localowner_gotit_port = local_owner_desk_setup_data.local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip.clone();
    
    let remote_collaborator_name = local_owner_desk_setup_data.remote_collaborator_name.clone();
                
    debug_log("HLOD setup: cloned values.");
                
    // Instead of storing Option<&Ipv6Addr>, store the owned Ipv6Addr
    // let local_user_ipv6_address_2 = local_user_ipv6_address.clone();
    
    
    /*
    Works but moving to new more future-proofed system
    */
    
    // let ipv6_addr_list = local_owner_desk_setup_data.local_user_ipv6_addr_list.clone();

    // // Clone the address when extracting it
    // if let Some(addr) = ipv6_addr_list.get(0) {
    //     ipv6_addr_1 = Some(*addr); // Dereference and clone the IPv6 address
    //     ipv6_addr_2 = Some(*addr);
    // }
    
    /////////////////////////////////////////
    // Band: Load Network Band Configuration
    /////////////////////////////////////////
    /*
    Load from sync state files:
    - network_type
    - network_index
    - this_ipv4
    - this_ipv6
    
    nt/ni (typd/index) will be used for making and sending ReadySignal structs
    network Type + ipv6/ipv4 will be used to listen for files
    
    */
    
    
    
    // Load local owner band configuration data
    let (
        band_local_network_type, 
        band_local_network_index, 
        band_local_user_ipv4_address, 
        band_local_user_ipv6_address,
    ) = match read_band__network_config_type_index_specs() {
        Ok(data) => data,
        Err(e) => {
            // Handle the error (e.g., log and return or use default values)
            debug_log!("Error reading band configuration: error -> e'{}'e ", e);
            return Err(e); // Or handle differently
        }
    };
    debug_log("HLOD setup: read_band__network_config_type_index_specs() run");
    
    /////////////
    // Bootstrap
    /////////////
    /*
    HLOD needs is the (ip string, type string) to use with two actions:
        their_rmtclb_ip -> local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: local_ports.ready_port,
                           localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: local_ports.intray_port,
        their_rmtclb_ip -> local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: local_ports.gotit_port,
        
    ready and gotit are aimed at the RC ip.
    */
    let Ok((rc_network_type_string, rc_ip_addr_string)) = hlod_udp_handshake__rc_network_type_rc_ip_addr(
        &local_owner_desk_setup_data, //: &ForLocalOwnerDeskThread,
        &band_local_network_type, //: &str,
        &band_local_user_ipv4_address, //: &Ipv4Addr,
        &band_local_user_ipv6_address, //: &Ipv6Addr,
        band_local_network_index, //: u8,
    ) else { 
        // TODO, handled another way?
        return Err(ThisProjectError::NetworkError("Handshake failed".into())); 
        };
    debug_log("HLOD setup: hlod_udp_handshake__rc_network_type_rc_ip_addr() run");

    
    // let (
    //     network_type,
    //     network_index,
    //     this_ipv4,
    //     this_ipv6,
    //     ) = read_band__network_config_type_index_specs();
    
    
    // // 1. Use find_valid_local_owner_ip_address to get a valid address or an error.    
    // let local_user_ipv6_address = find_valid_local_owner_ipv6_address(
    //     &local_owner_desk_setup_data.local_user_ipv6_addr_list
    // )
    //     .ok_or(ThisProjectError::NetworkError("No valid local IPv6 address found".to_string()))?;
        
    
    // let option_ipindexint = read_sync_state_ip_availability_data();
    
    // let ip_index_int = match option_ipindexint {
    //     Ok(Some(Ok(ip_index))) => {
    //         match get_ip_by_index(
    //             ip_index,
    //             &local_owner_desk_setup_data.local_user_ipv4_addr_list,
    //             &local_owner_desk_setup_data.local_user_ipv6_addr_list,
    //         ) {
    //             Some(ip_addr) => ip_addr,
    //             None => {
    //                 // Handle the error case here
    //                 // Return a default value
    //                 std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    //             }
    //         }
    //     }
    //     _ => {
    //         // Handle the error case here
    //         // Return a default value
    //         std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    //     }
    // };
        
        
    
    // //
    // let local_user_ipv6_address = get_ip_by_index(
    //     ip_index_int, // as int_index
    //     &local_owner_desk_setup_data.local_user_ipv4_addr_list, // for ipv4_list, 
    //     &local_owner_desk_setup_data.local_user_ipv6_addr_list, // for ipv6_list, 
    // );
    
    
    
    
    
    // starting with ipv4 len and ipv6 len, see which list the ip is in,
    // and return the list item
    // challenge: the type of the output: ipv4 and ipv6 are not the same type



    // // get index of valid IP v6
    // let ip_index = get_index_byof_ip(
    //     &local_owner_desk_setup_data.local_user_ipv6_addr_list, // as ip_list
    //     &local_user_ipv6_address, // as ip_address
    // );

    // debug_log!(
    //     "Found IP/index <{:?} {:?}>", 
    //     local_user_ipv6_address, 
    //     ip_index
    // );

    // // set ipv6 state-file
    // // path: sync_data/ip.toml
    // write_local_band__save_network_band__type_index(
    //     ip_index.expect("REASON"),
    // );

    loop { // 1. start overall loop to (re)start whole desk
        debug_log("HLOD 1. start overall loop to (re)start whole desk");
        
        
        // 1. Create lookup table:
        let channel_dir_path_str = read_state_string("current_node_directory_path.txt")?; // read as string first
        debug_log!("1. Channel directory path (from session state): {}", channel_dir_path_str); 
        
        // use absolute file path
        let team_channel_path = PathBuf::from(channel_dir_path_str);
        let hashtable_node_id_to_path = create_node_id_to_path_lookup(&team_channel_path)?;

        let remote_collaborator_name_for_thread_1 = remote_collaborator_name.clone();
        let remote_collaborator_name_for_thread_2 = remote_collaborator_name.clone();
        let salt_list_1_drone_clone = salt_list_1.clone();

        // 1.1 check for halt/quit uma signal
        if should_halt_uma() {
            debug_log!("should_halt_uma(), exiting Uma in handle_local_owner_desk()");
            break Ok(());

        }

        // --- Get team channel name ---
        let team_channel_name = match get_current_team_channel_name_from_cwd() {
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

        // Drone Loop in a thread? TODO
        
        /*
        Balancing Accuracy and efficiency:
        the first time in a session the drone loop will use the full search
        to find the most recent file timestamp,
        but thereafter 
        the value is saved in a quasi-state or state.
        */

        // initialization
        let mut latest_received_from_rc_file_timestamp = match actual_latest_received_from_rc_file_timestamp(
            &team_channel_name, // Correct argument order.
            &remote_collaborator_name_for_thread_1,
        ) {
            Ok(temp_extractor) => temp_extractor, 
            Err(e) => {
                debug_log!("HLOD Error getting timestamp via actual_latest_received_from_rc_file_timestamp: e'{}'e. Using 0.", e);
                0 // Use a default timestamp (0) if an error occurs.
            }
        };
        debug_log!(
            "HLOD: latest_received_from_rc_file_timestamp -> {:?}",
            latest_received_from_rc_file_timestamp,
        );

        // initialization
        // update state: latest received timestamp
        write_save_latest_received_from_rc_file_timestamp_plaintext(
            &team_channel_name, // for team_channel_name
            &remote_collaborator_name.clone(), // for collaborator_name
            latest_received_from_rc_file_timestamp, // for timestamp
        );
        
        // clone to avoid closure issues:
        let band_local_network_type_clone = band_local_network_type.clone();
        let salty_the_clone_list = local_owner_desk_setup_data.local_user_salt_list.clone();
        
        let rc_ip_addr_string_1 = rc_ip_addr_string.clone();
        let rc_network_type_string_1 = rc_network_type_string.clone();
        
        // --- 1.5 Drone Loop to Send ReadySignals ---
        let ready_thread = thread::spawn(move || {
            ////////////////////////////////////
            // Drone Loop to Send ReadySignals  (hlod)
            //////////////////////////////////
            loop {
                
                // 1.1 Wait (and check for exit Uma)  this waits and checks N times: for i in 0..N {
                for i in 0..10 {
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
                // get timestamp of the file you (local owner user) recieved most recently from the RC
                // remote collaborator in this team-channel. 
                /*
                @
                sync_data/{team_channel}/latest_receivedfile_timestamps/bob/latest_receivedfromme_file_timestamp
                */

                latest_received_from_rc_file_timestamp = match read_rc_latest_received_from_rc_filetimestamp_plaintextstatefile(
                    &team_channel_name,
                    &remote_collaborator_name_for_thread_2,
                ) {
                    Ok(temp_extractor) => temp_extractor, 
                    Err(e) => {
                        debug_log!("HLOD GotItSignal Error getting timestamp via get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl: e'{}'e. Using 0.", e);
                        0 // Use a default timestamp (0) if an error occurs.
                    }
                };
                debug_log!(
                    "HLOD drone loop (ready-signals) latest_received_from_rc_file_timestamp -> {:?}",
                    latest_received_from_rc_file_timestamp,
                );
        
                // 1.3 Send Ready Signal (using a function)
                send_ready_signal(
                    &salty_the_clone_list, // local_user_salt_list: &[u128], 
                    rc_network_type_string_1.clone(), // local_user_ipv4_address: &Ipv4Addr, 
                    rc_ip_addr_string_1.clone(), // local_user_ipv6_address: &Ipv6Addr, 
                    local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
                    latest_received_from_rc_file_timestamp, // last_received_timestamp: u64, // for rst
                    &band_local_network_type_clone, // network_type: String, // for nt
                    band_local_network_index, //network_index: u8, // for ni
                );
                                    
                // if let Some(addr_1) = ipv6_addr_1 {
                //     send_ready_signal(
                //         &salt_list_1_drone_clone,
                //         &addr_1,
                //         readyport_1,
                //         latest_received_from_rc_file_timestamp,
                //         false,
                //     );
                // }

                debug_log!("\n");
            } // end drone loop (ready-signals)
        }); // end ready_thread

        //////////////////////////////
        // 3. InTrayListerLoop Start
        ////////////////////////////

        // 3.1 intrystruct_hash_set_session_nonce = HashSet::new() as protection against replay attacks Create a HashSet to store received hashes
        let mut intrystruct_hash_set_session_nonce = HashSet::new();  // Create a HashSet to store received hashes
        
        // to discard duplicate files already saved
        // TODO: to scale this should be perhaps a stub-file flag
        let mut file_hash_set_session_nonce = HashSet::new();  // Create a HashSet to store received hashes
        
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
            /*
            band_local_network_type, 
            band_local_user_ipv4_address, 
            band_local_user_ipv6_address,
            */
            debug_log("HLOD Creating intray socket listening UDP...");
            let intray_socket = create_local_udp_socket(
                &band_local_network_type, 
                &band_local_user_ipv4_address, 
                &band_local_user_ipv6_address,
                local_owner_desk_setup_data.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            )?;
            debug_log!("HLOD: Intray socket created.");            
            
            
            
            // debug_log("HLOD Creating intray socket listening UDP...");
            // let intray_socket = create_rc_udp_socket(
            //     &local_owner_desk_setup_data.local_user_ipv6_addr_list,
            //     local_owner_desk_setup_data.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            // )?;
            // debug_log!("HLOD: Intray socket created.");

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
                            debug_log("HLOD-InTray 2.3 SendFile listener: Receive File Data...do you copy, gold leader... >*<");

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
                        if intrystruct_hash_set_session_nonce.contains(&incoming_intray_file_struct_hash_vec) {
                            debug_log!("HLOD 4.2 quasi nonce check: Duplicate SendFile received (hash match). Discarding.");
                            continue; // Discard the duplicate signal
                        }
                        intrystruct_hash_set_session_nonce.insert(incoming_intray_file_struct_hash_vec); // Add hash to the set
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
                    let extracted_clearsigned_file_data = match extract_clearsign_data(&decrypted_clearsignfile_data) {
                        Ok(data) => data,
                        Err(e) => {
                            debug_log!("HLOD 6.3: Clearsign extraction failed: {}. Skipping.", e);
                            continue;
                        }
                    };
                    debug_log!(
                        "HLOD 6.3 extracted_clearsigned_file_data -> {:?}",
                        extracted_clearsigned_file_data
                    );
                    
                    // 7 Save File into Uma Folder Structure
                    // let received_toml: Value = toml::from_slice(&extracted_clearsigned_file_data)?;
                    /*
                    1. if X then save in A place
                    2. if Y then save in B place
                    for a message file, 
                    filepath_in_node = "/instant_message_browser"
                    for MVP: just add it the same way you add any message, next available number.
                    
                    current_path = project_graph_data/team_channels/{}/instant_message_browser/
                    
                    let incoming_file_path = get_next_message_file_path(current_path, local_owner_user); 
                    */
                    // 7.1 1. Identifying Instant Message Files
                    let file_str = std::str::from_utf8(&extracted_clearsigned_file_data).map_err(|_| {
                        ThisProjectError::InvalidData("Invalid UTF-8 in file content".into())
                    })?;
                    
                    
                    debug_log!(
                        "HLOD 7.1 found message file, file_str -> {:?}",
                        file_str
                    );
                    
                    let mut incoming_file_path: PathBuf = PathBuf::from("project_graph_data/team_channels");
                    
                    let team_channel_name = get_current_team_channel_name_from_cwd()
                        .ok_or(ThisProjectError::InvalidData(
                            "Unable to get team channel name".into())
                        )?;
                
                    // TODO for now only handling IM and Node files
                    if file_str.contains("filepath_in_node = \"/instant_message_browser\"") {
                        debug_log!("HLOD-InTray: an instant message file.");

                        // 7.2 
                        // 2. Generating File Path

                        let mut current_path = PathBuf::from("project_graph_data/team_channels");
                        current_path.push(&team_channel_name);
                        current_path.push("instant_message_browser");
                        
                        incoming_file_path = get_next_message_file_path(
                            &current_path, 
                            &local_owner_desk_setup_data.remote_collaborator_name // local user name
                        );
    
                        debug_log!(
                            "HLOD 7.2 got-made incoming_file_path -> {:?}",
                            incoming_file_path
                        );

                        // check: see if this same file was already saved
                        // 1. Calculate the hash of the received file content using the *local* user's salts and the *raw bytes*:
                        let received_file_hash_result = calculate_pearson_hashlist_for_string( // Use a byte-oriented hash function
                            &file_str,  // Hash the raw bytes
                            &local_owner_desk_setup_data.local_user_salt_list, // Use *local* user's salts
                        );

                        let received_file_hash = match received_file_hash_result {
                            Ok(hash) => hash,
                            Err(e) => {
                                debug_log!("Error calculating hash for received file: {}", e);
                                continue; // Skip to next file if hashing fails
                            }
                        };

                        // 2. Check for duplicates and insert the hash (as before)
                        if file_hash_set_session_nonce.contains(&received_file_hash) {
                            debug_log!("Duplicate file received (hash match). Discarding.");
                            continue; // Discard the duplicate file
                        }
                        file_hash_set_session_nonce.insert(received_file_hash); // Insert BEFORE saving

                        // 3. Saving the File
                        if let Err(e) = fs::write(&incoming_file_path, &extracted_clearsigned_file_data) {
                            debug_log!("HLOD-InTray: Failed to write message file: {:?}", e);
                            // Consider returning an error here instead of continuing the loop
                            return Err(ThisProjectError::from(e));
                        }
                        
                        debug_log!("7.3 HLOD-InTray: IM message file saved to: {:?}", incoming_file_path);
                    }
                    
                    
                    // TODO for now only handling IM and Node files
                    if file_str.contains("node_unique_id = \"") {
                        debug_log!("HLOD-InTray: an Ode file. (Grecian Urn...you know.)");

                        // 7.2 
                        // 2. Generating File Path
                        // attach to absolute path: TODO
                        
                        // Extract directory_path:
                        let new_node_directory_path_result = file_str
                            .lines()  // Iterate over lines
                            .find_map(|line| { // Use find_map to extract and parse in one step
                                if line.starts_with("directory_path = \"") && line.ends_with("\"") {
                                    let path_str = &line["directory_path = \"".len()..line.len() - 1];
                                    Some(PathBuf::from(path_str))
                                } else {
                                    None
                                }
                            });

                        let node_file_path = match new_node_directory_path_result {
                            Some(path) => path,
                            None => {
                                debug_log!("'directory_path' not found or invalid format in node.toml");
                                continue; // Or handle error as you see fit
                            }
                        };

                        // get absolute path
                        let new_full_abs_node_directory_path = PathBuf::from(node_file_path);
                        
                        // make sure path exists
                        fs::create_dir_all(&new_full_abs_node_directory_path)?;
                        
                        debug_log!(
                            "HLOD 7.2 got-made new_full_abs_node_directory_path -> {:?}",
                            &new_full_abs_node_directory_path
                        );
                        
                        let new_node_toml_file_path = new_full_abs_node_directory_path.join("node.toml"); // Path to the new node.toml
                        
                        debug_log!(
                            "HLOD 7.2 got-made new_node_toml_file_path -> {:?}",
                            &new_node_toml_file_path
                        );

                        // check: see if this same file was already saved
                        // 1. Calculate the hash of the received file content using the *local* user's salts and the *raw bytes*:
                        let received_file_hash_result = calculate_pearson_hashlist_for_string( // Use a byte-oriented hash function
                            &file_str,  // Hash the raw bytes
                            &local_owner_desk_setup_data.local_user_salt_list, // Use *local* user's salts
                        );

                        let received_file_hash = match received_file_hash_result {
                            Ok(hash) => hash,
                            Err(e) => {
                                debug_log!("Error calculating hash for received file: {}", e);
                                continue; // Skip to next file if hashing fails
                            }
                        };

                        // 2. Check for duplicates and insert the hash (as before)
                        if file_hash_set_session_nonce.contains(&received_file_hash) {
                            debug_log!("Duplicate file received (hash match). Discarding.");
                            continue; // Discard the duplicate file
                        }
                        file_hash_set_session_nonce.insert(received_file_hash); // Insert BEFORE saving

                        
                        /////////////////
                        // Move or Save
                        ////////////////
                        /*
                        1. Make a hash-table of node files' unique ID in session/team-channel: id: path lookup 
                        2. check this node uniqeu ID
                        3. if this node is an existing node:
                        4. remove the old path
                        5. (re)save at the new path
                        */
                        
                        // 2. Access node data (must match `node_unique_id_str` from `create_node_id_to_path_lookup`):
                        let node_unique_id_str_result = extract_string_from_toml_bytes(&extracted_clearsigned_file_data, "node_unique_id");
                        // ?
                        // let new_node_dir_path_str = match extract_string_from_toml_bytes(received_file_bytes, "directory_path") {
                        //     Ok(s) => s,
                        //     Err(_) => return Err(ThisProjectError::InvalidData("directory_path field missing from node file".into())),
                        // };
                        
                        match node_unique_id_str_result {
                            Ok(node_unique_id_str) => { // Node exists, handle move/replace:
                                /*
                                Establish Variables
                                1. new node directory path (get) - Done Above
                                    new_full_abs_node_directory_path
                                    
                                2. new node file path (matke) - Done Above
                                    new_node_toml_file_path
                                
                                Look for (opposite make/get order from above): 
                                3. Old node file path (get)
                                4. old node directory path (make)
                                
                                If no old path: 
                                5A. make new directory, 
                                6A. save new file
                                
                                If old path exists:
                                5B. remove OLD node FILE (just the file, not the directory)
                                6B. save (relace) new node file in old directory
                                7. recoursively move the old directory to the NEW directory path
                                                                
                                */
                                // Use the node_unique_id_str
                                
                                // let new_node_dir_path = PathBuf::from(new_node_dir_path_str);
                                // let new_node_toml_path = new_node_dir_path.join("node.toml"); // Path to the new node.toml

                                // Get old node.toml file path (if exists)
                                if let Some(olddir_existing_node_directory_path) = hashtable_node_id_to_path.get(&node_unique_id_str) {

                                    // make old directory path
                                    let olddir_abs_node_directory_path = PathBuf::from(olddir_existing_node_directory_path);
                                    
                                    debug_log!(
                                        "HLOD 7.2 got-made olddir_abs_node_directory_path -> {:?}",
                                        &olddir_abs_node_directory_path
                                    );

                                    let oldfile_node_toml_file_path = olddir_abs_node_directory_path.join("node.toml"); // Path to the new node.toml

                                    debug_log!(
                                        "HLOD 7.2 got-made oldfile_node_toml_file_path -> {:?}",
                                        &oldfile_node_toml_file_path
                                    );                                    
                                                                                          
                                    // 3.2 replace (delete the old) node.toml file (file, not directory)
                                    // Write the received data to the OLD node.toml location, replacing it:
                                    if let Err(e) = fs::write(&oldfile_node_toml_file_path, &extracted_clearsigned_file_data) {
                                        debug_log!("Error writing node.toml: {:?} - {}", &oldfile_node_toml_file_path, e);
                                        return Err(ThisProjectError::from(e));
                                    }

                                    // 3.3 Move old node directory (not remove/delete) (directory, not file)
                                    // TODO HERE HERE
                                    // from olddir_abs_node_directory_path to new_full_abs_node_directory_path
                                    if let Err(error) = move_directory__from_path_to_path(&olddir_abs_node_directory_path, &new_full_abs_node_directory_path) {
                                        debug_log!("An error occurred: {}", error);
                                    }
                                    
                                    debug_log!("7.3 HLOD-InTray: moved file moved from: {:?}", &olddir_abs_node_directory_path);
                                    debug_log!("7.3 HLOD-InTray: moved-new file saved to: {:?}", &new_full_abs_node_directory_path);

                                } else {
                                    // Node is new, save it:
                                    // 3. Unpacking/Saving the File as node.toml file
                                    
                                    match unpack_new_node_save_toml_and_create_dir(
                                        &extracted_clearsigned_file_data, 
                                        &new_full_abs_node_directory_path
                                    ) {
                                        Ok(_) => debug_log("Node unpacked and saved successfully."),
                                        Err(e) => debug_log!("Error unpacking node: {}", e),
                                    }
                                    
                                    debug_log!("7.3 HLOD-InTray: new file saved to: {:?}", new_full_abs_node_directory_path);
                                    
                                    // unpack_new_node_save_toml_and_create_dir(
                                    //     &extracted_clearsigned_file_data,
                                    //     &new_full_abs_node_directory_path,
                                    // );
                                    
                                    // if let Err(e) = fs::write(
                                    //     &new_node_toml_file_path, 
                                    //     &extracted_clearsigned_file_data
                                    // ) {
                                    //     debug_log!("HLOD-InTray: Failed to write message file: {:?}", e);
                                    //     // Consider returning an error here instead of continuing the loop
                                    //     return Err(ThisProjectError::from(e));
                                    // }
                                }
                            }
                            Err(e) => {
                                // Handle error
                                continue;
                            }
                        }   
                    }  
                    
                    

                      /////////////
                     // Echo Base
                    /////////////
                    /*
                    After a file is received and saved
                    a miniature ReadySignal is sent out
                    using the timestamp of the 'current file' as the latest file
                    and saving that in state
                    so that the drone-loop (above) sending ready signals will also know
                    there is a new latest-date
                    */

                    // Extract timestamp
                    let received_file_updatedat_timestamp = match extract_updated_at_timestamp(
                        &extracted_clearsigned_file_data
                    ) {
                        Ok(temp_extraction_timestamp) => temp_extraction_timestamp,
                        Err(e) => {
                            debug_log!("HLOD-InTray: Error extracting timestamp: {}. Skipping.", e);
                            continue;
                        }
                    };

                    // update state: latest received timestamp
                    write_save_latest_received_from_rc_file_timestamp_plaintext(
                        &team_channel_name, // for team_channel_name
                        &local_owner_desk_setup_data.remote_collaborator_name, // for collaborator_name
                        received_file_updatedat_timestamp, // for timestamp
                    );

                    // Now you have the received_file_updatedat_timestamp timestamp
                    debug_log!("7.3 HLOD-InTray: Received file was updated_at: {}", received_file_updatedat_timestamp);
                    // println!("Received file updated at: {}", received_file_updatedat_timestamp);
                    
                    // 1.4 Send Echo Ready Signal (using a function)
                    /*
                    struct GotItSignal {
                        gst: Option<u64>, // send-time: 
                            generate_terse_timestamp_freshness_proxy(); for replay-attack protection
                        di: Option<u64>, // the 'id' is updated_at file timestamp 
                            (because context= filesync timeline ID)
                        gh: Option<Vec<u8>>, // N hashes of rt + re
                    */

                    debug_log("7.3 HLOD-InTray: send_gotit_signal ");
                    send_gotit_signal(
                        &local_owner_desk_setup_data.local_user_salt_list,
                        &band_local_user_ipv4_address, // local_user_ipv4_address: &Ipv4Addr, 
                        &band_local_user_ipv6_address, // local_user_ipv6_address: &Ipv6Addr, 
                        &band_local_network_type, // network_type: String, // for nt
                        localowner_gotit_port,
                        received_file_updatedat_timestamp, // as di
                    );
                    
                    
                    //
                    


                    // 1.4 Send Echo Ready Signal (using a function)
                    // 2nd copy for other threads
                    let rc_network_type_string_2 = rc_network_type_string.clone();
                    let rc_ip_addr_string_2 = rc_ip_addr_string.clone();
                        
                    // TODO: how long?
                    // this lets last item run
                    thread::sleep(Duration::from_secs(5));
                    thread::sleep(Duration::from_secs(3));
                                 
                    send_ready_signal(
                        &local_owner_desk_setup_data.local_user_salt_list, // local_user_salt_list: &[u128], 
                        rc_network_type_string_2, // Remote collaborator's network type (ipv4, ipv6
                        rc_ip_addr_string_2,  // Remote collaborator's IP string
                        local_owner_desk_setup_data.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
                        received_file_updatedat_timestamp, // last_received_timestamp: u64, // for rst
                        &band_local_network_type, // network_type: String, // for nt
                        band_local_network_index, //network_index: u8, // for ni
                    )?;
                    // if let Some(addr_2) = ipv6_addr_2 {
                    //     send_ready_signal(
                    //         &salt_list_2,
                    //         &addr_2,
                    //         readyport_2,
                    //         received_file_updatedat_timestamp,
                    //         false,
                    //     );
                    // }
                
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
    debug_log(">*< Halt signal received. Exiting The Uma. Closing... handle_local_owner_desk() |o|");
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
// fn serialize_ready_signal(this_readysignal: &ReadySignal) -> std::io::Result<Vec<u8>> {
//     let mut bytes = Vec::new();

//     // Handle rt (timestamp) -  return an error if None:
//     if let Some(rt) = this_readysignal.rt {
//         bytes.extend_from_slice(&rt.to_be_bytes()); 
//     } else {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData, 
//             "Missing timestamp (rt) in ReadySignal",
//         )); 
//     }

//     // Handle rst (send timestamp) - return an error if None: 
//     if let Some(rst) = this_readysignal.rst {
//         bytes.extend_from_slice(&rst.to_be_bytes()); 
//     } else {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData, 
//             "Missing send timestamp (rst) in ReadySignal",
//         )); 
//     }

//     // Handle re (echo_send) -  use a default value (false) if None:
//     let re = this_readysignal.re.unwrap_or(false); // Default to false if None
//     bytes.push(if re { 1 } else { 0 }); 

//     // Handle rh (hash list) - append if Some:
//     if let Some(rh) = &this_readysignal.rh {
//         bytes.extend_from_slice(rh);
//     }
 
//     Ok(bytes) 
// }

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
///
///  "Data length" refers to verifying that the received byte slice 
/// has enough bytes to successfully extract all the fields of the 
/// ReadySignal struct. If the byte slice is too short,
///  attempting to access elements outside its bounds will lead to a "panic".
///
/// Do not attempt to use Serde crate with this function!!!
fn deserialize_ready_signal(bytes: &[u8], salt_list: &[u128]) -> Result<ReadySignal, ThisProjectError> {
    // 1. Calculate the expected minimum length, *including* the hash list.
    /*
    rt: u64, // ready signal timestamp: last file obtained timestamp
    rst: u64, // send-time: generate_terse_timestamp_freshness_proxy(); for replay-attack protection
    b: u8, // Network Index (e.g. which ipv6 in the list)
    rh: Vec<u8>, // N hashes of rt + re
    */
    let timestamp_len = std::mem::size_of::<u64>();         // Length of a u64 (8 bytes)
    let band_index_len = std::mem::size_of::<u8>();           // Length of the band index (1 byte)
    let hash_list_len = salt_list.len() * std::mem::size_of::<u8>(); // Length of the hash list (4 bytes in current design: 4 salts * 1 byte/hash)
    let expected_len = timestamp_len * 2 + band_index_len + hash_list_len; // Total expected length

    // 2. Full Length Check
    if bytes.len() != expected_len {  // Note: Now a strict equality check
        return Err(ThisProjectError::InvalidData(format!("Invalid byte array length for ReadySignal. Expected: {}, Received: {}", expected_len, bytes.len())));
    }

    // 3. Extract rt (receive timestamp)
    let rt = u64::from_be_bytes(bytes[0..timestamp_len].try_into().map_err(|_| ThisProjectError::InvalidData("Failed to convert rst bytes to u64".into()))?);
    
    
    // 4. Extract rst (send timestamp)
    let rst_start = timestamp_len;
    let rst_end = rst_start + timestamp_len;
    if bytes.len() < rst_end {
        return Err(ThisProjectError::InvalidData("Data too short for rst".into()));
    }
    let rst_bytes = &bytes[rst_start..rst_end];
    let rst = u64::from_be_bytes(rst_bytes.try_into().map_err(|_| ThisProjectError::InvalidData("Failed to convert rst bytes to u64".into()))?);


    // 6. Extract b (network index) -- u8
    let b_start = rst_start + timestamp_len;
    if bytes.len() <= b_start {  // Check length *before* access
        return Err(ThisProjectError::InvalidData("Data too short for b".into()));
    }
    let b = bytes[b_start];  // Directly access as u8
    
    // 7. Extract rh (hash list) – Length Check
    let rh_start = b_start + 1;  // one byte for b
    let rh_end = rh_start + hash_list_len;
    if bytes.len() < rh_end {
        return Err(ThisProjectError::InvalidData("Data too short for rh".into()));
    }
    let rh = bytes[rh_start..rh_end].to_vec();
    
    Ok(ReadySignal { rt, rst, b, rh })
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

fn serialize_gotit_signal(signal: &GotItSignal) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&signal.gst.to_be_bytes()); // gst is now u64, no expect needed
    bytes.extend_from_slice(&signal.di.to_be_bytes());  // di is now u64, no expect needed
    bytes.extend_from_slice(&signal.gh);             // gh is now Vec<u8>, no Option

    Ok(bytes)
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
    remote_collaborator_name: &str,
    mut session_send_queue: SendQueue,
    ready_signal_rt_timestamp: u64,
    bootstrap_sendqueue: bool,
) -> Result<SendQueue, ThisProjectError> {
    /*
    
    TODO is this checking for fail-flag dates...or is the done before calling this?
    
    #[derive(Debug, Clone)]
    struct SendQueue {
        back_of_queue_timestamp: u64,
        // echo_send: bool, //
        items: Vec<PathBuf>,  // ordered list, filepaths
    }
    */
    // let mut back_of_queue_timestamp = session_send_queue.back_of_queue_timestamp.clone();
    debug_log!(
        "inHRCD->get_or_create_send_queue 1: start;  ready_signal_rt_timestamp -> {:?}",
        ready_signal_rt_timestamp   
    );
    
    /*
    Conditions for making a new send_queue
    
    1. First Time Bootstrap
    
    2. Backtrack Order: If the ready_signal_rt_timestamp is older 
       than session_send_queue.back_of_queue_timestamp
       indicating that the user is requesting a back-track.
    
    3. Prefail Flag Check: If there is a fail flag, 
       remake the queue with that timestamp
    
    'normally' only one queue is ever made, 
    and that queue most-times remains empty with nothing sent
    unless and until a new local-owned-filed is made and added to the queue
    which should be checked for ~last.
    */
    let mut make_a_new_queue_flag = false;
    if bootstrap_sendqueue {
        make_a_new_queue_flag = true;
    }
    debug_log!(
        "inHRCD->get_or_create_send_queue: bootstrap_sendqueue={:?}, make_a_new_queue_flag={:?}",
        bootstrap_sendqueue,
        make_a_new_queue_flag
    );
    /*
    It is not clear that this comparison needs to be done:
    ready_signal_rt_timestamp == session_send_queue.back_of_queue_timestamp
    
    because preset-fail-flags are set, moving ahead cannot be done
    unless a confirmed gotit recept (of a confirmed file recept) happens.
    changing the back_of_queue_timestamp date may have no advanstage
    (or maybe some use will be discovered, likely it is not harmful)
    */

    debug_log("inHRCD->get_or_create_send_queue  checking: ready_signal_rt_timestamp < back_of_queue_timestamp");
    // Backtrack Order
    // if remote collaborator requests a reset to an older time (ah, those were the days...)
    // set the back_of_queue_timestamp to be sent .rt time ... if the .rt is older
    if ready_signal_rt_timestamp < session_send_queue.back_of_queue_timestamp {
        session_send_queue.back_of_queue_timestamp = ready_signal_rt_timestamp;
        make_a_new_queue_flag = true;
        debug_log("inHRCD->get_or_create_send_queue: found: ready_signal_rt_timestamp < back_of_queue_timestamp, make_a_new_queue_flag = true");
    }

    ///////////////////////////////////
    // Prefail Flag Check on Isle Five
    ///////////////////////////////////
    match get_oldest_sendfile_prefailflag_rt_timestamp_or_0_w_cleanup(&remote_collaborator_name) {
        Ok(oldest_prefail_flag_rt_timestamp) => {
            // 2. Now you can compare: (zero means no timestamps exist)
            if oldest_prefail_flag_rt_timestamp != 0 {
                // 3. Reset the send queue:
                session_send_queue = SendQueue {
                    back_of_queue_timestamp: oldest_prefail_flag_rt_timestamp,
                    items: Vec::new(),
                };
                debug_log!("inHRCD->get_or_create_send_queue  Resetting send queue using timestamp from flag: {}", oldest_prefail_flag_rt_timestamp);
                debug_log("inHRCD->get_or_create_send_queue: found: prefailflag(s), make_a_new_queue_flag = true");
                make_a_new_queue_flag = true
            } else {
                debug_log("inHRCD->get_or_create_send_queue  No retry flags found. Using ReadySignal timestamp.");
                // Handle the case where no pre-fail flags were found. Perhaps use the timestamp from the ready signal?
                session_send_queue.back_of_queue_timestamp = ready_signal_rt_timestamp
            }
        }
        Err(e) => {
            // 4. Handle the error:
            debug_log!("inHRCD->get_or_create_send_queue  Error getting oldest retry timestamp: {}", e);
            // Decide how to handle the error. You might:
            // - continue; // Skip to the next iteration
            // - return Err(e); // Or wrap the error: return Err(ThisProjectError::from(e));
            // - use a default timestamp: back_of_queue_timestamp = 0;
            
            debug_log("inHRCD->get_or_create_send_queue: error, so: make_a_new_queue_flag = true");
            make_a_new_queue_flag = true
        }
    }

    // 1. Get the path RESULT
    let team_channel_path_result = get_absolute_team_channel_path(team_channel_name);


    // 2. HANDLE the Result from get_absolute_team_channel_path()
    let team_channel_path = match team_channel_path_result {
        Ok(path) => path,
        Err(e) => {
            debug_log!("inHRCD->get_or_create_send_queue 4: Error getting absolute team channel path: {}", e);
            return Err(e.into());  // Or handle the error differently
        }
    };

    // --- 3. Make a new Queue ---
    debug_log!("inHRCD->get_or_create_send_queue 5: no crawl if false, make_a_new_queue_flag -> {:?}", make_a_new_queue_flag);
    
    if make_a_new_queue_flag {
        debug_log!("inHRCD->get_or_create_send_queue 5: Starting crawl of directory: {:?}", team_channel_path);
        /*
        Only when a new send-queue is needed, 
        get the paths of files
        for only files that are owned by you
        for only files in the current team_channel
        for only files where current remote collaborator is on the list of teamchannel_collaborators_with_access
        for only files dated after (younger than) the .rt ready_signal_rt_timestamp
        which is not the time the ready-signal was sent, but is 
        the updated_at timestamp
        of the last received-by-them sent-by-you file.
        */
        // ...Use the unwrapped PathBuf with WalkDir
        for entry in WalkDir::new(&team_channel_path) { // Note the & for borrowing
            let entry = entry?;
            if entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("toml")) {
                debug_log!("inHRCD->get_or_create_send_queue 6: file is toml, entry -> {:?}", entry);
                // If a .toml file
                let toml_string = fs::read_to_string(entry.path())?;
                let toml_value: Value = toml::from_str(&toml_string)?;

                // If owner = target collaborator
                if toml_value.get("owner").and_then(Value::as_str) == Some(localowneruser_name) {
                    debug_log!("inHRCD->get_or_create_send_queue 7: file owner == colaborator name {:?}", toml_value);

                    // if current remote collaborator is on the list of teamchannel_collaborators_with_access
                    
                    // 1. Get collaborators for this file (if available):
                    let file_collaborators: Vec<String> = toml_value
                        .get("teamchannel_collaborators_with_access") // Must match the key in your TOML files
                        .and_then(Value::as_array)
                        .map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect())
                        .unwrap_or_default();  // Handle case where the field is missing
                        
                        
                    // 2. Check if remote collaborator is in the access list:
                    if file_collaborators.contains(&remote_collaborator_name.to_string()) {  // Accessing remote_collaborator_name correctly here
                        debug_log!(
                            "inHRCD->get_or_create_send_queue 8, access: file_collaborators=>{:?} vs. remote_collaborator_name=>{:?}", 
                            file_collaborators,
                            remote_collaborator_name,
                        );

                        // If updated_at_timestamp exists
                        if let Some(toml_updatedat_timestamp) = toml_value.get("updated_at_timestamp").and_then(Value::as_integer) {
                            debug_log!(
                                "inHRCD->get_or_create_send_queue 9: updated_at_timestamp=>{:?} vs. rt=>{:?}", 
                                toml_updatedat_timestamp,
                                ready_signal_rt_timestamp,
                            );
                            let toml_updatedat_timestamp = toml_updatedat_timestamp as u64;

                            // If updated_at_timestamp > back_of_queue_timestamp (or back_of_queue_timestamp is 0)
                            // if timestamp > back_of_queue_timestamp || back_of_queue_timestamp == 0 {
                            if toml_updatedat_timestamp > session_send_queue.back_of_queue_timestamp {
                                debug_log("inHRCD->get_or_create_send_queue 10: timestamp > back_of_queue_timestamp");
                                // Add filepath to send_queue
                                session_send_queue.items.push(entry.path().to_path_buf());
                            }
                        }
                    } else {
                        debug_log!(
                            "get_or_create_send_queue, Collaborator '{}' does not have access to file: {:?}",
                            remote_collaborator_name,
                            entry.path()
                        );
                    }
                }
            }
        }
    }

    debug_log("inHRCD-> get_or_create_send_queue 11: calling, get_toml_file_updated_at_timestamp(), Hello?");

    
    // Get update flag paths
    let newpath_list = match get_sendq_update_flag_paths(
        team_channel_name, // No & needed now
        localowneruser_name, // Correct collaborator name
    ) {
        Ok(paths) => paths,
        Err(e) => {
            debug_log!("inHRCD->get_or_create_send_queue 2: Error getting update flag paths: {}", e);
            return Err(e); // Or handle as needed
        }
    };

    // Add new paths to the front of the queue
    for this_iter_newpath in newpath_list {
        session_send_queue.add_to_front_of_sendq(this_iter_newpath); // Use the new method
    }

    //////////////
    // New Files
    //////////////
    // Check for new-file flags, add those to the queue 
    // this needs to be done ~last (before sorting is ok)

    // // --- Get new file paths and add them to the send queue ---
    // let new_file_paths_result = read_all_newfile_sendq_flags_w_cleanup(
    //     remote_collaborator_name,
    //     &team_channel_name, 
    // );
    
    // // add to sendqueue
    // match new_file_paths_result {
    //     Ok(new_file_paths) => {
    //         session_send_queue.items.extend(new_file_paths); // Extend the items Vec directly
    //     },
    //     Err(e) => {
    //         debug_log!("Error reading new file flags: {}", e);
    //         // Handle error as needed
    //     }
    // };

    // Sort the files in the queue based on their modification time
    debug_log("Sequence of queue should be yougnest last, oldest first");
    session_send_queue.items.sort_by_key(|path| {
        get_toml_file_updated_at_timestamp(path).unwrap_or(0) // Handle potential errors in timestamp retrieval
        // std::cmp::Reverse(get_toml_file_updated_at_timestamp(path).unwrap_or(0)) // puts older items' first in queue
    });
    
    // reverse order so oldest are at the front
    session_send_queue.items.reverse();
    
    debug_log!(
        "session_send_queue.items -> {:?}",
        session_send_queue.items   
    );
    
    // remove duplicates
    session_send_queue.items = remove_duplicates_from_path_array(session_send_queue.items);
    
    // Remove duplicates?

    // TODO(remove this later) extra Inspection here:
    debug_log("|| Extra Insepction || get_or_create_send_queue: end: Q");
    debug_log!(
        "inHRCD->get_or_create_send_queue 12: start;  ready_signal_rt_timestamp -> {:?}",
        ready_signal_rt_timestamp   
    );
    debug_log!("inHRCD->get_or_create_send_queue 13: end: Q -> {:?}", session_send_queue);
    
    // Testing?
    // 1.5.6 Sleep for a duration (e.g., 100ms)
    // thread::sleep(Duration::from_millis(100000));

    Ok(session_send_queue)
}

/// get latest Remote Collaborator file timestamp 
/// for use by handl local owner desk
/// 
///
/// This is one of those values and functions that can be confusing
/// because both you and your remote collaborate have quasi-mirror-image sync systems
/// with reversed roles. Both of you are making 'latest_received' timestamps
/// and both of you are using your and their 'latest_received' timestamps,
/// which are simultanously 'the same' abstract value but very different local-context-role-specific values
///
/// note: this result should usuall be saved e.g. with
/// write_save_latest_received_from_rc_file_timestamp_plaintext()
fn get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl(
    collaborator_name: &str,
) -> Result<u64, ThisProjectError> {
    let mut last_timestamp: u64 = 0; // Initialize with 0 (for bootstrap when no files exist)
    debug_log!("get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl() started"); 

    let channel_dir_path_str = read_state_string("current_node_directory_path.txt")?; // read as string first
    debug_log!("get_latest_received_from_rc... 1. Channel directory path (from session state): {}", channel_dir_path_str); 
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
                if let Some(this_timestamp) = toml_value
                    .get("updated_at_timestamp")
                    .and_then(Value::as_integer)
                    .map(|ts| ts as u64) // Convert to u64
                {
                    debug_log!(
                        "rc: path({:?}) -> this_timestamp={:?} <-> last_timestamp{:?}",
                        path,
                        this_timestamp,
                        last_timestamp,
                    );
                    if this_timestamp > last_timestamp {
                        last_timestamp = this_timestamp;
                    }
                }
            }
        }
    }
    
    debug_log!(
        "get_latest_received_from_rc_in_teamchannel_file_timestamp_filecrawl() -> last_timestamp {:?}",
        last_timestamp
    ); 

    let team_channel_name = get_current_team_channel_name_from_cwd()
        .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;
    
    // update state: latest received timestamp
    write_save_latest_received_from_rc_file_timestamp_plaintext(
        &team_channel_name, // for team_channel_name
        &collaborator_name, // for collaborator_name
        last_timestamp, // for timestamp
    );

    Ok(last_timestamp) // Returns 0 if no matching files are found
}


/// Waits and checks indefintely until either a legitimate ready signal or exit uma
/// Retrieves SocketAddrs for the remote collaborator's ready and "got it" ports.
/// and saves remote collaborator IP band info
///
/// Continually, as when a remote collaborator may be never or belatedly online:
/// Iterates through the ipv6 and ipv4 addresses, listening for a ReadySignal. Returns SocketAddrs
/// for the ready and "got it" ports on the first valid IP. Directly uses UdpSocket::bind for
/// improved simplicity and efficiency. Does One Thing Well.
///
/// # Arguments
///
/// * `room_sync_input`: The collaborator's connection data.
///
/// # Returns
///
/// * `Result<(SocketAddr, SocketAddr), ThisProjectError>`: 
/// Tuple of SocketAddrs (ready, gotit), or an error.
///
fn get_rc_band_ready_gotit_socketaddrses_hrcd(
    room_sync_input: &ForRemoteCollaboratorDeskThread,
) -> Result<(SocketAddr, SocketAddr), ThisProjectError> {
    let timeout_duration = Duration::from_secs(15);
    let mut buf = [0; 1024];

    // --- 1. Load Local Band Information (as before) ---
    debug_log("get_rc_band...HRCD: 1. load local band");
    let (
        local_network_type,
        _, // local_network_index is not used here
        local_ipv4,
        local_ipv6,
    ) = read_band__network_config_type_index_specs()?;


    // --- 2. Determine Local IP Address (as before) ---
    debug_log("get_rc_band...HRCD: 2. load local band");
    let local_ip = match local_network_type.as_str() {
        "ipv6" => IpAddr::V6(local_ipv6),
        "ipv4" => IpAddr::V4(local_ipv4),
        _ => return Err(ThisProjectError::NetworkError("get_rc_band_..._hrcd Invalid local network type".into())),
    };


    // 3. Create SocketAddr for Listening (as before)
    debug_log("get_rc_band...HRCD: 3. SocketAddr for Listening");
    let ready_socket_addr = SocketAddr::new(
        local_ip,
        room_sync_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip,
    );
    

    // --- 4. Bind Socket (outside the loop) ---
    debug_log("get_rc_band...HRCD: 4. create_rc_udp_socket(ready_socket_addr)");
    let socket = create_rc_udp_socket(ready_socket_addr)?;
    
    // --- 5. Enter Loop to Continuously Listen ---
    debug_log("get_rc_band...HRCD: 5. loop");
    loop { // Main listening loop
        // 5.1 Check for UMA shutdown
        if should_halt_uma() {
            return Err(ThisProjectError::NetworkError("get_rc_band_..._hrcd UMA halt signal received during band handshake".into()));
        }
        
        debug_log!("get_rc_band...HRCD: 5.1 Listening for ReadySignal on: {:?}", ready_socket_addr);

        // 5.2 Set Timeout (inside loop, in case it's reset by recv)
        socket.set_read_timeout(Some(timeout_duration))?;

        // 5.3 Receive and Process
        match receive_ready_signal_with_timeout(&socket, &mut buf, &room_sync_input.remote_collaborator_salt_list) {
            Ok(Some((_, ready_signal))) => {
                debug_log("get_rc_band...HRCD: 5.3 Receive and Process");
                // Note: this Hash Verification  is already performed inside receive_ready_signal_with_timeout()
                // 5.3.1 Hash and Timestamp Verification (Perform checks *inside* the Ok case)
                // if !verify_readysignal_hashes(&ready_signal, &room_sync_input.remote_collaborator_salt_list) {
                //     debug_log!("get_rc_band_..._hrcd ReadySignal hash verification failed. Discarding and continuing to listen.");
                //     continue; // Continue to listen for a valid signal
                // }
                
                let current_timestamp = get_current_unix_timestamp();
                if ready_signal.rst > current_timestamp + 5 || current_timestamp - 10 > ready_signal.rst {
                    debug_log!("get_rc_band_..._hrcd Received outdated or future-dated ReadySignal. Discarding and continuing to listen.");
                    continue; // Continue listening
                }
                
                // --- 5.3.2 Extract and Save Remote Band Information ---
                debug_log("get_rc_band...HRCD: 5.3.2 Extract and Save Remote");
                // let (rc_network_type, rc_network_index) = decompress_banddata_byte(ready_signal.b);
                let (rc_network_type, rc_network_index) = { // Create a new inner scope here
                    let band_result = decompress_banddata_byte(ready_signal.b);
                    debug_log!(
                        "get_rc_band...HRCD: 5.3.2 Extract and Save -> band_result: {:?}",
                        band_result,
                        );
                
                    match band_result {
                        Ok((tempnetworktype, tempnetworkindex)) => (tempnetworktype, tempnetworkindex), // Assign values.
                        Err(e) => {
                            debug_log!("Error decompressing band data: {}. Skipping.", e);
                            continue;  // Skip to next iteration if an error occurs during decompression.
                        }
                    }
                }; 
                
                // --- Select IP for "got it" signal ---
                let rc_ip = match get_ip_from_index_and_type(
                    &room_sync_input.remote_collaborator_ipv4_addr_list, 
                    &room_sync_input.remote_collaborator_ipv6_addr_list, 
                    &rc_network_type, 
                    rc_network_index,
                ) {
                    Some(ip) => ip,
                    None => {
                        debug_log!("get_rc_band_..._hrcd Failed to get remote collaborator IP address from received network index and type. Continuing to listen.");
                        continue; // Continue listening for valid signal
                    }
                };
                let gotit_socket_addr = SocketAddr::new(rc_ip, room_sync_input.remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip);  // Correct port from room_sync_input

                // --- Write/Save Received Band Data ---
                let team_channel_name = match get_current_team_channel_name_from_cwd() {
                    Some(name) => name,
                    None => {
                        debug_log!("Error: get_rc_band_ Could not get current channel name. Skipping set_as_active.");
                        return Err(ThisProjectError::InvalidData("Could not get team channel name".into()));
                    },
                };
                
                debug_log("get_rc_band...HRCD: next: write_save_rc_bandnetwork_type_index");
                write_save_rc_bandnetwork_type_index(
                    room_sync_input.remote_collaborator_name.clone(),
                    team_channel_name,
                    rc_network_type,
                    rc_network_index,
                    local_ipv4,
                    local_ipv6,
                )?;

                // --- 5.4 Return Socket Addresses (Valid Signal Received) ---
                return Ok((ready_socket_addr, gotit_socket_addr)); // Return SocketAddrs on success
            }
            Ok(None) => {
                // 5.5 Handle timeout (Ok(None) from receive_ready_signal_with_timeout) - Just continue listening
                debug_log!("get_rc_band_..._hrcd Timeout waiting for ReadySignal. Continuing to listen.");
                continue; // Continue listening. The loop handles the timeout. No explicit error.
            },
            Err(e) => {
                debug_log!("get_rc_band_ready_gotit_socketaddrses_hrcd: Error receiving ReadySignal: {}", e);                
                return Err(e); // Return any other errors
            }
        }
    } // End of main listening loop
}

/// Gets the IP address from combined IPv4/IPv6 lists based on index and type.
///
/// # Arguments
///
/// * `ipv4_list`: A slice of IPv4 addresses.
/// * `ipv6_list`: A slice of IPv6 addresses.
/// * `network_type`: The network type string.
/// * `network_index`: The index into the appropriate list.
///
/// # Returns
///
/// * `Option<IpAddr>`: The `IpAddr` at the given index and type, or `None` if the index is out of bounds or the network type is invalid.
fn get_ip_from_index_and_type(
    ipv4_list: &[Ipv4Addr], 
    ipv6_list: &[Ipv6Addr], 
    network_type: &str, 
    network_index: u8
) -> Option<IpAddr> {
    match network_type {
        "ipv4" => ipv4_list.get(network_index as usize).map(|&ip| IpAddr::V4(ip)),
        "ipv6" => ipv6_list.get(network_index as usize).map(|&ip| IpAddr::V6(ip)),
        _ => None, // Or handle an invalid network type in another way
    }
}

/// Receives a ReadySignal with a timeout, performing hash and timestamp verification.
/// Goal purpose and scope: screening valid packets to verify a live-ip
///
/// This function now includes both hash verification and timestamp freshness checks.
///
/// # Arguments
///
/// * `socket`: The UDP socket to receive data on.
/// * `buf`: A mutable buffer to store the received data.
/// * `salt_list`: The salt list for hash verification.
///
/// # Returns
///
/// * `Result<Option<SocketAddr>, ThisProjectError>`: The sender's `SocketAddr` on success, an error, or `Ok(None)` on timeout.
fn receive_ready_signal_with_timeout( // Hash and timestamp checks moved HERE!
    socket: &UdpSocket, 
    buf: &mut [u8], 
    senders_salt_list: &[u128],
) -> Result<Option<(SocketAddr, ReadySignal)>, ThisProjectError> { // Changed to return the signal
    debug_log!("receive_ready_signal_with_timeout(): Starting...");

    let timeout_duration = Duration::from_secs(15);
    
    socket.set_read_timeout(Some(timeout_duration))?; 

    match socket.recv_from(buf) {
        Ok((amt, src)) => {
            debug_log!("receive_ready_signal_with_timeout(): Received {} bytes from {}", amt, src);

            // 1. Deserialize
            let ready_signal = match deserialize_ready_signal(&buf[..amt], senders_salt_list) { // Deserialize first.  Use the passed-in senders_salt_list
                Ok(signal) => signal,
                Err(e) => {
                    debug_log!("receive_ready_signal_with_timeout():  Failed to deserialize ReadySignal: {}", e);
                    return Err(e);  // Or continue to listen for the next signal
                },
            };

            // 2. Hash Verification: PERFORM HASH CHECK HERE!
            if !verify_readysignal_hashes(&ready_signal, senders_salt_list) { // Hash verification alongside timestamp check
                debug_log!("receive_ready_signal_with_timeout(): ReadySignal hash verification failed. Discarding.");
                return Ok(None); // Or continue to listen, but return nothing.
            };
            debug_log!("receive_ready_signal_with_timeout(): ReadySignal hashes verified.");

            // 3. Timestamp Freshness Check: PERFORM TIMESTAMP CHECK HERE!
            let current_timestamp = get_current_unix_timestamp();
            if ready_signal.rst > current_timestamp + 5 || current_timestamp - 10 > ready_signal.rst {  // Freshness check, combined
                debug_log!("receive_ready_signal_with_timeout(): Received outdated or future-dated ReadySignal.  Discarding.");
                return Ok(None); // Indicate invalid signal without returning an Error.
            };
            debug_log!("receive_ready_signal_with_timeout():  ReadySignal timestamp verified.");

            // 4. Return the source address and ReadySignal if all checks pass.
            Ok(Some((src, ready_signal))) // Include ReadySignal
        },

        Err(e) if e.kind() == ErrorKind::WouldBlock => {
            debug_log!("receive_ready_signal_with_timeout(): Timeout");
            Ok(None) // Correct handling of timeout, not returning an error!
        }
        Err(e) => {
            debug_log!("receive_ready_signal_with_timeout(): Error receiving data: {}", e);
            Err(ThisProjectError::NetworkError(e.to_string()))
        },
    }
}

/// TODO: What on earth is this thing???
///
/// Gets the latest `updated_at_timestamp` from the current team channel's files.
///
/// This function crawls through the current team channel's directory and retrieves
/// the most recent `updated_at_timestamp` from the TOML files it finds.
///
/// # Returns
///
/// `Result<u64, ThisProjectError>`:  The latest timestamp, or an error if the directory read fails, a TOML file cannot be parsed, or the updated_at_timestamp is invalid.
fn get_latest_timestamp_from_team_channel_dir() -> Result<u64, ThisProjectError> {
    let mut latest_timestamp = 0u64; // Initialize to zero
    
    let channel_dir_path_str = match read_state_string("current_node_directory_path.txt") {
        Ok(s) => s,
        Err(e) => {
            debug_log!("Error reading channel directory path: {}", e);
            return Err(e.into()); // Or handle error differently
        }
    };

    //  Crawl through the team channel directory
    for entry in WalkDir::new(channel_dir_path_str) {
        let entry = entry?; // Check for WalkDir errors
        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("toml")) { 
            match get_toml_file_updated_at_timestamp(path) {
                Ok(timestamp) => { 
                    if timestamp > latest_timestamp {
                        latest_timestamp = timestamp;
                    }
                },
                Err(e) => {
                    debug_log!("Error reading or parsing TOML file: {:?} - {}", path, e);
                    // Handle the error as you see fit. Perhaps continue or return the error.
                    continue; // Skip to the next file
                },
            };
        }
    }
    Ok(latest_timestamp)
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
            "HRCD room_sync_input -> {:?}", 
            room_sync_input
        );
        
        /////////////
        // Bootstrap
        /////////////
        
        // TODO
        // setup: Get Team Channel Name
        let team_channel_name = get_current_team_channel_name_from_cwd()
            .ok_or(ThisProjectError::InvalidData("Unable to get team channel name".into()))?;
            
        // 1.2 Get Remote Collaborator's IP and Network Type
        debug_log("HRCD starting search for Remote Collaborator's IP");

        let (ready_socket_addr, gotit_socket_addr) =
            match get_rc_band_ready_gotit_socketaddrses_hrcd(room_sync_input) {
                Ok(addrs) => addrs,
                Err(e) => {
                    debug_log!("HRCD: Error getting SocketAddrs: {}", e);
                    return Err(e);
                }
            };
        
        debug_log!(
            "HRCD get_rc_band_ready_gotit_socketaddrses_hrcd: RC -> {:?} || ready_socket_addr -> {:?} || gotit_socket_addr -> {:?}", 
            room_sync_input.remote_collaborator_name,
            ready_socket_addr,
            gotit_socket_addr
        );
        
        
        

        // 1. UPD Handshake
        // hrcd_udp_handshake(&room_sync_input);
        
        

        // --- 1.3 Create two UDP Sockets for Ready and GotIt Signals ---`
        debug_log("HRCD 1.3 Making ready_port listening UDP socket...");
        let ready_socket = create_rc_udp_socket(ready_socket_addr)?;
        
        debug_log("HRCD 1.3 Making gotit_port listening UDP socket...");
        let gotit_socket = create_rc_udp_socket(gotit_socket_addr)?;

        // --- 1.4 Initialize (empty for starting) Send Queue ---
        // let mut session_send_queue: Option<SendQueue> = None;
        // 1.4 Initialize Send Queue (empty, with zero timestamp)
        let mut session_send_queue = SendQueue {
            back_of_queue_timestamp: 0,
            items: Vec::new(),
        };
        
        debug_log!(
            // this does require &
            "HRCD 1.5.2 check: new session_send_queue.items -> {:?} (Should be empty...)", 
            session_send_queue.items
        ); 

        let remote_collaborator_name_clone = room_sync_input.remote_collaborator_name.clone();
        
        // --- HRCD 1.5 Spawn a thread to handle recieving GotItSignal(s) and SendFile prefail-flag removal ---
        let gotit_thread = thread::spawn(move || {
            //////////////////////////////////////
            // Listen for 'I got it' GotItSignal
            ////////////////////////////////////

            loop { // gotit loop
                debug_log(
                    "HRCD Got it loop starting. GotItloop"
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
                        let gotit_signal: GotItSignal = match process_incoming_gotit_signal_bytes(&buf[..amt]) {
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
                        */

                        remove_one_prefail_flag__for_sendfile(
                            document_id, // di_flag_id: String,
                            &remote_collaborator_name_clone, // remote_collaborator_name: String,
                            &team_channel_name, // team_channel_name: String,
                        );
                        // 1.5.6 update ~timestamp_of_latest_received_file_that_i_sent
                            
                    // // 1.5.7 Sleep for a short duration (e.g., 100ms)
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
        }); // End of GotIt Loooooop

        // 1.6.1 zero_timestamp_counter = 0 for ready signal send-at timestamps
        let mut zero_timestamp_counter = 0;
        
        // 1.6.2 intrystruct_hash_set_session_nonce = HashSet::new() as protection against replay attacks Create a HashSet to store received hashes
        let mut intrystruct_hash_set_session_nonce = HashSet::new();  // Create a HashSet to store received hashes

        let mut rc_set_as_active = false;
        
        // For first-time bootstrap
        let mut bootstrap_sendqueue = true;
        
        
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
                    
                    debug_log!(
                        "HRCD 2.2.1 check queue {:?}", 
                        session_send_queue.items,
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
                                        // --- Inspect Raw Bytes ---
                    debug_log!(
                        "HRCD thread::sleep(Duration::from_secs(3));", 
                    ); 
                    
                    // TODO: how long?
                    // this lets last item run
                    // thread::sleep(Duration::from_secs(5));

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
                    let mut ready_signal: ReadySignal = match deserialize_ready_signal(&buf[..amt], &room_sync_input.remote_collaborator_salt_list) {
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
                    let ready_signal_hash_vec = ready_signal.rh.clone();

                    if !ready_signal_hash_vec.is_empty() {
                        if intrystruct_hash_set_session_nonce.contains(&ready_signal_hash_vec) {
                            debug_log!("HRCD 2.6 quasi nonce check: Duplicate ReadySignal received (hash match). Discarding.");
                            continue; // Discard the duplicate signal
                        }
                        intrystruct_hash_set_session_nonce.insert(ready_signal_hash_vec); // Add hash to the set
                    } else {
                        debug_log!("HRCD 2.6 quasi nonce check: ReadySignal received without hashes. Discarding."); // Or handle differently
                        continue;
                    }

                    // --- 3. Get or Create Send Queue ---

                    // 3.1 ready_signal_timestamp for send-queue
                    let rst_sent_ready_signal_timestamp = ready_signal.rst; // Unwrap the timestamp outside the match, as it's always required.
                    
                    debug_log!(
                        "HRCD 3.1 check rst_sent_ready_signal_timestamp for send-queue: rst_sent_ready_signal_timestamp -> {:?}", 
                        rst_sent_ready_signal_timestamp
                    );
                    
                    debug_log!(
                        "HRCD 3.1 check rt: rc's last-file-received-from-you timestamp received in a readysignal. ready_signal.rt -> {:?}", 
                        ready_signal.rt,
                    );
                    
                    // --- 3.2 timestamp freshness checks ---
                    let current_timestamp = get_current_unix_timestamp();
                    
                    debug_log!(
                        "HRCD 3.2 check timestamp freshness checks: current_timestamp -> {:?}",
                        current_timestamp,
                    );

                    // 3.2.1 No Future Dated Requests
                    if rst_sent_ready_signal_timestamp > current_timestamp + 5 { // Allow for some clock skew (5 seconds)
                        debug_log!("HRCD 3.2.1 check: Received future-dated timestamp. Discarding.");
                        continue;
                    }

                    // 3.2.2 No Requests Older Than ~10 sec
                    if current_timestamp - 10 > rst_sent_ready_signal_timestamp {
                        debug_log!("HRCD 3.2.2 check: Received outdated timestamp (older than 10 seconds). Discarding.");
                        continue;
                    }

                    // 3.2.3 only 3 0=timstamp requests per session (count them!)
                    if rst_sent_ready_signal_timestamp == 0 {
                        if zero_timestamp_counter >= 5 {
                            debug_log("HRCD 3.2.3 check: Too many zero-timestamp requests. Discarding.");
                            continue;
                        }
                        zero_timestamp_counter += 1;
                    }

                    debug_log("##HRCD## [Done] checks(plaid) 3.2.3\n");
                    
                    // 3.2.4 look for fail-flags:
                    
                    ////////////////////////////////
                    // Set back_of_queue_timestamp
                    //////////////////////////////

                    // --- 3.3 Get / Make Send-Queue ---
                    let this_team_channelname = match get_current_team_channel_name_from_cwd() {
                        Some(name) => name,
                        None => {
                            debug_log("HRCD 3.3: Error: Could not get current channel name. Skipping send queue creation.");
                            continue; // Skip to the next iteration of the loop
                        }
                    }; 
                    debug_log!("HRCD 3.3 this_team_channelname -> {:?}", this_team_channelname);

                    // TODO currently set to always run... ok?
                    debug_log("HRCD 3.3 get_or_create_send_queue");
                    
                    session_send_queue = get_or_create_send_queue(
                        &this_team_channelname, // for team_channel_name
                        &room_sync_input.local_user_name, // local owner user name
                        &room_sync_input.remote_collaborator_name, // remote_collaborator_name
                        session_send_queue, // for session_send_queue
                        ready_signal.rt, // for ready_signal_rt_timestamp
                        bootstrap_sendqueue,
                    )?;
                    
                    bootstrap_sendqueue = false;

                    debug_log!(
                        "HRCD ->[]<- 3.3 Get / Make session_send_queue {:?}",
                        session_send_queue   
                    );

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
                    
                    debug_log!(
                        "HRCD ->[cue]<- 4.1 Send One File from Queue, session_send_queue -> {:?}",
                        session_send_queue   
                    );

                    // 4. while: Send File: Send One File from Queue
                    if let ref mut queue = session_send_queue {
                        
                        debug_log!(
                            "HRCD 4 before le pop, queue.items -> {:?}",
                            queue.items   
                        );
                        
                        while let Some(file_path) = queue.items.pop() {

                            debug_log!(
                                "HRCD 4 after le pop, queue.items -> {:?}",
                                queue.items   
                            );
                            
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
                            
                            // // 4.5. Calculate SendFile Struct Hashes (Using Collaborator's Salts)
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
                            
                            debug_log!("HRCD 4.7.2 ready_signal.rt for set_prefail_flag_rt_timestamp__for_sendfile {:?}", ready_signal.rt);
                            
                            
                            // get updatedat value of .toml
                            let file_last_updatedat_time: u64 = get_updated_at_timestamp_from_toml_file(&file_path)?;
                            
                            
                            // 4.7.2 HRCD set_prefail_flag_rt_timestamp__for_sendfile
                            if let Err(e) = set_prefail_flag_rt_timestamp__for_sendfile(
                                file_last_updatedat_time, // for fail flag file name
                                ready_signal.rt, // for fail flag file value
                                &room_sync_input.remote_collaborator_name,
                            ) {
                                debug_log!("HRCD 4.7.2.e Error setting pre-fail flag: {}", e);
                                continue; // Handle error as you see fit
                            }
                            debug_log!("HRCD 4.7.2 prefail flag set using timestamp {:?}", &ready_signal.rt);
                            
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
                                    match send_data_via_udp(
                                        &extracted_serialized_data, 
                                        src, 
                                        room_sync_input.remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip,
                                        ) {
                                        Ok(_) => {
                                            debug_log!("HRCD 4.7 File sent successfully");
                                            // ... (Handle successful send, e.g., update timestamp log)
                                            
                                            // --- 4.7.3 Get Timestamp ---
                                            //  Timestamp Log is depricated (most likely)
                                            debug_log("HRCD calling calling get_toml_file_updated_at_timestamp(), yes...");
                                            if let Ok(timestamp) = get_toml_file_updated_at_timestamp(&file_path) {
                                            //     update_collaborator_sendqueue_timestamp_log(
                                            //         // TODO: Replace with the actual team channel name
                                            //         &this_team_channelname, 
                                            //         &room_sync_input.remote_collaborator_name,
                                            //     )?;
                                                // debug_log!("HRCD 4.7.3  Updated timestamp log for {}", room_sync_input.remote_collaborator_name);
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
                            // debugpause(30);
                            debug_log!("\nHRCD: bottom of ready_signal listener. (maybe)\n");


                        } // end of while
                    } // end of 4.4: if let Some(ref mut queue) = session_send_queue {
                    debug_log!("\nHRCD: end of inner match.\n");    
                }, // end of the Ok inside the match: Ok((amt, src)) => {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // TODO What is all this then?
                    // // --- 3.6 No Ready Signal, Log Periodically ---
                    // terrible idea: most people are simply not online most of the time
                    // this is not an error!!
                    // if last_debug_log_time.elapsed() >= Duration::from_secs(5) {
                    //     debug_log!("HRCD 3.6 {}: Listening for ReadySignal on port {}", 
                    //                room_sync_input.remote_collaborator_name, 
                    //                room_sync_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip);
                    //     last_debug_log_time = Instant::now();
                    // }
                    debug_log!("HRCD Err(e) if e.kind() == ErrorKind::WouldBlock =>"); 
                },
                Err(e) => {
                    // --- 3.7 Handle Other Errors ---
                    debug_log!("HRCD #? {}: Error receiving data on ready_port: {} ({:?})", 
                            room_sync_input.remote_collaborator_name, e, e.kind());
                    return Err(ThisProjectError::NetworkError(e.to_string()));
                }
            // thread::sleep(Duration::from_millis(100));
            } // match ready_socket.recv_from(&mut buf) { 
        } // closes main loop
        debug_log!("\nHRCD: bottom of main loop.\n");
    } 
    debug_log!("\nending HRCD\n");
    Ok(())
}

/// Creates a UDP socket bound to the specified address and port.
///
/// Simplifies socket creation by taking a SocketAddr directly.
/// Does one thing well.
///
/// # Arguments
///
/// * `socket_addr`: The address and port to bind to.
///
/// # Returns
///
/// * `Result<UdpSocket, ThisProjectError>`: The bound socket or an error if binding fails.
fn create_rc_udp_socket(socket_addr: SocketAddr) -> Result<UdpSocket, ThisProjectError> { 
    UdpSocket::bind(socket_addr).map_err(|e| {
        ThisProjectError::NetworkError(format!("Failed to bind to UDP socket: {}", e))
    })
}

/// Creates a UDP socket bound to a locally chosen IP address and port based on the network band configuration.
///
/// This function uses the provided `band_local_network_type`, `band_local_user_ipv4_address`, and `band_local_user_ipv6_address`
/// to determine the appropriate IP address to bind to. 
/// if type says ivp6 or ipv4, this function then attempts to bind 
/// a UDP socket to that ip address and the specified port.
///
/// # Arguments
///
/// * `band_local_network_type`: A string slice indicating the network type ("ipv4" or "ipv6").
/// * `band_local_user_ipv4_address`: The local user's IPv4 address (used if `band_local_network_type` is "ipv4").
/// * `band_local_user_ipv6_address`: The local user's IPv6 address (used if `band_local_network_type` is "ipv6").
/// * `port`: The port number.
///
/// # Returns
///
/// * `Result<UdpSocket, ThisProjectError>`:  The created and bound UDP socket on success, or a `ThisProjectError` on failure (invalid IP, binding error, unsupported network type).
fn create_local_udp_socket(
    band_local_network_type: &str,  
    band_local_user_ipv4_address: &Ipv4Addr,
    band_local_user_ipv6_address: &Ipv6Addr,
    port: u16,
) -> Result<UdpSocket, ThisProjectError> {
    let socket_addr = match band_local_network_type {
        "ipv6" => SocketAddr::new(IpAddr::V6(*band_local_user_ipv6_address), port),
        "ipv4" => SocketAddr::new(IpAddr::V4(*band_local_user_ipv4_address), port),
        _ => return Err(ThisProjectError::NetworkError("Unsupported network type".into())),
    };

    UdpSocket::bind(socket_addr).map_err(|e| {
        ThisProjectError::NetworkError(format!("Failed to bind to {} address: {}", band_local_network_type, e))
    })
}

// Result enum for the sync operation, allowing communication between threads
enum SyncResult {
    Success(u64), // Contains the new timestamp after successful sync
    Failure(ThisProjectError), // Contains an error if sync failed 
}

/// Extracts the team channel name from the current working directory path.
/// 
/// Looks for the pattern "project_graph_data/team_channels/[CHANNEL_NAME]" in the absolute path
/// and returns the CHANNEL_NAME if found.
///
/// # Returns
/// * `Some(String)` - The team channel name if found
/// * `None` - If no channel name could be extracted (invalid path, missing markers, etc.)
///
/// # Example
/// ```
/// match get_current_team_channel_name_from_cwd() {
///     Some(channel) => println!("Found channel: {}", channel),
///     None => println!("No channel found"),
/// }
/// ```
/// or:
/// let team_channel_name = match get_current_team_channel_name_from_cwd() {
///     Some(name) => name,
///     None => {
///         debug_log!("Error: Could not get current channel name. Skipping set_as_active.");
///         return Err(ThisProjectError::InvalidData("Could not get team channel name".into()));
///     },
/// };
fn get_current_team_channel_name_from_cwd() -> Option<String> {
    debug_log!("Starting: get_current_team_channel_name_from_cwd()");

    // Get absolute path from current directory
    let absolute_path = match PathBuf::from(".").canonicalize() {
        Ok(path) => path,
        Err(e) => {
            debug_log!("Failed to get absolute path: {}", e);
            return None;
        }
    };

    debug_log!("Absolute path: {:?}", absolute_path);

    // Convert path to string
    let path_str = absolute_path.to_string_lossy();
    
    // Define the marker we're looking for
    let marker = "project_graph_data/team_channels/";
    
    // Find marker position
    let position = match path_str.find(marker) {
        Some(pos) => pos,
        None => {
            debug_log!("Marker '{}' not found in path", marker);
            return None;
        }
    };

    // Extract everything after the marker
    let after_marker = &path_str[position + marker.len()..];
    debug_log!("Path after marker: {:?}", after_marker);

    // Get the first component after the marker
    let team_channel = after_marker
        .split(std::path::MAIN_SEPARATOR)
        .next()
        .map(String::from);

    // Validate and return
    match team_channel {
        Some(channel) if !channel.is_empty() => {
            debug_log!("Found team channel: {}", channel);
            Some(channel)
        }
        _ => {
            debug_log!("No valid team channel found");
            None
        }
    }
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
        debug_log(">*< Halt signal received. Exiting The Uma. Closing... you_love_the_sync_team_office() |o|");
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
        debug_log!(
            "Configuring Connection: Setting up proverbial meetingroom and desk for/with: {}", 
            this_meetingroom_iter.remote_collaborator_name,
        );
        
        // Create sub-structs
        let data_baggy_for_owner_desk = ForLocalOwnerDeskThread { 
            local_user_name: this_meetingroom_iter.local_user_name.clone(),
            remote_collaborator_name: this_meetingroom_iter.remote_collaborator_name.clone(),
            local_user_salt_list: this_meetingroom_iter.local_user_salt_list.clone(),
            remote_collaborator_salt_list: this_meetingroom_iter.remote_collaborator_salt_list.clone(),
            local_user_ipv6_addr_list: this_meetingroom_iter.local_user_ipv6_addr_list.clone(),
            local_user_ipv4_addr_list: this_meetingroom_iter.local_user_ipv4_addr_list.clone(),
            remote_collaborator_ipv6_addr_list: this_meetingroom_iter.remote_collaborator_ipv6_addr_list.clone(),
            remote_collaborator_ipv4_addr_list: this_meetingroom_iter.remote_collaborator_ipv4_addr_list.clone(),
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
            local_user_ipv6_addr_list: this_meetingroom_iter.local_user_ipv6_addr_list,
            local_user_ipv4_addr_list: this_meetingroom_iter.local_user_ipv4_addr_list,
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

// fn update_current_path_and_state(app: &mut App, selected_channel: &str) {
//     app.current_path = app.current_path.join(selected_channel);
//     app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
//     app.graph_navigation_instance_state.nav_graph_look_read_node_toml(); 
//     debug_log!("Updated path and state. New path: {:?}", app.current_path);
// }

// Updated helper function:
fn update_current_path_and_state(app: &mut App, selected_item: String, input_mode: InputMode) {
    // if input_mode == InputMode::TaskCommand && app.is_at_task_browser_root() {
    //     app.current_path.push(selected_item);  // Only push if in TaskCommand mode and at root (for column selection).
    // } else if input_mode == InputMode::MainCommand {
    //     app.current_path.push(selected_item);  // Only push when not in task mode (directory or IM message selection).
    // }
    
    // Populate next_path_lookup_table:
    app.next_path_lookup_table.clear(); // Clear previous entries.

    if input_mode == InputMode::MainCommand  {
        for (i, item) in app.tui_directory_list.iter().enumerate() {
            let next_path = app.current_path.join(item);
            app.next_path_lookup_table.insert(i + 1, next_path);
        }    
    }

    app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
    app.graph_navigation_instance_state.nav_graph_look_read_node_toml(); // Always call to update state.
    debug_log!("Updated path and state. New path: {:?}", app.current_path);
}

// In handle_task_selection:
fn handle_task_selection(app: &mut App, selection: usize) -> Result<bool, io::Error> { // Now returns a bool
    if app.is_at_task_browser_root() {
        // ... Column selection:
        // todo this may be wrong
        // Update current_path using handle_selection:
        if let Some(selected_column) = app.tui_directory_list.get(selection - 1) {
            update_current_path_and_state(app, selected_column.clone(), app.input_mode.clone());  //FIX 1
            app.load_tasks(); // Refresh task browser to show tasks within the column
        } else { // Invalid selection
            app.display_error("hts Invalid column selection.");
            app.load_tasks(); //Refresh view
            return Ok(false); //Stay in task mode
        }

    } else { //Task selection
        if let Some(full_task_path) = app.get_full_task_path(selection - 1) {
            // No need to push here (current_path is already inside a column directory):
            debug_log!(
                "hts app.current_path: {:?}", app.current_path
            );
            debug_log!(
                "hts full_task_path: {:?}", full_task_path
            );
            app.current_path = full_task_path.clone(); // Update current_path directly
            app.graph_navigation_instance_state.current_full_file_path = full_task_path;
            
            debug_log!(
                "hts  app.graph_navigation_instance_state.current_full_file_path: {:?}",
                app.graph_navigation_instance_state.current_full_file_path
            );
            
            app.graph_navigation_instance_state.nav_graph_look_read_node_toml();
            return Ok(true); // Return true to signal exiting task mode

        } else {
            app.display_error("hts Invalid task number");
            app.load_tasks();
            return Ok(false); //Stay in task mode
        }
    }
    Ok(false)  // Stay in task mode by default (if no task is selected).
}

// /// Function for broadcasting to theads to wrapup and end uma session: quit
// fn should_halt_uma() -> bool {
//     // 1. Read the 'continue_uma.txt' file
//     let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
//         Ok(content) => content,
//         Err(e) => {
//             eprintln!("Error reading 'continue_uma.txt': {:?}", e); // Log the error
//             return false; // Don't halt on error reading the file
//         }
//     };

//     // 2. Check if the file content is "0"
//     file_content.trim() == "0"
// }

// Proverbial Main()
fn we_love_projects_loop() -> Result<(), io::Error> {
    /*
    
    setup and bootstrap
    - load data
    - start Graph Navigation Struct instance
    - do first bootstrap TUI display of team-channel choices
    
    Command Loop
    1. Get input
    2. process input/command
    3. show updated state
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
        current_node_unique_id: Vec::new(),
        current_node_members: Vec::new(),
        home_square_one: true,
        agenda_process: String::new(),
        goals_features_subfeatures_tools_targets: String::new(),
        scope: String::new(),
        schedule_duration_start_end: Vec::new(), // Vec<u64>,?
            
    
    };

    // if !verify_gpg_signature(&local_user) {
    //     println!("GPG key verification failed (placeholder)");
    //     return Err(io::Error::new(io::ErrorKind::Other, "GPG Verification Failed"));
    // }
    
    // Create App instance
    let mut app = App::new(graph_navigation_instance_state.clone()); // Pass graph_navigation_instance_state
    
    // -- bootstrap: Start in MainCommand Mode --- 
    app.input_mode = InputMode::MainCommand; // Initialize app in command mode
    
    // bootstrap: load team-channels
    app.update_directory_list()?;

    // bootstrap: TUI display: TODO not yet working to display first options
    print!("\x1B[2J\x1B[1;1H"); // Clear the screen
    tiny_tui::simple_render_list(
        &app.tui_directory_list, 
        &app.current_path,
    );
    

    // Start 
    loop {
        // Read the 'continue_uma.txt' file 
        let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
            Ok(content) => content,
            Err(_) => {
                debug_log!("Error reading 'continue_uma.txt'. Continuing..."); // Handle the error (e.g., log it) but continue for now
                continue; // Skip to the next loop iteration
            }
        };
        // break loop if continue=0
        if file_content.trim() == "0" {
            debug_log("wlpl 'continue_uma.txt' is 0. we_love_projects_loop() Exiting loop.");
            break; 
        }
        
        // Update GraphNavigationInstanceState based on the current path
        debug_log("start loop: we_love_projects_loop()");
        debug_log!(
            "wlpl &app.current_path -> {:?}", 
            &app.current_path,
        ); 
        
        debug_log!("wlpl app.input_mode {:?}", &app.input_mode); 
        
        debug_log!(
            "wlpl &app.next_path_lookup_table -> {:?}", 
            &app.next_path_lookup_table
        ); 
        
        debug_log!(
            "wlpl &app.task_display_table -> {:?}", 
            &app.task_display_table
        ); 
        
        
        app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
        
        
        debug_log!(
            "wlpl app.current_path.clone(); -> {:?}", 
            &app.current_path.clone(),
        ); 
        
        debug_log!(
            "wlpl &app.graph_navigation_instance_state.current_full_file_path -> {:?}", 
            &app.graph_navigation_instance_state.current_full_file_path,
        ); 
        
        // -- Here: this function reads state and adds current graph-node-location data
        app.graph_navigation_instance_state.nav_graph_look_read_node_toml();
        
        // --- this is or maybe should be part of the TUI (no state record)
        
        //  Check for exit signal
        if should_halt_uma() {
            debug_log("Exiting we_love_projects_loop");
            break;
        }
        
        /*
        Command Loop
        1. Get input
        2. process input/command
        3. show updated state
        

        # Main Command Loop
        1. input: getting a command from the user
	       - Q: for refresh, is there a way to separate input (input buffer?)
	       to display current user typing along with refreshed other items etc?

        2. process the command

        If int: 
        - move to the path
        - check if new place is a node
        - load new path into Nav state
        - load basic display info:
        -- name
        -- description
        -- scope n schedule (user feature:, subfeatures:, days:}

        Handle commands such as T, M, etc.

        Handle change of Mode:
        (maybe all input-mode is handled not in this loop)

        3. Tui: showing the user where they are
        (loop)

        */
        
        // 1. get input/command
        let input = tiny_tui::get_input()?; 
        
        // 2. handle input/command
        // If in main command mode, handle main commands:
        // ?. Update directory list (only in MainCommand mode) - MOVE THIS
        if app.input_mode == InputMode::MainCommand {
            if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? { 
                return Ok(()); 
            }
            app.update_directory_list()?;
            
        }
        
        // // 2. handle input/command
        // if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? {
        //     return Ok(());
        // } else if app.input_mode == InputMode::MainCommand {
        //     handle_numeric_input(&input, &mut app, &graph_navigation_instance_state)?;
        // }
        


        // 3. Render TUI *before* input:
        if app.input_mode == InputMode::InsertText {

            debug_log("we love projects: handle_insert_text_input");
            
            if input == "m" {
                // pass

            } else if input == "back" {
                debug_log("escape toggled");
                app.input_mode = InputMode::MainCommand; // Access input_mode using self
                app.current_path.pop(); // Go back to the parent directory
                app.update_directory_list()?;
            } else if input == "q" {
                debug_log("escape toggled");
                app.input_mode = InputMode::MainCommand; // Access input_mode using self
                app.current_path.pop(); // Go back to the parent directory
                app.update_directory_list()?;  // refresh to current cwd display items
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

                app.load_im_messages(); // Access using self
            }
        }

        // 3. Render TUI *before* input:
        if app.input_mode == InputMode::TaskCommand {

            debug_log("we love projects: task mode");

            // First, try to handle numeric input
            if let Ok(index) = input.trim().parse::<usize>() {
                // Check if the index exists in the path lookup table
                if let Some(target_path) = app.next_path_lookup_table.get(&index) {
                    debug_log(&format!("Selected path from lookup table: {:?}", target_path));          
                    // Regular directory navigation
                    app.current_path = target_path.clone();
                    app.input_mode = InputMode::MainCommand; // Access input_mode using self

                } else {
                    debug_log(&format!("Invalid index: {} not found in path lookup table", index));
                }
            }


            // // app.update_task_display()?;
            // let (headers, data) = app.update_task_display()?;
            // debug_log!(
            //     "headers -> {:?} data -> {:?}", 
            //      headers,
            //      data,
            // );
            // tiny_tui::display_table(&headers, &data);

            // app.handle_tui_action(); // Remove the extra argument here

            debug_log!(
                "we_love_projects_loop() app.next_path_lookup_table {:?}", 
                 app.next_path_lookup_table,
            );

            debug_log("handle_tui_action() started in we_love_projects_loop()");

            if input == "t" {
                
                // pass (no additional action if task mode entered)
            
            } else if input == "move" {
                move_task(
                    &app.next_path_lookup_table,
                );
                

            } else if input == "back" {
                debug_log("escape toggled");
                app.input_mode = InputMode::MainCommand; // Access input_mode using self
                app.current_path.pop(); // Go back to the parent directory
                tiny_tui::render_list(
                    &app.tui_directory_list, 
                    &app.current_path,
                    &app.graph_navigation_instance_state.agenda_process,
                    &app.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                    &app.graph_navigation_instance_state.scope,
                    &app.graph_navigation_instance_state.schedule_duration_start_end,
                );
                app.update_directory_list()?;  // refresh to current cwd display items
                
            } else if input == "q" {
                debug_log("escape toggled");
                app.input_mode = InputMode::MainCommand; // Access input_mode using self
                app.current_path.pop(); // Go back to the parent directory
                tiny_tui::render_list(
                    &app.tui_directory_list, 
                    &app.current_path,
                    &app.graph_navigation_instance_state.agenda_process,
                    &app.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                    &app.graph_navigation_instance_state.scope,
                    &app.graph_navigation_instance_state.schedule_duration_start_end,
                );
                app.update_directory_list()?;  // refresh to current cwd display items
            
            } else if !input.is_empty() {
                debug_log("!input.is_empty()");

                // let local_owner_user = &app.graph_navigation_instance_state.local_owner_user; // Access using self

                // // 1. final path name (.toml)
                // let message_path = get_next_message_file_path(&app.current_path, local_owner_user); 
                // debug_log(&format!("Next message path: {:?}", message_path)); // Log the calculated message path

                // // 2. make message file
                // add_im_message(
                //     &message_path,
                //     local_owner_user,
                //     input.trim(), 
                //     None,
                //     &app.graph_navigation_instance_state, // Pass using self
                // ).expect("handle_insert_text_input: Failed to add message");

                // app.load_im_messages(); // Access using self
            }
        }

        
        ///////////
        // Display
        ///////////
        
        // boostrap
        
        
        // Clear the screen
        print!("\x1B[2J\x1B[1;1H");

        // bootstrap: simple TUI display when at home screen
        debug_log!("app.current_path.to_string_lossy() -> {:?}", app.current_path.to_string_lossy());
        
        if app.current_path.to_string_lossy() == "project_graph_data/team_channels" {
            tiny_tui::simple_render_list(
                &app.tui_directory_list, 
                &app.current_path);
                
        } else {
            
            match app.input_mode {
                InputMode::MainCommand => tiny_tui::render_list(
                    &app.tui_directory_list, 
                    &app.current_path,
                    &app.graph_navigation_instance_state.agenda_process,
                    &app.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                    &app.graph_navigation_instance_state.scope,
                    &app.graph_navigation_instance_state.schedule_duration_start_end,
                ),
                InputMode::TaskCommand => { /* Task list rendering logic */ },
                InputMode::InsertText => tiny_tui::simple_render_list(
                    &app.tui_textmessage_list, 
                    &app.current_path,
                    // &app.graph_navigation_instance_state.agenda_process,
                    // &app.graph_navigation_instance_state.goals_features_subfeatures_tools_targets,
                    // &app.graph_navigation_instance_state.scope,
                    // &app.graph_navigation_instance_state.schedule_duration_start_end,
                ),
            };
        }

    } // end of main loop
    debug_log("Finish: we love project loop.");
    debug_log(">*< Halt signal received. Exiting The Uma. Closing... we_love_projects_loop() |o|");

    Ok(())
}

        // // 1. Render TUI *before* input:
        // match app.input_mode {
        //     InputMode::MainCommand => tiny_tui::render_list(&app.tui_directory_list, &app.current_path),
        //     InputMode::TaskCommand => app.load_tasks(), // Renders the task table.
        //     InputMode::InsertText => tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path),
        // };

        // let input = tiny_tui::get_input()?;

        // match app.input_mode {
        //     InputMode::MainCommand => {
        //         if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? {
        //             break;
        //         } else if let Ok(index) = input.parse::<usize>() {
        //             // ... (Directory selection logic - see below)
        //         } // ... other commands ...
        //     },
        //     InputMode::TaskCommand => {
        //         if let Ok(selection) = input.parse::<usize>() {
        //             if handle_task_selection(&mut app, selection)? {  // Exit task mode if selection is successful.
        //                 app.input_mode = InputMode::MainCommand; // Switch back to main command mode.
        //                 // Refresh list after leaving task browser (if going back to previous main context)
        //                 tiny_tui::render_list(&app.tui_directory_list, &app.current_path); 
        //             } else {  //Stay in task browser: If invalid selection, refresh task list
        //                 app.load_tasks(); // Stay in TaskCommand mode.
        //             }
        //         } else if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? { // Handle commands like "q"
        //             // Refresh list after leaving task browser (if exiting Uma or team channel)
        //             app.load_tasks(); // Refresh task view.
        //         }
        //     },
        //     InputMode::MainCommand => {
        //         if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? {
        //             break;
        //         } else if let Ok(index) = input.parse::<usize>() {
        //             // ... (Directory selection logic - see below)
        //         } // ... other commands ...
        //     },
        //     // ... (other InputMode cases)
        // }
            
            
        
        
        
        // // Update the directory list (if in command mode)
        // if app.input_mode == InputMode::MainCommand {
        //      debug_log(" if app.input_mode == InputMode::MainCommand");
        //     app.update_directory_list()?; 
        // }

        // // Render the appropriate list based on the mode
        // // TODO this 2nd input is a legacy kludge, but is needed to show TUI for now
        // // TODO this is most likely VERY wrong and will not work for task-browser
        // match app.input_mode {
        //     InputMode::MainCommand => {
        //         tiny_tui::render_list(&app.tui_directory_list, &app.current_path);
        //         debug_log("InputMode::MainCommand => tiny_tui::render_list(&app.tui_directory_list, &app.current_path)");
                
        //     }
        //     // InputMode::TaskCommand => {
        //     //     tiny_tui::render_list(&app.tui_directory_list, &app.current_path);
        //     //     debug_log("InputMode::TaskCommand => tiny_tui::render_list(&app.tui_directory_list, &app.current_path)");
                
        //     // }
        //     InputMode::TaskCommand => {
        //         // Now render the task list using the TUI
        //         // app.load_tasks(); // This is already called in handle_main_command_mode("t", ...)
        //         // The table is already rendered within load_tasks, using the new tiny_tui::render_tasks_list
        //          debug_log!("InputMode::TaskCommand. render_tasks_list now used. ");  // Clear the screen
                
        //     },
        //     // TODO why is theis here? tui_textmessage_list is not the only option
        //     InputMode::InsertText => {
        //         tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path);
        //         debug_log("InputMode::InsertText => tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path);");
        //     }
        // }

        // // Read user inputs
        // let input = tiny_tui::get_input()?;

        // // Handle the input based on the mode
        // match app.input_mode {
            
            // InputMode::MainCommand => {
                
            //     // Handle commands (including 'm')s
            //     // if handle_main_command_mode(&input, &mut app, &mut graph_navigation_instance_state) {
            //     if handle_main_command_mode(&input, &mut app, &mut graph_navigation_instance_state)? {
            //         debug_log("QUIT");
            //         break; // Exit the loop if handle_main_command_mode returns true (e.g., for "q")
            //     } else if let Ok(index) = input.parse::<usize>() {
            //         let item_index = index - 1; // Adjust for 0-based indexing
            //         if item_index < app.tui_directory_list.len() {
            //             debug_log("main: if item_index < app.tui_directory_list.len()");
            //             debug_log!(
            //                 "main: app.tui_directory_list: {:?}",
            //                 app.tui_directory_list
            //             );
                        
            //             ////////////////////////////
            //             // Handle channel selection
            //             ////////////////////////////
                        
            //             // app.handle_tui_action(); // Remove the extra argument here

            //             debug_log("handle_tui_action() started in we_love_projects_loop()");
                        
            //             if app.current_path.display().to_string() == "project_graph_data/team_channels".to_string() {
            //                 debug_log("app.current_path == project_graph_data/team_channels");
            //                 debug_log(&format!("current_path: {:?}", app.current_path));

            //                 let input = tiny_tui::get_input()?; // Get input here
            //                 if let Ok(index) = input.parse::<usize>() { 
            //                     let item_index = index - 1; // Adjust for 0-based indexing
            //                     if item_index < app.tui_directory_list.len() {
            //                         let selected_channel = &app.tui_directory_list[item_index];
            //                         debug_log(&format!("Selected channel: {}", selected_channel)); // Log the selected channel name


            //                         //////////////////////////
            //                         // Enable sync flag here!
            //                         //////////////////////////
            //                         debug_log("About to set sync flag to true!");
            //                         set_sync_start_ok_flag_to_true();  //TODO turn on to use sync !!! (off for testing)
                                    
                                    
            //                         app.current_path = app.current_path.join(selected_channel);
                                    
            //                         debug_log(&format!("New current_path: {:?}", app.current_path)); // Log the updated current path
                                    
            //                         app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
                                    
            //                         // flag to start sync is set INSIDE nav_graph_look_read_node_toml() if a team_channel is entered
            //                         app.graph_navigation_instance_state.nav_graph_look_read_node_toml(); 

            //                         // Log the state after loading node.toml
            //                         debug_log(&format!("we_love_projects_loop() State after nav_graph_look_read_node_toml: {:?}", app.graph_navigation_instance_state));
                                    
            //                         // ... enter IM browser or other features ...
            //                     } else {
            //                         debug_log("Invalid index.");
            //                     }
            //                 } 
            //             } else if app.is_in_instant_message_browser_directory() {
            //                 // ... handle other TUI actions ...
            //                 debug_log("else if self.is_in_instant_message_browser_directory()");
                            
                            
            //             }
            //             debug_log("end handle_tui_action()");
            //         } else {
            //             debug_log("Invalid index.");
            //         }
            //     }
            // }

            // InputMode::TaskCommand => {
                
            //     // Handle Task commands (including 'm')
            //     if let Ok(num_input) = input.trim().parse::<usize>() { // Check for number first
            //         debug_log!("Task number input: {}", num_input);
                    
            //         if app.handle_task_number_selection(num_input) { // Exit task mode if selection is valid
            //             app.input_mode = InputMode::MainCommand; // Reset mode, return to previous context
            //         } else {
            //             app.load_tasks(); // If invalid selection, refresh task list, stay in TaskCommand mode.
            //         }                    
            //     } else if handle_main_command_mode(&input, &mut app, &graph_navigation_instance_state)? { // Handle other commands, like "q"
            //             break; // Pass to main command handler, quit if it returns true, staying in main loop otherwise.
            //         }
                                    
            // } // end TaskCommand case
                

            // InputMode::InsertText => {
                
            //     debug_log("handle_insert_text_input");
            //     // if input == "esc" { 
            //     if input == "q" {
            //         debug_log("esc toggled");
            //         app.input_mode = InputMode::MainCommand; // Access input_mode using self
            //         app.current_path.pop(); // Go back to the parent directory
            //     } else if !input.is_empty() {
            //         // TODO
            //         /*
            //         add feature and functionality
            //         to put likely json type into
            //         into the message text
            //         to be used for 'howler'
            //         selected rc 
            //         and expiration dates
            //         */
                    
            //         debug_log("!input.is_empty()");

            //         let local_owner_user = &app.graph_navigation_instance_state.local_owner_user; // Access using self

            //         // 1. final path name (.toml)
            //         let incoming_file_path = get_next_message_file_path(&app.current_path, local_owner_user); 
            //         debug_log(&format!("Next message path: {:?}", incoming_file_path)); // Log the calculated message path
                    
            //         // 2. make message file
            //         add_im_message(
            //             &incoming_file_path,
            //             local_owner_user,
            //             input.trim(), 
            //             None,
            //             &app.graph_navigation_instance_state, // Pass using self
            //         ).expect("handle_insert_text_input: Failed to add message");
                    
            //         let this_team_channelname = match get_current_team_channel_name_from_cwd() {
            //             Some(name) => name,
            //             None => "XYZ".to_string(),
            //         }; 
                    
            //         app.load_im_messages(); // Access using self
            //     }
            // } // end of InputMode::InsertText => {
        // } // end of match
//     } // end of main loop
//     debug_log("Finish: we love project loop.");
//     debug_log(">*< Halt signal received. Exiting The Uma. Closing... we_love_projects_loop() |o|");
    
//     Ok(())
// }

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
    let team_channel_name = match get_current_team_channel_name_from_cwd() {
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
    initialize_continue_uma_signal(); // set boolean flag for loops to hault
    initialize_hard_restart_signal(); // set boolean flag for uma restart

    let mut online_mode: bool = false;
    
    loop { // Main loop: let it fail, and try again

        if should_not_hard_restart() { // Check for restart
            debug_log("should_halt_uma(), exiting Uma in main()");
            break;
        }

        debug_log("boot...");
        match initialize_uma_application() {
            Ok(temp_online_val) => { 
                online_mode = temp_online_val;  
                if online_mode {   
                    debug_log!("UMA initialized in online mode.");
                } else {
                    debug_log!("UMA initialized in offline mode.")
                }
            }
            Err(e) => {  
                eprintln!("Initialization failed: {}", e);
                debug_log!("Initialization failed: {}", e);  
                std::process::exit(1);
                // break;
            }
        }
        
        debug_log("Start!");
        
        // Thread 1: Executes the thread1_loop function
        let we_love_projects_loop = thread::spawn(move || {
            we_love_projects_loop();
        });

        // Thread 2: Executes the thread2_loop function
        if online_mode {
            let you_love_the_sync_team_office = thread::spawn(move || {
                you_love_the_sync_team_office();
            });
            you_love_the_sync_team_office.join().unwrap(); // Wait for finish
        };
        
        we_love_projects_loop.join().unwrap(); // Wait for finish
        // if online_mode {
        //     you_love_the_sync_team_office.join().unwrap();
        //     } // Wait for finish
        // End
        println!("All threads completed. The Uma says fare well and strive.");
        debug_log("All threads completed. The Uma says fare well and strive.");
        debug_log(">*< Halt signal received. Exiting The Uma. Closing... main() |o|");
    }
}
