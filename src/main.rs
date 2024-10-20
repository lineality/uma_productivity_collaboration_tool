/*
Uma
2024.09-10
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
    Read,
};
use std::error::Error as StdError; 
use walkdir::WalkDir;
use std::path::Path;
use std::path::{
    PathBuf,
};
use std::time::{
    SystemTime, 
    UNIX_EPOCH,
    Instant,
};
use std::fs;
use std::fs::{
    File,
    OpenOptions,
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
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;

use std::process::Command;


// For Sync
use rand::prelude::{
    // SliceRandom,
    IteratorRandom,
    // Rng,
};

use std::thread;

use std::time::Duration;
use std::net::{
    IpAddr, 
    Ipv4Addr, 
    Ipv6Addr,
    TcpListener,
    TcpStream,
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
    IoError(io::Error),
    TomlError(toml::de::Error),
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
            (MyCustomError::TomlError(e1), MyCustomError::TomlError(e2)) => e1 == e2, 
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
            MyCustomError::TomlError(ref err) => Some(err),
            _ => None, // No underlying source for these variants
        }
    }
}

impl std::fmt::Display for MyCustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MyCustomError::IoError(err) => write!(f, "IO Error: {}", err),
            // MyCustomError::TomlError(err) => write!(f, "TOML Error: {}", err),
            MyCustomError::TomlError(err) => write!(f, "TOML Error: {}", err),
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
        MyCustomError::TomlError(error)
    }
}

#[derive(Debug)]
pub enum UmaError {
    IoError(io::Error),
    TomlError(toml::de::Error),
    InvalidData(String),
    PortCollision(String), 
    NetworkError(String),
    // ... Add other error types as needed ...
}

// Implement the std::error::Error trait for UmaError
impl std::error::Error for UmaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            UmaError::IoError(ref err) => Some(err),
            UmaError::TomlError(ref err) => Some(err),
            _ => None, 
        }
    }
}

// Implement the Display trait for UmaError for easy printing 
impl std::fmt::Display for UmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            UmaError::IoError(ref err) => write!(f, "IO Error: {}", err),
            UmaError::TomlError(ref err) => write!(f, "TOML Error: {}", err),
            UmaError::InvalidData(ref msg) => write!(f, "Invalid Data: {}", msg),
            UmaError::PortCollision(ref msg) => write!(f, "Port Collision: {}", msg),
            UmaError::NetworkError(ref msg) => write!(f, "Network Error: {}", msg), 
            // ... add formatting for other error types
        }
    }
}

// Implement the From trait to easily convert from other error types into UmaError
impl From<io::Error> for UmaError {
    fn from(err: io::Error) -> UmaError {
        UmaError::IoError(err)
    }
}

impl From<toml::de::Error> for UmaError {
    fn from(err: toml::de::Error) -> UmaError {
        UmaError::TomlError(err)
    }
}

/// get unix time 
/// e.g. for use with updated_at_timestamp
fn get_current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before the Unix epoch!") // Handle errors appropriately
        .as_secs()
}


fn check_all_ports_in_team_channels() -> Result<(), UmaError> {
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
                            return Err(UmaError::PortCollision(format!("Port {} is already in use.", ready_port)));
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
fn is_port_in_use(port: u16) -> bool {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => false, // Port is available
        Err(_) => true, // Port is in use
    }
}


// original for reference: 
// // 2. Read the 'continue_uma.txt' file 
// let file_content = match fs::read_to_string(CONTINUE_UMA_PATH) {
//     Ok(content) => content,
//     Err(_) => {
//         println!("Error reading 'continue_uma.txt'. Continuing..."); // Handle the error (e.g., log it) but continue for now
//         continue; // Skip to the next loop iteration
//     }
// };
// // break loop if continue=0
// if file_content.trim() == "0" {
//     debug_log("'continue_uma.txt' is 0. we_love_projects_loop() Exiting loop.");
//     break; 
// }
/// Function for broadcasting to theads to wrapup and end uma session: quit
fn should_halt() -> bool {
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
/// which is checked with a should_halt checker.
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

pub fn sign_toml_file(file_path: &Path) -> Result<(), Error> {
    let output = Command::new("gpg")
        .arg("--clearsign") 
        .arg(file_path)
        .output() 
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to run GPG: {}", e)))?;

    if output.status.success() {
        fs::write(file_path, output.stdout)?; // Overwrite with the signed content 
        debug_log!("File {} successfully signed with GPG.", file_path.display()); 
        Ok(())
    } else {
        debug_log!("GPG signing failed: {}", String::from_utf8_lossy(&output.stderr));
        Err(Error::new(ErrorKind::Other, "GPG signing failed"))
    }
}

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
fn get_toml_file_timestamp(file_path: &Path) -> Result<u64, UmaError> {
    let toml_string = std::fs::read_to_string(file_path)?;
    let toml_value: Value = toml::from_str(&toml_string)?;

    let timestamp = toml_value
        .get("updated_at_timestamp") // Access the "updated_at_timestamp" field
        .and_then(Value::as_integer) // Try to convert to an integer
        .and_then(|ts| ts.try_into().ok()) // Try to convert to u64
        .ok_or_else(|| {
            UmaError::InvalidData(format!(
                "Missing or invalid 'updated_at_timestamp' in TOML file: {}",
                file_path.display()
            ))
        })?;

    Ok(timestamp)
}

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


// // maybe deprecated
// #[derive(Debug, Clone, Hash, PartialEq, Eq)]
// struct LocalOwnerSyncPortsData {
//     local_user_name: String,
//     local_ipv6_address: Ipv6Addr,
//     local_public_gpg: String,
//     local_sync_interval: u64,
//     local_ready_port__your_desk_you_send: u16, // locally: 'you' send a signal through your port on your desk
//     local_intray_port__your_desk_you_listen: u16, // locally: 'you' listen for files sent by the other collaborator
//     local_gotit_port__your_desk_you_send: u16, // locally: 'you' send a signal through your port on your desk
// }

// maybe deprecated
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RemoteCollaboratorPortsData {
    remote_collaborator_name: String,
    remote_ipv6_address: Ipv6Addr,
    remote_public_gpg: String,
    remote_sync_interval: u64,
    remote_ready_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
    remote_intray_port__their_desk_you_send: u16, // locally: 'you' add files to their port on 'their' desk
    remote_gotit_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
}

// struct for reading/extracting raw abstract port assignments 
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
    local_user_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    local_user_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
    local_user_public_gpg: String,
    local_user_sync_interval: u64,
    local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: u16, // locally: 'you' listen for files sent by the other collaborator
    local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: u16, // locally: 'you' send a signal through your port on your desk
    remote_collaborator_name: String,
    remote_collaborator_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    remote_collaborator_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
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
    local_user_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    local_user_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
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
    remote_collaborator_ipv6_addr_list: Vec<Ipv6Addr>, // list of ip addresses
    remote_collaborator_ipv4_addr_list: Vec<Ipv4Addr>, // list of ip addresses
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
    let meeting_room_key = get_meeting_room_key(local_user_name, remote_collaborator_name);
    debug_log!("tpa 1. Meeting room key: {}", meeting_room_key);

    // 2. Get the port assignment vector for this meeting room
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




// // Helper function for translate_port_assignments
// // to construct the meeting room key
// Helper function to construct the meeting room key
fn get_meeting_room_key(user1: &str, user2: &str) -> String {
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

// // ALPHA VERSION
// // Function to read a TOML file and deserialize it into a Value
// pub fn read_state_items_tomls(file_name: &str) -> Result<Value, MyCustomError> {
//     let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
//     let toml_string = fs::read_to_string(file_path)?; // Now `?` converts to MyCustomError
//     toml::from_str(&toml_string).map_err(MyCustomError::from)  // Convert TomlError
// } 

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
    
    
    // fn handle_insert_text_input(input: &str, app: &mut App, graph_navigation_instance_state: &mut GraphNavigationInstanceState) {
   fn handle_insert_text_input(&mut self, input: &str) { // Correct function signature
        debug_log("fn handle_insert_text_input");
        if input == "^[" { 
            debug_log("esc toggled");
            self.input_mode = InputMode::Command; // Access input_mode using self
        } else if !input.is_empty() {
            debug_log("!input.is_empty()");

            let local_owner_user = &self.graph_navigation_instance_state.local_owner_user; // Access using self
            let message_path = get_next_message_file_path(&self.current_path, local_owner_user); // Access using self
            debug_log(&format!("Next message path: {:?}", message_path)); // Log the calculated message path
            
            add_im_message(
                &message_path,
                local_owner_user,
                input.trim(), 
                None,
                &self.graph_navigation_instance_state, // Pass using self
            ).expect("handle_insert_text_input: Failed to add message");

            self.load_im_messages(); // Access using self
        }
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


#[derive(Debug, Deserialize, serde::Serialize, Clone)]
struct CollaboratorTomlData {
    user_name: String,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_key_public: String,
    sync_interval: u64,
    updated_at_timestamp: u64,
}

impl CollaboratorTomlData {
    fn new(
        user_name: String, 
        ipv4_addresses: Option<Vec<Ipv4Addr>>,
        ipv6_addresses: Option<Vec<Ipv6Addr>>,
        gpg_key_public: String, 
        sync_interval: u64,
        updated_at_timestamp: u64,
    ) -> CollaboratorTomlData {
        CollaboratorTomlData {
            user_name,
            ipv4_addresses,
            ipv6_addresses,
            gpg_key_public,
            sync_interval,
            updated_at_timestamp,
        }
    }

    // Add any other methods you need here
}


fn add_collaborator_setup_file(
    user_name: String,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_key_public: String,
    sync_interval: u64,
    updated_at_timestamp: u64,
) -> Result<(), std::io::Error> {
    debug_log("Starting: fn add_collaborator_setup_file( ...cupa tea?");
    // Create the CollaboratorTomlData instance using the existing new() method:
    let collaborator = CollaboratorTomlData::new(
        user_name, 
        ipv4_addresses,
        ipv6_addresses, 
        gpg_key_public,
        sync_interval,
        updated_at_timestamp,
    );

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

    println!("Enter collaborator username:");
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();


    // choice...
    // Get IP address input method
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

    
    
    println!("Enter the collaborator's public GPG key:");
    let mut gpg_key_public = String::new();
    io::stdin().read_line(&mut gpg_key_public)?; 
    let gpg_key_public = gpg_key_public.trim().to_string();

    println!("Enter the collaborator's sync file transfer port (default: 40000):");
    let mut sync_port_input = String::new();
    io::stdin().read_line(&mut sync_port_input)?; 

    // Generate a random port within the desired range
    let mut rng = rand::thread_rng(); 

    println!("Enter the collaborator's sync interval in seconds (default: 60):");
    let mut sync_interval_input = String::new();
    io::stdin().read_line(&mut sync_interval_input)?;
    let sync_interval: u64 = sync_interval_input.trim().parse().unwrap_or(60);

    // Error Handling (You'll want to add more robust error handling here)
    if username.is_empty() { 
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Username cannot be empty",
        ));
    }

    // Create the CollaboratorTomlData struct
    // updated_at_now = SystemTime::now()
    
    // TODO: port not listed here anymore
    
    let new_collaborator = CollaboratorTomlData::new(
        username,
        ipv4_addresses, 
        ipv6_addresses, 
        gpg_key_public, 
        sync_interval,
        get_current_unix_timestamp(),
    ); 

    // Load existing collaborators from files
    // let existing_collaborators = read_a_collaborator_setup_toml().unwrap_or_default();
    let (existing_collaborators, errors) = read_a_collaborator_setup_toml().unwrap_or_default(); 

    // Log any errors encountered while reading collaborator files
    for error in errors {
        // HERE!! HERE!! HERE!!
        // You can use your debug_log macro here or any other logging mechanism
        debug_log!("Error reading collaborator file: {}", error); 
        println!("Error reading collaborator file: {}", error); 
    }
    
    // (You should add more validation here - for IPs, GPG keys, port uniqueness, etc.)

    // Check for collisions with existing collaborators (Add more comprehensive checks as needed)
    if let Some(error_message) = check_collaborator_collisions(
        &new_collaborator, 
        &existing_collaborators
    ) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            error_message, 
        ));
    } 

    // Persist the new collaborator
    add_collaborator_setup_file(
        new_collaborator.user_name.clone(), 
        new_collaborator.ipv4_addresses, 
        new_collaborator.ipv6_addresses,
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
// TODO: how to load value for active_team_channel when channel is entered

// todo, maybe make boostrap_uma_session_network()
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
        debug_log!("node_toml_path -> {:?}", &node_toml_path);
        
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

// /// Loads CollaboratorData from a TOML file.
// ///
// /// # Arguments
// ///
// /// * `file_path` - The path to the TOML file containing the collaborator data.
// ///
// /// # Returns
// ///
// /// * `Result<CollaboratorData, UmaError>` - `Ok(CollaboratorData)` if the data is 
// ///    successfully loaded, `Err(UmaError)` if an error occurs.
// fn load_collaborator_data_from_toml_file(file_path: &Path) -> Result<CollaboratorData, UmaError> {
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

//old 
// fn load_core_node_from_toml_file(file_path: &Path) -> Result<CoreNode, String> {
//     // 1. Read File Contents 
//     let toml_string = match fs::read_to_string(file_path) {
//         Ok(content) => content,
//         Err(e) => return Err(format!("Error reading file: {} in load_core_node_from_toml_file", e)),
//     };

//     // 2. Parse TOML String 
//     let toml_value = match toml_string.parse::<Value>() {
//         Ok(value) => value,
//         Err(e) => return Err(format!("Error parsing TOML in load_core_node_from_toml_file: {}", e)),
//     };

//     // 3. Deserialize into CoreNode Struct 
//     let core_node = match toml::from_str::<CoreNode>(&toml_string) {
//         Ok(node) => node,
//         Err(e) => return Err(format!("Error deserializing TOML in load_core_node_from_toml_file: {}", e)),
//     };

//     Ok(core_node)
// }


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

// TODO
/*

*/
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
    
    //old
    // let new_node = CoreNode::new(
    //     team_channel_name.clone(), // node_name
    //     team_channel_name.clone(), // description_for_tui
    //     new_channel_path.clone(),  // directory_path
    //     5,                // Order number (you might want to manage this)
    //     NodePriority::Medium, // Priority (you might want to make this configurable)
    //     owner,   // owner
    //     HashMap::new(),  // teamchannel_collaborators_with_access, Create an empty HashMap

    // );
    new_node.save_node_to_file().expect("Failed to save initial node data"); 
}



fn add_im_message(
    path: &Path,
    owner: &str,
    text: &str,
    signature: Option<String>,
    graph_navigation_instance_state: &GraphNavigationInstanceState, // Pass local_user_metadata here
) -> Result<(), io::Error> {
    
    // separate name and path
    let parent_dir = if let Some(parent) = path.parent() {
        parent
    } else {
        Path::new("")
    };

    // Now you can use `parent_dir` as needed
    // For example, you can check if it's an empty string
    if parent_dir == Path::new("") {
        debug_log("The path has no parent directory.");
    } else {
        debug_log(&format!("parent directory  {:?}", &parent_dir)); 
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
        
        
        
        // owner, // owner: owner.to_string(),
        // graph_navigation_instance_state.current_node_members, // teamchannel_collaborators_with_access: teamchannel_collaborators_with_access,
        // &node_name, // node_name: node_name.to_string(), , // Store the node name
        // &filepath_in_node, // filepath_in_node: filepath_in_node.to_string(), , // Store the filepath
        // text, // text_message: text_message.to_string(),
        // get_current_unix_timestamp(), // updated_at_timestamp: timestamp, , // utc posix timestamp
        // get_current_unix_timestamp(), // expires_at: expires_at, , // utc posix timestamp , // TODO!! update this
        // None, // links: Vec::new(),
        // signature, // signature,

        
        // owner, 
        // &node_name, 
        // &filepath_in_node, 
        // text, 
        // signature, 
        // &graph_navigation_instance_state
    );
    let toml_data = toml::to_string(&message).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
    })?; // Wrap TOML error in io::Error
    fs::write(path, toml_data)?;
    Ok(())
}


/// read_a_collaborator_setup_toml
/// e.g. for getting fields from collaborator setup files in roject_graph_data/collaborator_files_address_book
fn read_a_collaborator_setup_toml() -> Result<(Vec<CollaboratorTomlData>, Vec<UmaError>), UmaError> {
    let mut collaborators = Vec::new();
    let mut errors = Vec::new();
    let dir_path = Path::new("project_graph_data/collaborator_files_address_book");

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(OsStr::to_str) == Some("toml") {
            match fs::read_to_string(&path) {
                Ok(toml_string) => {
                    match toml::from_str::<CollaboratorTomlData>(&toml_string) {
                        Ok(collaborator) => collaborators.push(collaborator),
                        Err(e) => errors.push(UmaError::TomlError(e)),
                    }
                }
                Err(e) => errors.push(UmaError::IoError(e)),
            }
        }
    }

    if errors.is_empty() {
        Ok((collaborators, errors)) // All files parsed successfully
    } else {
        // Some files failed to parse, return the successfully parsed collaborators and the errors
        Ok((collaborators, errors)) 
    }
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
        // If the data directory does not exist, create it
        fs::create_dir_all(project_graph_directory).expect("Failed to create data directory");
    }

    /////////////////////
    // Log Housekeeping
    /////////////////////

    // 1. Create the archive directory if it doesn't exist.
    /// saves archives not in the project_graph_data directory, not for sync
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
        println!("Enter a GPG key:  // Posix? $gpg --list-keys");
        let mut gpg_key_public = String::new();
        io::stdin().read_line(&mut gpg_key_public).unwrap();
        let gpg_key_public = gpg_key_public.trim().to_string();

        // // load names of current collaborators to check for collisions: TODO
        // if check_collaborator_name_collision();

        let mut rng = rand::thread_rng(); 
        
        // let updated_at_timestamp = get_current_unix_timestamp()
        
        // // Add a new user to Uma file system
        add_collaborator_setup_file(
            username, 
            ipv4_addresses, 
            ipv6_addresses, 
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
            
                loop { // Enter the refresh loop
                    // 1. Read and display the log contents.
                    match fs::read_to_string("uma.log") {
                        Ok(log_contents) => {
                            println!("{}", log_contents); // Print to console for now
                        }
                        Err(e) => {
                            eprintln!("Failed to read uma.log: {}", e);
                        }
                    }
                    
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
               
            //     debug_log("Displaying debug log contents...");
            //     // 1. Read the contents of uma.log.
            //     match fs::read_to_string("uma.log") {
            //         Ok(log_contents) => {
            //             // 2. Print the log contents to the console.
            //             println!("{}", log_contents);
            //         }
            //         Err(e) => {
            //             debug_log!("Failed to read uma.log: {}", e);
            //         }
            //     }
            // }
            
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
                debug_log(&format!("app.current_path {:?}", &app.current_path)); 
                app.input_mode = InputMode::InsertText;

                // TODO Assuming you have a way to get the current node's name:
                let current_node_name = app.current_path.file_name().unwrap().to_string_lossy().to_string();

                app.current_path = app.current_path.join("instant_message_browser");

                debug_log(&format!("app.current_path after joining 'instant_message_browser': {:?}", &app.current_path)); 
                
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
fn get_next_message_file_path(current_path: &Path, local_owner_user: &str) -> PathBuf {
    let mut i = 1;
    loop {
        
        let file_path = current_path.join(format!("{}__{}.toml", i, local_owner_user));
        if !file_path.exists() {
            return file_path;
        }
        i += 1;
    }
}



/// Loads collaborator data from a TOML file based on the username.
///
/// This function constructs the path to the collaborator's TOML file
/// in the `project_graph_data/collaborator_files_address_book` directory, reads the file contents,
/// deserializes the TOML data into a `Collaborator` struct, and returns the result.
/// 
/// # Arguments 
///
/// * `username` - The username of the collaborator whose data needs to be loaded.
///
/// # Errors
/// 
/// This function returns a `Result<Collaborator, MyCustomError>` to handle potential errors:
///  - `MyCustomError::IoError`: If the collaborator file is not found or if there is an error reading the file.
///  - `MyCustomError::TomlError`: If there is an error parsing the TOML data.
///
/// # Example 
///
/// ```
/// let collaborator = get_addressbook_file_by_username("alice").unwrap(); // Assuming alice's data exists
/// println!("Collaborator: {:?}", collaborator); 
/// ```
fn get_addressbook_file_by_username(username: &str) -> Result<CollaboratorTomlData, MyCustomError> {
    debug_log!("Starting get_addressbook_file_by_username(username),  for -> '{}'", username);
    let toml_file_path = Path::new("project_graph_data/collaborator_files_address_book")
        .join(format!("{}__collaborator.toml", username));

    if toml_file_path.exists() {
        let toml_string = fs::read_to_string(&toml_file_path)?;
        let loaded_collaborator: CollaboratorTomlData = toml::from_str(&toml_string)
            .map_err(|e| MyCustomError::TomlError(e))?;
        debug_log!("in get_addressbook_file_by_username(), ??Collaborator file found ok: {:?}", &toml_file_path);
        Ok(loaded_collaborator)
    } else {
        debug_log!("in get_addressbook_file_by_username(), ??Collaborator file not found: {:?}", toml_file_path);
        debug_log!("??Collaborator file not found for '{}'", username);

        Err(MyCustomError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            format!("??Collaborator file not found: {:?}", toml_file_path),
        )))
    }
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
    debug_log!("1. Channel node.toml path: {:?}", &channel_node_toml_path); 

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
            debug_log!("Error 2. reading channel node.toml: {:?}", &channel_node_toml_path);
            debug_log!("Error 2. details: {}", e);
            return Err(MyCustomError::from(io::Error::new(io::ErrorKind::Other, e))); // Convert the error
        }
    };
    debug_log!("2. teamchannel_nodetoml_data->{:?}", &teamchannel_nodetoml_data);
    
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
    debug_log!("4. collaborators_names_array->{:?}", &collaborators_names_array);
    
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
                return Err(e); // Propagate the error
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

        // --- 11. Construct MeetingRoomSyncDataset (struct) ---
        // Assemble this one meeting room data-bundle from multiple sources
        // - from node.toml data
        // - from addressbook data
        // - from Instance-Role-Specific Local-Meeting-Room-Struct
        let mut meeting_room_sync_data = MeetingRoomSyncDataset {
            local_user_name: uma_local_owner_user.to_string(),  // TODO source?
            
            local_user_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.clone().unwrap_or_default(), // Assuming you want to use the first IPv6 address for the local user
            // local_user_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.expect("REASON"), // Assuming you want to use the first IPv6 address for the local user
            local_user_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.clone().unwrap_or_default(), // Get IPv4 addresses or an empty vector
            // local_user_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.expect("REASON"), // Assuming you want to use the first 
            local_user_public_gpg: these_collaboratorfiles_toml_data.gpg_key_public.clone(),
            local_user_sync_interval: these_collaboratorfiles_toml_data.sync_interval,
            
            local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip,
            localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip: role_based_ports.localuser_intray_port__yourdesk_youlisten__bind_yourlocal_ip,
            local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.local_user_gotit_port__yourdesk_yousend__aimat_their_rmtclb_ip,
            
            remote_collaborator_name: collaborator_name.clone(), // TODO source?
            
            remote_collaborator_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.unwrap_or_default(), // Get ip addresses or empty vector
            remote_collaborator_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.unwrap_or_default(), // Get IP addresses or empty vector
            // remote_collaborator_ipv6_addr_list: these_collaboratorfiles_toml_data.ipv6_addresses.expect("REASON"), // Get ip addresses or empty vector
            // remote_collaborator_ipv4_addr_list: these_collaboratorfiles_toml_data.ipv4_addresses.expect("REASON"), // Get IP addresses or empty vector
            remote_collaborator_public_gpg: these_collaboratorfiles_toml_data.gpg_key_public,
            remote_collaborator_sync_interval: these_collaboratorfiles_toml_data.sync_interval,
            
            remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip: role_based_ports.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip,
            remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip: role_based_ports.remote_collab_intray_port__theirdesk_yousend__aimat_their_rmtclb_ip,
            remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip: role_based_ports.remote_collab_gotit_port__theirdesk_youlisten__bind_yourlocal_ip,
        };
                
        // --- 12. add meeting room to set-of-rooms-table ---
        // add this one meeting room data-bundle to the larger set
        sync_config_data_set.insert(meeting_room_sync_data.clone()); 
        debug_log!("12. Created MeetingRoomSyncDataset: {:?}", &meeting_room_sync_data);
            
        
    } // End of collaborator loop

    debug_log!("12,13: sync_config_data_set created: {:?}", &sync_config_data_set);
    
    // 13. after iterating, return full set of meeting-rooms
    Ok(sync_config_data_set) 
}


fn send_hello_signal(target_addr: SocketAddr) -> Result<(), io::Error> {
    match TcpStream::connect(target_addr) {
        Ok(mut stream) => {
            stream.write_all(b"Hello, UMA!")?;
            println!("Sent 'Hello, UMA!' signal to {}", target_addr);
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to send signal to {}: {}", target_addr, e);
            Err(e) 
        }
    }
}

// // TODO which struct?
// // fn is_ip_allowlisted(ip: &IpAddr, sync_config_data_set: &HashSet<RemoteCollaboratorPortsData>) -> bool {
// fn is_ip_allowlisted(ip: &IpAddr, sync_config_data_set: &HashSet<ForRemoteCollaboratorDeskThread>) -> bool {
//     sync_config_data_set.iter().any(|sc| match ip {
//         IpAddr::V4(_) => false, // Currently only handling IPv6 
//         IpAddr::V6(ip_v6) => *ip_v6 == sc.remote_ipv6_address, 
//     })
// }


// // Helper function to check if a port is in use by another collaborator
// fn port_is_used_by_another_collaborator(port: u16, collaborators: &HashSet<RemoteCollaboratorPortsData>) -> bool { 
// }


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

// fn get_next_sync_request_username(sync_config_data_set: &HashSet<RemoteCollaboratorPortsData>) -> Option<String> {
//     // Choose a random collaborator from the set:
//     sync_config_data_set
//         .iter()
//         .choose(&mut rand::thread_rng())
//         .map(|collaborator| collaborator.remote_collaborator_name.clone())
// }


#[derive(Serialize, Deserialize, Debug)] // Add Serialize/Deserialize for sending/receiving
struct ReadySignal {
    id: String, // Unique event ID get a u64 representation of the ThreadId using the as_u64() method.
    timestamp: u64,
    echo: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct GotItSignal {
    id: u64, 
}

#[derive(Debug, Clone)] // Add other necessary derives later
struct SendQueue {
    timestamp: u64,
    echo: bool,
    items: Vec<PathBuf>,  // ordered list, filepaths
}


// let timestamp_request_port = // ... port for sending "ready to receive" to collaborator
// let file_receive_port = // ...  port for receiving files from collaborator 
// let receipt_confirmation_port = // ... port for sending confirmations to collaborator


fn send_data(data: &[u8], target_addr: SocketAddr) -> Result<(), io::Error> { 
    let socket = UdpSocket::bind(":::0")?; 
    socket.send_to(data, target_addr)?;
    Ok(())
}

/// Set up the local owner users in-tray desk
/// requests to recieve are sent from here
/// other people's owned docs are recieved here
/// gpg confirmed
/// save .toml (handle the type: content, node, etc.)
/// and 'gotit' signal sent out from here
///
/// echo: if any document comes in
/// automatically send out an echo-type request
/// to get a next file, in parallel
/// a thread per 'sync-event'
///     after entering loop
///     Alice follows these steps...
///     1. Check for halt/quit uma signal
///     2. Make a sync-event thread, enter thread
///     3. set sync_event_id to be unique thread id
///     4. Creates a ReadySignal instance to be the ready signal
///     5. Serialize the ReadySignal 
///     6. Send the signal @ local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip (exact ip choice pending...)
///     7. Listen at in-box for file for that event:
///        Alice waits N-miliseconds. If no reply, end thread.
///     if there is a reply to that event unqiue ID:
///     - gpg verify input (if not, kill thread)
///     - save .toml etc if ok (if not, end thread)
///     - make another echo-thread (repeat)
///     - if ok: send 'gotit!!' signal
///     - update 'last updated' file log (maybe append a timestamp stub file to a dir)
///     - end thread
fn handle_owner_desk(
    own_desk_setup_data: ForLocalOwnerDeskThread, 
) {
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
    // wait, if only for testing
    thread::sleep(Duration::from_millis(1000)); // Avoid busy-waiting
    
    // ALPHA non-parallel version
    debug_log!("Start HOD handle_owner_desk()");
    // Print all sync data for the desk
    debug_log!("
        HOD handle_owner_desk own_desk_setup_data: {:?}", 
        &own_desk_setup_data
    );

    loop { 
        // 1. check for halt/quit uma signal
        if should_halt() {
            break;
        }

        // Clone the data before moving it into the thread
        let own_desk_setup_data_clone = own_desk_setup_data.clone();

        // TODO (ideally put all this into a function...so it can echo itself)
        // 2. Spawn a thread to send the ReadySignal
        thread::spawn(move || {
            
            // 3. thread_id = 
            let sync_event_id__for_this_thread = format!("{:?}", thread::current().id()); 
            debug_log!(
                "HOD New sync-event thread id: {:?}; in handle_owner_desk()", 
                sync_event_id__for_this_thread
            );
            
            // // TODO eventually this should be the id of a thread
            // // Generate a unique event ID
            // let sync_event_id__for_this_thread: u64 = rand::random(); 

            // 4. Creates a ReadySignal instance to be the ready signal
            let ready_signal_to_send_from_this_loop = ReadySignal {
                id: sync_event_id__for_this_thread,
                timestamp: get_current_unix_timestamp(), 
                echo: false,
            };

            // 5. Serialize the ReadySignal
            let data = serialize_ready_signal(
                &ready_signal_to_send_from_this_loop
            ).expect("HOD Failed to serialize ReadySignal, ready_signal_to_send_from_this_loop"); 


            // TODO possibly have some mechanism to try addresses until one works?
            // 6. Send the signal @ local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
            // TODO figure out way to specify ipv6, 4, prioritizing, trying, etc.
            // (in theory...you could try them all?)
            // Select the first IPv6 address if available
            if let Some(first_ipv6_address) = own_desk_setup_data_clone.local_user_ipv6_addr_list.first() {
                // Copy the IPv6 address
                let ipv6_address_copy = *first_ipv6_address; 
            
                // Send the signal to the collaborator's ready_port
                let target_addr = SocketAddr::new(
                    IpAddr::V6(ipv6_address_copy), // Use the copied address
                    own_desk_setup_data_clone.local_user_ready_port__yourdesk_yousend__aimat_their_rmtclb_ip
                ); 

                // Log before sending
                debug_log!(
                    "HOD Attempting to send ReadySignal to {}: {:?}", 
                    target_addr, 
                    &data
                );

                // If sending to the first address succeeds, no need to iterate further
                if send_data(&data, target_addr).is_ok() {
                    debug_log("HOD Successfully sent ReadySignal to {} (first address)"//, target_addr
                        );
                    return; // Exit the thread
                } else {
                    debug_log("HOD Failed to send ReadySignal to {} (first address)"//, target_addr
                        );
                }
            } else {
                debug_log("HOD No IPv6 addresses available for {}"
                    // , own_desk_setup_data.local_user_name
                    );
            }

        
        // 7. Listen at in-box for file for that event:
        //     Alice waits N-miliseconds. If no reply, end thread.
        // if there is a reply to that event unqiue ID:
        // - gpg verify input (if not, kill thread)
        // - save .toml etc if ok (if not, end thread)
        // - make another echo-thread (repeat)
        // - if ok: send 'gotit!!' signal
        // - update 'last updated' file log (maybe append a timestamp stub file to a dir)
        // - end thread
        
        }); // End Thread
        
        // Pause and Tea
        thread::sleep(Duration::from_secs(3)); 
    } // end loop
    debug_log!(
        "HOD Exiting handle_owner_desk() for {}", 
        own_desk_setup_data.local_user_name
    ); // Add collaborator name
}


/// Vanilla serialize (no serde!)
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
fn serialize_ready_signal(signal: &ReadySignal) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();

    // Convert String to bytes using as_bytes()
    bytes.extend_from_slice(signal.id.as_bytes()); 

    bytes.extend_from_slice(&signal.timestamp.to_be_bytes()); 
    bytes.push(if signal.echo { 1 } else { 0 });
    Ok(bytes) 
}
/// Vanilla Deserilize json signal
fn deserialize_ready_signal(bytes: &[u8]) -> Result<ReadySignal, io::Error> {
    // Ensure the byte array has enough data for both fields:
    if bytes.len() != std::mem::size_of::<u64>() * 2 { // 2 u64 fields
        return Err(Error::new(
            ErrorKind::InvalidData, 
            "Invalid byte array length for ReadySignal"
        ));
    }

    // Extract id:
    let id = u64::from_be_bytes(bytes[0..8].try_into().unwrap()); 

    // Extract timestamp:
    let timestamp = u64::from_be_bytes(bytes[8..16].try_into().unwrap()); 

    // Extract timestamp:
    let echo = bytes[16] != 0; 
    
    Ok(ReadySignal { id: id.to_string(), timestamp, echo })

}


// // TODO, uncomment and debug 
// fn send_file_and_see_next_signal(collaborator: &RemoteCollaboratorPortsData, mut send_queue: SendQueue, event_id: u64, intray_port: u16, gotit_port: u16) {
//     // // 5. Send Files (One at a Time)
//     // while let Some(file_to_send) = send_queue.items.pop() { // Assuming items are file paths
//     //     // 6. Send One Item 
//     //     match send_file_to_collaborator(collaborator, &file_to_send, intray_port) {
//     //         Ok(_) => {
//     //             // 7. Listen for "Got it" or "Ready" on `gotit_port` (with timeout)
//     //             let listener = match TcpListener::bind(format!("[{}]:{}", collaborator.ipv6, gotit_port)) {
//     //                 Ok(listener) => listener,
//     //                 Err(e) => {
//     //                     debug_log(&format!("Failed to bind to 'Got it' port for {}: {}", collaborator.user_name, e));
//     //                     return; // Exit the sync event if we can't listen 
//     //                 }
//     //             };
//     //             listener.set_nonblocking(true).expect("Cannot set non-blocking");

//     //             let timeout = Duration::from_secs(5); // Adjust timeout as needed
//     //             let start_time = std::time::Instant::now();

//     //             loop {
//     //                 match listener.accept() {
//     //                     Ok((mut stream, _)) => {
//     //                         let mut buffer = [0; 1024];
//     //                         match stream.read(&mut buffer) {
//     //                             Ok(n) => {
//     //                                 if n == 0 {
//     //                                     continue; // Connection closed, try again
//     //                                 }

//     //                                 // Handle either GotItSignal or ReadySignal (both have the `id` field)
//     //                                 let signal_result: Result<GotItSignal, serde_json::Error> = serde_json::from_slice(&buffer[..n]);

//     //                                 match signal_result {
//     //                                     Ok(got_it_signal) => {
//     //                                         if got_it_signal.id == event_id {
//     //                                             debug_log(&format!("Got confirmation for file: {} from {}", file_to_send, collaborator.user_name));
//     //                                             break; // File successfully sent, exit the listening loop 
//     //                                         }
//     //                                     },
//     //                                     Err(_) => { 
//     //                                         let ready_signal_result: Result<ReadySignal, serde_json::Error> = serde_json::from_slice(&buffer[..n]);
//     //                                         match ready_signal_result {
//     //                                             Ok(ready_signal) if ready_signal.id == event_id => {
//     //                                                 debug_log(&format!("Collaborator {} is ready for the next file", collaborator.user_name));
//     //                                                 break; // Collaborator is ready, move to the next file
//     //                                             }
//     //                                             Ok(_) => {}, // Ignore ready signals with a different event ID
//     //                                             Err(e) => {
//     //                                                 debug_log(&format!("Failed to parse signal from {}: {}", collaborator.user_name, e));
//     //                                             }
//     //                                         }
//     //                                     }
//     //                                 }
//     //                             }
//     //                             Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
//     //                                 // No data available yet, check timeout
//     //                                 if start_time.elapsed() > timeout {
//     //                                     debug_log(&format!("Timeout waiting for confirmation from {}", collaborator.user_name));
//     //                                     return; // Exit sync event on timeout
//     //                                 }
//     //                                 thread::sleep(Duration::from_millis(100)); // Small delay to avoid busy-waiting 
//     //                             }
//     //                             Err(e) => {
//     //                                 debug_log(&format!("Error reading from 'Got it' port for {}: {}", collaborator.user_name, e));
//     //                                 return; // Exit on error 
//     //                             }
//     //                         } 
//     //                     }
//     //                     Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
//     //                         // No incoming connections yet, check timeout
//     //                         if start_time.elapsed() > timeout {
//     //                             debug_log(&format!("Timeout waiting for confirmation from {}", collaborator.user_name));
//     //                             return; // Exit sync event on timeout
//     //                         }
//     //                         thread::sleep(Duration::from_millis(100)); // Small delay
//     //                     }
//     //                     Err(e) => {
//     //                         debug_log(&format!("Error accepting connection on 'Got it' port for {}: {}", collaborator.user_name, e));
//     //                         return; // Exit on error
//     //                     }
//     //                 }
//     //             } // End of listening loop
//     //         }, 
//     //         Err(e) => {
//     //             debug_log(&format!("Failed to send file {} to {}: {}", file_to_send, collaborator.user_name, e));
//     //         }
//     //     } 
//     // } // End of file sending loop
// }


// TODO: which struct?
fn send_file_to_collaborator(
    collaborator: &RemoteCollaboratorPortsData,
    is_echo_request: bool,
    ready_timestamp: u64,
    file_to_send: &PathBuf, 
    tx: Sender<SyncResult>, 
    retry_flag_path: PathBuf, 
) -> SyncResult {
    /*
    TODO
    handling file_transfer_successful
    */
    // preset/reset
    let mut file_transfer_successful = false;
    
    // 1. Establish a connection to the collaborator's intray_port
    // ... (Implement connection logic)

    // 2. Send the file data
    // ... (Implement file sending logic)

    // 3. Listen for confirmation on the gotit_port
    // ... (Implement confirmation logic)

    // 4. Handle Success or Failure
    if file_transfer_successful && !is_echo_request{
        // Remove the retry flag
        // ... (Implement flag removal logic)
        return SyncResult::Success(ready_timestamp);
    } else {
        let error = UmaError::NetworkError("File transfer failed".to_string()); 
        return SyncResult::Failure(error);
    }
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




// TODO this is using a depricated struct...should this have its own struct? (WHY SO MANY STRUCTS???)
fn get_or_create_send_queue(
    collaborator_sync_data: &RemoteCollaboratorPortsData,
    received_timestamp: u64,
) -> Result<SendQueue, io::Error> {
    

    let mut new_queue = SendQueue {
        timestamp: received_timestamp,
        echo: received_timestamp == 0, // If timestamp is 0, it's an echo request
        items: Vec::new(),
    };

    // Iterate over owned files, only considering those modified AFTER the received timestamp
    let owned_files_dir = Path::new("project_graph_data/owned_files")
        .join(&collaborator_sync_data.remote_collaborator_name);

    for entry in WalkDir::new(owned_files_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        // let file_timestamp = get_toml_file_timestamp(&entry.path()); 
        // if file_timestamp > received_timestamp {
        //     new_queue.items.push(entry.path().to_path_buf());
        // }

        // Han dle the Result from get_file_timestamp 
        match get_toml_file_timestamp(&entry.path()) {
            Ok(file_timestamp) => { 
                if file_timestamp > received_timestamp {
                    new_queue.items.push(entry.path().to_path_buf());
                }
            }
            Err(e) => {
                // Handle the error appropriately. You might want to:
                // - Log the error
                // - Skip this file and continue with the next one
                // - Return an error from get_or_create_send_queue 
                eprintln!("Error getting timestamp for file: {:?} - {}", entry.path(), e);
            }
        }
    }

    // Sort the files in the queue based on their modification time
    new_queue.items.sort_by_key(|path| {
        get_toml_file_timestamp(path).unwrap_or(0) // Handle potential errors in timestamp retrieval
    });

    Ok(new_queue)
}



/// For each collaborator's-in-tray-desk:
/// - ports are specified in team_channel node.toml
/// - collaborator IP in NAME__collaborator.toml
///
/// Explanation
/// Listener Creation: The TcpListener is created and bound to the specified IP address and port.
///
/// Non-Blocking Mode: Setting the listener to non-blocking allows the loop to check for the halt signal even if no connection is available.
///
/// Halt Signal Check: The should_halt() function (which you need to implement based on your halt signal mechanism) is called at the beginning of each loop iteration. If the halt signal is detected, the loop breaks, and the listener is closed.
///
/// Connection Handling:
/// Ok((stream, _addr)): If a connection is successfully established, the code inside the Ok branch will execute. Here, you can spawn a new thread to handle the connection and process the received data.
///
/// Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock: If the accept() method returns a WouldBlock error, it means no connection is available at the moment. The code sleeps briefly to avoid consuming excessive CPU resources by busy-waiting.
///
/// Err(e): This branch handles any other errors that might occur during the connection process. You can log the error, notify the user, or take other appropriate actions depending on the error type.
///
/// Key Points
/// Non-Blocking Listener: Essential for checking the halt signal without waiting indefinitely for a connection.
///
/// Loop Structure: The loop continuously checks for a halt signal and attempts to accept connections.
/// start a loop that:
///
/// Error Handling:
/// 1. Distinguish Between Error Types: Not all errors are equal. Some errors might be transient (e.g., WouldBlock indicating no data is available yet), while others might be fatal (e.g., a socket error).
/// 2. Handle Transient Errors: For transient errors, we can simply continue the loop and try to receive data again.
/// 3. Handle Fatal Errors: For fatal errors, we should log the error, potentially notify the user, and consider exiting the function or the entire sync process.
///
/// TODO add  "Flow" steps: handle_collaborator_intray_desk()
fn handle_collaborator_intray_desk(
    meeting_room_sync_data_fn_input: &ForRemoteCollaboratorDeskThread,
) -> Result<(), UmaError> {
        /*
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
    */
    // TODO: why are  intray_port__their_desk_you_send and gotit_port__their_desk_you_listen never used here????
    debug_log!(
        "Started HCID the handle_collaborator_intray_desk() for->{}", 
        meeting_room_sync_data_fn_input.remote_collaborator_name
    );

    // 1. Create UDP socket
    // let socket = UdpSocket::bind(format!(
    //     "[{}]:{}", 
    //     meeting_room_sync_data_fn_input.remote_collaborator_ipv6_addr_list, 
    //     meeting_room_sync_data_fn_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip));
    // 1. Iterate over IPv6 addresses and attempt to bind the socket
    let mut socket: Option<UdpSocket> = None;
    for ipv6_address in &meeting_room_sync_data_fn_input.remote_collaborator_ipv6_addr_list {
        let bind_result = UdpSocket::bind(SocketAddr::new(
            IpAddr::V6(*ipv6_address), 
            meeting_room_sync_data_fn_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip
        ));

        match bind_result {
            Ok(sock) => {
                socket = Some(sock);
                debug_log!("HCID Bound UDP socket to [{}]:{}", ipv6_address, meeting_room_sync_data_fn_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip);
                break; // Exit the loop if binding is successful
            },
            Err(e) => {
                debug_log!("HCID Failed to bind to [{}]:{}: {}", ipv6_address, meeting_room_sync_data_fn_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip, e);
                // Continue to the next address
            }
        }
    }
    // Print all sync data for the collaborator
    debug_log!(
        "HCID Print all sync data for the collaborator:meeting_room_sync_data_fn_input {:?}", 
        meeting_room_sync_data_fn_input
    );

    // 3. Check if socket binding was successful (simplified)
    let socket = socket.ok_or(UmaError::NetworkError("HCID Failed to bind to any IPv6 address".to_string()))?;
                    
    debug_log!(
        "HCID 3. listen at this socket {:?}", 
        &socket,
    );

    // 2. Main loop
    let mut last_log_time = Instant::now(); // Track the last time we logged a message
    loop {
        debug_log("HCID starting Main loop...");
        // 3. Check for halt signal
        if should_halt() {
            debug_log!(
                "HCID Check for halt signal. Halting handle_collaborator_intray_desk() for {}", 
                meeting_room_sync_data_fn_input.remote_collaborator_name
            );
            break;
        }

        // 4. Receive data
        let mut buf = [0; 1024];
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                debug_log!("HCID 4. Received {} bytes from {} on ready_port", amt, src);

                // 5. Deserialize the ReadySignal
                let ready_signal: ReadySignal = match deserialize_ready_signal(&buf[..amt]) {
                    Ok(ready_signal) => {
                        println!("HCID 4. {}: Received ReadySignal: {:?}",
                             meeting_room_sync_data_fn_input.remote_collaborator_name, ready_signal
                        ); // Print to console
                        debug_log!("HCID 4. {}: Received ReadySignal: {:?}",
                             meeting_room_sync_data_fn_input.remote_collaborator_name, 
                             ready_signal
                        ); // Log the signal
                        ready_signal
                    },
                    Err(e) => {
                        debug_log!("HCID 4. Receive data Failed to parse ready signal: {}", e);
                        continue; // Continue to the next iteration of the loop
                    }
                };

                // ... (You can add logic here to handle the received ReadySignal) ...
            },
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // No data available yet, continue listening
                // Periodically log that we're listening
                if last_log_time.elapsed() >= Duration::from_secs(5) {
                    debug_log!("HCID 4. {}: Listening for ReadySignal on port {}", 
                               meeting_room_sync_data_fn_input.remote_collaborator_name, 
                               meeting_room_sync_data_fn_input.remote_collab_ready_port__theirdesk_youlisten__bind_yourlocal_ip);
                    last_log_time = Instant::now();
                }
            },
            Err(e) => {
                // Handle other errors
                debug_log!("HCID 4. {}: Error receiving data on ready_port: {} ({:?})", 
                           meeting_room_sync_data_fn_input.remote_collaborator_name, e, e.kind());
                // Consider exiting the function or the sync process if it's a fatal error
                return Err(UmaError::NetworkError(e.to_string())); // Example: Return a NetworkError
            }
        }

        thread::sleep(Duration::from_millis(100)); // Avoid busy-waiting
    }
    debug_log("ending HCID");
    Ok(())
}


// Result enum for the sync operation, allowing communication between threads
enum SyncResult {
    Success(u64), // Contains the new timestamp after successful sync
    Failure(UmaError), // Contains an error if sync failed 
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
        
        // TODO What is this doing? re: room_config_datasets
        Ok(room_config_datasets) => {
            debug_log!("Successfully generated room_config_datasets: {:?}", &room_config_datasets); 
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
            local_user_ipv6_addr_list: this_meetingroom_iter.local_user_ipv6_addr_list,
            local_user_ipv4_addr_list: this_meetingroom_iter.local_user_ipv4_addr_list,
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
            remote_collaborator_ipv6_addr_list: this_meetingroom_iter.remote_collaborator_ipv6_addr_list,
            remote_collaborator_ipv4_addr_list: this_meetingroom_iter.remote_collaborator_ipv4_addr_list,
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
            handle_owner_desk(data_baggy_for_owner_desk); 
        });
        // Their Desk
        let collaborator_desk_thread = thread::spawn(move || {
            handle_collaborator_intray_desk(&data_baggy_for_collaborator_desk);
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
                        debug_log(&format!("main: app.tui_directory_list: {:?}", &app.tui_directory_list));
                        
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
                if input == "esc" { 
                    debug_log("esc toggled");
                    app.input_mode = InputMode::Command; // Access input_mode using self
                    app.current_path.pop(); // Go back to the parent directory
                } else if !input.is_empty() {
                    debug_log("!input.is_empty()");

                    let local_owner_user = &app.graph_navigation_instance_state.local_owner_user; // Access using self
                    let message_path = get_next_message_file_path(&app.current_path, local_owner_user); // Access using self
                    debug_log(&format!("Next message path: {:?}", message_path)); // Log the calculated message path
                    
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
                "Halting handle_collaborator_intray_desk()"
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
