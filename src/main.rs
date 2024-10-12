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
    Rng,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct OthersCollaboratorPortsData {
    user_name: String,
    ipv6_address: Ipv6Addr,
    // sync_file_transfer_port: u16,
    sync_interval: u64,
    ready_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
    intray_port__their_desk_you_send: u16, // locally: 'you' add files to their port on 'their' desk
    gotit_port__their_desk_you_listen: u16, // locally: 'you' listen to their port on 'their' desk
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct LocalOwnerSyncPortsData {
    user_name: String,
    ipv6_address: Ipv6Addr,
    // sync_file_transfer_port: u16,
    sync_interval: u64,
    ready_port__your_desk_you_send: u16, // locally: 'you' send a signal through your port on your desk
    intray_port__your_desk_you_listen: u16, // locally: 'you' listen for files sent by the other collaborator
    gotit_port__your_desk_you_send: u16, // locally: 'you' send a signal through your port on your desk
}

// ALPHA VERSION
// Function to read a simple string from a file
pub fn read_state_string(file_name: &str) -> Result<String, std::io::Error> {
    let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
    fs::read_to_string(file_path)
}

// ALPHA VERSION
// Function to read a TOML file and deserialize it into a Value
pub fn read_state_items_tomls(file_name: &str) -> Result<Value, MyCustomError> {
    let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
    let toml_string = fs::read_to_string(file_path)?; // Now `?` converts to MyCustomError
    toml::from_str(&toml_string).map_err(MyCustomError::from)  // Convert TomlError
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
    // sync_file_transfer_port: u16,
    sync_interval: u64,
    updated_at_timestamp: u64,
}

impl CollaboratorTomlData {
    fn new(
        user_name: String, 
        ipv4_addresses: Option<Vec<Ipv4Addr>>,
        ipv6_addresses: Option<Vec<Ipv6Addr>>,
        gpg_key_public: String, 
        // sync_file_transfer_port: u16, 
        sync_interval: u64,
        updated_at_timestamp: u64,
    ) -> CollaboratorTomlData {
        CollaboratorTomlData {
            user_name,
            ipv4_addresses,
            ipv6_addresses,
            gpg_key_public,
            // sync_file_transfer_port,
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
    // sync_file_transfer_port: u16,
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
        // sync_file_transfer_port,
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
    let file_path = Path::new("project_graph_data/collaborator_files")
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
    // let sync_file_transfer_port: u16 = sync_port_input.trim().parse().unwrap_or(40000);
    // Generate a random port within the desired range
    let mut rng = rand::thread_rng(); 
    // let sync_file_transfer_port: u16 = rng.gen_range(40000..=50000); // depricated

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
        // sync_file_transfer_port, 
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
        // new_collaborator.sync_file_transfer_port, 
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
                
                
                
                // TODO why is graph-nav loading ports??? (and not including local user ports?)
                // // 4. Load Collaborator Ports (Only for Team Channel Nodes)
                // for collaborator_name in &this_node.teamchannel_collaborators_with_access {
                //     debug_log!("Loading this_collaborators_ports for: {}", collaborator_name);
            
                //     if let Some(next_iter_collaborators_ports) = this_node.collaborator_port_assignments.get(collaborator_name) {
                //         // --- LOAD COLLABORATOR DATA ONCE ---
                //         let collaborator_data = load_collaborator_by_username(collaborator_name)
                //             .unwrap_or_else(|e| {
                //                 debug_log!("Error loading collaborator {}: {}", collaborator_name, e);
                //                 panic!("Failed to load collaborator data."); // Or handle the error differently
                //             });
            
                //         // Now, USE collaborator_data to extract the values
                //         let collaborator_sync_data = OthersCollaboratorPortsData {
                //             user_name: collaborator_name.clone(),
                //             ipv6_address: collaborator_data.ipv6_addresses.unwrap()[0], // Assuming you always have at least one IPv6 address
                //             // sync_file_transfer_port: collaborator_data.sync_file_transfer_port,
                //             // TODO What is going in here?? tray_port? ready_port?
                //             sync_interval: collaborator_data.sync_interval,
                //             ready_port__their_desk_you_listen: next_iter_collaborators_ports.ready_port__other_collaborator,
                //             intray_port__their_desk_you_send: next_iter_collaborators_ports.intray_port__other_collaborator,
                //             gotit_port__their_desk_you_listen: next_iter_collaborators_ports.gotit_port__other_collaborator,
                //         };
            

                //     } else { 
                //         debug_log!("WARNING: No port assignments found for collaborator: {}", collaborator_name); 
                //     }
                // }
                // old archive
                // // 4. Load Collaborator Ports (Only for Team Channel Nodes)
                // for collaborator_name in &this_node.teamchannel_collaborators_with_access {
                //     if let Some(ports) = this_node.collaborator_port_assignments.get(collaborator_name) {
                //         // Create a OthersCollaboratorPortsData instance:
                //         let collaborator_sync_data = OthersCollaboratorPortsData {
                //             user_name: collaborator_name.clone(),
                //             ipv6_address: {
                //                 // Load IPv6 address from the collaborator's TOML file using `collaborator_name`
                //                 // Example: 
                //                 let collaborator_data = load_collaborator_by_username(collaborator_name)
                //                     .unwrap_or_else(|e| {
                //                         debug_log!("Error loading collaborator {}: {}", collaborator_name, e);
                //                         panic!("Failed to load collaborator data."); // Or handle the error differently
                //                     });

                //                 // Assuming `collaborator_data` has a field `ipv6_address`
                //                 collaborator_data.ipv6_addresses.unwrap()[0]
                //             },
                //             sync_file_transfer_port:  {
                //                 // Load sync_file_transfer_port from the collaborator's TOML file
                //                 // ... similar to loading ipv6_address ...
                //                 let collaborator_data = load_collaborator_by_username(collaborator_name)
                //                     .unwrap_or_else(|e| {
                //                         debug_log!("Error loading collaborator {}: {}", collaborator_name, e);
                //                         panic!("Failed to load collaborator data."); // Or handle the error differently
                //                     });
                //                 collaborator_data.sync_file_transfer_port
                //             },
                //             sync_interval: {
                //                 // Load sync_interval from the collaborator's TOML file
                //                 // ... similar to loading ipv6_address ...
                //                 let collaborator_data = load_collaborator_by_username(collaborator_name)
                //                     .unwrap_or_else(|e| {
                //                         debug_log!("Error loading collaborator {}: {}", collaborator_name, e);
                //                         panic!("Failed to load collaborator data."); // Or handle the error differently
                //                     });
                //                 collaborator_data.sync_interval
                //             },
                //             ready_port: ports.ready_port,
                //             intray_port: ports.tray_port,
                //             gotit_port: ports.gotit_port,
                //         };

                //         // Add to the relevant data structure for managing sync connections (e.g., a HashSet):
                //         // ... 
                        
                //         // Log success:
                //         debug_log!("Successfully loaded collaborator data for: {}", collaborator_name);
                //     } else {
                //         debug_log!("WARNING: No port assignments found for collaborator: {}", collaborator_name);
                //     } 
                // }
                
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
/// between collaborators within a UMA project node. Each collaborator associated with
/// a node has a unique `CollaboratorPortsAllData` instance. 
#[derive(Debug, Deserialize, Serialize, Clone)]
struct CollaboratorPortsAllData {
    /// The port used by the REMOTE collaborator to signal readiness to receive data.
    ready_port__other_collaborator: u16,
    /// The port used to send files to the REMOTE collaborator (their "in-tray").
    intray_port__other_collaborator: u16,
    /// The port used by the REMOTE collaborator to confirm file receipt.
    gotit_port__other_collaborator: u16,
    /// The port the LOCAL USER listens on for ready signals from the collaborator.
    ready_port__localowneruser: u16,
    /// The port the LOCAL USER listens on to receive files from the collaborator.
    intray_port__localowneruser: u16,
    /// The port the LOCAL USER uses to confirm file receipt to the collaborator.
    gotit_port__localowneruser: u16,
}

// old archive
// #[derive(Debug, Deserialize, Serialize, Clone)]
// struct CollaboratorPorts {
//     /// The port used by the collaborator to signal readiness to receive data.
//     ready_port: u16,
//     /// The port used to send files to the collaborator (their "in-tray").
//     tray_port: u16,
//     /// The port used by the collaborator to confirm file receipt.
//     gotit_port: u16,
//     /// The port this node listens on for ready signals from the collaborator.
//     self_ready_port: u16,
//     /// The port this node listens on to receive files from the collaborator.
//     self_tray_port: u16,
//     /// The port this node uses to confirm file receipt to the collaborator.
//     self_gotit_port: u16,
// }

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
/// Collaborator port assignments are stored in the `collaborator_port_assignments` field, which is a 
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
/// the `collaborator_port_assignments` field is serialized as a TOML table where the keys are the 
/// collaborator usernames and the values are tables containing the six port assignments.
///
/// When loading a `CoreNode` from a `node.toml` file (using the `load_node_from_file` function),
/// the TOML table representing collaborator ports is deserialized into the 
/// `collaborator_port_assignments` field. 
///
/// ## Example `node.toml` Section 
/// 
/// ```toml
/// [collaborator_port_assignments]
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
    collaborator_port_assignments: HashMap<String, CollaboratorPortsAllData>,
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
        Err(e) => return Err(format!("Error reading file: {}", e)),
    };

    // 2. Parse TOML String 
    let toml_value = match toml_string.parse::<Value>() {
        Ok(value) => value,
        Err(e) => return Err(format!("Error parsing TOML: {}", e)),
    };

    // 3. Deserialize into CoreNode Struct 
    let core_node = match toml::from_str::<CoreNode>(&toml_string) {
        Ok(node) => node,
        Err(e) => return Err(format!("Error deserializing TOML: {}", e)),
    };

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
collaborator_port_assignments: HashMap<String, CollaboratorPorts>,
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
/// * `collaborator_port_assignments` - A map of collaborator port assignments.
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
        collaborator_port_assignments: HashMap<String, CollaboratorPortsAllData>,
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
            collaborator_port_assignments, 
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
    /// * `collaborator_port_assignments` - A HashMap mapping collaborator usernames to their respective `CollaboratorPorts` struct, containing port assignments for synchronization.
    /// * `owner` - The username of the owner of this child node.
    /// * `description_for_tui` - A description of the child node, intended for display in the TUI.
    /// * `directory_path` - The file path where the child node's data will be stored.
    /// * `order_number` - The order number of the child node, determining its position within a list or hierarchy.
    /// * `priority` - The priority level of the child node (High, Medium, or Low).
    fn add_child(
        &mut self,
        teamchannel_collaborators_with_access: Vec<String>, 
        collaborator_port_assignments: HashMap<String, CollaboratorPortsAllData>, 
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
            collaborator_port_assignments,   
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
/// e.g. for getting fields from collaborator setup files in roject_graph_data/collaborator_files
fn read_a_collaborator_setup_toml() -> Result<(Vec<CollaboratorTomlData>, Vec<UmaError>), UmaError> {
    let mut collaborators = Vec::new();
    let mut errors = Vec::new();
    let dir_path = Path::new("project_graph_data/collaborator_files");

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

    // Ensure project_graph_data/collaborator_files directory exists
    let collaborator_files_dir = project_graph_directory.join("collaborator_files");
    if !collaborator_files_dir.exists() {
        fs::create_dir_all(&collaborator_files_dir).expect("Failed to create collaborator_files directory");
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
    
    


    
    
    // if !dir_at_path_is_empty_returns_false("project_graph_data/collaborator_files") {
    debug_log("if !dir_at_path_is_empty_returns_false(Path::new(project_graph_data/collaborator_files)) { ");
    if !dir_at_path_is_empty_returns_false(Path::new("project_graph_data/collaborator_files")) { 
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
        // let sync_file_transfer_port: u16 = rng.gen_range(40000..=50000); 
        
        // let updated_at_timestamp = get_current_unix_timestamp()
        
        // // Add a new user to Uma file system
        add_collaborator_setup_file(
            username, 
            ipv4_addresses, 
            ipv6_addresses, 
            gpg_key_public, 
            // sync_file_transfer_port, // sync_file_transfer_port
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
            
            "node" => {
                debug_log("Creating a new node...");

                // 1. Get input for node name
                println!("Enter a name for the new node:");
                let mut node_name_input = String::new();
                io::stdin().read_line(&mut node_name_input).expect("Failed to read node name input");
                let node_name = node_name_input.trim().to_string();

                // 2. Get input for description
                println!("Enter a description for the new node:");
                let mut description_input = String::new();
                io::stdin().read_line(&mut description_input).expect("Failed to read description input");
                let description_for_tui = description_input.trim().to_string();

                // 3. Get input for teamchannel_collaborators_with_access (comma-separated)
                println!("Enter teamchannel_collaborators_with_access (comma-separated usernames):");
                let mut teamchannel_collaborators_with_access_input = String::new();
                io::stdin().read_line(&mut teamchannel_collaborators_with_access_input).expect("Failed to read teamchannel_collaborators_with_access input");
                let teamchannel_collaborators_with_access: Vec<String> = teamchannel_collaborators_with_access_input
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();

                // 4. Construct collaborator_port_assignments HashMap
                let mut collaborator_port_assignments: HashMap<String, CollaboratorPortsAllData> = HashMap::new();
                for collaborator_name in &teamchannel_collaborators_with_access { 
                    // Load collaborator from file
                    let collaborator = match load_collaborator_by_username(collaborator_name) {
                        Ok(collaborator) => collaborator,
                        Err(e) => {
                            eprintln!("Error loading collaborator {}: {}", collaborator_name, e);
                            continue; // Skip to the next collaborator if there's an error
                        }
                    };

                    // Generate random ports for the collaborator 
                    let mut rng = rand::thread_rng();
                    let ready_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
                    let intray_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
                    let gotit_port__other_collaborator: u16 = rng.gen_range(40000..=50000);
                    let ready_port__localowneruser: u16 = rng.gen_range(40000..=50000);
                    let intray_port__localowneruser: u16 = rng.gen_range(40000..=50000);
                    let gotit_port__localowneruser: u16 = rng.gen_range(40000..=50000);

                    // Create CollaboratorPortsAllData and insert into the HashMap
                    collaborator_port_assignments.insert(
                        collaborator_name.clone(), 
                        CollaboratorPortsAllData {
                            ready_port__other_collaborator,
                            intray_port__other_collaborator,
                            gotit_port__other_collaborator,
                            ready_port__localowneruser,
                            intray_port__localowneruser,
                            gotit_port__localowneruser,
                        }
                    );
                }

                // 5. Get input for order number
                // TODO what is this?
                println!("Enter the (optional) order number for the new node:");
                let mut order_number_input = String::new();
                io::stdin().read_line(&mut order_number_input).expect("Failed to read order number input");
                let order_number: u32 = order_number_input.trim().parse().expect("Invalid order number");

                // 6. Get input for priority
                println!("Enter the (optional) priority for the new node (High, Medium, Low):");
                let mut priority_input = String::new();
                io::stdin().read_line(&mut priority_input).expect("Failed to read priority input");
                let priority = match priority_input.trim().to_lowercase().as_str() {
                    "high" => NodePriority::High,
                    "medium" => NodePriority::Medium,
                    "low" => NodePriority::Low,
                    _ => {
                        println!("Invalid priority. Defaulting to Medium.");
                        NodePriority::Medium
                    }
                };

                // 7. Create the new node directory
                let new_node_path = graph_navigation_instance_state.current_full_file_path.join(&node_name);
                fs::create_dir_all(&new_node_path).expect("Failed to create node directory");

                // 8. Create the Node instance
                let new_node = CoreNode::new(
                    node_name,
                    description_for_tui,
                    new_node_path,
                    order_number,
                    priority,
                    graph_navigation_instance_state.local_owner_user.clone(),
                    teamchannel_collaborators_with_access, // Pass the collaborators vector
                    collaborator_port_assignments, // Pass the collaborator_port_assignments HashMap
                );

                // 9. Save the node data to node.toml
                if let Err(e) = new_node.save_node_to_file() {
                    eprintln!("Failed to save node data: {}", e);
                    // Optionally handle the error more gracefully here
                } else {
                    debug_log!("New node created successfully!"); 
                }
            }, // end of node match arm

            
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
/// in the `project_graph_data/collaborator_files` directory, reads the file contents,
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
/// let collaborator = load_collaborator_by_username("alice").unwrap(); // Assuming alice's data exists
/// println!("Collaborator: {:?}", collaborator); 
/// ```
fn load_collaborator_by_username(username: &str) -> Result<CollaboratorTomlData, MyCustomError> {
    debug_log!("Starting load_collaborator_by_username(username),  for -> '{}'", username);
    let toml_file_path = Path::new("project_graph_data/collaborator_files")
        .join(format!("{}__collaborator.toml", username));

    if toml_file_path.exists() {
        let toml_string = fs::read_to_string(&toml_file_path)?;
        let loaded_collaborator: CollaboratorTomlData = toml::from_str(&toml_string)
            .map_err(|e| MyCustomError::TomlError(e))?;
        debug_log!("in load_collaborator_by_username(), ??Collaborator file found ok: {:?}", &toml_file_path);
        Ok(loaded_collaborator)
    } else {
        debug_log!("in load_collaborator_by_username(), ??Collaborator file not found: {:?}", toml_file_path);
        debug_log!("??Collaborator file not found for '{}'", username);

        Err(MyCustomError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            format!("??Collaborator file not found: {:?}", toml_file_path),
        )))
    }
}


/// Loads connection data for members of the currently active team channel.
/// On success, returns a `HashSet` of `OthersCollaboratorPortsData` structs, 
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
/// =/project_graph_data/collaborator_files/NAME__collaborator.toml
///
/// step 1: get team_channel list of (and data about) all possible team_channel_members
///     from externalized session state item doc @: 
///     project_graph_data/session_items/current_node_teamchannel_collaborators_with_access.toml
///     The 6-port assignments come from this source.
///
/// step 2: get /collaborator_files data @:
///     .../project_graph_data/collaborator_files/ directory
///     as: NAME__collaborator.toml
///
/// step 3: Remove any collaborator from that 'possible list' whose information
///     is not in the .../project_graph_data/collaborator_files directory
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
/// sample: project_graph_data/collaborator_files/alice__collaborator.toml
/// [[collaborator]]
/// user_name = "alice"
/// ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
/// ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
/// gpg_key_public = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
/// sync_file_transfer_port = 5000
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
/// # collaborator_port_assignments
/// [collaborator.alice]
/// collaborator_name = "alice"
/// ready_port = 50001
/// tray_port = 50002
/// gotit_port = 50003
/// self_ready_port = 50004
/// self_tray_port = 50005
/// self_gotit_port = 50006
///
/// [collaborator.bob]
/// collaborator_name = "bob"
/// ready_port = 50011
/// tray_port = 50012
/// gotit_port = 50013
/// self_ready_port = 50014
/// self_tray_port = 50015
/// self_gotit_port = 50016
///
/// maybe detects any port collisions, 
/// excluding those who collide with senior members
/// or returning an error if found.
fn make_session_connection_allowlists(uma_local_owner_user: &str) -> Result<HashSet<OthersCollaboratorPortsData>, MyCustomError> { 
    debug_log!("Entering make_session_connection_allowlists() function"); 

    // --- 1. LOAD TEAM CHANNEL node.toml ---
    let channel_dir_path_str = read_state_string("current_node_directory_path.txt")?; // read as string first
    debug_log!("Channel directory path (from session state): {}", channel_dir_path_str); 
    

    // TODO: use absolute file path
    let channel_dir_path = PathBuf::from(channel_dir_path_str);
    
    // A. Print the absolute path of the channel directory
    match channel_dir_path.canonicalize() {
        Ok(abs_path) => debug_log!("Absolute channel directory path: {:?}", abs_path),
        Err(e) => debug_log!("Error getting absolute path of channel directory: {}", e),
    }

    // let channel_dir_path = base_dir.join(channel_dir_path_str);
    
    // Construct the path to node.toml 
    let channel_node_toml_path = channel_dir_path.join("node.toml");
    debug_log!("Channel node.toml path: {:?}", &channel_node_toml_path); 

    // B. Print the absolute path of the node.toml file
    match channel_node_toml_path.canonicalize() {
        Ok(abs_path) => debug_log!("Absolute channel_dir_path node.toml path: {:?}", abs_path),
        Err(e) => debug_log!("Error getting absolute path of channel_dir_path node.toml: {}", e),
    }

    // --- 2. READ node.toml USING load_core_node_from_toml_file ---
    let channel_node_toml: CoreNode = match load_core_node_from_toml_file(&channel_node_toml_path) { 
        Ok(node) => {
            debug_log!("Successfully read channel node.toml"); 
            node
        },
        Err(e) => {
            debug_log!("Error reading channel node.toml: {:?}", &channel_node_toml_path);
            debug_log!("Error details: {}", e);
            return Err(MyCustomError::from(io::Error::new(io::ErrorKind::Other, e))); // Convert the error
        }
    };

    // Access data from the loaded CoreNode
    let collaborators_array = channel_node_toml.teamchannel_collaborators_with_access;
    // let collaborator_port_assignments = channel_node_toml.collaborator_port_assignments;

    // 3. CREATE ALLOWLIST SET
    let mut sync_config_data_set: HashSet<OthersCollaboratorPortsData> = HashSet::new();

    // // 4. PARSE COLLABORATORS
    // let collaborators_array = channel_node_toml.get("teamchannel_collaborators_with_access") 
    //     .and_then(Value::as_array)
    //     .ok_or_else(|| MyCustomError::InvalidData(
    //         "Missing or invalid 'teamchannel_collaborators_with_access' array in node.toml".to_string())
    //     )?;

    // debug_log!("??Collaborator array found: {:?}", &collaborators_array); 
    // for collaborator_data in collaborators_array { // collaborator_data is now a String
    for collaborator_name in collaborators_array { // collaborator_data is now a String

        //  5. GET COLLABORATOR USERNAME
        // let collaborator_name = if let toml::Value::String(name) = collaborator_data {
        //     name // Assign the string value directly
        // } else {
        //     return Err(MyCustomError::InvalidData("Invalid collaborator name in node.toml".to_string()));
        // };
            
        debug_log!("Processing collaborator: {}", collaborator_name);
        
        // --- 6. LOAD COLLABORATOR CONFIGURATION FILE (NAME__collaborator.toml) --- 
        let this_makelist_collaborator = match load_collaborator_by_username(&collaborator_name) {
            Ok(this_makelist_collaborator) => this_makelist_collaborator,
            Err(e) => {
                // This is where you'll most likely get the "No such file or directory" error
                debug_log!("Error loading collaborator {}. File might be missing. Error: {}", collaborator_name, e); 
                return Err(e); // Propagate the error
            }
        };

        debug_log!("??????Collaborator data loaded: {:?}", &this_makelist_collaborator);
        

        // Get the collaborator's ports from `collaborator_port_assignments` in `node.toml`
        // 7. GET COLLABORATOR PORTS from CoreNode
        let ports = channel_node_toml.collaborator_port_assignments.get(&collaborator_name) // Borrow collaborator_name
            .ok_or_else(|| {
                MyCustomError::InvalidData(format!("Missing port assignments for {} in node.toml", collaborator_name))
            })?;
    
        debug_log!("Port data found for {} : {:?}", collaborator_name, ports);

        // 8. GET IPv6 ADDRESS (If available) 
        let ipv6_address = this_makelist_collaborator
            .ipv6_addresses
            .and_then(|v| v.first().cloned())
            .ok_or_else(|| MyCustomError::InvalidData(format!("No IPv6 address found for {}", collaborator_name)))?;

        debug_log!("IPv6 address: {}", ipv6_address);

        // --- 9. CONSTRUCT `OthersCollaboratorPortsData` AND ADD TO ALLOWLIST ---

        if collaborator_name == uma_local_owner_user {
            // Create LocalOwnerSyncPortsData
            let local_owner_sync_data = Some(LocalOwnerSyncPortsData {
                user_name: collaborator_name.clone(),
                ipv6_address,
                sync_interval: this_makelist_collaborator.sync_interval,
                ready_port__your_desk_you_send: ports.ready_port__localowneruser,
                intray_port__your_desk_you_listen: ports.intray_port__localowneruser,
                gotit_port__your_desk_you_send: ports.gotit_port__localowneruser,
            });
        } else {
            // Create OthersCollaboratorPortsData
            let other_collaborator_syncdata = OthersCollaboratorPortsData {
                user_name: collaborator_name.clone(),
                ipv6_address,
                sync_interval: this_makelist_collaborator.sync_interval,
                ready_port__their_desk_you_listen: ports.ready_port__other_collaborator,
                intray_port__their_desk_you_send: ports.intray_port__other_collaborator,
                gotit_port__their_desk_you_listen: ports.gotit_port__other_collaborator,
            };
            // sync_config_data_set.insert(other_collaborator_syncdata);
            sync_config_data_set.insert(other_collaborator_syncdata.clone());
            debug_log!("Created OthersCollaboratorPortsData: {:?}", &other_collaborator_syncdata);
        }

    } // End of collaborator loop

    debug_log!("Allowlist created: {:?}", &sync_config_data_set);
    Ok(sync_config_data_set) 
}


// old archive
//         // --- 9. CONSTRUCT `OthersCollaboratorPortsData` AND ADD TO ALLOWLIST ---
//         // TODO HERE HERE HERE: what on earth is going into this? .tray_port???
//         let sync_collaborator = OthersCollaboratorPortsData {
//             user_name: collaborator_name.clone(), // Clone collaborator_name
//             ipv6_address, 
//             // sync_file_transfer_port: collaborator.sync_file_transfer_port, 
//             sync_interval: collaborator.sync_interval,
//             ready_port__their_desk_you_listen: ports.ready_port, // Access ports directly from the CollaboratorPorts struct
//             intray_port__their_desk_you_send: ports.tray_port,
//             gotit_port__their_desk_you_listen: ports.gotit_port,
//         };
//         debug_log!("Created OthersCollaboratorPortsData: {:?}", &sync_collaborator);

//         sync_config_data_set.insert(sync_collaborator); 
//     } // End of collaborator loop

//     debug_log!("Allowlist created: {:?}", &sync_config_data_set);
//     Ok(sync_config_data_set) 
// }

// old
// fn make_session_connection_allowlists(uma_local_owner_user: &str) -> Result<HashSet<OthersCollaboratorPortsData>, MyCustomError> { 
//     // 1. Load team channel node.toml: 
//     let channel_node_toml_path = Path::new("project_graph_data/session_state_items/current_node_directory_path.txt"); // TODO this file and system are not working yet
//     let channel_node_toml = read_state_items_tomls("node.toml")?; // Assuming you have a way to get the correct path 

//     // 2. Get the teamchannel_collaborators_with_access array:
//     let collaborators_array = channel_node_toml.get("teamchannel_collaborators_with_access") 
//         .and_then(Value::as_array)
//         .ok_or(MyCustomError::InvalidData(
//             "Missing or invalid 'teamchannel_collaborators_with_access' array in node.toml".to_string() // Add .to_string()
//         ))?;

//     // 3. Create the allowlist set:
//     let mut sync_config_data_set: HashSet<OthersCollaboratorPortsData> = HashSet::new();

//     // 4. Parse the teamchannel_collaborators_with_access array:
//     for collaborator_data in collaborators_array {
//         // TODO HERE!! HERE!! HERE!!
//         // ... (parse collaborator_data to get user_name, ready_port, intray_port, gotit_port)

//         // ... (Load IP information from NAME__collaborator.toml)

//         // ... (Construct OthersCollaboratorPortsData and add to sync_config_data_set) 
//     }
//     Ok(sync_config_data_set)

//     // ... (Rest of your function logic)
// }



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

fn is_ip_allowlisted(ip: &IpAddr, sync_config_data_set: &HashSet<OthersCollaboratorPortsData>) -> bool {
    sync_config_data_set.iter().any(|sc| match ip {
        IpAddr::V4(_) => false, // Currently only handling IPv6 
        IpAddr::V6(ip_v6) => *ip_v6 == sc.ipv6_address, 
    })
}


// // Helper function to check if a port is in use by another collaborator
// fn port_is_used_by_another_collaborator(port: u16, collaborators: &HashSet<OthersCollaboratorPortsData>) -> bool { 
//     collaborators.iter().any(|c| c.sync_file_transfer_port == port)
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

fn get_next_sync_request_username(sync_config_data_set: &HashSet<OthersCollaboratorPortsData>) -> Option<String> {
    // Choose a random collaborator from the set:
    sync_config_data_set
        .iter()
        .choose(&mut rand::thread_rng())
        .map(|collaborator| collaborator.user_name.clone())
}


#[derive(Serialize, Deserialize, Debug)] // Add Serialize/Deserialize for sending/receiving
struct ReadySignal {
    id: u64, // Unique event ID
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

/// local owner users in-try desk
/// requests to recieve are sent from here
/// other people's owned docs are recieved here
/// gpg confirmed
/// save .toml (handle the type: content, node, etc.)
/// and 'gotit' signal sent out
///
/// echo: if any docuemnt comes in
/// automatically sent out an echo-type request
fn handle_owner_desk(
    collaborator_input_for_desk: &OthersCollaboratorPortsData, 
) {
    // wait, if only for testing
    thread::sleep(Duration::from_millis(1000)); // Avoid busy-waiting
    
    // ALPHA non-parallel version
    debug_log!("Start handle_owner_desk()");
    // debug_log!(" for user_name->{}", collaborator.user_name); // Add collaborator name
    // debug_log!(" for user_name->{}", collaborator.user_name); // Add collaborator name

    // Print all sync data for the collaborator
    debug_log!("
        handle_owner_desk collaborator_input_for_desk Sync Data: {:?}", 
        collaborator_input_for_desk
    );

    loop { 
        // 1. check for halt/quit uma signal
        if should_halt() {
            break;
        }

        // TODO eventually this should probably be the id of a thread
        // Generate a unique event ID
        let sync_event_id__for_this_loop: u64 = rand::random(); 

        // Create a ReadySignal
        let ready_signal_to_send_from_this_loop = ReadySignal {
            id: sync_event_id__for_this_loop,
            timestamp: get_current_unix_timestamp(), 
            echo: false,
        };

        // Serialize the ReadySignal
        let data = serialize_ready_signal(
            &ready_signal_to_send_from_this_loop
        ).expect("Failed to serialize ReadySignal, ready_signal_to_send_from_this_loop"); 

        // Send the signal to the collaborator's ready_port
        let target_addr = SocketAddr::new(
            IpAddr::V6(collaborator_input_for_desk.ipv6_address), 
            collaborator_input_for_desk.ready_port__their_desk_you_listen
        ); 

        // Log before sending
        debug_log!(
            "Attempting to send ReadySignal to {}: {:?}", 
            target_addr, 
            ready_signal_to_send_from_this_loop
        );


        if let Err(e) = send_data(&data, target_addr) { // Assuming you have a send_data function
            debug_log!("Failed to send ReadySignal to {}: {}", target_addr, e);
            eprintln!("Failed to send ReadySignal to {}: {}", target_addr, e);
        } else {
            debug_log!("Sent ReadySignal to {}", target_addr);
            // println!("Sent ReadySignal to {}", target_addr);
            debug_log(&format!("Sent ReadySignal to {}", target_addr));
        }

        thread::sleep(Duration::from_secs(3)); 
    }
    debug_log!(
        "Exiting handle_owner_desk() for {}", 
        collaborator_input_for_desk.user_name
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
    bytes.extend_from_slice(&signal.id.to_be_bytes()); // Convert id to bytes
    bytes.extend_from_slice(&signal.timestamp.to_be_bytes()); // Convert timestamp to bytes
    // Serialize bool as a single byte (0 for false, 1 for true)
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
    
    Ok(ReadySignal { id, timestamp, echo })
}


// TODO, uncomment and debug 
fn send_file_and_see_next_signal(collaborator: &OthersCollaboratorPortsData, mut send_queue: SendQueue, event_id: u64, intray_port: u16, gotit_port: u16) {
    // // 5. Send Files (One at a Time)
    // while let Some(file_to_send) = send_queue.items.pop() { // Assuming items are file paths
    //     // 6. Send One Item 
    //     match send_file_to_collaborator(collaborator, &file_to_send, intray_port) {
    //         Ok(_) => {
    //             // 7. Listen for "Got it" or "Ready" on `gotit_port` (with timeout)
    //             let listener = match TcpListener::bind(format!("[{}]:{}", collaborator.ipv6, gotit_port)) {
    //                 Ok(listener) => listener,
    //                 Err(e) => {
    //                     debug_log(&format!("Failed to bind to 'Got it' port for {}: {}", collaborator.user_name, e));
    //                     return; // Exit the sync event if we can't listen 
    //                 }
    //             };
    //             listener.set_nonblocking(true).expect("Cannot set non-blocking");

    //             let timeout = Duration::from_secs(5); // Adjust timeout as needed
    //             let start_time = std::time::Instant::now();

    //             loop {
    //                 match listener.accept() {
    //                     Ok((mut stream, _)) => {
    //                         let mut buffer = [0; 1024];
    //                         match stream.read(&mut buffer) {
    //                             Ok(n) => {
    //                                 if n == 0 {
    //                                     continue; // Connection closed, try again
    //                                 }

    //                                 // Handle either GotItSignal or ReadySignal (both have the `id` field)
    //                                 let signal_result: Result<GotItSignal, serde_json::Error> = serde_json::from_slice(&buffer[..n]);

    //                                 match signal_result {
    //                                     Ok(got_it_signal) => {
    //                                         if got_it_signal.id == event_id {
    //                                             debug_log(&format!("Got confirmation for file: {} from {}", file_to_send, collaborator.user_name));
    //                                             break; // File successfully sent, exit the listening loop 
    //                                         }
    //                                     },
    //                                     Err(_) => { 
    //                                         let ready_signal_result: Result<ReadySignal, serde_json::Error> = serde_json::from_slice(&buffer[..n]);
    //                                         match ready_signal_result {
    //                                             Ok(ready_signal) if ready_signal.id == event_id => {
    //                                                 debug_log(&format!("Collaborator {} is ready for the next file", collaborator.user_name));
    //                                                 break; // Collaborator is ready, move to the next file
    //                                             }
    //                                             Ok(_) => {}, // Ignore ready signals with a different event ID
    //                                             Err(e) => {
    //                                                 debug_log(&format!("Failed to parse signal from {}: {}", collaborator.user_name, e));
    //                                             }
    //                                         }
    //                                     }
    //                                 }
    //                             }
    //                             Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    //                                 // No data available yet, check timeout
    //                                 if start_time.elapsed() > timeout {
    //                                     debug_log(&format!("Timeout waiting for confirmation from {}", collaborator.user_name));
    //                                     return; // Exit sync event on timeout
    //                                 }
    //                                 thread::sleep(Duration::from_millis(100)); // Small delay to avoid busy-waiting 
    //                             }
    //                             Err(e) => {
    //                                 debug_log(&format!("Error reading from 'Got it' port for {}: {}", collaborator.user_name, e));
    //                                 return; // Exit on error 
    //                             }
    //                         } 
    //                     }
    //                     Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    //                         // No incoming connections yet, check timeout
    //                         if start_time.elapsed() > timeout {
    //                             debug_log(&format!("Timeout waiting for confirmation from {}", collaborator.user_name));
    //                             return; // Exit sync event on timeout
    //                         }
    //                         thread::sleep(Duration::from_millis(100)); // Small delay
    //                     }
    //                     Err(e) => {
    //                         debug_log(&format!("Error accepting connection on 'Got it' port for {}: {}", collaborator.user_name, e));
    //                         return; // Exit on error
    //                     }
    //                 }
    //             } // End of listening loop
    //         }, 
    //         Err(e) => {
    //             debug_log(&format!("Failed to send file {} to {}: {}", file_to_send, collaborator.user_name, e));
    //         }
    //     } 
    // } // End of file sending loop
}



fn send_file_to_collaborator(
    collaborator: &OthersCollaboratorPortsData,
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
    collaborator: &OthersCollaboratorPortsData, 
    file_path: &PathBuf, 
    timestamp: u64,
) -> Result<PathBuf, io::Error> {
    let retry_flags_dir = Path::new("project_graph_data/sync_state_items")
        .join(&collaborator.user_name)
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




///
fn get_or_create_send_queue(
    collaborator_sync_data: &OthersCollaboratorPortsData,
    received_timestamp: u64,
) -> Result<SendQueue, io::Error> {
    

    let mut new_queue = SendQueue {
        timestamp: received_timestamp,
        echo: received_timestamp == 0, // If timestamp is 0, it's an echo request
        items: Vec::new(),
    };

    // Iterate over owned files, only considering those modified AFTER the received timestamp
    let owned_files_dir = Path::new("project_graph_data/owned_files")
        .join(&collaborator_sync_data.user_name);

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
    // TODO: why are  intray_port__their_desk_you_send and gotit_port__their_desk_you_listen never used here????
    collaborator_sync_data: &OthersCollaboratorPortsData,
) -> Result<(), UmaError> {
    debug_log!("Started the handle_collaborator_intray_desk() for->{}", collaborator_sync_data.user_name);

    // 1. Create UDP socket
    let socket = UdpSocket::bind(format!("[{}]:{}", 
                                        collaborator_sync_data.ipv6_address, 
                                        collaborator_sync_data.ready_port__their_desk_you_listen));

    // Print all sync data for the collaborator
    debug_log!("???Collaborator Sync Data: {:?}", collaborator_sync_data);

    let socket = match socket {
        Ok(sock) => {
            debug_log!("Bound UDP socket to [{}]:{}", collaborator_sync_data.ipv6_address, collaborator_sync_data.ready_port__their_desk_you_listen);
            sock
        },
        Err(e) => {
            debug_log!(
                "Error in handle_collaborator_intray_desk, binding UDP socket: {} ({:?}), 
                @port->{}", 
                e, 
                e.kind(), 
                collaborator_sync_data.ready_port__their_desk_you_listen
            );
            // Handle the error appropriately (e.g., return an error from the function)
            return Err(UmaError::NetworkError(e.to_string()));
        }
    };                                     
                                        
    debug_log!("Bound UDP socket to [{}]:{}", collaborator_sync_data.ipv6_address, collaborator_sync_data.ready_port__their_desk_you_listen);

    // 2. Main loop
    let mut last_log_time = Instant::now(); // Track the last time we logged a message
    loop {
        // 3. Check for halt signal
        if should_halt() {
            debug_log!("Halting handle_collaborator_intray_desk() for {}", collaborator_sync_data.user_name);
            break;
        }

        // 4. Receive data
        let mut buf = [0; 1024];
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                debug_log!("Received {} bytes from {} on ready_port", amt, src);

                // 5. Deserialize the ReadySignal
                let ready_signal: ReadySignal = match deserialize_ready_signal(&buf[..amt]) {
                    Ok(ready_signal) => {
                        println!("{}: Received ReadySignal: {:?}", collaborator_sync_data.user_name, ready_signal); // Print to console
                        debug_log!("{}: Received ReadySignal: {:?}", collaborator_sync_data.user_name, ready_signal); // Log the signal
                        ready_signal
                    },
                    Err(e) => {
                        debug_log!("Failed to parse ready signal: {}", e);
                        continue; // Continue to the next iteration of the loop
                    }
                };

                // ... (You can add logic here to handle the received ReadySignal) ...
            },
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // No data available yet, continue listening
                // Periodically log that we're listening
                if last_log_time.elapsed() >= Duration::from_secs(5) {
                    debug_log!("{}: Listening for ReadySignal on port {}", 
                               collaborator_sync_data.user_name, 
                               collaborator_sync_data.ready_port__their_desk_you_listen);
                    last_log_time = Instant::now();
                }
            },
            Err(e) => {
                // Handle other errors
                debug_log!("{}: Error receiving data on ready_port: {} ({:?})", 
                           collaborator_sync_data.user_name, e, e.kind());
                // Consider exiting the function or the sync process if it's a fatal error
                return Err(UmaError::NetworkError(e.to_string())); // Example: Return a NetworkError
            }
        }

        thread::sleep(Duration::from_millis(100)); // Avoid busy-waiting
    }

    Ok(())
}



// old archive works
// fn handle_collaborator_intray_desk(
//     collaborator_sync_data: &OthersCollaboratorPortsData,
// ) -> Result<(), UmaError> {
//     debug_log!("Started the handle_collaborator_intray_desk() for {}", collaborator_sync_data.user_name);

//     // 1. Create UDP socket
//     let socket = UdpSocket::bind(format!("[{}]:{}", 
//                                         collaborator_sync_data.ipv6_address, 
//                                         collaborator_sync_data.ready_port))?;
//     debug_log!("Bound UDP socket to [{}]:{}", collaborator_sync_data.ipv6_address, collaborator_sync_data.ready_port);

//     // 2. Main loop
//     // let mut last_log_time = Instant::now(); // Track the last time we logged a message
//     loop {
//         // 3. Check for halt signal
//         if should_halt() {
//             debug_log!("Halting handle_collaborator_intray_desk() for {}", collaborator_sync_data.user_name);
//             break;
//         }

//         // 4. Receive data
//         let mut buf = [0; 1024];
//         match socket.recv_from(&mut buf) {
//             Ok((amt, src)) => {
//                 debug_log!("Received {} bytes from {} on ready_port", amt, src);

//                 // 5. Deserialize the ReadySignal
//                 let ready_signal: ReadySignal = match deserialize_ready_signal(&buf[..amt]) {
//                     Ok(ready_signal) => {
//                         println!("{}: Received ReadySignal: {:?}", collaborator_sync_data.user_name, ready_signal); // Print to console
//                         debug_log!("{}: Received ReadySignal: {:?}", collaborator_sync_data.user_name, ready_signal); // Log the signal
//                         ready_signal
//                     },
//                     Err(e) => {
//                         debug_log!("Failed to parse ready signal: {}", e);
//                         continue;
//                     }
//                 };

//                 // ... (You can add logic here to handle the received ReadySignal) ...
//             },
//             Err(e) => {
//                 // Handle errors, but don't break the loop unless it's a fatal error
//                 debug_log!("Error receiving data on ready_port: {}", e);
//             }
//         }
//     }

//     Ok(())
// }



// // tcp version
// fn handle_collaborator_intray_desk(
//     collaborator_sync_data: &OthersCollaboratorPortsData,
// ) -> Result<(), UmaError> { // Consider using a custom error type for UMA
//     debug_log("Started the handle_collaborator_intray_desk()");

//     // 1. Initialize the send queue
//     let mut send_queue: Option<SendQueue> = None; 

//     // 2. Create the listener
//     let listener = TcpListener::bind(format!("[{}]:{}", 
//                                             collaborator_sync_data.ipv6_address, 
//                                             collaborator_sync_data.ready_port))?; 
//     listener.set_nonblocking(true)?;

//     // 3. Main loop
//     loop {
//         // 4. Check for halt signal
//         if should_halt() { 
//             break; 
//         }

//         // 5. Attempt to accept a connection (non-blocking)
//         match listener.accept() {
//             Ok((mut stream, _addr)) => {
//                 // 6. Read the incoming data
//                 let mut buffer = [0; 1024]; 
//                 match stream.read(&mut buffer) {
//                     Ok(n) => {
//                         if n == 0 {
//                             continue; // Connection closed gracefully, continue to next connection
//                         }

//                         // 7. Deserialize the ReadySignal
//                         let ready_signal: ReadySignal = match deserialize_ready_signal(&buffer[..n]) {
//                             Ok(ready_signal) => {
//                                 println!("Received ReadySignal: {:?}", ready_signal); // Print the received signal for testing
//                                 debug_log!("Received ReadySignal: {:?}", ready_signal); // Print the received signal for testing
//                                 ready_signal // Return the ReadySignal here
//                             },
//                             Err(e) => {
//                                 debug_log(&format!("Failed to parse ready signal: {}", e)); 
//                                 continue; 
//                             }
//                         };

//                         // 8. Determine if this is an echo request
//                         let is_echo_request = ready_signal.echo; // Directly check the echo field
                        
//                         let ready_timestamp = ready_signal.timestamp; // Directly check the echo field

//                         // 9. Handle echo requests
//                         if is_echo_request {
//                             if let Some(queue) = &mut send_queue {
//                                 if let Some(file_to_send) = queue.items.pop() {
//                                     // Call a function to handle the file transfer in a separate thread
//                                     //  You'll need to implement this function 
//                                     handle_sync_event_thread(
//                                         collaborator_sync_data, 
//                                         is_echo_request,
//                                         ready_timestamp,
//                                         &file_to_send, 
//                                         queue.timestamp, 
//                                         queue)?; 
//                                 }
//                             }
//                             continue; // Skip to the next iteration 
//                         }

//                         // 10. Handle non-echo requests: Get ready_timestamp
//                         let ready_timestamp = ready_signal.timestamp;

//                         // 11. Check for retry flags
//                         let oldest_retry_timestamp = get_oldest_retry_timestamp(&collaborator_sync_data.user_name)?;

//                         // 12. Create or rebuild the send queue
//                         if let Some(retry_timestamp) = oldest_retry_timestamp {
//                             if retry_timestamp < ready_timestamp {
//                                 send_queue = Some(get_or_create_send_queue(collaborator_sync_data, retry_timestamp)?); 
//                             } 
//                         } else if send_queue.is_none() || ready_timestamp < send_queue.as_ref().unwrap().timestamp {
//                             send_queue = Some(get_or_create_send_queue(collaborator_sync_data, ready_timestamp)?); 
//                         }

//                         // 13. Process the send queue (send one file) 
//                         if let Some(queue) = &mut send_queue {
//                             if let Some(file_to_send) = queue.items.pop() {
//                                 // Call the same thread handling function as in step 9
//                                 handle_sync_event_thread(
//                                     collaborator_sync_data,
//                                     is_echo_request,
//                                     ready_timestamp,
//                                     &file_to_send, 
//                                     queue.timestamp,  
//                                     queue)?;
//                             }
//                         }
//                     },
//                     Err(e) => { 
//                         debug_log(&format!("Failed to read data: {}", e)); 
//                     }
//                 }
//             },
//             Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => { 
//                 thread::sleep(Duration::from_millis(100));
//             },
//             Err(e) => { 
//                 debug_log(&format!("Failed to accept connection: {}", e)); 
//             }
//         } 
//     }

//     Ok(())
// }

// Result enum for the sync operation, allowing communication between threads
enum SyncResult {
    Success(u64), // Contains the new timestamp after successful sync
    Failure(UmaError), // Contains an error if sync failed 
}

// Function to handle the sync event in a separate thread
fn handle_sync_event_thread(
    collaborator_sync_data: &OthersCollaboratorPortsData,
    is_echo_request: bool,
    ready_timestamp: u64,
    file_to_send: &PathBuf,
    timestamp: u64, // Current base timestamp of the queue
    send_queue: &mut SendQueue, // Pass a mutable reference to the send queue
) -> Result<(), UmaError> {
    /*
    TODO
    possible factors:
    base-timestamp
    echo-no-timestamp
    echo modified success or no return (just remove fail flag?)
    */
    // Create a channel for communication between threads
    let (tx, rx) = channel::<SyncResult>(); 

    // Create the retry flag before spawning the thread
    // Clone the data before moving it into the thread
    let collaborator_clone = collaborator_sync_data.clone();
    let file_to_send_clone = file_to_send.clone(); 
    let retry_flag_path = create_retry_flag(collaborator_sync_data, file_to_send, timestamp)?;

    // Spawn the thread to handle file transfer
    thread::spawn(move || {
        // Now use the cloned data
        let result = send_file_to_collaborator(
            &collaborator_clone, // Pass a reference to the clone
            is_echo_request,
            ready_timestamp,
            &file_to_send_clone, 
            tx.clone(), 
            retry_flag_path
        );
        tx.send(result).unwrap(); 
    });

    // Receive the result from the thread and update the send queue
    match rx.recv().unwrap() {
        SyncResult::Success(new_timestamp) => {
            // 1. Update the base date 
            send_queue.timestamp = new_timestamp; 
        },
        SyncResult::Failure(error) => {
            eprintln!("File transfer failed: {:?}", error);
            // Handle failure (log, potentially notify user)
        }
    }

    Ok(())
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

    // let session_connection_allowlists = make_session_connection_allowlists(&uma_local_owner_user)?;
    // debug_log!("session_connection_allowlists -> {:?}", &session_connection_allowlists);
    //  --- 1. GET ALLOW LIST ---
    let session_connection_allowlists = match make_session_connection_allowlists(&uma_local_owner_user) {
        Ok(allowlist) => {
            debug_log!("Successfully generated allowlist: {:?}", &allowlist); 
            allowlist
        },
        Err(e) => {
            debug_log!("Error creating allowlist: {}", e);
            return Err(Box::new(e)); // Return the error early
        }
    };    
        
    // Create threads for each collaborator on the allowlist: 
    let mut collaborator_threads = Vec::new();
    for this_allowlisted_collaborator in session_connection_allowlists { 
        if this_allowlisted_collaborator.user_name != uma_local_owner_user {
            // debug_log!("Setting up connection with {}", this_allowlisted_collaborator.user_name);
            debug_log!("Setting up connection with {}", this_allowlisted_collaborator.user_name);
    
            // Move ownership directly into the threads
            // Clone the collaborator data before moving it into the closures
            
            // your desk
            // Get the local user's data
            let localowneruser_port_assignments = match make_session_connection_allowlists(&uma_local_owner_user) {
                Ok(allowlist) => {
                    allowlist.iter().find(|c| c.user_name == uma_local_owner_user).cloned()
                },
                Err(e) => {
                    debug_log!("Error creating allowlist for owner: {}", e);
                    return Err(Box::new(e));
                }
            }.expect("Local user not found in allowlist"); // Handle this error appropriately
            // Create the two "meeting room desks" for each collaborator pair:
            let owner_desk_thread = thread::spawn(move || {
                handle_owner_desk(&localowneruser_port_assignments); 
            });

            // their desk
            let collaborator_desk_collaborator = this_allowlisted_collaborator.clone();
            let collaborator_desk_thread = thread::spawn(move || {
                handle_collaborator_intray_desk(&collaborator_desk_collaborator);
            });

            collaborator_threads.push(owner_desk_thread); 
            collaborator_threads.push(collaborator_desk_thread);
        } 
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
fn initialize_continue_uma_signal() { 
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
    /* initialize_uma should happen in main
    before spawning threads:
    - safely start application for the first time ever
    - handle new setup files upon load
    - make sure directories all exist, etc.
    */

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
