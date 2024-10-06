/*
Uma
2024.09
The Uma Collaboration Protocol 
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
// use std::collections::HashMap;
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
};

// For TUI
mod tiny_tui_module;
use tiny_tui_module::tiny_tui;

const CONTINUE_UMA_PATH: &str = "project_graph_data/session_state_items/continue_uma.txt";
const SYNC_START_OK_FLAG_PATH: &str = "project_graph_data/session_state_items/ok_to_start_sync_flag.txt";

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
struct SyncCollaborator {
    user_name: String, 
    ipv6_address: Ipv6Addr,
    sync_file_transfer_port: u16,
    sync_interval: u64, 
    ready_port: u16,          // Add ready_port
    intray_port: u16,         // Add intray_port
    gotit_port: u16,    
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

#[derive(PartialEq)]
enum InputMode {
    Command,
    InsertText, // Or Insert_Text
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
                    debug_log(&format!("State after look_read_node_toml: {:?}", self.graph_navigation_instance_state));
                    
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
                // add_im_message(
                //     &self.current_path.join(this_file_name), 
                //     last_section,
                //     None,
                //     &local_owner_user, 
                //     first_message.trim(), 
                //     None,
                // )

                    // .expect("Failed to add first message");
                    
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
}

impl LocalUserUma {
    fn new(uma_local_owner_user: String) -> LocalUserUma {
        LocalUserUma { 
            uma_local_owner_user,
            uma_default_im_messages_expiration_days: 28, // Default to 7 days
            uma_default_task_nodes_expiration_days: 90, // Default to 30 days 
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
struct Collaborator {
    user_name: String,
    ipv4_addresses: Option<Vec<Ipv4Addr>>,
    ipv6_addresses: Option<Vec<Ipv6Addr>>,
    gpg_key_public: String,
    sync_file_transfer_port: u16,
    sync_interval: u64,
    updated_at_timestamp: u64,
}

impl Collaborator {
    fn new(
        user_name: String, 
        ipv4_addresses: Option<Vec<Ipv4Addr>>,
        ipv6_addresses: Option<Vec<Ipv6Addr>>,
        gpg_key_public: String, 
        sync_file_transfer_port: u16, 
        sync_interval: u64,
        updated_at_timestamp: u64,
    ) -> Collaborator {
        Collaborator {
            user_name,
            ipv4_addresses,
            ipv6_addresses,
            gpg_key_public,
            sync_file_transfer_port,
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
    sync_file_transfer_port: u16,
    sync_interval: u64,
    updated_at_timestamp: u64,
) -> Result<(), std::io::Error> {
    debug_log("Starting: fn add_collaborator_setup_file( ...cupa tea?");
    // Create the Collaborator instance using the existing new() method:
    let collaborator = Collaborator::new(
        user_name, 
        ipv4_addresses,
        ipv6_addresses, 
        gpg_key_public,
        sync_file_transfer_port,
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
    new_collaborator: &Collaborator, 
    existing_collaborators: &Vec<Collaborator> 
 ) -> Option<String> { 
    for existing in existing_collaborators { 
        if existing.user_name == new_collaborator.user_name { 
            return Some("Error: A collaborator with that username already exists!".to_string());
        } 
        // Add checks for IP and port conflicts
    }
    None // No collisions
}

fn check_team_channel_collision(channel_name: &str) -> bool {
     let team_channels_dir = Path::new("project_graph_data/team_channels");
     let channel_path = team_channels_dir.join(channel_name);
     channel_path.exists() 
}

fn add_collaborator_qa(
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> Result<(), io::Error> {

    debug_log("Enter collaborator username:");
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    // debug_log("Enter IPv4 address (or 'done' if finished, leave blank to skip):");
    // let ipv4_addresses = get_ip_addresses(IpAddrKind::V4)?;

    // debug_log("Enter IPv6 address (or 'done' if finished, leave blank to skip):");
    // let ipv6_addresses = get_ip_addresses(IpAddrKind::V6)?;


    debug_log("Enter IPv4 address (or 'done' if finished, leave blank to skip):");
    let ipv4_addresses = get_ipv4_addresses()?; // Use the new function

    debug_log("Enter IPv6 address (or 'done' if finished, leave blank to skip):");
    let ipv6_addresses = get_ipv6_addresses()?; // Use the new function
    
    debug_log("Enter the collaborator's public GPG key:");
    let mut gpg_key_public = String::new();
    io::stdin().read_line(&mut gpg_key_public)?; 
    let gpg_key_public = gpg_key_public.trim().to_string();

    debug_log("Enter the collaborator's sync file transfer port (default: 40000):");
    let mut sync_port_input = String::new();
    io::stdin().read_line(&mut sync_port_input)?; 
    // let sync_file_transfer_port: u16 = sync_port_input.trim().parse().unwrap_or(40000);
    // Generate a random port within the desired range
    let mut rng = rand::thread_rng(); 
    let sync_file_transfer_port: u16 = rng.gen_range(40000..=50000); 

    debug_log("Enter the collaborator's sync interval in seconds (default: 60):");
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

    // Create the Collaborator struct
    // updated_at_now = SystemTime::now()
    
    
    
    let collaborator = Collaborator::new(
        username,
        ipv4_addresses, 
        ipv6_addresses, 
        gpg_key_public, 
        sync_file_transfer_port, 
        sync_interval,
        get_current_unix_timestamp(),
    ); 

    // Load existing collaborators from files
    let existing_collaborators = read_a_collaborator_setup_toml().unwrap_or_default();

    // (You should add more validation here - for IPs, GPG keys, port uniqueness, etc.)

    // Check for collisions with existing collaborators (Add more comprehensive checks as needed)
    if let Some(error_message) = check_collaborator_collisions(&collaborator, &existing_collaborators) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            error_message, 
        ));
    } 

    // Persist the new collaborator
    add_collaborator_setup_file(
        collaborator.user_name.clone(), 
        collaborator.ipv4_addresses, 
        collaborator.ipv6_addresses,
        collaborator.gpg_key_public, 
        collaborator.sync_file_transfer_port, 
        collaborator.sync_interval,
        collaborator.updated_at_timestamp,
    )?; 

    println!("Collaborator '{}' added!", collaborator.user_name); 
    debug_log(&format!("Collaborator '{}' added!", collaborator.user_name)); 
    Ok(())
} 


// TODO: how to load value for active_team_channel when channel is entered
#[derive(Debug, Deserialize, Serialize, Clone)]
struct GraphNavigationInstanceState {
    local_owner_user: String, // Store the local user data here
    active_team_channel: String,  // TODO new
    default_im_messages_expiration_days: u64,
    default_task_nodes_expiration_days: u64,
    tui_height: u8,
    tui_width: u8,
    current_full_file_path: PathBuf,
    current_node_collaborators_with_access: Vec<String>,
    current_node_name: String,
    current_node_owner: String,
    current_node_description_for_tui: String,
    current_node_directory_path: PathBuf,
    current_node_unique_id: u64,
    current_node_members: Vec<String>,
    // app.&App,  // TODO really?
}

impl GraphNavigationInstanceState {

    
    fn look_read_node_toml(&mut self) {
        debug_log(&format!("fn look_read_node_toml() self.current_full_file_path -> {:?}", self.current_full_file_path)); 

        let node_toml_path = self.current_full_file_path.join("node.toml");

        if node_toml_path.exists() {
            match CoreNode::load_node_from_file(&node_toml_path) {
                Ok(this_node) => {
                    // ... (Existing node.toml loading logic)
                    // Check if this node is a team channel:
                    let path_components: Vec<_> = self.current_full_file_path.components().collect();
                    if path_components.len() >= 3 
                        && path_components[path_components.len() - 3].as_os_str() == "team_channels" 
                    {

                        
                        if let Some(team_channel_component) = path_components.get(path_components.len() - 2) {
                            self.active_team_channel = team_channel_component.as_os_str().to_string_lossy().to_string();


                        }
                    } else {
                        // This node is not a team channel node,
                        // potentially reset active_team_channel if needed:
                        // self.active_team_channel = "".to_string(); // Or a default value 
                    }
                }
                Err(e) => {
                    // ... (Handle node.toml loading error) 
                }
            }
        } else {
            // Handle case where node.toml doesn't exist (e.g., log a message)
            debug_log("node.toml not found at the current path. This directory is not a node.");
        }
    }
    
    // fn look_read_node_toml(&mut self) {
        
    //     debug_log(&format!("fn look_read_node_toml() self.current_full_file_path -> {:?}", self.current_full_file_path)); 
        
    //     let node_toml_path = self.current_full_file_path.join("node.toml");

        // if node_toml_path.exists() {
        //     match CoreNode::load_node_from_file(&node_toml_path) { // Load from node_toml_path
        //         Ok(this_node) => {
        //             // Update GraphNavigationInstanceState fields with data from node.toml
        //             self.current_node_collaborators_with_access = this_node.collaborators_with_access.clone(); // Use collaborators_with_access
        //             self.current_node_name = this_node.node_name;
        //             self.current_node_owner = this_node.owner;
        //             self.current_node_description_for_tui = this_node.description_for_tui;
        //             self.current_node_directory_path = this_node.directory_path;
        //             self.current_node_unique_id = this_node.node_unique_id;
        //             self.current_node_members = this_node.collaborators_with_access.clone(); // Use collaborators_with_access for members
        //             // self.current_node_last_updated = node.updated_at_timestamp; // Assuming Node has an 'updated_at_timestamp' field

        //             debug_log("Successfully loaded node.toml"); // Optional: Indicate success
        //         }
        //         Err(e) => {
        //             // Handle error (e.g., log the error or display an error message)
        //             eprintln!("Error loading node.toml: {}", e);
        //             debug_log(&format!("Error loading node.toml: {}", e)); 
        //         }
        //     }



    // /// Loads GraphNavigationInstanceState from a TOML file.
    // fn load_graph_navigation_state_from_toml(file_path: &Path) -> Result<GraphNavigationInstanceState, Error> {
    //     let raw_toml_string = fs::read_to_string(file_path)?;
    //     let state: GraphNavigationInstanceState = toml::from_str(&raw_toml_string).map_err(|e| {
    //         Error::new(
    //             ErrorKind::InvalidData,
    //             format!("Failed to deserialize GraphNavigationInstanceState from TOML: {}", e),
    //         )
    //     })?;
    //     Ok(state)
    // }

    // /// Saves GraphNavigationInstanceState to a TOML file.
    // fn save_graph_navigation_state_to_toml(state: &GraphNavigationInstanceState, file_path: &Path) -> Result<(), Error> {
    //     let toml_string = toml::to_string(state).map_err(|e| {
    //         Error::new(ErrorKind::Other, format!("TOML serialization error: {}", e))
    //     })?;
    //     fs::write(file_path, toml_string)?;
    //     Ok(())
    // }

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
            let collaborators_toml = toml::to_string(&self.current_node_collaborators_with_access).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to serialize collaborators to TOML: {}", e),
                )
            })?;
            fs::write(session_items_path.join("current_node_collaborators_with_access.toml"), collaborators_toml)?;
            
            // ... (save other Vec<String> values similarly)

            Ok(())
    }
}
    

//e.g.
// // Load active_team_channel:
// self.active_team_channel = fs::read_to_string(session_items_path.join("active_team_channel.txt"))?;
    
    


#[derive(Debug, Deserialize, Serialize)]
enum NodePriority {
    High,
    Medium,
    Low,
}

/*
the .toml files and the overall Uma~browser must be able to know their location in the overall project_graph_data/file-system

1. command 'make node' needs to be filled in to make a node in the 'current'
graph-dungeon location.
2. produce a .toml file in the node when node is made
3. load from the .toml file node is navigated into
4. node_name needs to be integrated, and accessed when the node is navigated into
*/

#[derive(Debug, Deserialize, Serialize)]
struct CoreNode {
    // Metadata
    node_name: String,
    description_for_tui: String, 
    node_unique_id: u64,
    directory_path: PathBuf,
    order_number: u32,
    priority: NodePriority,
    // Collaboration 
    owner: String, 
    collaborators_with_access: Vec<String>, 
    // Timestamps
    updated_at_timestamp: u64, 
    expires_at: u64, 
    // Children (potentially deprecated)
    children: Vec<CoreNode>, 
}

impl CoreNode {
    fn new(
        node_name: String,
        description_for_tui: String,
        directory_path: PathBuf,
        order_number: u32, // Add order number parameter
        priority: NodePriority, // Add priority parameter
        owner: String,
        collaborators_with_access: Vec<String>,
        // TODO expires_at
    ) -> CoreNode {
        let expires_at = get_current_unix_timestamp() + 86400; // 1 day from now
        let updated_at_timestamp = get_current_unix_timestamp();
        let node_unique_id = get_current_unix_timestamp(); // Generate a unique ID using a timestamp 
        CoreNode {
            node_name,
            description_for_tui,
            node_unique_id,
            directory_path,
            order_number, // Assign the order_number parameter
            priority,       // Assign the priority parameter
            owner,
            collaborators_with_access,
            updated_at_timestamp,
            expires_at,
            children: Vec::new(),
        }
    }


    /*
    TODO
    not used, not needed?
    */
    // fn add_collaborator_setup_file_by_username(&mut self, user_name: &str, contact_list: &CollaboratorList) {
    //     if let Some(contact) = contact_list.get_collaborator_by_username(user_name) {
    //         self.collaborators_with_access.push(contact.user_name.clone());
    //     }
    // }

    // fn remove_collaborator(&mut self, user_name: &str) {
    //     if let Some(pos) = self.collaborators_with_access.iter().position(|x| x == user_name) {
    //         self.collaborators_with_access.remove(pos);
    //     }
    // }

    fn add_child(
        &mut self,
        collaborators_with_access: Vec<String>,
        owner: String,
        description_for_tui: String,
        directory_path: PathBuf,
        order_number: u32,
        priority: NodePriority, 
        // node_unique_id: u64, // Remove this extra parameter 
    ) {
        let child = CoreNode::new(
            self.node_name.clone(), 
            description_for_tui,
            directory_path,
            order_number,
            priority,
            owner,
            collaborators_with_access, 
            // node_unique_id, // Remove this extra argument
        );
        self.children.push(child);
    }
            
    fn update_updated_at_timestamp(&mut self) {
        self.updated_at_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    }
    fn save_node_to_file(&self) -> Result<(), io::Error> {
        let toml_string = toml::to_string(&self).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
        })?; // Wrap TOML error in io::Error
        let file_path = self.directory_path.join("node.toml");
        fs::write(file_path, toml_string)?;
        Ok(())
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
    collaborators_with_access: Vec<String>, 
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
            updated_at_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            collaborators_with_access: Vec::new(), // by default use state-struct node members
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
    collaborators_with_access: Vec<String>, 
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
        let collaborators_with_access = graph_navigation_instance_state.current_node_collaborators_with_access.clone();

        InstantMessageFile {
            owner: owner.to_string(),
            collaborators_with_access: collaborators_with_access,
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
    //         collaborators_with_access: Vec<String>,
    //         owner: String,
    //         description_for_tui: String,
    //         directory_path: PathBuf,
    //         node_name: String,
    //         order_number: u32,
    //         priority: NodePriority, 
    //     ) -> Node {
    //     */
    // 3. Create node.toml with initial data for the team channel
    let new_node = CoreNode::new(
        team_channel_name.clone(), // node_name
        team_channel_name.clone(), // description_for_tui
        new_channel_path.clone(),  // directory_path
        5,                // Order number (you might want to manage this)
        NodePriority::Medium, // Priority (you might want to make this configurable)
        owner,   // owner
        vec![],  // collaborators_with_access

    );
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
        owner, 
        &node_name, 
        &filepath_in_node, 
        text, 
        signature, 
        &graph_navigation_instance_state
    );
    let toml_data = toml::to_string(&message).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
    })?; // Wrap TOML error in io::Error
    fs::write(path, toml_data)?;
    Ok(())
}



// fn get_collaborator_count() -> usize {
//     // Load the collaborator list from the data directory
//     let collaborator_list = dir_at_path_is_empty_returns_false("project_graph_data/collaborator_files");

//     // Return the number of collaborators in the list
//     collaborator_list.collaborators.len()
// }


// fn load_collaborator_list() -> CollaboratorList {
//     // Open the collaborator list file
//     // debug_log put cwd here
//     debug_log(&format!("get: project_graph_data/collaborators.toml  {:?}", PathBuf::from("")));
//     let mut file = File::open("project_graph_data/collaborators.toml").expect("Failed to open collaborator list file");

//     // Read the contents of the file into a string
//     let mut contents = String::new();
//     file.read_to_string(&mut contents).expect("Failed to read collaborator list file");

//     // Parse the TOML data into a CollaboratorList
//     let collaborator_list: CollaboratorList = toml::from_str(&contents).expect("Failed to parse collaborator list file");
    
//     debug_log(&format!("collaborator_list  {:?}", &collaborator_list));

//     collaborator_list
// }



fn read_a_collaborator_setup_toml() -> Result<Vec<Collaborator>, MyCustomError> {
    /*
    this...may be needed to read one file...but not used anywhere
    */
    let mut collaborators = Vec::new();
    let dir_path = Path::new("project_graph_data/collaborator_files");

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?; 
        let path = entry.path(); 

        if path.is_file() && path.extension().and_then(OsStr::to_str) == Some("toml") { 
            let toml_string = fs::read_to_string(path)?;
            let collaborator: Collaborator = toml::from_str(&toml_string)?;
            collaborators.push(collaborator); 
        } 
    }

    Ok(collaborators)
}

fn initialize_uma_application() {
    // Welcome to Uma Land!!
    

    // Check if the data directory exists
    let project_graph_directory = Path::new("project_graph_data");
    if !project_graph_directory.exists() {
        // If the data directory does not exist, create it
        fs::create_dir_all(project_graph_directory).expect("Failed to create data directory");
    }

    // Ensure project_graph_data/team_channels directory exists
    let team_channels_dir = project_graph_directory.join("team_channels");
    if !team_channels_dir.exists() {
        fs::create_dir_all(&team_channels_dir).expect("Failed to create team_channels directory");
    }

    // Ensure project_graph_data/team_channels directory exists
    let collaborator_files_dir = project_graph_directory.join("collaborator_files");
    if !collaborator_files_dir.exists() {
        fs::create_dir_all(&collaborator_files_dir).expect("Failed to create collaborator_files directory");
    }
    
    // Ensure project_graph_data/team_channels directory exists
    let session_state_dir = project_graph_directory.join("session_state_items");
    if !session_state_dir.exists() {
        fs::create_dir_all(&session_state_dir).expect("Failed to create session_state_items directory");
    }

    // Ensure project_graph_data/team_channels directory exists
    let sync_state_dir = project_graph_directory.join("sync_state_items");
    if !sync_state_dir.exists() {
        fs::create_dir_all(&sync_state_dir).expect("Failed to create sync_state_items directory");
    }
    
    // To stop sync from starting before a channel is entered:
    initialize_ok_to_start_sync_flag();

    // Check if there are any directories in project_graph_data/team_channels
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

    
    
    // In initialize_uma_application, when creating the first channel:
    // Get the owner from somewhere (e.g., user input or instance metadata)
    let owner = "initial_owner".to_string(); // Replace with actual owner

    create_team_channel(team_channel_name, owner);
    }
    
    

    // // Check if there are any existing users in the system
    // let user_count = get_collaborator_count();
    
    
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

      // Prompt for IPv6 addresses (potentially multiple):
        let mut ipv6_addresses = Vec::new();
        loop { 
            println!("Enter an IPv6 address (or 'done' if finished):"); 
            let mut ipv6_input = String::new();
            io::stdin().read_line(&mut ipv6_input).expect("Failed to read input.");

            let ipv6_input = ipv6_input.trim();
            if ipv6_input.to_lowercase() == "done" { 
                break; // Exit the loop
            }

            match ipv6_input.parse::<Ipv6Addr>() { 
                Ok(addr) => {
                    ipv6_addresses.push(addr);
                }
                Err(_) => {
                    println!("Invalid IPv6 address. Please try again.");
                }
            }
        }

      // Prompt for IPv6 addresses (potentially multiple):
        let mut ipv4_addresses = Vec::new();
        loop { 
            println!("Enter an IPv4 address (or 'done' if finished):"); 
            let mut ipv4_input = String::new();
            io::stdin().read_line(&mut ipv4_input).expect("Failed to read input.");

            let ipv4_input = ipv4_input.trim();
            if ipv4_input.to_lowercase() == "done" { 
                break; // Exit the loop
            }

            match ipv4_input.parse::<Ipv4Addr>() { 
                Ok(addr) => {
                    ipv4_addresses.push(addr);
                }
                Err(_) => {
                    println!("Invalid IPv4 address. Please try again.");
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
        let sync_file_transfer_port: u16 = rng.gen_range(40000..=50000); 
        
        // let updated_at_timestamp = get_current_unix_timestamp()
        
        // // Add a new user to Uma file system
        add_collaborator_setup_file(
            username, 
            Some(ipv4_addresses), // Wrap ipv4_addresses in Some()
            Some(ipv6_addresses), // Wrap ipv6_addresses in Some()
            gpg_key_public, 
            sync_file_transfer_port, // sync_file_transfer_port
            60,   // Example sync_interval (in seconds)
            get_current_unix_timestamp(),
        );

        // // Save the updated collaborator list to the data directory
        // let toml_data = toml::to_string(&collaborator_list).expect("Failed to serialize collaborator list");
        // fs::write(collaborator_list_file, toml_data).expect("Failed to write collaborator list file");

        println!("User added successfully!");
    }

    // Check if uma.toml exists
    let uma_toml_path = Path::new("uma.toml");
    if !uma_toml_path.exists() {
        // If uma.toml does not exist, prompt for owner and create it
        println!("Welcome to Uma! Please enter your username (this will be the owner for this Uma instance):");
        let mut owner_input = String::new();
        io::stdin().read_line(&mut owner_input).unwrap();
        let owner = owner_input.trim().to_string();

        let local_user_metadata = LocalUserUma::new(owner);
        local_user_metadata.save_owner_to_file(&uma_toml_path).expect("Failed to create uma.toml");
    } 
}

fn handle_command(
    input: &str, 
    app: &mut App, 
    graph_navigation_instance_state: &GraphNavigationInstanceState
) -> bool {
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
            "make node" | "new node" | "add node" => {
                debug_log("make node!");

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

                // 3. Get input for collaborators (comma-separated)
                println!("Enter collaborators (comma-separated usernames):");
                let mut collaborators_input = String::new();
                io::stdin().read_line(&mut collaborators_input).expect("Failed to read collaborators input");
                let collaborators_with_access: Vec<String> = collaborators_input
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();

                // 4. Get input for order number
                println!("Enter the order number for the new node:");
                let mut order_number_input = String::new();
                io::stdin().read_line(&mut order_number_input).expect("Failed to read order number input");
                let order_number: u32 = order_number_input.trim().parse().expect("Invalid order number");

                // 5. Get input for priority
                println!("Enter the priority for the new node (High, Medium, Low):");
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

                // 6. Create the new node directory
                let new_node_path = graph_navigation_instance_state.current_full_file_path.join(&node_name);
                fs::create_dir_all(&new_node_path).expect("Failed to create node directory");

                /*
                fn new(
                node_name: String,
                description_for_tui: String,
                directory_path: PathBuf,
                order_number: u32, // Add order number parameter
                priority: NodePriority, // Add priority parameter
                owner: String,
                collaborators_with_access: Vec<String>,
                */
                // 7. Create the Node instance
                let new_node = CoreNode::new(
                    node_name, // node_name: String,
                    description_for_tui, // description_for_tui: String,
                    new_node_path, // directory_path: PathBuf,
                    order_number, // order_number: u32, // Add order number parameter
                    priority, // priority: NodePriority, // Add priority parameter
                    graph_navigation_instance_state.local_owner_user.clone(), // owner: String,
                    collaborators_with_access, // collaborators_with_access: Vec<String>,               
                );

                // 8. Save the node data to node.toml
                new_node
                    .save_node_to_file()
                    .expect("Failed to save node data");

                // 9. Update the TUI to reflect the new node (if necessary)
            }
           "d" | "datalab" | "data lab" | "data" => {
                debug_log("Help!");
                // Display help information
            }
            "home" => {
                debug_log("home");
                app.current_path = PathBuf::from("project_graph_data/team_channels");
                // Update TUI display
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
                quit_set_continue_uma_to_false();
                
                return true; // Signal to exit the loop
            }
            _ => {
                // Display error message (e.g., "Invalid command")
                debug_log(" 'other' commend? _ => {...");
            }
            // ... (handle other commands)
            
        }
    }
    debug_log("end fn handle_command()");
    false // Don't exit by default
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




fn load_collaborator_by_username(username: &str) -> Result<Collaborator, MyCustomError> {
    let toml_file_path = Path::new("project_graph_data/collaborator_files")
        .join(format!("{}__collaborator.toml", username)); 

    // Check if the file exists before trying to read it:
    if toml_file_path.exists() {
        let toml_string = fs::read_to_string(toml_file_path)?;
        let collaborator: Collaborator = toml::from_str(&toml_string)
            .map_err(|e| MyCustomError::TomlError(e))?;

        Ok(collaborator)
    } else {
        Err(MyCustomError::IoError(io::Error::new(
            io::ErrorKind::NotFound, 
            format!("Collaborator file not found for '{}'", username)
        ))) 
    }
}



/// Loads connection data for members of the currently active team channel.
/// On success, returns a `HashSet` of `SyncCollaborator` structs, 
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
/// =project_graph_data/session_items/current_node_collaborators_with_access.toml
/// =/project_graph_data/collaborator_files/NAME__collaborator.toml
///
/// step 1: get team_channel list of (and data about) all possible team_channel_members
///     from externalized session state item doc @: 
///     project_graph_data/session_items/current_node_collaborators_with_access.toml
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
/// owner = "alice"
/// collaborators_with_access = [
///     { collaborator_name = "alice", 
///     ready_port = 50001, 
///     intray_port = 50002, 
///     gotit_port = 50003, 
///     self_ready_port = 50004, 
///     self_intray_port = 50005, 
///     self_gotit_port = 50006 
///     },
///     { collaborator_name = "bob", 
///     ready_port = 50011, 
///     intray_port = 50012, 
///     gotit_port = 50013, 
///     self_ready_port = 50014, 
///     self_intray_port = 50015, 
///     self_gotit_port = 50016  
///     },
///     # Add more collaborators as needed
/// ]
/// updated_at_timestamp = 1727641034
/// expires_at = 1727727434
/// node_name = "neem"
/// description_for_tui = "neem"
/// directory_path = "project_graph_data/team_channels/neem"
/// node_unique_id = 1727641034
/// children = []
/// order_number = 5
/// priority = "Medium"
/// maybe detects any port collisions, 
/// excluding those who collide with senior members
/// or returning an error if found.
fn make_session_connection_allowlists(uma_local_owner_user: &str) -> Result<HashSet<SyncCollaborator>, MyCustomError> { 
    // 1. Load team channel node.toml: 
    let channel_node_toml_path = Path::new("project_graph_data/session_state_items/current_node_directory_path.txt"); // TODO this file and system are not working yet
    let channel_node_toml = read_state_items_tomls("node.toml")?; // Assuming you have a way to get the correct path 

    // 2. Get the collaborators_with_access array:
    let collaborators_array = channel_node_toml.get("collaborators_with_access") 
        .and_then(Value::as_array)
        .ok_or(MyCustomError::InvalidData(
            "Missing or invalid 'collaborators_with_access' array in node.toml".to_string() // Add .to_string()
        ))?;

    // 3. Create the allowlist set:
    let mut sync_config_data_set: HashSet<SyncCollaborator> = HashSet::new();

    // 4. Parse the collaborators_with_access array:
    for collaborator_data in collaborators_array {
        // TODO HERE!! HERE!! HERE!!
        // ... (parse collaborator_data to get user_name, ready_port, intray_port, gotit_port)

        // ... (Load IP information from NAME__collaborator.toml)

        // ... (Construct SyncCollaborator and add to sync_config_data_set) 
    }
    Ok(sync_config_data_set)

    // ... (Rest of your function logic)
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

fn is_ip_allowlisted(ip: &IpAddr, sync_config_data_set: &HashSet<SyncCollaborator>) -> bool {
    sync_config_data_set.iter().any(|sc| match ip {
        IpAddr::V4(_) => false, // Currently only handling IPv6 
        IpAddr::V6(ip_v6) => *ip_v6 == sc.ipv6_address, 
    })
}


// Helper function to check if a port is in use by another collaborator
fn port_is_used_by_another_collaborator(port: u16, collaborators: &HashSet<SyncCollaborator>) -> bool { 
    collaborators.iter().any(|c| c.sync_file_transfer_port == port)
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

fn get_next_sync_request_username(sync_config_data_set: &HashSet<SyncCollaborator>) -> Option<String> {
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



fn handle_owner_desk(
    collaborator: &SyncCollaborator, 
//     rx: mpsc::Receiver<YourMessageType>,  // Optional channel receiver
//     tx: mpsc::Sender<YourMessageType>   // Optional channel sender 
) {
    // let timestamp_request_port = // ... port for sending "ready to receive" to collaborator
    // let file_receive_port = // ...  port for receiving files from collaborator 
    // let receipt_confirmation_port = // ... port for sending confirmations to collaborator

    // ... (Implement timestamp sending, file receiving, and confirmation logic)

    loop { // Add this dummy loop 
        // let timestamp_request_port = // ... port for sending "ready to receive" to collaborator
        // let file_receive_port = // ...  port for receiving files from collaborator 
        // let receipt_confirmation_port = // ... port for sending confirmations to collaborator

        // ... Implement your logic here using the port variables ...

        break; // Exit the loop immediately - we'll replace this with real logic later 
    } 

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
fn send_file_and_see_next_signal(collaborator: &SyncCollaborator, mut send_queue: SendQueue, event_id: u64, intray_port: u16, gotit_port: u16) {
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
    collaborator: &SyncCollaborator,
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
    collaborator: &SyncCollaborator, 
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
    collaborator_sync_data: &SyncCollaborator,
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
/// TODO add  "Flow" steps: handle_collaborator_intray_desk()
fn handle_collaborator_intray_desk(
    collaborator_sync_data: &SyncCollaborator,
) -> Result<(), UmaError> { // Consider using a custom error type for UMA
    debug_log("Started the handle_collaborator_intray_desk()");

    // 1. Initialize the send queue
    let mut send_queue: Option<SendQueue> = None; 

    // 2. Create the listener
    let listener = TcpListener::bind(format!("[{}]:{}", 
                                            collaborator_sync_data.ipv6_address, 
                                            collaborator_sync_data.ready_port))?; 
    listener.set_nonblocking(true)?;

    // 3. Main loop
    loop {
        // 4. Check for halt signal
        if should_halt() { 
            break; 
        }

        // 5. Attempt to accept a connection (non-blocking)
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                // 6. Read the incoming data
                let mut buffer = [0; 1024]; 
                match stream.read(&mut buffer) {
                    Ok(n) => {
                        if n == 0 {
                            continue; // Connection closed gracefully, continue to next connection
                        }

                        // 7. Deserialize the ReadySignal
                        let ready_signal: ReadySignal = match deserialize_ready_signal(&buffer[..n]) {
                            Ok(signal) => signal,
                            Err(e) => {
                                debug_log(&format!("Failed to parse ready signal: {}", e)); 
                                continue; 
                            }
                        };

                        // 8. Determine if this is an echo request
                        let is_echo_request = ready_signal.echo; // Directly check the echo field
                        
                        let ready_timestamp = ready_signal.timestamp; // Directly check the echo field

                        // 9. Handle echo requests
                        if is_echo_request {
                            if let Some(queue) = &mut send_queue {
                                if let Some(file_to_send) = queue.items.pop() {
                                    // Call a function to handle the file transfer in a separate thread
                                    //  You'll need to implement this function 
                                    handle_sync_event_thread(
                                        collaborator_sync_data, 
                                        is_echo_request,
                                        ready_timestamp,
                                        &file_to_send, 
                                        queue.timestamp, 
                                        queue)?; 
                                }
                            }
                            continue; // Skip to the next iteration 
                        }

                        // 10. Handle non-echo requests: Get ready_timestamp
                        let ready_timestamp = ready_signal.timestamp;

                        // 11. Check for retry flags
                        let oldest_retry_timestamp = get_oldest_retry_timestamp(&collaborator_sync_data.user_name)?;

                        // 12. Create or rebuild the send queue
                        if let Some(retry_timestamp) = oldest_retry_timestamp {
                            if retry_timestamp < ready_timestamp {
                                send_queue = Some(get_or_create_send_queue(collaborator_sync_data, retry_timestamp)?); 
                            } 
                        } else if send_queue.is_none() || ready_timestamp < send_queue.as_ref().unwrap().timestamp {
                            send_queue = Some(get_or_create_send_queue(collaborator_sync_data, ready_timestamp)?); 
                        }

                        // 13. Process the send queue (send one file) 
                        if let Some(queue) = &mut send_queue {
                            if let Some(file_to_send) = queue.items.pop() {
                                // Call the same thread handling function as in step 9
                                handle_sync_event_thread(
                                    collaborator_sync_data,
                                    is_echo_request,
                                    ready_timestamp,
                                    &file_to_send, 
                                    queue.timestamp,  
                                    queue)?;
                            }
                        }
                    },
                    Err(e) => { 
                        debug_log(&format!("Failed to read data: {}", e)); 
                    }
                }
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => { 
                thread::sleep(Duration::from_millis(100));
            },
            Err(e) => { 
                debug_log(&format!("Failed to accept connection: {}", e)); 
            }
        } 
    }

    Ok(())
}

// Result enum for the sync operation, allowing communication between threads
enum SyncResult {
    Success(u64), // Contains the new timestamp after successful sync
    Failure(UmaError), // Contains an error if sync failed 
}

// Function to handle the sync event in a separate thread
fn handle_sync_event_thread(
    collaborator_sync_data: &SyncCollaborator,
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


// Function for thread 2's file_sync loop: demo version
fn you_love_the_sync_team_office(
    // current_collaborator: &Collaborator, // The collaborator running this instance of UMA
    // allowlist: &HashSet<SyncCollaborator>,  // Collaborators to sync with in the current channel 
) -> Result<(), Box<dyn std::error::Error>> {
    /*
    "It's all fun and games until someone syncs a file."
    
    node.toml toml tables! store the ports: (check they are unique)
    { collaborator_name = "bob", ready_port = 50001, 
        intray_port = 50002, gotit_port = 50003, 
        self_ready_port = 50004, 
        self_intray_port = 50005, 
        self_gotit_port = 50006 },
    
    // ... other imports ...
    use std::sync::mpsc; // For message passing between threads (if needed)
    
    Version 2:
    as set by node.toml in the team_channel node
    
    for every other collaborator, you make:
    two threds:
        - your in-tray desk
        - their in-tray desk
        
    Each thred has six ports:
        - three for each 'in-tray desk'
        
    For each this-session-active-collaborator you keep a send-queue.
    For one who never requested a file (who isn't online): no need to make a send-queue
          
          if should_halt() { 
         println!("UMA exiting. Closing connection to collaborator...");
         // ... (Perform cleanup, close network connections, etc.)
         break; // Exit the thread's loop.
      }
    */
    
    // Read uma_local_owner_user from uma.toml
    let uma_toml_path = Path::new("uma.toml");
    let user_metadata = toml::from_str::<toml::Value>(&fs::read_to_string(uma_toml_path)?)?; 
    let uma_local_owner_user = user_metadata["uma_local_owner_user"].as_str().unwrap().to_string();

    debug_log!("Starting UMA Sync Team Office for {}", &uma_local_owner_user);

    let session_connection_allowlists = make_session_connection_allowlists(&uma_local_owner_user)?;
    // let session_connection_allowlists_clone = session_connection_allowlists.clone();
    
    /*issue:
    error[E0597]: `session_connection_allowlists_clone` does not live long enough
        --> src/main.rs:2898:42
        |
    2893 |     let session_connection_allowlists_clone = session_connection_allowlists.clone();
        |         ----------------------------------- binding `session_connection_allowlists_clone` declared here
    ...
    2898 |     for this_allowlisted_collaborator in &session_connection_allowlists_clone { 
        |                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        |                                          |
        |                                          borrowed value does not live long enough
        |                                          argument requires that `session_connection_allowlists_clone` is borrowed for `'static`
    ...
    2925 | }
        | - `session_connection_allowlists_clone` dropped here while still borrowed
    
        Neither session_connection_allowlists nor a clone can be used...
    */

    // // Create threads for each collaborator on the allowlist: 
    // let mut collaborator_threads = Vec::new();
    // for this_allowlisted_collaborator in &session_connection_allowlists { 
    //     if this_allowlisted_collaborator.user_name != uma_local_owner_user {
    //         println!("Setting up connection with {}", this_allowlisted_collaborator.user_name);

    //         // Create the two "meeting room desks" for each collaborator pair:
    //         // let (tx_owner_desk, rx_owner_desk) = mpsc::channel(); // Optional channels for thread communication
    //         // let (tx_collaborator_desk, rx_collaborator_desk) = mpsc::channel(); 

    //         let owner_desk_thread = thread::spawn(move || {
    //             handle_owner_desk(&this_allowlisted_collaborator); 
    //         });
    //         let collaborator_desk_thread = thread::spawn(move || {
    //             handle_collaborator_intray_desk(&this_allowlisted_collaborator);
    //         });

    //         collaborator_threads.push(owner_desk_thread); 
    //         collaborator_threads.push(collaborator_desk_thread); 
    //     } 
    // } 

        
    // Create threads for each collaborator on the allowlist: 
    let mut collaborator_threads = Vec::new();
    for this_allowlisted_collaborator in session_connection_allowlists { 
        if this_allowlisted_collaborator.user_name != uma_local_owner_user {
            println!("Setting up connection with {}", this_allowlisted_collaborator.user_name);
    
            // Move ownership directly into the threads
            // Clone the collaborator data before moving it into the closures
            let owner_desk_collaborator = this_allowlisted_collaborator.clone(); 
            let collaborator_desk_collaborator = this_allowlisted_collaborator.clone();

            // Create the two "meeting room desks" for each collaborator pair:
            let owner_desk_thread = thread::spawn(move || {
                handle_owner_desk(&owner_desk_collaborator); 
            });
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


    // 'state'
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

        current_full_file_path: PathBuf::new(),
        // Initialize other fields of GraphNavigationInstanceState
        current_node_collaborators_with_access: Vec::new(),
        current_node_name: String::new(),
        current_node_owner: String::new(),
        current_node_description_for_tui: String::new(),
        current_node_directory_path: PathBuf::new(),
        current_node_unique_id: 0,
        current_node_members: Vec::new(),

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
                if handle_command(&input, &mut app, &mut graph_navigation_instance_state) {
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
                                    debug_log(&format!("State after look_read_node_toml: {:?}", app.graph_navigation_instance_state));
                                    
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
            // InputMode::InsertText => {
            //     // handle_insert_text_input(&input, &mut app, &mut graph_navigation_instance_state);
            //     app.handle_insert_text_input(&input);
            // }
            
            
            InputMode::InsertText => {
                
                debug_log("handle_insert_text_input");
                if input == "esc" { 
                    debug_log("esc toggled");
                    app.input_mode = InputMode::Command; // Access input_mode using self
                    app.current_path.pop(); // Go back to the parent directory
                // } else if input == "^[" { 
                //     debug_log("esc toggled");
                //     app.input_mode = InputMode::Command; // Access input_mode using self
                //     app.current_path.pop(); // Go back to the parent directory
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

                // debug_log("what is this code block?");
                // // Handle insert mode (add message to list)
                // if input == "^[" { // Exit insert mode if the user types "esc"
                //     debug_log("esc toggled");
                //     app.input_mode = InputMode::Command;
                //     // app.current_path.pop(); // Go back to the parent directory
                // } else if !input.is_empty() {
                //     debug_log("!input.is_empty()");
                

                
            //     // Get local_owner_user DIRECTLY from the state!
            //     let local_owner_user = graph_navigation_instance_state.local_owner_user.clone();
        

      
            //     let message_path = get_next_message_file_path(&app.current_path, &local_owner_user);
            //     add_im_message(
            //         &message_path, 
            //         &local_owner_user, 
            //         input.trim(), 
            //         None,
            //         &graph_navigation_instance_state,
            //     ).expect("Failed to add message");
            //     app.load_im_messages();                
                            
                

            //     }
            // }
        }
    }
    debug_log("Finish: we love project loop.");
    Ok(())
}


fn set_sync_start_ok_flag_to_true() { 
    if fs::remove_file(SYNC_START_OK_FLAG_PATH).is_ok() {
        debug_log("Old 'ok_to_start_sync_flag.txt' file deleted."); // Optional log.
    }

    let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH)
        .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

    file.write_all(b"1")
        .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
}

fn initialize_ok_to_start_sync_flag() { 
    if fs::remove_file(SYNC_START_OK_FLAG_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH)
        .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

    file.write_all(b"0")
        .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
}


fn initialize_continue_uma_signal() { 
    if fs::remove_file(CONTINUE_UMA_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(CONTINUE_UMA_PATH)
        .expect("Failed to create 'continue_uma.txt' file.");

    file.write_all(b"1")
        .expect("Failed to write to 'continue_uma.txt' file.");
}


fn quit_set_continue_uma_to_false() { 
    if fs::remove_file(CONTINUE_UMA_PATH).is_ok() {
        debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
    } 

    let mut file = fs::File::create(CONTINUE_UMA_PATH)
        .expect("Failed to create 'continue_uma.txt' file.");

    file.write_all(b"0")
        .expect("Failed to write to 'continue_uma.txt' file.");
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
    debug_log("Start!");
    
    initialize_uma_application();
    
    // set boolean flag for loops to know when to hault
    initialize_continue_uma_signal();     
    
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
