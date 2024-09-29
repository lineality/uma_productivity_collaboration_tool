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

use std::io;
use std::io::{
    Error,
    ErrorKind,
    Write,
    Read,
};
use walkdir::WalkDir;
use std::path::PathBuf;
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
use std::path::Path;
use std::ffi::OsStr;
use std::collections::HashMap;
use std::collections::HashSet;

// For Sync
use rand::prelude::SliceRandom;
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

// Set debug flag (future: add time stamp with 24 check)
const DEBUG_FLAG: bool = true;


#[derive(Debug)]
enum MyCustomError {
    IoError(io::Error),
    // Add other variants for different error types as needed
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


// ALPHA VERSION
// Function to read a simple string from a file
pub fn read_state_string(file_name: &str) -> Result<String, std::io::Error> {
    let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
    fs::read_to_string(file_path)
}

// ALPHA VERSION
// Function to read a TOML file and deserialize it into a Value
pub fn read_state_toml(file_name: &str) -> Result<Value, toml::de::Error> {
    let file_path = Path::new("project_graph_data/session_state_items").join(file_name);
    let toml_string = fs::read_to_string(file_path)?;
    toml::from_str(&toml_string)
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
    // ipv4_address: Option<Ipv4Addr>, // Optional IPv4 address
    ipv6_address: Option<Ipv6Addr>, // Optional IPv6 address
    gpg_key: String,
    signal_port: u16, 
    file_transfer_port: u16,
    sync_interval: u64,
}

impl Collaborator {
    fn new(
        user_name: String, 
        // ipv4_address: Option<Ipv4Addr>, // Pass optional IPv4
        ipv6_address: Option<Ipv6Addr>, // Pass optional IPv6
        gpg_key: String, 
        signal_port: u16, 
        file_transfer_port: u16, 
        sync_interval: u64
    ) -> Collaborator {
        Collaborator {
            user_name,
            // ipv4_address,
            ipv6_address,
            gpg_key,
            signal_port,
            file_transfer_port,
            sync_interval,
        }
    }

    // Add any other methods you need here
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct CollaboratorList {
    collaborators: Vec<Collaborator>,
}

impl CollaboratorList {
    fn new() -> CollaboratorList {
        CollaboratorList {
            collaborators: Vec::new(),
        }
    }

    fn add_collaborator(
        &mut self, 
        user_name: String, 
        // ipv4_address: Option<IpvAddr>, 
        ipv6_address: Option<Ipv6Addr>, 
        gpg_key: String,
        signal_port: u16, // Add signal_port
        file_transfer_port: u16, // Add file_transfer_port
        sync_interval: u64, // Add sync_interval
    ) {
        let collaborator = Collaborator::new(
            user_name, 
            // ipv4_address,
            ipv6_address, 
            gpg_key, 
            signal_port, 
            file_transfer_port, 
            sync_interval,
        );
        self.collaborators.push(collaborator);
    }

    fn get_collaborator_by_username(&self, user_name: &str) -> Option<&Collaborator> {
        self.collaborators.iter().find(|c| c.user_name == user_name)
    }
}



// TODO: how to load value for active_team_channel when channel is entered
#[derive(Debug, Deserialize, Serialize, Clone)]
struct GraphNavigationInstanceState {
    local_owner_user: String, // Store the local user data here
    active_team_channel: String,  // TODO new
    default_im_messages_expiration_days: u64,
    default_task_nodes_expiration_days: u64,
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
        //             // self.current_node_last_updated = node.updated_at; // Assuming Node has an 'updated_at' field

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
            fs::write(session_items_path.join("current_full_file_path.txt"), self.current_full_file_path.to_string_lossy())?;
            fs::write(session_items_path.join("current_node_directory_path.txt"), self.current_node_directory_path.to_string_lossy())?;

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
    
    
}

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
    // every .toml has these four
    owner: String, // owner of this item
    collaborators_with_access: Vec<String>, 
    updated_at: u64, // utc posix timestamp
    expires_at: u64, // utc posix timestamp
    
    node_name: String,
    description_for_tui: String,
    directory_path: PathBuf,
    node_unique_id: u64,
    children: Vec<CoreNode>, // TODO: this will (probably) be depricated and removed
    order_number: u32, // Add order number
    priority: NodePriority, // Add priority
}

impl CoreNode {
    fn new(
        collaborators_with_access: Vec<String>,
        owner: String,
        description_for_tui: String,
        directory_path: PathBuf,
        node_name: String,
        order_number: u32, // Add order number parameter
        priority: NodePriority, // Add priority parameter
    ) -> CoreNode {
        let node_unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = node_unique_id + 86400; // 1 day from now
        let updated_at = node_unique_id;

        CoreNode {
            collaborators_with_access,
            node_name,
            owner,
            description_for_tui,
            directory_path,
            node_unique_id,
            expires_at,
            updated_at,
            children: Vec::new(),
            order_number, // Assign the order_number parameter
            priority,       // Assign the priority parameter
        }
    }


    
    fn add_collaborator_by_username(&mut self, user_name: &str, contact_list: &CollaboratorList) {
        if let Some(contact) = contact_list.get_collaborator_by_username(user_name) {
            self.collaborators_with_access.push(contact.user_name.clone());
        }
    }   
    fn remove_collaborator(&mut self, user_name: &str) {
        if let Some(pos) = self.collaborators_with_access.iter().position(|x| x == user_name) {
            self.collaborators_with_access.remove(pos);
        }
    }
    fn add_child(
        &mut self,
        collaborators_with_access: Vec<String>,
        owner: String,
        description_for_tui: String,
        directory_path: PathBuf,
        order_number: u32, // Add order_number
        priority: NodePriority, // Add priority
    ) {
        let child = CoreNode::new(
            collaborators_with_access,
            owner,
            description_for_tui,
            directory_path,
            self.node_name.clone(), // Assuming you want the child to have the same node_name as the parent
            order_number,
            priority,
        );
        self.children.push(child);
    }
        
    fn update_updated_at(&mut self) {
        self.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
    updated_at: u64, // utc posix timestamp
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
            updated_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
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
    updated_at: u64, // utc posix timestamp
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
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
            updated_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), // utc posix timestamp
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), // utc posix timestamp // TODO!! update this
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
        vec![],  // collaborators_with_access
        owner,   // owner
        team_channel_name.clone(), // description_for_tui
        new_channel_path.clone(),  // directory_path
        team_channel_name, // node_name
        5,                // Order number (you might want to manage this)
        NodePriority::Medium, // Priority (you might want to make this configurable)
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



fn get_collaborator_count() -> usize {
    // Load the collaborator list from the data directory
    let collaborator_list = load_collaborator_list();

    // Return the number of collaborators in the list
    collaborator_list.collaborators.len()
}


fn load_collaborator_list() -> CollaboratorList {
    // Open the collaborator list file
    // debug_log put cwd here
    debug_log(&format!("get: project_graph_data/collaborators.toml  {:?}", PathBuf::from("")));
    let mut file = File::open("project_graph_data/collaborators.toml").expect("Failed to open collaborator list file");

    // Read the contents of the file into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Failed to read collaborator list file");

    // Parse the TOML data into a CollaboratorList
    let collaborator_list: CollaboratorList = toml::from_str(&contents).expect("Failed to parse collaborator list file");
    
    debug_log(&format!("collaborator_list  {:?}", &collaborator_list));

    collaborator_list
}


fn initialize_application() {
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
    let session_state_dir = project_graph_directory.join("session_state_items");
    if !session_state_dir.exists() {
        fs::create_dir_all(&session_state_dir).expect("Failed to create team_channels directory");
    }
    
    // directory for people to share user and team_channel confi toml (or json maybe)
    let shared_setup_files_dir = project_graph_directory.join("shared_setup_files");
    if !shared_setup_files_dir.exists() {
        fs::create_dir_all(&shared_setup_files_dir).expect("Failed to create team_channels directory");
    }
    
    // Check if there are any directories in project_graph_data/team_channels
    let project_count = fs::read_dir(&team_channels_dir)
        .unwrap()
        .filter(|entry| entry.as_ref().unwrap().path().is_dir())
        .count();

    if project_count == 0 {
        // If no team channels exist, create the first one
        println!("There are no existing team channels. Let's create one.");
        println!("Enter a name for the team channel:");

        let mut team_channel_name = String::new();
        io::stdin().read_line(&mut team_channel_name).unwrap();
        let team_channel_name = team_channel_name.trim().to_string();

    // In initialize_application, when creating the first channel:
    // Get the owner from somewhere (e.g., user input or instance metadata)
    let owner = "initial_owner".to_string(); // Replace with actual owner

    create_team_channel(team_channel_name, owner);
    }
    
    
    // Check if the collaborator list file exists
    let collaborator_list_file = project_graph_directory.join("collaborators.toml");
    if !collaborator_list_file.exists() {
        // If the collaborator list file does not exist, create it with an empty list of collaborators
        let collaborator_list = CollaboratorList { collaborators: Vec::new() };
        let toml_data = toml::to_string(&collaborator_list).expect("Failed to serialize collaborator list");
        fs::write(collaborator_list_file.clone(), toml_data).expect("Failed to write collaborator list file");
    }

    // Check if there are any existing users in the system
    let user_count = get_collaborator_count();
    if user_count == 0 {
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
        
        // Prompt the user to enter an IP address
        println!("Enter an ipv6_address:");
        let mut ipv6_address = String::new();
        io::stdin().read_line(&mut ipv6_address).unwrap();
        let ipv6_address: Ipv6Addr = ipv6_address.trim().parse().unwrap(); // Parse into Ipv6Addr

        // Prompt the user to enter a GPG key
        println!("Enter a GPG key:");
        let mut gpg_key = String::new();
        io::stdin().read_line(&mut gpg_key).unwrap();
        let gpg_key = gpg_key.trim().to_string();

        // Load the collaborator list from the data directory
        let mut collaborator_list = load_collaborator_list();

        // // Add a new user to the system
        // // ... (In your code where you add a collaborator)
        collaborator_list.add_collaborator(
            username, 
            // ipv4_address,
            Some(ipv6_address), // Wrap ipv6_address in Some()
            gpg_key, 
            40000, // Example signal_port
            40001, // Example file_transfer_port
            60,   // Example sync_interval (in seconds)
        );

        // Save the updated collaborator list to the data directory
        let toml_data = toml::to_string(&collaborator_list).expect("Failed to serialize collaborator list");
        fs::write(collaborator_list_file, toml_data).expect("Failed to write collaborator list file");

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

                // 7. Create the Node instance
                let new_node = CoreNode::new(
                    collaborators_with_access,
                    graph_navigation_instance_state.local_owner_user.clone(),
                    description_for_tui,
                    new_node_path,
                    node_name,
                    order_number,
                    priority,
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
            //     // TODO: update the updated_at filed in the node.toml
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


// fn load_teamchannel_ip_whitelist(channel_name: &str) -> Result<HashSet<IpAddr>, io::Error> {
//     /*
//     // step 1: get team_channel_members from project_graph_data/session_items/current_node_collaborators_with_access.toml
//     step 2: get current user project_graph_data/session_items/uma_local_owner_user.txt
//     stem 3: remove current user from IP whitelist
//     step 4: get only the ipv4, ipv6 addresses for those members
//     from the larger collaborators filr project_graph_data/collaborators.toml
    
//     (note: members should have a list of ipv4, ipv6 addresses, not just one)
    
//     sample: project_graph_data/collaborators.toml
//         [[collaborators]]
//     user_name = "alice"
//     ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
//     ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
//     gpg_key = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
//     signal_port = 5000
//     file_transfer_port = 5000
//     sync_interval = 5000
        
//     [[collaborators]]
//     user_name = "bob"
//     ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
//     ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
//     gpg_key = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
//     signal_port = 5000
//     file_transfer_port = 5000
//     sync_interval = 5000
//     */
//     let collaborators = load_collaborators()?;
//     let channel_members = get_team_channel_members(channel_name)?;

//     let filtered_collaborators: Vec<&Collaborator> = collaborators
//         .collaborators
//         .iter()
//         .filter(|c| channel_members.contains(&c.user_name))
//         .collect();

//     let mut ip_whitelist = HashSet::new();
//     for collaborator in filtered_collaborators {
//         if let Some(ipv4) = collaborator.ipv4_address {
//             ip_whitelist.insert(IpAddr::V4(ipv4));
//         }
//         if let Some(ipv6) = collaborator.ipv6_address {
//             ip_whitelist.insert(IpAddr::V6(ipv6));
//         }
//         // ... (Handle multiple IP addresses per collaborator if needed)
//     }

//     Ok(ip_whitelist)
// }




fn load_teamchannel_ip_whitelist() -> Result<HashSet<IpAddr>, io::Error> {
        /*
    // step 1: get team_channel_members from project_graph_data/session_items/current_node_collaborators_with_access.toml
    step 2: get current user project_graph_data/session_items/uma_local_owner_user.txt
    stem 3: remove current user from IP whitelist
    step 4: get only the ipv4, ipv6 addresses for those members
    from the larger collaborators filr project_graph_data/collaborators.toml
    
    (note: members should have a list of ipv4, ipv6 addresses, not just one)
    
    sample: project_graph_data/collaborators.toml
        [[collaborators]]
    user_name = "alice"
    ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
    ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
    gpg_key = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
    signal_port = 5000
    file_transfer_port = 5000
    sync_interval = 5000
        
    [[collaborators]]
    user_name = "bob"
    ipv4_addresses = ["24.0.189.112", "24.0.189.112"]
    ipv6_addresses = ["2601:80:4803:9490::2e79","2601:80:4803:9490::2e79"]
    gpg_key = "304A9A525A5D00D6AD269F765C3E7C56E5A3D0D8"
    signal_port = 5000
    file_transfer_port = 5000
    sync_interval = 5000
    */
    // 1. Load team channel members from session_state_items:
    let channel_members_toml = read_state_toml("current_node_collaborators_with_access.toml")?;
    let channel_members: Vec<String> = channel_members_toml.as_array()
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to parse current_node_collaborators_with_access.toml",
        ))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // 2. Load current user from session_state_items:
    let current_user = read_state_string("local_owner_user.txt")?;

    // 3. Load all collaborators from project_graph_data/collaborators.toml:
    let collaborators = load_collaborators()?;

    // 4. Filter collaborators based on team members, excluding current user:
    let filtered_collaborators: Vec<&Collaborator> = collaborators
        .collaborators
        .iter()
        .filter(|c| channel_members.contains(&c.user_name) && c.user_name != current_user)
        .collect();

    // 5. Extract IP addresses from filtered collaborators:
    let mut ip_whitelist = HashSet::new();
    for collaborator in filtered_collaborators {
        // if let Some(ipv4) = collaborator.ipv4_address {
        //     ip_whitelist.insert(IpAddr::V4(ipv4));
        // }
        if let Some(ipv6) = collaborator.ipv6_address {
            ip_whitelist.insert(IpAddr::V6(ipv6));
        }
        // ... (Handle multiple IP addresses per collaborator if needed)
    }

    Ok(ip_whitelist)
}


// // file is always here project_graph_data/collaborators.toml
// fn is_ip_whitelisted(ip: &IpAddr, whitelist: &Vec<Collaborator>) -> bool {
//     whitelist.iter().any(|c| {
//         match ip {
//             IpAddr::V4(v4) => c.ipv4_address == Some(*v4), // Compare with Some(*v4)
//             IpAddr::V6(v6) => c.ipv6_address == Some(*v6), // Compare with Some(*v6)
//         }
//     })
// }

fn is_ip_whitelisted(ip: &IpAddr, whitelist: &HashSet<IpAddr>) -> bool {
    whitelist.contains(ip) 
}

fn load_collaborators() -> Result<Vec<Collaborator>, io::Error> {
    // 1. Read the collaborators.toml file contents
    let collaborators_file = "project_graph_data/collaborators.toml";
    let toml_string = fs::read_to_string(collaborators_file)?; // Use ? to propagate errors

    // 2. Deserialize the TOML data into a CollaboratorList struct 
    let collaborator_list: CollaboratorList = toml::from_str(&toml_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML parsing error: {}", e)))?; // Map TOML error to io::Error

    // 3. Extract the collaborators from the CollaboratorList
    Ok(collaborator_list.collaborators) // Return the collaborators wrapped in Ok
}


// // Alpha demo functions! TODO
// fn attempt_channel_entry(channel_name: &str) -> Result<(), io::Error> { 
//     let current_user = load_current_user()?; // Load current user data, including port

//     // ... (Load channel metadata and collaborators for the channel)
//     let channel_collaborators = // ...

//     if let Some(conflicting_user) = detect_port_collision(current_user, &channel_collaborators) {
//         let suggested_port = get_random_unused_port(40000, 50000);
//         eprintln!("Port collision detected! Your port ({}) conflicts with {}'s port ({}).",
//                 current_user.uma_port.unwrap_or(0), 
//                 conflicting_user,
//                 // conflicting_user.uma_port.unwrap_or(0) 
//         ); 
//         eprintln!("Suggested Port: {}", suggested_port); 
//         eprintln!("Please update your collaborator_tomls file and try again.");
//         return Err(io::Error::new(io::ErrorKind::Other, "Port collision detected")); 
//     }

//     // ... (Proceed with channel entry and sync logic)
//     Ok(()) 
// }

fn detect_port_collision() -> Option<String> {
/*
The purpose/role of this function is to look at all the collaborators in a team_channel
which will in the ~current_collaborators state_items value
and look up their preferred ports in the collaborator's NAME.toml file

a question (design choice) is how to  prioritize older collaborators from 
newer ones, requiring newer ones to pick a new port, and not bothering older ones
*/
    
}

// fn get_random_unused_port(start: u16, end: u16) -> u16 {
//     // ... (Generate a random port within the range and check if it's in use) 
// }


            
fn out_request_sync_loop() {
    loop {

        // Load the whitelist once outside the loop
        let whitelist = load_whitelist().unwrap_or_else(|e| { 
            eprintln!("Error loading whitelist: {}", e);
            Vec::new()
        });    

        let target_username = get_next_sync_request_username(&whitelist);
        
        // Handle the case where target_username is None (no sync request found)
        if let Some(ref username) = target_username { 
            // 2. Find the target collaborator in the whitelist (now using 'username')
            if let Some(collaborator) = whitelist.iter().find(|&c| c.user_name == target_username) {
                let target_ip = collaborator.ipv6_address; // No more Option here!
                let target_addr = SocketAddr::new(IpAddr::V6(target_ip), target_port); 
                let target_port = collaborator.file_transfer_port;
                let sync_interval = collaborator.sync_interval;

                // 3. Establish a connection to the target instance
                // match TcpStream::connect((target_ip, target_port)) {
                    match TcpStream::connect(target_addr) { 
                    Ok(mut stream) => {
                        // 4. Send the TOML file data through the stream
                        let toml_data = fs::read_to_string("path/to/toml/file")
                            .expect("Failed to read TOML file");
                        if let Err(e) = stream.write_all(toml_data.as_bytes()) {
                            eprintln!("Error sending TOML data to {}: {}", target_ip, e);
                        } else {
                            println!("Sent TOML file to {}", target_ip);

                            // 5. Optionally receive a response signal (e.g., Sync Done)
                            // ... (Implement response signal logic here)
                        }
                    }
                    Err(e) => {
                        eprintln!("Error connecting to target instance {}: {}", target_ip, e);
                    }
                }

                // 6. Wait for the specified sync interval before checking for the next request
                thread::sleep(Duration::from_secs(sync_interval));
            } else {
                match target_username {
                    Some(username) => println!("Target collaborator not found in whitelist: {}", username),
                    None => println!("No target username found for the sync request (this should not happen)."), 
                }
            }
        }
    }
}

fn get_next_sync_request_username(whitelist: &Vec<Collaborator>) -> Option<String> {
    let mut rng = rand::thread_rng(); // Create a random number generator
    let mut shuffled_whitelist = whitelist.clone(); // Create a copy to shuffle

    // Get the username of the first collaborator in the shuffled list
    shuffled_whitelist.shuffle(&mut rng); // Shuffle the collaborators randomly 

    // Get the username of the first collaborator in the shuffled list
    shuffled_whitelist.first().map(|c| c.user_name.clone()) 
}

fn in_queue_sync_loop() {
    // 1. Listen on the designated signal port for incoming connections
    let listener = TcpListener::bind("0.0.0.0:SIGNAL_PORT").expect("Failed to bind to signal port"); 

    
    // Load the whitelist once outside the loop
    let whitelist = load_whitelist().unwrap_or_else(|e| { 
        eprintln!("Error loading whitelist: {}", e);
        Vec::new()
    });
    
    loop {
        // 2. Accept incoming connections
        match listener.accept() {
            Ok((mut stream, addr)) => {
                // 3. Verify the sender's IP address against the whitelist
                if is_ip_whitelisted(&addr.ip(), &whitelist) {
                    // 4. Receive the signal data from the stream
                    let mut buffer = [0; 1024]; // Adjust buffer size as needed
                    let bytes_read = stream.read(&mut buffer).expect("Failed to read from stream");

                    // 5. Process the received signal (e.g., Sync Request)
                    let signal = String::from_utf8_lossy(&buffer[..bytes_read]);
                    match signal.trim() {
                        "Sync Request" => {
                            // Initiate the synchronization operation (e.g., send relevant files)
                            // ... (Implement sync logic here)
                            println!("Received Sync Request from {}", addr.ip());
                        }
                        _ => {
                            println!("Received unknown signal: {}", signal);
                        }
                    }

                    // 6. Optionally send a response signal (e.g., Sync Done)
                    // ... (Implement response signal logic here)
                } else {
                    println!("Connection rejected from non-whitelisted IP: {}", addr.ip());
                }
            }
            Err(e) => {
                println!("Error accepting connection: {}", e);
            }
        }
    }
}

// Function for thread 2's file_sync loop: demo version
fn you_love_file_sync_base_loop() {
    /*
    "It's all fun and games until someone syncs a file."
    
    2.2 a user thread:  user_thread
    2.2.1 initialization of the software and file system (especially first setup bootstrapping)
    2.2.2 start loop:
    2.2.3 loading initial instance_graph_navigation_state from files in uma_state_toml_dir
    2.2.4 running one action-set in the user_app()
    2.2.5 saving state in files in uma_state_toml_dir
    (loop, to 2.2.2)
    
    
    */

    // Thread 1: Executes the in_queue_sync_loop function
    let in_queue_sync_loop_handle = thread::spawn(move || {
        in_queue_sync_loop(); // Pass the whitelist by reference
    });

    // Thread 2: Executes the out_request_sync_loop function
    let out_request_sync_loop_handle = thread::spawn(move || {
        out_request_sync_loop(); // Pass the whitelist by value (it's already cloned)
    });

    // Keep the main thread alive and wait for the loops to finish (if they ever do)
    if let Err(err) = in_queue_sync_loop_handle.join() {
        eprintln!("Error joining in_queue_sync_loop: {:?}", err);
    }
    if let Err(err) = out_request_sync_loop_handle.join() {
        eprintln!("Error joining out_request_sync_loop: {:?}", err);
    }
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
    // Setup files etc.
    initialize_application();

    // Load UMA configuration from uma.toml
    let uma_toml_path = Path::new("uma.toml");
    // let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)?; 
    let user_metadata = toml::from_str::<toml::Value>(&std::fs::read_to_string(uma_toml_path)?)
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e)))?;


    // 'state'
    let mut graph_navigation_instance_state = GraphNavigationInstanceState {
        local_owner_user: user_metadata["uma_local_owner_user"].as_str().unwrap().to_string(),
        active_team_channel: String::new(), // or perhaps "None", or "Default"
        default_im_messages_expiration_days: user_metadata["uma_default_im_messages_expiration_days"].as_integer().unwrap() as u64,
        default_task_nodes_expiration_days: user_metadata["uma_default_task_nodes_expiration_days"].as_integer().unwrap() as u64,

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
    // TODO borrow issue here
    // let mut app = App::new(graph_navigation_instance_state); // Pass graph_navigation_instance_state
    let mut app = App::new(graph_navigation_instance_state.clone()); // Pass graph_navigation_instance_state
    

    // -- Here: save first version of starting 'state'
    
    loop {
        // Update GraphNavigationInstanceState based on the current path
        debug_log("start loop");
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
                    break; // Exit the loop if handle_command returns true (e.g., for 'q')
                } else if let Ok(index) = input.parse::<usize>() {
                    let item_index = index - 1; // Adjust for 0-based indexing
                    if item_index < app.tui_directory_list.len() {
                        debug_log("main: if item_index < app.tui_directory_list.len()");
                        debug_log(&format!("main: app.tui_directory_list: {:?}", &app.tui_directory_list));
                        
                        ////////////////////////////
                        // Handle channel selection
                        ////////////////////////////
                        // app.handle_tui_action(); // Remove the extra argument here

                        debug_log(" handle_tui_action() started");
                        
                        if app.current_path.display().to_string() == "project_graph_data/team_channels".to_string() {
                            debug_log("app.current_path == project_graph_data/team_channels");
                            debug_log(&format!("current_path: {:?}", app.current_path));
                            
                            let input = tiny_tui::get_input()?; // Get input here
                            if let Ok(index) = input.parse::<usize>() { 
                                let item_index = index - 1; // Adjust for 0-based indexing
                                if item_index < app.tui_directory_list.len() {
                                    let selected_channel = &app.tui_directory_list[item_index];
                                    debug_log(&format!("Selected channel: {}", selected_channel)); // Log the selected channel name
                                    
                                    app.current_path = app.current_path.join(selected_channel);
                                    
                                    debug_log(&format!("New current_path: {:?}", app.current_path)); // Log the updated current path
                                    
                                    app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
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
                        println!("Invalid index.");
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

    Ok(())
}




/*
An Appropriately Svelt Mainland:
*/

// Function for thread 1's projects loop: demo version
fn we_love_projects_looop__demo() {
    loop {
        println!("we_love_projects_loop Thread 1 is running");
        thread::sleep(Duration::from_secs(2));
    }
}
// Function for thread 2's file_sync loop: demo version
fn you_love_file_sync_looop__demo() {
    loop {
        println!("you_love_file_sync_loop Thread 2 is running");
        thread::sleep(Duration::from_secs(3));
    }
}

fn main() {
    // Thread 1: Executes the thread1_loop function
    let we_love_projects_loop = thread::spawn(move || {
        we_love_projects_loop();
    });
    // Thread 2: Executes the thread2_loop function
    let you_love_file_sync_loop = thread::spawn(move || {
        you_love_file_sync_base_loop();
    });
    // Keep the main thread alive
    we_love_projects_loop.join().unwrap();
    you_love_file_sync_loop.join().unwrap();
}
