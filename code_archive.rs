
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
        pa2_schedule: Vec<u64>,
    ) -> Result<CoreNode, ThisProjectError> {
        debug_log!("Starting CoreNode::new");
        debug_log!("Directory path received: {:?}", directory_path);
        debug_log!("Checking if directory exists: {}", directory_path.exists());
        debug_log!("Absolute path: {:?}", directory_path.canonicalize().unwrap_or(directory_path.clone()));

        // Log all input parameters
        debug_log!("input dump: {:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
            node_name,
            description_for_tui,
            directory_path,
            owner,
            teamchannel_collaborators_with_access,
            abstract_collaborator_port_assignments,
            agenda_process,
            goals_features_subfeatures_tools_targets,
            scope,
            pa2_schedule
        );

        debug_log!("About to get current timestamp");
        let expires_at = get_current_unix_timestamp() + 11111111111; // Expires in 352 years
        let updated_at_timestamp = get_current_unix_timestamp();
        debug_log!("Got timestamps");

        // 1. Get the salt list, handling potential errors:
        debug_log!("About to get salt list for owner: {}", owner);
        let salt_list = match get_saltlist_for_collaborator(&owner) {
            Ok(list) => {
                debug_log!("Successfully got salt list");
                list
            },
            Err(e) => {
                debug_log!("Error getting salt list: {:?}", e);
                return Err(ThisProjectError::IoError(
                    std::io::Error::new(std::io::ErrorKind::NotFound, "Failed to get salt list")
                ));
            }
        };

        debug_log!("About to calculate node_unique_id");
        // 2. Calculate the hash, using the retrieved salt list:
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
        // 3. Create the CoreNode instance:
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
            pa2_schedule,
        };
        debug_log!("Successfully created CoreNode instance");

        Ok(node)
        }

    fn new(
        node_name: String,
        description_for_tui: String,
        directory_path: PathBuf,
        owner: String,
        teamchannel_collaborators_with_access: Vec<String>,
        abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>>,
        // project state task items
        agenda_process: String,
        goals_features_subfeatures_tools_targets: String,
        scope: String,
        pa2_schedule: Vec<u64>,
    ) -> Result<CoreNode, ThisProjectError> {
        debug_log("Starting CoreNode::new");
        debug_log!("Directory path received: {:?}", directory_path);
        debug_log!("Checking if directory exists: {}", directory_path.exists());
        debug_log!("Absolute path: {:?}", directory_path.canonicalize().unwrap_or(directory_path.clone()));


        debug_log!(
            "input dump: {:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
            node_name,
            description_for_tui,
            directory_path,
            owner,
            teamchannel_collaborators_with_access,
            abstract_collaborator_port_assignments,
            agenda_process,
            goals_features_subfeatures_tools_targets,
            scope,
            pa2_schedule
            );
        let expires_at = get_current_unix_timestamp() + 11111111111; // Expires in 352 years
        let updated_at_timestamp = get_current_unix_timestamp();

        // 1. Get the salt list, handling potential errors:
        let salt_list = get_saltlist_for_collaborator(&owner)?; // Use the ? operator to propagate errors

        debug_log("starting make node-unique-id");
        // 2. *Now* calculate the hash, using the retrieved salt list:
        let node_unique_id = calculate_corenode_hashes(
            &node_name,            // &str
            &description_for_tui,  // &str
            updated_at_timestamp,  // u64
            &salt_list,            // &[u128]
        )?;

        debug_log!(
            "CoreNode::new, node_unique_id{:?}",
            node_unique_id
        );

        // // Project State
        // let agenda_process: String = "".to_string();
        // let goals_features_subfeatures_tools_targets: String = "".to_string();
        // let scope: String = "".to_string();
        // let pa2_schedule: Vec<u64> = [].to_vec();

        // 3. Create the CoreNode instance (all fields now available):
        Ok(CoreNode {
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
            pa2_schedule,
        })
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
    // fn save_node_to_clearsigned_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_clearsigned_file");
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
    // fn save_node_to_clearsigned_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_clearsigned_file");
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
    // fn save_node_to_clearsigned_file(&self) -> Result<(), io::Error> {
    //     debug_log!("Starting save_node_to_clearsigned_file()");

    //     debug_log!("save_node_to_clearsigned_file(), Directory path: {:?}", self.directory_path);
    //     // 1. Serialize the CoreNode struct to a TOML string.
    //     let toml_string = toml::to_string(&self).map_err(|e| {
    //         io::Error::new(
    //             io::ErrorKind::Other,
    //             format!("TOML serialization error: {}", e),
    //         )
    //     })?;

    //     // 2. Construct the full file path for the node.toml file.
    //     let file_path = self.directory_path.join("node.toml");

    //     debug_log!("save_node_to_clearsigned_file(), file_path in save_node_to_clearsigned_file {:?}",
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
    
    
    // TODO: this will need to be replaced with a
    // clearsigntoml version
    fn load_node_from_file(path: &Path) -> Result<CoreNode, io::Error> {
        let toml_string = fs::read_to_string(path)?;
        let node: CoreNode = toml::from_str(&toml_string).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("TOML deserialization error: {}", e))
        })?;
        Ok(node)
    }
        
        
    
// pseudocode draft
// fn get_local_owner_username() -> String {  // Returns String directly
//     debug_log!("___ Step 1: Reading LOCAL OWNER USER's name from uma.toml");

//     // Get absolute path to uma.toml configuration file
//     let relative_uma_toml_path = "uma.toml";
//     let absolute_uma_toml_path = make_file_path_abs_executabledirectoryrelative_canonicalized_or_error(relative_uma_toml_path)
//         .map_err(|e| {
//             let error_msg = format!("___ Failed to locate uma.toml configuration file: {}", e);
//             println!("Error: {}", error_msg);
//             GpgError::PathError(error_msg)
//         })?;

//     // Convert PathBuf to string for TOML reading
//     let absolute_uma_toml_path_str = absolute_uma_toml_path
//         .to_str()
//         .ok_or_else(|| {
//             let error_msg = "__ Unable to convert UMA TOML path to string".to_string();
//             println!("Error: {}", error_msg);
//             GpgError::PathError(error_msg)
//         })?;

//     // Read LOCAL OWNER USER's name from uma.toml
//     let local_owner_user_name = read_single_line_string_field_from_toml(
//         absolute_uma_toml_path_str,
//         "uma_local_owner_user"
//     ).map_err(|e| {
//         let error_msg = format!("___ Failed to read LOCAL OWNER USER's name: {}", e);
//         println!("Error: {}", error_msg);
//         GpgError::ValidationError(error_msg)
//     })?;

//     debug_log!("___ LOCAL OWNER USER's name is: {}", local_owner_user_name);

//     local_owner_user_name
// }



        
    // /// saves the `CoreNode` data to a `node.gpgtoml` file.
    // ///
    // /// This function serializes the `CoreNode` struct into TOML format
    // /// and writes it as a gpg encrypted clearsigned file
    // /// at the path specified by the `directory_path` field, creating
    // /// the directory if it doesn't exist.
    // ///
    // /// # Error Handling
    // ///
    // /// Returns a `Result<(), io::Error>` to handle potential errors during:
    // ///  - TOML serialization
    // ///  - Directory creation
    // ///  - File writing
    // fn save_node_as_gpgtoml(&self) -> Result<(), io::Error> {
    //     // Debug logging for initial state
    //     debug_log!("in imple CoreNode: SNTF -> Starting save_node_to_clearsigned_file!");
    //     debug_log!("SNTF: Current working directory: {:?}", std::env::current_dir()?);
    //     debug_log!("SNTF: Target directory path: {:?}", self.directory_path);

    //     // 1. Verify and create directory structure
    //     if !self.directory_path.exists() {
    //         debug_log!("SNTF: Directory doesn't exist, creating it");
    //         fs::create_dir_all(&self.directory_path)?;
    //     }
    //     debug_log!("SNTF: Directory now exists: {}", self.directory_path.exists());

    //     // 2. Verify directory is actually a directory
    //     if !self.directory_path.is_dir() {
    //         debug_log!("SNTF: Path exists but is not a directory!");
    //         return Err(io::Error::new(
    //             io::ErrorKind::Other,
    //             "SNTF: Path exists but is not a directory"
    //         ));
    //     }

    //     // TODO this looks wrong, no toml-crate
    //     // 3. Serialize the CoreNode struct to a TOML string
    //     let toml_string = toml::to_string(&self).map_err(|e| {
    //         debug_log!("SNTF: TOML serialization error: {}", e);
    //         io::Error::new(
    //             io::ErrorKind::Other,
    //             format!("SNTF: TOML serialization error: {}", e),
    //         )
    //     })?;
    //     debug_log!("SNTF: Successfully serialized CoreNode to TOML");

    //     // 4. Construct and verify the file path
    //     let file_path = self.directory_path.join("node.toml");
    //     debug_log!("SNTF: Full file path for node.toml: {:?}", file_path);

    //     // 5. Verify parent directory one more time
    //     if let Some(parent) = file_path.parent() {
    //         if !parent.exists() {
    //             debug_log!("SNTF: Parent directory missing, creating: {:?}", parent);
    //             fs::create_dir_all(parent)?;
    //         }
    //     }

    //     // 6. Write the TOML data to the file
    //     debug_log!("SNTF: Writing TOML data to file...");
    //     fs::write(&file_path, &toml_string)?;

    //     // 7. Verify the file was created
    //     if file_path.exists() {
    //         debug_log!("SNTF: Successfully created node.toml at: {:?}", file_path);
    //     } else {
    //         debug_log!("SNTF: Warning: File write succeeded but file doesn't exist!");
    //     }

    //     /*

    //     this will include an extra lookup step:
    //             1. get file_owner name from the clearsign-toml file
    //             2. look up user addressbook file by user-name
    //             3. get key-id from file-owner's addressbook file
    //             4. clearsign with key-id so that reader can varify clearsign with public-key
    //             from addressbook file.
    //             convert_toml_filewithkeyid_into_clearsigntoml_inplace?
    //             maybe new function with extra lookup step...

    //     the new function will be:
    //     fn convert_tomlfile_without_keyid_into_clearsigntoml_inplace(
    //         path_to_toml_file: &Path,
    //     ) -> Result<(), GpgError> {

    //     these may be the needed steps:

    //         // Read username from the configuration file, mapping any reading errors to our error type
    //         let file_owner_username = read_single_line_string_field_from_toml(config_path_str, "owner")
    //             .map_err(|error_message| ThisProjectError::TomlVanillaDeserialStrError(
    //                 format!("Failed to read file_owner_username from config: {}", error_message)
    //             ))?;

    //         debug_log!("file_owner_username {}", file_owner_username);

    //         // Convert the collaborator files directory to an absolute path based on the executable's location
    //         // AND verify that the directory exists (returns error if not found or not a directory)
    //         let addressbook_files_directory_relative = COLLABORATOR_ADDRESSBOOK_PATH_STR;
    //         let addressbook_files_directory_absolute = make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error(
    //             addressbook_files_directory_relative
    //         ).map_err(|io_error| ThisProjectError::IoError(io_error))?;

    //         // Construct the path to the user's collaborator file, which contains their GPG key ID
    //         let collaborator_filename = format!("{}__collaborator.toml", file_owner_username);
    //         let user_config_path = addressbook_files_directory_absolute.join(collaborator_filename);

    //         debug_log!("user_config_path {}", user_config_path.display());

    //         // Convert the collaborator file path to string for TOML reading
    //         let user_config_path_str = user_config_path.to_str()
    //             .ok_or_else(|| ThisProjectError::InvalidInput("Cannot convert collaborator file path to string".to_string()))?;

    //         debug_log!("user_config_path {}", user_config_path.display());
    //         println!("user_config_path {}", user_config_path.display());

    //         // Extract the GPG key ID from the collaborator file
    //         let gpg_key_id = read_singleline_string_from_clearsigntoml(user_config_path_str, "gpg_publickey_id")
    //             .map_err(|error_message| ThisProjectError::TomlVanillaDeserialStrError(
    //                 format!("export_public_gpg_key_converts_to_abs_path() Failed read_singleline_string_from_clearsigntoml() to read GPG key ID from clearsigntoml collaborator file: {}", error_message)
    //             ))?;


    //             notes:
    //             File Types Being Handled:

    //     The Target TOML File (the one we want to clearsign):

    //     Initially: Plain TOML file (NOT clearsigned)
    //     Contains: An owner field with the username
    //     Read with: read_single_line_string_field_from_toml()
    //     End state: Will become clearsigned after our function runs


    //     The Collaborator Addressbook File ({username}__collaborator.toml):

    //     Already clearsigned TOML
    //     Contains: The gpg_publickey_id field
    //     Read with: read_singleline_string_from_clearsigntoml()
    //     Remains unchanged by our function

    //     scope summary:
    //             Scope Confirmation
    //     Purpose
    //     Create a function that clearsigns a plain TOML file in-place, but unlike the existing function, this one does not expect the gpg_publickey_id to be present in the target TOML file. Instead, it performs a multi-step lookup process to determine which GPG key to use for signing.
    //     Key Differences from Existing Function

    //     Target TOML file: Does NOT contain gpg_publickey_id field
    //     Target TOML file: MUST contain an owner field with the file owner's username
    //     Additional lookup: Uses the owner's username to find their collaborator addressbook file
    //     GPG key source: Extracts the gpg_publickey_id from the owner's addressbook file (not from the target file)

    //     Process Flow

    //     Read owner username from the target TOML file (plain TOML)

    //     Field name: "owner"
    //     Use: read_single_line_string_field_from_toml()


    //     Construct addressbook file path

    //     Base directory: COLLABORATOR_ADDRESSBOOK_PATH_STR (relative to executable)
    //     Convert to absolute path using: make_dir_path_abs_executabledirectoryrelative_canonicalized_or_error()
    //     Filename pattern: {owner_username}__collaborator.toml


    //     Read GPG key ID from the addressbook file

    //     The addressbook file is already clearsigned
    //     Field name: "gpg_publickey_id"
    //     Use: read_singleline_string_from_clearsigntoml()


    //     Clearsign the target file

    //     Use the extracted GPG key ID to sign the original target TOML file
    //     Replace the original file in-place with its clearsigned version



    //     File States

    //     Target TOML file: Starts as plain TOML → Ends as clearsigned TOML
    //     Addressbook file: Already clearsigned → Remains unchanged (read-only operation)

    //     */
    //     debug_log!("SNTF: Starting convert_tomlfile_without_keyid_into_clearsigntoml_inplace()");

    //     // Get armored public key, using key-id (full fingerprint in)
    //     let gpg_full_fingerprint_key_id_string = match LocalUserUma::read_gpg_fingerprint_from_file() {
    //         Ok(fingerprint) => fingerprint,
    //         Err(e) => {
    //             return Err(io::Error::new(
    //                 io::ErrorKind::Other,
    //                 format!("implCoreNode save node to file: Failed to read GPG fingerprint from uma.toml: {}", e)
    //             ));
    //         }
    //     };

    //     // convert_tomlfile_without_keyid_using_gpgtomlkeyid_into_clearsigntoml_inplace(
    //     //     &file_path,
    //     //     COLLABORATOR_ADDRESSBOOK_PATH_STR,
    //     //     &gpg_full_fingerprint_key_id_string,
    //     // )
    //     // .map_err(|gpg_err| {
    //     //     // Convert GpgError to std::io::Error
    //     //     std::io::Error::new(
    //     //         std::io::ErrorKind::Other,
    //     //         format!("SNTF: GPG into_clearsign operation failed: {:?}", gpg_err),
    //     //     )
    //     // })?;

    //     // TODO
    //     // Something like this to make gpg encrypted file as .gpgtoml extension
    //     // not just clearsigned
    //     /*
    //     // 2. Construct paths
    //     let address_book_export_dir = PathBuf::from("invites_updates/addressbook_invite/export");
    //     let key_file_path = address_book_export_dir.join("key.asc");
    //     let collaborator_file_path = PathBuf::from(COLLABORATOR_ADDRESSBOOK_PATH_STR)
    //         .join(format!("{}__collaborator.toml", local_owner_username));

    //     let key_file_path = address_book_export_dir.join("key.asc");
    //     let collaborator_file_path = PathBuf::from(COLLABORATOR_ADDRESSBOOK_PATH_STR)
    //         .join(format!("{}__collaborator.toml", local_owner_username));

    //     // 3. Read public key (early return on error).  Handles NotFound.
    //     let public_key_string = match read_to_string(&key_file_path) {
    //         Ok(key) => key,
    //         Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
    //             debug_log!("Public key file ('key.asc') not found. Skipping address book export.");
    //             return Ok(()); // Return Ok if the file isn't found, not continuing.
    //         },
    //         Err(e) => return Err(ThisProjectError::IoError(e)),
    //     };

    //     // 4. Clearsign collaborator file
    //     let clearsign_output = StdCommand::new("gpg")
    //         .arg("--sign")
    //         .arg(&collaborator_file_path)
    //         .output()?;


    //     // Error handling: (exit early on error)
    //     if !clearsign_output.status.success() {
    //         let stderr = String::from_utf8_lossy(&clearsign_output.stderr);
    //         return Err(ThisProjectError::GpgError(format!("GPG clearsign failed: {}", stderr)));
    //     }
    //     let clearsigned_data = clearsign_output.stdout;

    //     // 5. Encrypt clearsigned data
    //     let encrypted_data = encrypt_with_gpg(&clearsigned_data, &public_key_string)?;

    //     // 6. Create export directory if it doesn't exist
    //     let export_dir = PathBuf::from("invites_updates/addressbook_invite/export");
    //     create_dir_all(&export_dir)?;

    //     // 7. Write encrypted data to file. Use a timestamp to avoid overwriting.
    //     let export_file_path = export_dir.join(format!(
    //         "{}_addressbook_{}.gpgtoml",
    //         local_owner_username,
    //         get_current_unix_timestamp() // Or use a UUID
    //     ));
    //     let mut file = File::create(&export_file_path)?;
    //     file.write_all(&encrypted_data)?;

    //     debug_log("export complete");
    //      *
    //      *
    //      */

    //     Ok(())
    // }




// /// check for port collision
// /// Checks if a given port is currently in use.
// ///
// /// This function attempts to bind a TCP listener to the specified port on the loopback
// /// interface (127.0.0.1). If the binding is successful, it means the port is likely
// /// available. If the binding fails, it suggests the port is already in use.
// ///
// /// # Caveats:
// ///
// /// * **TCP-Specific:** This check only verifies if a TCP listener can be bound.
// ///   It does not guarantee that the port is not being used by a UDP process
// ///   or a process using a different protocol.
// /// * **UMA is UDP-Only:** Ideally, this function should be replaced with a more
// ///   accurate check that is specific to UDP port availability.
// /// * **Resource Usage:** Binding a TCP listener, even momentarily, consumes system resources.
// /// * **Race Conditions:** It's possible for another process to bind to the port
// ///   between the time this check is performed and the time UMA actually attempts
// ///   to use the port.
// ///
// /// # Arguments
// ///
// /// * `port` - The port number to check.
// ///
// /// # Returns
// ///
// /// * `bool` - `true` if the port is likely in use, `false` if it's likely available.
// fn is_port_in_use(port: u16) -> bool {
//     match TcpListener::bind(("127.0.0.1", port)) {
//         Ok(_) => false, // Port is available
//         Err(_) => true, // Port is in use
//     }
// }


// // it's a total garbage function!
// fn check_all_ports_in_team_channels() -> Result<(), ThisProjectError> {

//     // let team_channels_dir = Path::new("project_graph_data/team_channels");

//     // Ensure the project graph data directory exists relative to the executable
//     let team_channelsdir_result = make_verify_or_create_executabledirectoryrelative_canonicalized_dir_path("project_graph_data/team_channels");

//     // Handle any errors that might occur during directory creation or verification
//     let team_channels_dir = match team_channelsdir_result {
//         Ok(directory_path) => directory_path,
//         Err(io_error) => {
//             // Log the error and handle appropriately for your application
//             return Err(format!("in check_all_ports_in_team_channels(), Failed to ensure team_channels_dir exists: {}", io_error).into());
//         }
//     };

//     let mut ports_in_use = HashSet::new();

//     // Iterate over all team channel directories
//     for entry in WalkDir::new(team_channels_dir)
//         .into_iter()
//         .filter_map(|e| e.ok())
//         .filter(|e| e.file_type().is_dir())
//     {
//         let node_toml_path = entry.path().join("node.toml");
//         if node_toml_path.exists() {
//             // Read the node.toml file
//             let toml_string = std::fs::read_to_string(&node_toml_path)?;

//             // TODO -> this needs to use use clear-sign reading
//             let toml_value: Value = toml::from_str(&toml_string)?;

//             // Extract the teamchannel_collaborators_with_access array

//             // teamchannel_collaborators_with_access -> array of strings
//             if let Some(collaborators_array) = toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array) {
//                 for collaborator_data in collaborators_array {

//                     /*
//                     e.g.
//                     [[abstract_collaborator_port_assignments.bob_bob.collaborator_ports]]
//                     user_name = "bob"
//                     ready_port = 55342
//                     intray_port = 54493
//                     gotit_port = 58652
//                     */
//                     // Extract each port and check if it's in use
//                     if let Some(ready_port) = collaborator_data.get("ready_port").and_then(|v| v.as_integer()).map(|p| p as u16) {
//                         if is_port_in_use(ready_port) && !ports_in_use.insert(ready_port) {
//                             return Err(ThisProjectError::PortCollision(format!("Port {} is already in use.", ready_port)));
//                         }
//                     }
//                     // Repeat for intray_port, gotit_port, self_ready_port, self_intray_port, self_gotit_port
//                     // ... (add similar checks for the other five ports)
//                 }
//             }
//         }
//     }

//     debug_log("Done check_all_ports_in_team_channels()");

//     Ok(()) // No port collisions found
// }


// old relative path
// /// Function for broadcasting to theads to wrapup and end uma session: quit
// fn should_halt_uma() -> bool {
//     // 1. Read the 'continue_uma.txt' file
//     let file_content = match fs::read_to_string(CONTINUE_UMA_PATH_STR) {
//         Ok(content) => content,
//         Err(e) => {
//             eprintln!("Error reading 'continue_uma.txt': {:?}", e); // Log the error
//             return false; // Don't halt on error reading the file
//         }
//     };

//     // 2. Check if the file content is "0"
//     file_content.trim() == "0"
// }

// /// Check for a Restart
// /// The logic here is easy to get backwards:
// /// There are two flags that are checked
// /// regarding shut-down.
// /// There is the normal ~should_continue flag,
// /// which is checked with a should_halt_uma checker.
// /// To keep things symetric, there is a parallel
// /// system for hard-reboot, working the same way
// /// with one exception:
// /// If you should restart this also re-reset the 'quit'
// /// function (so you are not in an infinite loop of quit-restart).
// /// if you check should_not_hard_restart() (this function)
// /// and find that you should (quite) not-restart, it works the same way.
// fn should_not_hard_restart() -> bool {
//     // 1. Read the 'hard_restart_flag.txt' file
//     let file_content = match fs::read_to_string(HARD_RESTART_FLAG_PATH_STR) {
//         Ok(content) => content,
//         Err(e) => {
//             eprintln!("Error in should_not_hard_restart(), error reading 'yes_hard_restart_flag.txt': {:?}", e); // Log the error
//             return false; // Don't halt on error reading the file
//         }
//     };

//     if file_content.trim() == "0" {
//         return true; // Hard restart requested
//     } else {
//         // Reset the quit flag using the safe function
//         // In the case that you ARE restarting.
//         // So you don't loop from restart to quit-again.
//         initialize_continue_uma_signal();
//         return false;
//     }
// }



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



// #[derive(Debug, Clone)]
// struct LocalUserUma {
//     uma_local_owner_user: String,
//     gpg_full_fingerprint_key_id_string: String,
//     uma_default_im_messages_expiration_days: u64,
//     uma_default_task_nodes_expiration_days: u64,
//     tui_height: u8,
//     tui_width: u8,
//     log_mode_refresh: f32,
// }

// impl LocalUserUma {
//     fn new(
//         uma_local_owner_user: String,
//         gpg_full_fingerprint_key_id_string: String,
//         ) -> LocalUserUma {
//         LocalUserUma {
//             uma_local_owner_user,
//             gpg_full_fingerprint_key_id_string,
//             uma_default_im_messages_expiration_days: 28, // Default to 7 days
//             uma_default_task_nodes_expiration_days: 90, // Default to 30 days
//             tui_height: 24,
//             tui_width: 80,
//             log_mode_refresh: 1.5 // how fast log mode refreshes
//             }
//     }

//     fn save_localuserumastruct_as_umatoml_file(&self, path: &Path) -> Result<(), io::Error> {
//         let toml_string = ...&self).map_err(|e| {
//             io::Error::new(io::ErrorKind::Other, format!("TOML serialization error: {}", e))
//         })?;
//         fs::write(path, toml_string)?;
//         Ok(())
//     }
// }



    // /// Loads a LocalUserUma configuration from a file.
    // /// Parses the plain text key-value format and constructs a new instance.
    // ///
    // /// # Arguments
    // /// * `path` - The absolute path to the configuration file
    // ///
    // /// # Returns
    // /// * `Ok(LocalUserUma)` if the file was read and parsed successfully
    // /// * `Err(io::Error)` if there was an I/O error or parsing error
    // fn load_from_uma_toml_file(path: &Path) -> Result<LocalUserUma, io::Error> {
    //     let file = fs::File::open(path)?;
    //     let reader = BufReader::new(file);

    //     // Initialize with empty/default values
    //     let mut uma_local_owner_user = String::new();
    //     let mut gpg_full_fingerprint_key_id_string = String::new();
    //     let mut uma_default_im_messages_expiration_days = 28u64;
    //     let mut uma_default_task_nodes_expiration_days = 90u64;
    //     let mut tui_height = 24u8;
    //     let mut tui_width = 80u8;
    //     let mut log_mode_refresh = 1.5f32;

    //     // Parse each line
    //     for line in reader.lines() {
    //         let line = line?;
    //         let trimmed = line.trim();

    //         // Skip empty lines
    //         if trimmed.is_empty() {
    //             continue;
    //         }

    //         // Split on '=' and process key-value pairs
    //         if let Some(equals_pos) = trimmed.find('=') {
    //             let key = trimmed[..equals_pos].trim();
    //             let value = trimmed[equals_pos + 1..].trim();

    //             match key {
    //                 "uma_local_owner_user" => {
    //                     uma_local_owner_user = Self::parse_string_value(value)?;
    //                 }
    //                 "gpg_full_fingerprint_key_id_string" => {
    //                     gpg_full_fingerprint_key_id_string = Self::parse_string_value(value)?;
    //                 }
    //                 "uma_default_im_messages_expiration_days" => {
    //                     uma_default_im_messages_expiration_days = Self::parse_u64_value(value)?;
    //                 }
    //                 "uma_default_task_nodes_expiration_days" => {
    //                     uma_default_task_nodes_expiration_days = Self::parse_u64_value(value)?;
    //                 }
    //                 "tui_height" => {
    //                     tui_height = Self::parse_u8_value(value)?;
    //                 }
    //                 "tui_width" => {
    //                     tui_width = Self::parse_u8_value(value)?;
    //                 }
    //                 "log_mode_refresh" => {
    //                     log_mode_refresh = Self::parse_f32_value(value)?;
    //                 }
    //                 _ => {
    //                     // Ignore unknown keys for forward compatibility
    //                     eprintln!("Warning: Unknown configuration key: {}", key);
    //                 }
    //             }
    //         }
    //     }

    //     // Validate required fields
    //     if uma_local_owner_user.is_empty() {
    //         return Err(io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             "Missing required field: uma_local_owner_user",
    //         ));
    //     }
    //     if gpg_full_fingerprint_key_id_string.is_empty() {
    //         return Err(io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             "Missing required field: gpg_full_fingerprint_key_id_string",
    //         ));
    //     }

    //     Ok(LocalUserUma {
    //         uma_local_owner_user,
    //         gpg_full_fingerprint_key_id_string,
    //         uma_default_im_messages_expiration_days,
    //         uma_default_task_nodes_expiration_days,
    //         tui_height,
    //         tui_width,
    //         log_mode_refresh,
    //     })
    // }



    /// Helper function to parse a u64 value from the configuration format.
    ///
    /// # Arguments
    /// * `value` - The raw value string from the configuration file
    ///
    /// # Returns
    /// * `Ok(u64)` if the value could be parsed
    /// * `Err(io::Error)` if the value couldn't be parsed as u64
    fn parse_u64_value(value: &str) -> Result<u64, io::Error> {
        value.trim().parse::<u64>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse u64 value: {}", e),
            )
        })
    }

    /// Helper function to parse a u8 value from the configuration format.
    ///
    /// # Arguments
    /// * `value` - The raw value string from the configuration file
    ///
    /// # Returns
    /// * `Ok(u8)` if the value could be parsed
    /// * `Err(io::Error)` if the value couldn't be parsed as u8
    fn parse_u8_value(value: &str) -> Result<u8, io::Error> {
        value.trim().parse::<u8>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse u8 value: {}", e),
            )
        })
    }

    /// Helper function to parse a f32 value from the configuration format.
    ///
    /// # Arguments
    /// * `value` - The raw value string from the configuration file
    ///
    /// # Returns
    /// * `Ok(f32)` if the value could be parsed
    /// * `Err(io::Error)` if the value couldn't be parsed as f32
    fn parse_f32_value(value: &str) -> Result<f32, io::Error> {
        value.trim().parse::<f32>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse f32 value: {}", e),
            )
        })
    }
    
    
    



/// Extract Salt Value:
/// It uses get("user_salt") to access the user_salt field in the TOML data.
/// and_then(Value::as_integer) attempts to convert the value to an integer.
/// and_then(|salt| salt.try_into().ok()) attempts to convert the integer to a u8.
/// ok_or_else(|| ...) handles the case where the salt is missing or invalid,
/// returning a ThisProjectError::InvalidData.
fn get_team_member_collaborator_salt(collaborator_name: &str) -> Result<u8, ThisProjectError> {
    // 1. Construct File Path
    let file_path = Path::new(COLLABORATOR_ADDRESSBOOK_PATH_STR)
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


// /// Adds a new collaborator by creating a TOML configuration file in the executable-relative
// /// collaborator directory.
// ///
// /// This function creates a `CollaboratorTomlData` instance from the provided parameters,
// /// serializes it to TOML format, and saves it to a file in the collaborator directory.
// /// The file path is determined relative to the executable location rather than the current
// /// working directory to ensure consistent path resolution regardless of where the program
// /// is executed from.
// ///
// /// adds as clearsign-toml file
// ///
// /// # Arguments
// ///
// /// * `user_name` - The collaborator's username
// /// * `user_salt_list` - List of salt values used for this collaborator
// /// * `ipv4_addresses` - Optional list of IPv4 addresses associated with the collaborator
// /// * `ipv6_addresses` - Optional list of IPv6 addresses associated with the collaborator
// /// * `gpg_publickey_id` - The GPG public key ID for the collaborator
// /// * `gpg_key_public` - The GPG public key content for the collaborator
// /// * `sync_interval` - The synchronization interval in seconds
// /// * `updated_at_timestamp` - Unix timestamp of when this collaborator data was last updated
// ///
// /// # Returns
// ///
// /// * `Result<(), std::io::Error>` - Ok(()) if the operation succeeded, or an error if any step failed
// ///
// /// # Errors
// ///
// /// This function can return errors in the following cases:
// /// * If creating the collaborator directory fails
// /// * If serializing the collaborator data to TOML fails
// /// * If creating or writing to the file fails
// pub fn make_new_collaborator_addressbook_toml_file(
//     user_name: String,
//     user_salt_list: Vec<u128>,
//     ipv4_addresses: Option<Vec<Ipv4Addr>>,
//     ipv6_addresses: Option<Vec<Ipv6Addr>>,
//     gpg_publickey_id: String,
//     gpg_key_public: String,
//     sync_interval: u64,
//     updated_at_timestamp: u64,
// ) -> Result<(), std::io::Error> {
//     /*
//     use std::fs::File;
//     use std::io::Write;
//     use std::net::{Ipv4Addr, Ipv6Addr};
//     use std::path::Path;

//     // Import the path management module
//     use crate::manage_absolute_executable_directory_relative_paths::make_input_path_name_abs_executabledirectoryrelative_nocheck;
//     use crate::manage_absolute_executable_directory_relative_paths::prepare_file_parent_directories_abs_executabledirectoryrelative;
//     */
//     debug_log("Starting: fn make_new_collaborator_addressbook_toml_file");

//     // Log function parameters for debugging
//     debug_log!("user_name {:?}", user_name);
//     debug_log!("user_salt_list {:?}", &user_salt_list);
//     debug_log!("ipv4_addresses {:?}", ipv4_addresses);
//     debug_log!("ipv6_addresses {:?}", ipv6_addresses);
//     debug_log!("gpg_publickey_id {:?}", &gpg_publickey_id);
//     debug_log!("gpg_key_public {:?}", &gpg_key_public);
//     debug_log!("sync_interval {:?}", sync_interval);
//     debug_log!("updated_at_timestamp {:?}", updated_at_timestamp);

//     // Create the CollaboratorTomlData instance
//     let collaborator = CollaboratorTomlData::new(
//         user_name,
//         user_salt_list,
//         ipv4_addresses,
//         ipv6_addresses,
//         gpg_publickey_id,
//         gpg_key_public,
//         sync_interval,
//         updated_at_timestamp,
//     );

//     debug_log!("collaborator {:?}", collaborator);

//     // Serialize the collaborator to TOML format
//     // TODO this may need to be done inhouse
//     let toml_string = match serialize_collaborator_to_toml(&collaborator) {
//         Ok(content) => {
//             debug_log!("Successfully serialized collaborator to TOML");
//             content
//         },
//         Err(e) => {
//             debug_log!("Error serializing to TOML: {}", e);
//             return Err(std::io::Error::new(
//                 std::io::ErrorKind::Other,
//                 format!("TOML serialization error: {}", e),
//             ));
//         }
//     };

//     // Construct the relative path to the collaborator file
//     let relative_path = format!(
//         "{}/{}__collaborator.toml",
//         COLLABORATOR_ADDRESSBOOK_PATH_STR,
//         collaborator.user_name,
//     );

//     // Convert the relative path to an absolute path based on the executable's directory
//     let file_path = match make_input_path_name_abs_executabledirectoryrelative_nocheck(&relative_path) {
//         Ok(path) => path,
//         Err(e) => {
//             debug_log!("Error creating absolute path: {}", e);
//             return Err(e);
//         }
//     };

//     // Ensure parent directories exist
//     let prepared_path = match prepare_file_parent_directories_abs_executabledirectoryrelative(&relative_path) {
//         Ok(path) => path,
//         Err(e) => {
//             debug_log!("Error preparing parent directories: {}", e);
//             return Err(e);
//         }
//     };

//     // Log the constructed file path
//     debug_log!("Attempting to write collaborator file to: {:?}", prepared_path.display());

//     // --- Block for file writing ---
//     // This ensures `file` is dropped and the file is closed before the GPG operation.
//     {
//         let mut file = match File::create(&prepared_path) {
//             Ok(f) => f,
//             Err(e) => {
//                 // Corrected debug_log! usage:
//                 debug_log!("Error creating file '{}': {}", prepared_path.display(), e);
//                 return Err(e); // Return immediately if file creation fails
//             }
//         };

//         // Write the serialized TOML to the file
//         match file.write_all(toml_string.as_bytes()) {
//             Ok(_) => {
//                 // Corrected debug_log! usage:
//                 debug_log!("Successfully wrote initial TOML data to collaborator file: {}", prepared_path.display());
//                 // Do NOT return Ok(()) here yet. Proceed to the next step.
//             },
//             Err(e) => {
//                 // Corrected debug_log! usage:
//                 debug_log!("Error writing TOML data to file '{}': {}", prepared_path.display(), e);
//                 return Err(e); // Return immediately if writing fails
//             }
//         }
//     } // `file` is dropped here, so it's closed.

//     // Now that the TOML file is written and closed, proceed to clearsign it in-place.
//     // Corrected debug_log! usage:
//     debug_log!("Attempting to clearsign the TOML file '{}' in-place.", prepared_path.display());

//     // Call the in-place clearsigning function.
//     // Note: `prepared_path` is a `PathBuf`. `&prepared_path` correctly provides a `&Path`.
//     match convert_toml_filewithkeyid_into_clearsigntoml_inplace(&prepared_path) {
//         Ok(()) => {
//             // Clearsigning was successful.
//             // Corrected debug_log! usage:
//             debug_log!("Successfully converted '{}' to clearsigned TOML in-place.", prepared_path.display());
//             // This is now the final successful outcome of make_new_collaborator_addressbook_toml_file.
//             Ok(())
//         }
//         Err(gpg_error) => {
//             // Clearsigning failed. Convert GpgError to std::io::Error.
//             let error_message = format!(
//                 "Failed to convert TOML file '{}' to clearsign TOML in-place: {}",
//                 prepared_path.display(),
//                 gpg_error.to_string() // Assumes GpgError has .to_string() or implements Display
//             );
//             // Corrected debug_log! usage for a pre-formatted string:
//             debug_log!("{}", error_message); // Log the detailed error
//             // Return an std::io::Error.
//             Err(std::io::Error::new(
//                 std::io::ErrorKind::Other, // Or a more contextually appropriate ErrorKind
//                 error_message, // Pass the already formatted string
//             ))
//         }
//     }
//     // The result of this final `match` expression is the return value of
//     // `make_new_collaborator_addressbook_toml_file`, satisfying its `Result<(), std::io::Error>` signature.
// }



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
    //     self.pa2_schedule = this_node.pa2_schedule;
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
//                 self.pa2_schedule = this_node.pa2_schedule;
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

// // Define the enum
// #[derive(Debug, Clone)]
// enum MaxPostsDurationUnitsEnum {
//     Hour,
//     Day,
//     Week,
//     // None,
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

// /*
// should not use any 3rd party crates
// - pending:
// -- clearsign validate
// */
// /// Loads a `CoreNode` from a TOML file, handling potential errors.
// ///
// /// # Arguments
// ///
// /// * `file_path` - The path to the TOML file containing the node data.
// ///
// /// # Returns
// ///
// /// * `Result<CoreNode, String>` - `Ok(CoreNode)` if the node is successfully loaded,
// ///    `Err(String)` containing an error message if an error occurs.
// fn load_core_node_from_toml_file(file_path: &Path) -> Result<CoreNode, String> {

//     debug_log!(
//         "Starting: load_core_node_from_toml_file(), file_path -> {:?}",
//         file_path,
//     );

//     // pending
//     /*
//     look up file owner
//     get gpg public key
//     validate clearsign
//     */

//     // 1. Read File Contents
//     let toml_string = match fs::read_to_string(file_path) {
//         Ok(content) => content,
//         Err(e) => return Err(format!("Error lcnftf reading file: {} in load_core_node_from_toml_file", e)),
//     };

//     // 2. Parse TOML String
//     let toml_value: Value = match toml_string.parse() {
//         Ok(value) => value,
//         Err(e) => return Err(format!("Error lcnftf parsing TOML in load_core_node_from_toml_file: {}", e)),
//     };

//     // 3. Extract node_unique_id as hex string and decode using your function:
//     // let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_str) {
//     //     Some(hex_string) => hex_string_to_pearson_hash(hex_string)?, // Use your function. Propagate error with ?.
//     //     None => return Err("error: load_core_node_from_toml_file(), Missing node_unique_id".to_string()),
//     // };

//     // 3. Extract node_unique_id as array
//     let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_array) {
//         Some(array) => {
//             let mut vec = Vec::new();
//             for value in array {
//                 if let Some(num) = value.as_integer() {
//                     if num >= 0 && num <= 255 {
//                         vec.push(num as u8);
//                     } else {
//                         return Err("Invalid byte value in node_unique_id".to_string());
//                     }
//                 } else {
//                     return Err("Invalid value in node_unique_id array".to_string());
//                 }
//             }
//             vec
//         },
//         None => return Err("Missing or invalid node_unique_id".to_string()),
//     };
//     // // Project Areas
//     // pa1_process
//     // pa2_schedule
//     // pa3_users
//     // pa4_features
//     // pa5_mvp
//     // pa6_feedback

//     // TODO

//     // 4. Task Items
//     let pa1_process = toml_value
//         .get("pa1_process")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa1_process")?
//         .to_string();

//     // schedule_duration
//     let pa2_schedule = toml_value
//         .get("pa2_schedule")
//         .and_then(Value::as_array)
//         .ok_or("Missing or invalid pa2_schedule")?
//         .iter()
//         .map(|v| v.as_integer().ok_or("Invalid integer in pa2_schedule"))
//         .collect::<Result<Vec<i64>, &str>>()?
//         .into_iter()
//         .map(|i| i as u64)
//         .collect();

//     let pa3_users = toml_value
//         .get("pa3_users")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa3_users")?
//         .to_string();

//     let pa4_features = toml_value
//         .get("pa4_features")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa4_features")?
//         .to_string();

//     let pa5_mvp = toml_value
//         .get("pa5_mvp")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa5_mvp")?
//         .to_string();

//     let pa6_feedback = toml_value
//         .get("pa6_feedback")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa6_feedback")?
//         .to_string();

//     // // 4. Handle abstract_collaborator_port_assignments
//     // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
//     //     for (pair_name, pair_data) in collaborator_assignments_table {
//     //         debug_log("Looking for 'collaborator_ports' load_core...");
//     //         if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
//     //             let mut collaborator_ports = Vec::new();
//     //             for port_data in ports_list {
//     //                 // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
//     //                 let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//     //                 // let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //                 let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //                 collaborator_ports.push(collaborator_port);
//     //             }
//     //             core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);
//     //             // let mut collaborator_ports = Vec::new();
//     //             // for port_data in ports_list {
//     //             //     // Deserialize each ReadTeamchannelCollaboratorPortsToml from the array
//     //             //     let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//     //             //     let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //             //     collaborator_ports.push(collaborator_port);
//     //             // }
//     //             // // this is doing what?
//     //             // core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);

//     //         }
//     //     }
//     // }

//     // 5. Deserialize into CoreNode Struct (Manually)
//     let mut core_node = CoreNode {
//         node_name: toml_value.get("node_name").and_then(Value::as_str).unwrap_or("").to_string(),
//         description_for_tui: toml_value.get("description_for_tui").and_then(Value::as_str).unwrap_or("").to_string(),
//         node_unique_id: node_unique_id,
//         directory_path: PathBuf::from(toml_value.get("directory_path").and_then(Value::as_str).unwrap_or("")),
//         // order_number: toml_value.get("order_number").and_then(Value::as_integer).unwrap_or(0) as u32,
//         // priority: match toml_value.get("priority").and_then(Value::as_str).unwrap_or("Medium") {
//         //     "High" => NodePriority::High,
//         //     "Medium" => NodePriority::Medium,
//         //     "Low" => NodePriority::Low,
//         //     _ => NodePriority::Medium,
//         // },
//         owner: toml_value.get("owner").and_then(Value::as_str).unwrap_or("").to_string(),
//         updated_at_timestamp: toml_value.get("updated_at_timestamp").and_then(Value::as_integer).unwrap_or(0) as u64,
//         expires_at: toml_value.get("expires_at").and_then(Value::as_integer).unwrap_or(0) as u64,
//         // children: Vec::new(), // You might need to load children recursively
//         teamchannel_collaborators_with_access: toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array).map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
//         abstract_collaborator_port_assignments: HashMap::new(),

//         // Project Areas
//         pa1_process: pa1_process,
//         pa2_schedule: pa2_schedule, // schedule_duration,
//         pa3_users: pa3_users,
//         pa4_features: pa4_features, //, goals_features,
//         pa5_mvp: pa5_mvp,
//         pa6_feedback: pa6_feedback,
//     };

//     // 6. collaborators
//     // Inside load_core_node_from_toml_file
//     // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
//     if let Some(collaborator_assignments_table) = toml_value.get("collaborator_port_assignments").and_then(Value::as_table) {
//         for (pair_name, pair_data) in collaborator_assignments_table {
//             debug_log("Looking for 'collaborator_ports' load_core...");
//             if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
//                 // Create a vector to hold ReadTeamchannelCollaboratorPortsToml instances for this pair
//                 let mut ports_for_pair = Vec::new();

//                 for port_data in ports_list {
//                     // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
//                     let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//                     let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;

//                     // Create ReadTeamchannelCollaboratorPortsToml and add it to the vector
//                     let read_teamchannel_collaborator_ports_toml = ReadTeamchannelCollaboratorPortsToml {
//                         collaborator_ports: vec![collaborator_port], // Wrap in a vector
//                     };
//                     ports_for_pair.push(read_teamchannel_collaborator_ports_toml);
//                 }

//                 // Insert the vector of ReadTeamchannelCollaboratorPortsToml into the HashMap
//                 core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), ports_for_pair);
//             }
//         }
//     }

//     Ok(core_node)
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

// /*
// should not use any 3rd party crates
// - pending:
// -- clearsign validate
// */
// /// Loads a `CoreNode` from a TOML file, handling potential errors.
// ///
// /// # Arguments
// ///
// /// * `file_path` - The path to the TOML file containing the node data.
// ///
// /// # Returns
// ///
// /// * `Result<CoreNode, String>` - `Ok(CoreNode)` if the node is successfully loaded,
// ///    `Err(String)` containing an error message if an error occurs.
// fn load_core_node_from_toml_file(file_path: &Path) -> Result<CoreNode, String> {

//     debug_log!(
//         "Starting: load_core_node_from_toml_file(), file_path -> {:?}",
//         file_path,
//     );

//     // pending
//     /*
//     look up file owner
//     get gpg public key
//     validate clearsign
//     */

//     // 1. Read File Contents
//     let toml_string = match fs::read_to_string(file_path) {
//         Ok(content) => content,
//         Err(e) => return Err(format!("Error lcnftf reading file: {} in load_core_node_from_toml_file", e)),
//     };

//     // 2. Parse TOML String
//     let toml_value: Value = match toml_string.parse() {
//         Ok(value) => value,
//         Err(e) => return Err(format!("Error lcnftf parsing TOML in load_core_node_from_toml_file: {}", e)),
//     };

//     // 3. Extract node_unique_id as hex string and decode using your function:
//     // let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_str) {
//     //     Some(hex_string) => hex_string_to_pearson_hash(hex_string)?, // Use your function. Propagate error with ?.
//     //     None => return Err("error: load_core_node_from_toml_file(), Missing node_unique_id".to_string()),
//     // };

//     // 3. Extract node_unique_id as array
//     let node_unique_id = match toml_value.get("node_unique_id").and_then(Value::as_array) {
//         Some(array) => {
//             let mut vec = Vec::new();
//             for value in array {
//                 if let Some(num) = value.as_integer() {
//                     if num >= 0 && num <= 255 {
//                         vec.push(num as u8);
//                     } else {
//                         return Err("Invalid byte value in node_unique_id".to_string());
//                     }
//                 } else {
//                     return Err("Invalid value in node_unique_id array".to_string());
//                 }
//             }
//             vec
//         },
//         None => return Err("Missing or invalid node_unique_id".to_string()),
//     };
//     // // Project Areas
//     // pa1_process
//     // pa2_schedule
//     // pa3_users
//     // pa4_features
//     // pa5_mvp
//     // pa6_feedback

//     // TODO

//     // 4. Task Items
//     let pa1_process = toml_value
//         .get("pa1_process")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa1_process")?
//         .to_string();

//     // schedule_duration
//     let pa2_schedule = toml_value
//         .get("pa2_schedule")
//         .and_then(Value::as_array)
//         .ok_or("Missing or invalid pa2_schedule")?
//         .iter()
//         .map(|v| v.as_integer().ok_or("Invalid integer in pa2_schedule"))
//         .collect::<Result<Vec<i64>, &str>>()?
//         .into_iter()
//         .map(|i| i as u64)
//         .collect();

//     let pa3_users = toml_value
//         .get("pa3_users")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa3_users")?
//         .to_string();

//     let pa4_features = toml_value
//         .get("pa4_features")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa4_features")?
//         .to_string();

//     let pa5_mvp = toml_value
//         .get("pa5_mvp")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa5_mvp")?
//         .to_string();

//     let pa6_feedback = toml_value
//         .get("pa6_feedback")
//         .and_then(Value::as_str)
//         .ok_or("Missing or invalid pa6_feedback")?
//         .to_string();

//     // // 4. Handle abstract_collaborator_port_assignments
//     // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
//     //     for (pair_name, pair_data) in collaborator_assignments_table {
//     //         debug_log("Looking for 'collaborator_ports' load_core...");
//     //         if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
//     //             let mut collaborator_ports = Vec::new();
//     //             for port_data in ports_list {
//     //                 // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
//     //                 let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//     //                 // let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //                 let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //                 collaborator_ports.push(collaborator_port);
//     //             }
//     //             core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);
//     //             // let mut collaborator_ports = Vec::new();
//     //             // for port_data in ports_list {
//     //             //     // Deserialize each ReadTeamchannelCollaboratorPortsToml from the array
//     //             //     let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//     //             //     let collaborator_port: ReadTeamchannelCollaboratorPortsToml = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;
//     //             //     collaborator_ports.push(collaborator_port);
//     //             // }
//     //             // // this is doing what?
//     //             // core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), collaborator_ports);

//     //         }
//     //     }
//     // }

//     // 5. Deserialize into CoreNode Struct (Manually)
//     let mut core_node = CoreNode {
//         node_name: toml_value.get("node_name").and_then(Value::as_str).unwrap_or("").to_string(),
//         description_for_tui: toml_value.get("description_for_tui").and_then(Value::as_str).unwrap_or("").to_string(),
//         node_unique_id: node_unique_id,
//         directory_path: PathBuf::from(toml_value.get("directory_path").and_then(Value::as_str).unwrap_or("")),
//         // order_number: toml_value.get("order_number").and_then(Value::as_integer).unwrap_or(0) as u32,
//         // priority: match toml_value.get("priority").and_then(Value::as_str).unwrap_or("Medium") {
//         //     "High" => NodePriority::High,
//         //     "Medium" => NodePriority::Medium,
//         //     "Low" => NodePriority::Low,
//         //     _ => NodePriority::Medium,
//         // },
//         owner: toml_value.get("owner").and_then(Value::as_str).unwrap_or("").to_string(),
//         updated_at_timestamp: toml_value.get("updated_at_timestamp").and_then(Value::as_integer).unwrap_or(0) as u64,
//         expires_at: toml_value.get("expires_at").and_then(Value::as_integer).unwrap_or(0) as u64,
//         // children: Vec::new(), // You might need to load children recursively
//         teamchannel_collaborators_with_access: toml_value.get("teamchannel_collaborators_with_access").and_then(Value::as_array).map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
//         abstract_collaborator_port_assignments: HashMap::new(),

//         // Project Areas
//         pa1_process: pa1_process,
//         pa2_schedule: pa2_schedule, // schedule_duration,
//         pa3_users: pa3_users,
//         pa4_features: pa4_features, //, goals_features,
//         pa5_mvp: pa5_mvp,
//         pa6_feedback: pa6_feedback,
//     };

//     // 6. collaborators
//     // Inside load_core_node_from_toml_file
//     // if let Some(collaborator_assignments_table) = toml_value.get("abstract_collaborator_port_assignments").and_then(Value::as_table) {
//     if let Some(collaborator_assignments_table) = toml_value.get("collaborator_port_assignments").and_then(Value::as_table) {
//         for (pair_name, pair_data) in collaborator_assignments_table {
//             debug_log("Looking for 'collaborator_ports' load_core...");
//             if let Some(ports_list) = pair_data.get("collaborator_ports").and_then(Value::as_array) {
//                 // Create a vector to hold ReadTeamchannelCollaboratorPortsToml instances for this pair
//                 let mut ports_for_pair = Vec::new();

//                 for port_data in ports_list {
//                     // Deserialize each AbstractTeamchannelNodeTomlPortsData from the array
//                     let port_data_str = toml::to_string(&port_data).unwrap(); // Convert Value to String
//                     let collaborator_port: AbstractTeamchannelNodeTomlPortsData = toml::from_str(&port_data_str).map_err(|e| format!("Error deserializing collaborator port: {}", e))?;

//                     // Create ReadTeamchannelCollaboratorPortsToml and add it to the vector
//                     let read_teamchannel_collaborator_ports_toml = ReadTeamchannelCollaboratorPortsToml {
//                         collaborator_ports: vec![collaborator_port], // Wrap in a vector
//                     };
//                     ports_for_pair.push(read_teamchannel_collaborator_ports_toml);
//                 }

//                 // Insert the vector of ReadTeamchannelCollaboratorPortsToml into the HashMap
//                 core_node.abstract_collaborator_port_assignments.insert(pair_name.clone(), ports_for_pair);
//             }
//         }
//     }

//     Ok(core_node)
// }




