
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



//     /*
//      plan A:
//      - ask use with Q&A about:
//         -- default to gpg, or type 'only clearsign' for readable file
//         encrypt_with_gpg()
//     */

//     // user Q&A: enter 'clearsign' for a clearsigned node.toml or by default secure node.gpgtoml

//     // Handle the CoreNode creation result
//     match new_node_result {
//         Ok(new_node) => {
//             debug_log!(" CoreNode created successfully, saving to file... -> new_node.save_node_as_gpgtoml()");
//             match new_node.save_node_as_gpgtoml() {
//                 Ok(_) => {
//                     debug_log!("save_node_as_gpgtoml CoreNode saved successfully");
//                     Ok(())
//                 },
//                 Err(e) => {
//                     debug_log!("save_node_as_gpgtoml Error saving CoreNode: {}", e);
//                     Err(ThisProjectError::IoError(e))
//                 }
//             }
//         },
//         Err(e) => {
//             debug_log!("Error creating CoreNode: {}", e);
//             Err(e)
//         }
//     }

//     // vs.

//     // Handle the CoreNode creation result
//     match new_node_result {
//         Ok(new_node) => {
//             debug_log!("CoreNode created successfully, saving to file... -> new_node.save_node_to_clearsigned_file()");
//             match new_node.save_node_to_clearsigned_file() {
//                 Ok(_) => {
//                     debug_log!("CoreNode saved successfully");
//                     Ok(())
//                 },
//                 Err(e) => {
//                     debug_log!("Error saving CoreNode: {}", e);
//                     Err(ThisProjectError::IoError(e))
//                 }
//             }
//         },
//         Err(e) => {
//             debug_log!("Error creating CoreNode: {}", e);
//             Err(e)
//         }
//     }


// }


// /// Updates an existing CoreNode by walking the user through optional field updates.
// ///
// /// This function loads an existing CoreNode from disk, presents the current values of
// /// updatable fields to the user, and allows them to optionally update each field through
// /// a Q&A process. The user can choose to keep existing values (default) or enter new ones.
// /// After all updates are collected, the modified node is saved back to disk.
// ///
// /// # Updatable Fields
// ///
// /// The following fields can be updated:
// /// - **Collaborators list** (primary update field)
// /// - **Port assignments** (regenerated if collaborators change)
// /// - **Project Areas**: pa1_process, pa2_schedule, pa3_users, pa4_features, pa5_mvp, pa6_feedback
// /// - **Message Post Configuration**: All Option fields for message post settings
// ///
// /// # Preserved Fields
// ///
// /// The following fields are NOT modified:
// /// - Core identity fields (owner, node_name, display_name, node_path)
// /// - Directory structure (no filesystem changes except the node TOML file)
// ///
// /// # Arguments
// ///
// /// * `node_path` - The absolute path to the CoreNode TOML file to update
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>` - `Ok(())` on successful update and save,
// ///   or a `ThisProjectError` describing what went wrong
// ///
// /// # Errors
// ///
// /// This function can fail with a `ThisProjectError` in the following cases:
// /// * If the node file cannot be loaded from the specified path
// /// * If the node file cannot be parsed as a valid CoreNode
// /// * If saving the updated node back to disk fails
// /// * If user input cannot be read during Q&A
// /// * If port assignment generation fails when collaborators are updated
// ///
// /// # Example
// ///
// /// ```
// /// let node_path = PathBuf::from("/absolute/path/to/node.toml");
// /// match update_core_node(node_path) {
// ///     Ok(()) => println!("Node updated successfully"),
// ///     Err(e) => eprintln!("Failed to update node: {}", e),
// /// }
// /// ```
// fn update_core_node(
//     node_path: PathBuf,
// ) -> Result<(), ThisProjectError> {
//     // Log function entry
//     debug_log!("UCN: Starting update_core_node for path: {:?}", node_path);

//     // Step 1: Load the existing CoreNode from disk
//         // Uses load_core_node_from_toml_file to read and parse the node.toml file
//         let mut existing_node = match load_core_node_from_toml_file(&node_path) {
//             Ok(node) => {
//                 debug_log!("UCN: Successfully loaded CoreNode from {:?}", node_path);
//                 node
//             }
//             Err(e) => {
//                 debug_log!("UCN: Failed to load CoreNode from {:?}: {}", node_path, e);
//                 // Map the error to ThisProjectError::InvalidData as per the error handling pattern
//                 return Err(ThisProjectError::InvalidData(e));
//             }
//         };

//     println!("\n=== CoreNode Update Wizard ===");
//     println!("Node: {}", existing_node.display_name);
//     println!("Owner: {}", existing_node.owner);
//     println!("\nYou will be prompted to update various fields.");
//     println!("Press Enter to keep existing values, or type new values when prompted.\n");

//     // Step 2: Update Collaborators (main field)
//     println!("\n--- COLLABORATORS UPDATE ---");
//     println!("Current collaborators: {:?}", existing_node.collaborators);
//     print!("Do you want to update the collaborators list? [y/N]: ");

//     // Flush stdout to ensure prompt appears
//     use std::io::{self, Write};
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut input = String::new();
//     io::stdin().read_line(&mut input).map_err(|e| ThisProjectError::IoError(e))?;

//     let update_collaborators = input.trim().to_lowercase() == "y";
//     let mut collaborators_changed = false;

//     if update_collaborators {
//         // Get new collaborators list
//         println!("Enter new collaborators (comma-separated usernames):");
//         println!("Note: The owner '{}' will be automatically included.", existing_node.owner);
//         print!("> ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut collab_input = String::new();
//         io::stdin().read_line(&mut collab_input).map_err(|e| ThisProjectError::IoError(e))?;

//         // Parse collaborators, ensuring owner is included
//         let mut new_collaborators: Vec<String> = collab_input
//             .trim()
//             .split(',')
//             .map(|s| s.trim().to_string())
//             .filter(|s| !s.is_empty())
//             .collect();

//         // Ensure owner is in the list
//         if !new_collaborators.contains(&existing_node.owner) {
//             new_collaborators.insert(0, existing_node.owner.clone());
//         }

//         // Check if collaborators actually changed
//         collaborators_changed = new_collaborators != existing_node.collaborators;

//         if collaborators_changed {
//             existing_node.collaborators = new_collaborators;
//             debug_log!("UCN: Collaborators updated to: {:?}", existing_node.collaborators);

//             // Step 3: Regenerate port assignments if collaborators changed
//             println!("\nRegenerating port assignments for updated collaborators...");

//             let (updated_collaborators, new_port_assignments) =
//                 match create_teamchannel_port_assignments(&existing_node.owner) {
//                     Ok((collab_list, port_assigns)) => {
//                         debug_log!(
//                             "UCN: Successfully regenerated port assignments for {} collaborators",
//                             collab_list.len()
//                         );
//                         (collab_list, port_assigns)
//                     }
//                     Err(e) => {
//                         let error_msg = format!(
//                             "UCN: Failed to regenerate port assignments: {}",
//                             e.to_string()
//                         );
//                         eprintln!("ERROR: {}", error_msg);
//                         return Err(ThisProjectError::from(error_msg));
//                     }
//                 };

//             // Update the node with new port assignments
//             existing_node.collaborators = updated_collaborators;
//             existing_node.abstract_collaborator_port_assignments = new_port_assignments;
//             println!("Port assignments regenerated successfully.");
//         } else {
//             println!("Collaborators unchanged.");
//         }
//     }

//     // Step 4: Optionally update port assignments (if collaborators didn't change)
//     if !collaborators_changed {
//         println!("\n--- PORT ASSIGNMENTS UPDATE ---");
//         print!("Do you want to regenerate port assignments? [y/N]: ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut port_input = String::new();
//         io::stdin().read_line(&mut port_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if port_input.trim().to_lowercase() == "y" {
//             println!("Regenerating port assignments...");

//             let (_, new_port_assignments) =
//                 match create_teamchannel_port_assignments(&existing_node.owner) {
//                     Ok((collab_list, port_assigns)) => {
//                         debug_log!("UCN: Port assignments regenerated");
//                         (collab_list, port_assigns)
//                     }
//                     Err(e) => {
//                         let error_msg = format!(
//                             "UCN: Failed to regenerate port assignments: {}",
//                             e.to_string()
//                         );
//                         eprintln!("ERROR: {}", error_msg);
//                         return Err(ThisProjectError::from(error_msg));
//                     }
//                 };

//             existing_node.abstract_collaborator_port_assignments = new_port_assignments;
//             println!("Port assignments regenerated successfully.");
//         }
//     }

//     // Step 5: Update Project Areas
//     println!("\n--- PROJECT AREAS UPDATE ---");

//     // PA1 Process
//     println!("\nPA1 Process (current value: {})", existing_node.pa1_process);
//     print!("Update PA1 Process? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa1_input = String::new();
//     io::stdin().read_line(&mut pa1_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa1_input.trim().to_lowercase() == "y" {
//         existing_node.pa1_process = match q_and_a_get_pa1_process() {
//             Ok(data) => {
//                 debug_log!("UCN: PA1 Process updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA1 Process: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // PA2 Schedule
//     println!("\nPA2 Schedule (current value: {})", existing_node.pa2_schedule);
//     print!("Update PA2 Schedule? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa2_input = String::new();
//     io::stdin().read_line(&mut pa2_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa2_input.trim().to_lowercase() == "y" {
//         existing_node.pa2_schedule = match q_and_a_get_pa2_schedule() {
//             Ok(data) => {
//                 debug_log!("UCN: PA2 Schedule updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA2 Schedule: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // PA3 Users
//     println!("\nPA3 Users (current value: {})", existing_node.pa3_users);
//     print!("Update PA3 Users? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa3_input = String::new();
//     io::stdin().read_line(&mut pa3_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa3_input.trim().to_lowercase() == "y" {
//         existing_node.pa3_users = match q_and_a_get_pa3_users() {
//             Ok(data) => {
//                 debug_log!("UCN: PA3 Users updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA3 Users: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // PA4 Features
//     println!("\nPA4 Features (current value: {})", existing_node.pa4_features);
//     print!("Update PA4 Features? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa4_input = String::new();
//     io::stdin().read_line(&mut pa4_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa4_input.trim().to_lowercase() == "y" {
//         existing_node.pa4_features = match q_and_a_get_pa4_features() {
//             Ok(data) => {
//                 debug_log!("UCN: PA4 Features updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA4 Features: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // PA5 MVP
//     println!("\nPA5 MVP (current value: {})", existing_node.pa5_mvp);
//     print!("Update PA5 MVP? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa5_input = String::new();
//     io::stdin().read_line(&mut pa5_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa5_input.trim().to_lowercase() == "y" {
//         existing_node.pa5_mvp = match q_and_a_get_pa5_mvp() {
//             Ok(data) => {
//                 debug_log!("UCN: PA5 MVP updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA5 MVP: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // PA6 Feedback
//     println!("\nPA6 Feedback (current value: {})", existing_node.pa6_feedback);
//     print!("Update PA6 Feedback? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut pa6_input = String::new();
//     io::stdin().read_line(&mut pa6_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if pa6_input.trim().to_lowercase() == "y" {
//         existing_node.pa6_feedback = match q_and_a_get_pa6_feedback() {
//             Ok(data) => {
//                 debug_log!("UCN: PA6 Feedback updated");
//                 data
//             }
//             Err(e) => {
//                 debug_log!("UCN: Error updating PA6 Feedback: {}", e);
//                 return Err(e);
//             }
//         };
//     }

//     // Step 6: Update Message Post Configuration (Optional fields)
//     println!("\n--- MESSAGE POST CONFIGURATION UPDATE ---");
//     print!("Update message post configuration fields? [y/N]: ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut msg_config_input = String::new();
//     io::stdin().read_line(&mut msg_config_input).map_err(|e| ThisProjectError::IoError(e))?;

//     if msg_config_input.trim().to_lowercase() == "y" {
//         // Helper function to update optional fields
//         // For now, we'll provide simple text input for these fields
//         // In a real implementation, you might want more sophisticated Q&A functions

//         println!("\nNote: Press Enter to keep existing value, or enter new value.");

//         // Max string length
//         print!("Max string length (current: {:?}): ", existing_node.message_post_max_string_length_int);
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut max_len_input = String::new();
//         io::stdin().read_line(&mut max_len_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if !max_len_input.trim().is_empty() {
//             match max_len_input.trim().parse::<usize>() {
//                 Ok(val) => {
//                     existing_node.message_post_max_string_length_int = Some(val);
//                     debug_log!("UCN: Max string length updated to: {}", val);
//                 }
//                 Err(_) => {
//                     println!("Invalid number, keeping existing value.");
//                 }
//             }
//         }

//         // Is public boolean
//         print!("Is public? (true/false, current: {:?}): ", existing_node.message_post_is_public_bool);
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut is_public_input = String::new();
//         io::stdin().read_line(&mut is_public_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if !is_public_input.trim().is_empty() {
//             match is_public_input.trim().parse::<bool>() {
//                 Ok(val) => {
//                     existing_node.message_post_is_public_bool = Some(val);
//                     debug_log!("UCN: Is public updated to: {}", val);
//                 }
//                 Err(_) => {
//                     println!("Invalid boolean, keeping existing value.");
//                 }
//             }
//         }

//         // User confirms boolean
//         print!("User confirms? (true/false, current: {:?}): ", existing_node.message_post_user_confirms_bool);
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut user_confirms_input = String::new();
//         io::stdin().read_line(&mut user_confirms_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if !user_confirms_input.trim().is_empty() {
//             match user_confirms_input.trim().parse::<bool>() {
//                 Ok(val) => {
//                     existing_node.message_post_user_confirms_bool = Some(val);
//                     debug_log!("UCN: User confirms updated to: {}", val);
//                 }
//                 Err(_) => {
//                     println!("Invalid boolean, keeping existing value.");
//                 }
//             }
//         }

//         // Start date (POSIX timestamp)
//         print!("Start date (POSIX timestamp, current: {:?}): ", existing_node.message_post_start_date_utc_posix);
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut start_date_input = String::new();
//         io::stdin().read_line(&mut start_date_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if !start_date_input.trim().is_empty() {
//             match start_date_input.trim().parse::<i64>() {
//                 Ok(val) => {
//                     existing_node.message_post_start_date_utc_posix = Some(val);
//                     debug_log!("UCN: Start date updated to: {}", val);
//                 }
//                 Err(_) => {
//                     println!("Invalid timestamp, keeping existing value.");
//                 }
//             }
//         }

//         // End date (POSIX timestamp)
//         print!("End date (POSIX timestamp, current: {:?}): ", existing_node.message_post_end_date_utc_posix);
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut end_date_input = String::new();
//         io::stdin().read_line(&mut end_date_input).map_err(|e| ThisProjectError::IoError(e))?;

//         if !end_date_input.trim().is_empty() {
//             match end_date_input.trim().parse::<i64>() {
//                 Ok(val) => {
//                     existing_node.message_post_end_date_utc_posix = Some(val);
//                     debug_log!("UCN: End date updated to: {}", val);
//                 }
//                 Err(_) => {
//                     println!("Invalid timestamp, keeping existing value.");
//                 }
//             }
//         }

//         // Note: The integer ranges and string ranges fields would need more complex parsing
//         // For now, leaving them as-is unless you have specific Q&A functions for them
//         println!("\nNote: Integer ranges and string ranges configuration not updated in this version.");
//     }

//     // Step 7: Save the updated node back to disk
//     println!("\n--- SAVING UPDATES ---");
//     println!("Saving updated CoreNode to {:?}...", node_path);

//     match existing_node.save_node_to_clearsigned_file() {
//         Ok(_) => {
//             debug_log!("UCN: CoreNode successfully saved to {:?}", node_path);
//             println!("CoreNode updated and saved successfully!");
//             Ok(())
//         }
//         Err(e) => {
//             debug_log!("UCN: Failed to save CoreNode: {}", e);
//             eprintln!("ERROR: Failed to save updated node: {}", e);
//             Err(ThisProjectError::IoError(e))
//         }
//     }
// }

// old relative path version
// /// Creates a new team-channel directory, subdirectories, and metadata files.
// /// Handles errors and returns a Result to indicate success or failure.
// ///
// /// # Arguments
// ///
// /// * `team_channel_name` - The name of the new team channel.
// /// * `owner` - The username of the channel owner.
// ///
// /// # Returns
// ///
// /// * `Result<(), ThisProjectError>` - `Ok(())` on success, or a `ThisProjectError`
// ///   describing the error.
// fn create_new_team_channel(team_channel_name: String, owner: String) -> Result<(), ThisProjectError> {
//     debug_log("starting create_new_team_channel()");
//     let team_channels_dir = Path::new("project_graph_data/team_channels");
//     let new_channel_path = team_channels_dir.join(&team_channel_name);

//     // 1. Create Directory Structure (with error handling)
//     fs::create_dir_all(new_channel_path.join("message_posts_browser"))?; // Propagate errors with ?
//     fs::create_dir_all(new_channel_path.join("task_browser"))?; // task browser directory
//     // for i in 1..=3 { // Using numbers
//     //     let col_name = format!("{}_col{}", i, i);
//     //     let col_path = new_channel_path.join("task_browser").join(col_name);
//     //     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel
//     // }
//     let col_name = "1_planning";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

//     let col_name = "2_started";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel

//     let col_name = "3_done";
//     let col_path = new_channel_path.join("task_browser").join(col_name);
//     fs::create_dir_all(&col_path)?; // Create default task browser column directories for new channel


//     // 2. Create and Save 0.toml Metadata (with error handling)
//     let metadata_path = new_channel_path.join("message_posts_browser/0.toml"); // Simplified path
//     let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
//     save_toml_to_file(&metadata, &metadata_path)?; // Use ? for error propagation

//     // Generate collaborator port assignments (simplified):
//     let mut abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();

//     // Add owner to collaborators list and port assignments:
//     // This makes it possible to create CoreNode and ensures the owner has port assignments
//     let mut collaborators = Vec::new();
//     collaborators.push(owner.clone());
//     debug_log!(
//         "create_new_team_channel(): owner 'added' to collaborators {:?}",
//         collaborators,
//         );

//     // let mut rng = rand::rng(); // Move RNG outside the loop for fewer calls

//     // Load the owner's data
//     // let owner_data = read_one_collaborator_addressbook_toml(&owner)?;

//     // Simplified port generation (move rng outside loop):
//     // Assign random ports to owner:  Only owner for new channel.
//     let mut rng = rand::rng(); // Move RNG instantiation outside the loop
//     let ready_port = rng.random_range(40000..60000) as u16; // Adjust range if needed
//     let tray_port = rng.random_range(40000..60000) as u16; // Random u16 port number
//     let gotit_port = rng.random_range(40000..60000) as u16; // Random u16 port number
//     let abstract_ports_data = AbstractTeamchannelNodeTomlPortsData {
//         user_name: owner.clone(),
//         ready_port,
//         intray_port: tray_port,
//         gotit_port,
//     };
//     debug_log!(
//         "create_new_team_channel(): owner's abstract_ports_data created {:?}",
//         abstract_ports_data
//         );

//     // Store in the HashMap with "owner_owner" key. If more than one user this key can become unique.
//     // abstract_collaborator_port_assignments.insert(
//     //     format!("{}_{}", owner.clone(), owner), // Key derived from collaborator names
//     //     vec![ReadTeamchannelCollaboratorPortsToml { collaborator_ports: vec![abstract_ports_data] }],
//     // );
//     // debug_log!("create_new_team_channel(): owner 'added' to abstract_collaborator_port_assignments");

//     // // // Project State
//     // let agenda_process = get_agenda_process()?;
//     // let features = get_features_and_goals()?;
//     // let scope = get_project_scope()?;
//     // let schedule = get_schedule_info()?;

//     // Store in the HashMap with "owner_owner" key. If more than one user this key can become unique.
//     abstract_collaborator_port_assignments.insert(
//         format!("{}_{}", owner.clone(), owner), // Key derived from collaborator names
//         vec![ReadTeamchannelCollaboratorPortsToml { collaborator_ports: vec![abstract_ports_data] }],
//     );
//     debug_log!("create_new_team_channel(): owner 'added' to abstract_collaborator_port_assignments");

//     /*
//     here here
//     Todo: likely needling to make a new toml reading function
//     to facilitate reading these types of fields.
//     also...new fields 12 fields now?
//     */

//     // Add debug logs for Project State retrieval
//     // Project Areas
//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pa1_process");
//     let pa1_process = q_and_a_get_pa1_process()?;
//     debug_log!("create_new_team_channel(): Got q_and_a_get_pa1_process");

//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pa2_schedule");
//     let pa2_schedule = q_and_a_get_pa2_schedule()?;
//     debug_log!("create_new_team_channel(): Got q_and_a_get_pa2_schedule");

//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pa3_users");
//     let pa3_users = q_and_a_get_pa3_users()?;
//     debug_log!("create_new_team_channel(): Got q_and_a_get_pa3_users");

//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pa4_features");
//     let pa4_features = q_and_a_get_pa4_features()?;
//     debug_log!("create_new_team_channel(): Got project_scope");

//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pa5_mvp");
//     let pa5_mvp = q_and_a_get_pa5_mvp()?;
//     debug_log!("create_new_team_channel(): Got q_and_a_get_pa5_mvp");

//     debug_log!("create_new_team_channel(): About to get q_and_a_get_pf6");
//     let pa6_feedback = q_and_a_get_pa6_feedback()?;
//     debug_log!("create_new_team_channel(): Got q_and_a_get_pa6_feedback");

//     debug_log!("create_new_team_channel(): About to create CoreNode");

//     // 3. Create and Save CoreNode (handling Result)
//     // node.toml file should be created after the directory structure is in place
//     // This is done during first-time initialization so there should be salt list for the owner user (if not exit!)
//     debug_log("create_new_team_channel(): Next is let new_node_result = CoreNode::new");


//     // let new_node_result = CoreNode::new(
//     //     team_channel_name.clone(),         // node_name
//     //     team_channel_name,                 // description_for_tui
//     //     new_channel_path.clone(),          // directory_path
//     //     owner,                             // owner
//     //     collaborators,                     // teamchannel_collaborators_with_access
//     //     abstract_collaborator_port_assignments, // ports
//     //     // project state task items
//     //     agenda_process,                    // new field: agenda process
//     //     features,                          // new field: features and goals
//     //     scope,                             // new field: project scope
//     //     schedule,                          // new field: schedule
//     // );


//     // 3. Create and Save CoreNode (handling Result)
//     let new_node_result = CoreNode::new(
//         team_channel_name.clone(),
//         team_channel_name,
//         new_channel_path.clone(),
//         owner,
//         collaborators,
//         abstract_collaborator_port_assignments,
//         // Project Areas TODO TODO
//         pa1_process,
//         pa2_schedule,
//         pa3_users,
//         pa4_features,
//         pa5_mvp,
//         pa6_feedback,
//         // agenda_process,
//         // features,
//         // scope,
//         // schedule,
//     );

//     debug_log!(
//         "create_new_team_channel(): next trying save_node_to_clearsigned_file with new_node_result -> {:?}",
//         new_node_result);

//     // Handle the result
//     match new_node_result {
//         Ok(new_node) => {
//             debug_log!("CoreNode created successfully, attempting to save...");
//             new_node.save_node_to_clearsigned_file().map_err(|e| ThisProjectError::IoError(e))?;
//             debug_log!("Node saved successfully");
//             Ok(())
//         }
//         Err(e) => {
//             debug_log!("Error creating CoreNode: {}", e);
//             Err(e)
//         }
//     }




//     // match new_node_result {  // Handle result of CoreNode::new
//     //     Ok(new_node) => {
//     //         new_node.save_node_to_clearsigned_file()?; // Then save the node
//     //         Ok(()) // Return Ok(()) to indicate success
//     //     }
//     //     Err(e) => {
//     //          debug_log!("Error creating CoreNode: {}", e);
//     //         Err(e) // Return the error if CoreNode creation fails
//     //     }
//     // }

// }



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
//     fs::create_dir_all(&node_path.join("message_posts_browser"))?;
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
//     let metadata_path = node_path.join("message_posts_browser/0.toml");
//     let metadata = NodeInstMsgBrowserMetadata::new(&team_channel_name, owner.clone());
//     save_toml_to_file(&metadata, &metadata_path)?;

//     // empty array
//     let abstract_collaborator_port_assignments: HashMap<String, Vec<ReadTeamchannelCollaboratorPortsToml>> = HashMap::new();

//     // Load the owner's data
//     let owner_data = read_one_collaborator_addressbook_toml(&owner)?;

//     let mut rng = rand::rng();

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
//             new_node.save_node_to_clearsigned_file()?;
//             Ok(())
//         }
//         Err(e) => {
//             debug_log!("Error creating CoreNode: {}", e);
//             Err(e)
//         }
//     }
// }



// // use std::io::{self, Write};
// // use std::time::{SystemTime, UNIX_EPOCH};

// /// Gets schedule information and converts to required format for create_core_node()
// ///
// /// This function provides two options for setting the project start time:
// /// - Use current UTC time ("now")
// /// - Enter a custom date
// ///
// /// After determining the start time, it prompts for project duration and calculates
// /// the end timestamp.
// ///
// /// # Returns
// /// * `Ok(Vec<u64>)` - Vector containing [start_timestamp, end_timestamp, duration_seconds]
// /// * `Err(ThisProjectError)` - If input/output operations fail or validation fails
// ///
// /// # Example Flow
// /// ```text
// /// Would you like to use current UTC time as your project's start time? (y/n): y
// /// Current UTC time selected: 2024-01-15 14:30:45
// ///
// /// Project Schedule: Enter project duration in days: 14
// ///
// /// Project Schedule Summary:
// ///   Start: 2024-01-15 14:30:45 UTC
// ///   End: 2024-01-29 14:30:45 UTC
// ///   Duration: 14 days (1209600 seconds)
// /// ```
// fn q_and_a_get_pa2_schedule() -> Result<Vec<u64>, ThisProjectError> {
//     debug_log("starting q_and_a_get_pa2_schedule()");

//     // Ask if user wants to use current time as start
//     println!("'Now'? -> Use current UTC time as project's start time? (y)es / (n)o");
//     print!("> ");

//     // Ensure prompt is displayed before reading input
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut use_now_input = String::new();
//     io::stdin().read_line(&mut use_now_input).map_err(|e| ThisProjectError::IoError(e))?;

//     let use_now = match use_now_input.trim().to_lowercase().as_str() {
//         "y" | "yes" | "now" => true,
//         "n" | "no" | "" => false,
//         _ => {
//             return Err(ThisProjectError::InvalidInput(
//                 "Please enter 'y' for yes or 'n' for no".into()
//             ));
//         }
//     };

//     // Get start timestamp based on user choice
//     let start_timestamp: u64 = if use_now {
//         // Use current UTC time
//         let now = SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .map_err(|e| {
//                 ThisProjectError::InvalidData(format!("System time error: {}", e))
//             })?;

//         let timestamp = now.as_secs();

//         // Display the current time for confirmation
//         let (year, month, day, hour, minute, second) = timestamp_to_utc_components(timestamp as i64);
//         println!("\nCurrent UTC time selected: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
//             year, month, day, hour, minute, second);

//         debug_log!("Using current UTC timestamp: {}", timestamp);
//         timestamp
//     } else {
//         // Get custom start date from user
//         println!("\nEnter project start date:");

//         // Year input and validation
//         println!("Enter start year (YYYY):");
//         print!("> ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut year = String::new();
//         io::stdin().read_line(&mut year).map_err(|e| ThisProjectError::IoError(e))?;
//         let year: i32 = year.trim().parse().map_err(|_|
//             ThisProjectError::InvalidInput("Invalid year".into()))?;
//         debug_log!("Parsed year: {}", year);

//         // Get current year for validation
//         let current_timestamp = SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .map_err(|e| {
//                 ThisProjectError::InvalidData(format!("System time error: {}", e))
//             })?
//             .as_secs() as i64;
//         let (current_year, _, _, _, _, _) = timestamp_to_utc_components(current_timestamp);

//         if year < current_year || year > 2100 {
//             return Err(ThisProjectError::InvalidInput(
//                 format!("Year must be between {} and 2100", current_year)
//             ));
//         }

//         // Month input and validation
//         println!("Enter start month (1-12):");
//         print!("> ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut month = String::new();
//         io::stdin().read_line(&mut month).map_err(|e| ThisProjectError::IoError(e))?;
//         let month: u32 = month.trim().parse().map_err(|_|
//             ThisProjectError::InvalidInput("Invalid month".into()))?;
//         debug_log!("Parsed month: {}", month);

//         if month < 1 || month > 12 {
//             return Err(ThisProjectError::InvalidInput("Month must be between 1 and 12".into()));
//         }

//         // Day input and validation with proper month checking
//         let max_day = get_days_in_month(year, month);
//         println!("Enter start day (1-{}):", max_day);
//         print!("> ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut day = String::new();
//         io::stdin().read_line(&mut day).map_err(|e| ThisProjectError::IoError(e))?;
//         let day: u32 = day.trim().parse().map_err(|_|
//             ThisProjectError::InvalidInput("Invalid day".into()))?;
//         debug_log!("Parsed day: {}", day);

//         if day < 1 || day > max_day {
//             return Err(ThisProjectError::InvalidInput(
//                 format!("Day must be between 1 and {} for {}/{}", max_day, year, month)
//             ));
//         }

//         // Optional: Ask for time or default to 00:00:00
//         println!("Enter start time? (y/n, default is 00:00:00 UTC):");
//         print!("> ");
//         io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//         let mut time_choice = String::new();
//         io::stdin().read_line(&mut time_choice).map_err(|e| ThisProjectError::IoError(e))?;

//         let (hour, minute) = if time_choice.trim().to_lowercase() == "y" {
//             // Get hour
//             println!("Enter hour (0-23):");
//             print!("> ");
//             io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//             let mut hour_input = String::new();
//             io::stdin().read_line(&mut hour_input).map_err(|e| ThisProjectError::IoError(e))?;
//             let hour: u32 = hour_input.trim().parse().map_err(|_|
//                 ThisProjectError::InvalidInput("Invalid hour".into()))?;

//             if hour > 23 {
//                 return Err(ThisProjectError::InvalidInput("Hour must be between 0 and 23".into()));
//             }

//             // Get minute
//             println!("Enter minute (0-59):");
//             print!("> ");
//             io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//             let mut minute_input = String::new();
//             io::stdin().read_line(&mut minute_input).map_err(|e| ThisProjectError::IoError(e))?;
//             let minute: u32 = minute_input.trim().parse().map_err(|_|
//                 ThisProjectError::InvalidInput("Invalid minute".into()))?;

//             if minute > 59 {
//                 return Err(ThisProjectError::InvalidInput("Minute must be between 0 and 59".into()));
//             }

//             (hour, minute)
//         } else {
//             (0, 0) // Default to midnight
//         };

//         // Use the accurate timestamp conversion function
//         let timestamp = utc_components_to_timestamp(year, month, day, hour, minute, 0)?;

//         // Confirm the selected start time
//         println!("\nProject start time: {:04}-{:02}-{:02} {:02}:{:02}:00 UTC",
//             year, month, day, hour, minute);

//         debug_log!("Calculated start timestamp: {}", timestamp);
//         timestamp as u64
//     };

//     // Duration input and validation
//     println!("\nProject Schedule: Enter project duration in days:");
//     print!("> ");
//     io::stdout().flush().map_err(|e| ThisProjectError::IoError(e))?;

//     let mut days = String::new();
//     io::stdin().read_line(&mut days).map_err(|e| ThisProjectError::IoError(e))?;
//     let days: u64 = days.trim().parse().map_err(|_|
//         ThisProjectError::InvalidInput("Invalid number of days".into()))?;
//     debug_log!("Parsed days: {}", days);

//     if days == 0 || days > 3650 { // 10 years max
//         return Err(ThisProjectError::InvalidInput("Duration must be between 1 and 3650 days".into()));
//     }

//     // Calculate end timestamp and duration
//     let seconds_per_day: u64 = 24 * 60 * 60;
//     let duration_seconds = days * seconds_per_day;
//     debug_log!("Calculated duration in seconds: {}", duration_seconds);

//     let end_timestamp = start_timestamp + duration_seconds;
//     debug_log!("Calculated end timestamp: {}", end_timestamp);

//     // Display summary
//     let (start_year, start_month, start_day, start_hour, start_minute, start_second) =
//         timestamp_to_utc_components(start_timestamp as i64);
//     let (end_year, end_month, end_day, end_hour, end_minute, end_second) =
//         timestamp_to_utc_components(end_timestamp as i64);

//     println!("\nProject Schedule Summary:");
//     println!("  Start: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
//         start_year, start_month, start_day, start_hour, start_minute, start_second);
//     println!("  End:   {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
//         end_year, end_month, end_day, end_hour, end_minute, end_second);
//     println!("  Duration: {} days ({} seconds)", days, duration_seconds);

//     // Final validation
//     if end_timestamp < start_timestamp {
//         return Err(ThisProjectError::InvalidInput("End time cannot be before start time".into()));
//     }

//     let result = vec![
//         start_timestamp,
//         end_timestamp,
//         duration_seconds
//     ];
//     debug_log!("Returning schedule info: {:?}", result);

//     Ok(result)
// }

// /// Gets schedule information and converts
// /// start_timestamp,
// /// end_timestamp,
// /// duration_seconds
// /// to required format of create_core_node()
// fn q_and_a_get_pa2_schedule() -> Result<Vec<u64>, ThisProjectError> {
//     debug_log("starting q_and_a_get_pa2_schedule()");

//     // Duration input and validation
//     println!("Project Schedule: Enter project duration in days:");
//     let mut days = String::new();
//     io::stdin().read_line(&mut days)?;
//     let days: u64 = days.trim().parse().map_err(|_|
//         ThisProjectError::InvalidInput("Invalid number of days".into()))?;
//     debug_log!("Parsed days: {}", days);

//     if days == 0 || days > 3650 { // 10 years max
//         return Err(ThisProjectError::InvalidInput("Duration must be between 1 and 3650 days".into()));
//     }

//     // Year input and validation
//     println!("Enter start year (YYYY):");
//     let mut year = String::new();
//     io::stdin().read_line(&mut year)?;
//     let year: u64 = year.trim().parse().map_err(|_|
//         ThisProjectError::InvalidInput("Invalid year".into()))?;
//     debug_log!("Parsed year: {}", year);

//     if year < 2023 || year > 2100 {
//         return Err(ThisProjectError::InvalidInput("Year must be between 2023 and 2100".into()));
//     }

//     // Month input and validation
//     println!("Enter start month (1-12):");
//     let mut month = String::new();
//     io::stdin().read_line(&mut month)?;
//     let month: u64 = month.trim().parse().map_err(|_|
//         ThisProjectError::InvalidInput("Invalid month".into()))?;
//     debug_log!("Parsed month: {}", month);

//     if month < 1 || month > 12 {
//         return Err(ThisProjectError::InvalidInput("Month must be between 1 and 12".into()));
//     }

//     // Day input and validation
//     println!("Enter start day (1-31):");
//     let mut day = String::new();
//     io::stdin().read_line(&mut day)?;
//     let day: u64 = day.trim().parse().map_err(|_|
//         ThisProjectError::InvalidInput("Invalid day".into()))?;
//     debug_log!("Parsed day: {}", day);

//     if day < 1 || day > 31 {
//         return Err(ThisProjectError::InvalidInput("Day must be between 1 and 31".into()));
//     }

//     // Time calculations
//     let seconds_per_day: u64 = 24 * 60 * 60;
//     let days_since_epoch = (year - 1970) * 365 + ((month - 1) * 30) + (day - 1);
//     debug_log!("Calculated days since epoch: {}", days_since_epoch);

//     let start_timestamp = days_since_epoch * seconds_per_day;
//     debug_log!("Calculated start timestamp: {}", start_timestamp);

//     let duration_seconds = days * seconds_per_day;
//     debug_log!("Calculated duration in seconds: {}", duration_seconds);

//     let end_timestamp = start_timestamp + duration_seconds;
//     debug_log!("Calculated end timestamp: {}", end_timestamp);

//     // Final validation
//     if end_timestamp < start_timestamp {
//         return Err(ThisProjectError::InvalidInput("End time cannot be before start time".into()));
//     }

//     let result = vec![
//         start_timestamp,
//         end_timestamp,
//         duration_seconds
//     ];
//     debug_log!("Returning schedule info: {:?}", result);

//     Ok(result)
// }






// /// Gets user input for message post integer-string validation ranges
// ///
// /// # Returns
// /// * `Result<Option<Vec<(i32, i32)>>, ThisProjectError>` - Vector of integer range tuples for int-string pairs or None
// fn q_and_a_get_message_post_int_string_ranges() -> Result<Option<Vec<(i32, i32)>>, ThisProjectError> {

//     println!("Integer:Write-In choices, if applicable:");
//     println!("For write-in answers/choices for Message-Posts, such as the third part of this form: 1. mustard-yellow  2. pink 3. write in your choice of colour");
//     println!("Or the third AND fourth parts of this form: 1. blue  2. yellow  3. write in: your choice of colour  4. write in: exceptional reason to avoid colour");
//     println!("Here the user enters BOTH an integer AND (after a colon) their write-in character-string -> integer:string -> 3:lilac");
//     println!("As with integer-only above, these can be single, continuous ranges, or (lists) discontinuous options (ranges or singles)");
//     println!("If applicable, enter integer ranges for integer-string pair options (format: min1-max1,min2-max2,... or press Enter to skip):");
//     println!("Example: 2-2,5-10");

//     let mut input = String::new();
//     io::stdout().flush()?;
//     io::stdin().read_line(&mut input)?;

//     let input = input.trim();
//     if input.is_empty() {
//         return Ok(None);
//     }

//     // Parse the ranges (same logic as integer ranges)
//     let mut ranges = Vec::new();
//     for range_str in input.split(',') {
//         let parts: Vec<&str> = range_str.trim().split('-').collect();
//         if parts.len() != 2 {
//             return Err(ThisProjectError::InvalidInput(format!("Invalid range format: {}", range_str)));
//         }

//         let min = parts[0].parse::<i32>()
//             .map_err(|_| ThisProjectError::InvalidInput(format!("Invalid minimum value: {}", parts[0])))?;
//         let max = parts[1].parse::<i32>()
//             .map_err(|_| ThisProjectError::InvalidInput(format!("Invalid maximum value: {}", parts[1])))?;

//         if min > max {
//             return Err(ThisProjectError::InvalidInput(format!("Minimum {} is greater than maximum {}", min, max)));
//         }

//         ranges.push((min, max));
//     }

//     Ok(Some(ranges))
// }



// /// Gets user input for message post start date
// ///
// /// # Returns
// /// * `Result<Option<i64>, ThisProjectError>` - Start date as UTC POSIX timestamp or None
// fn q_and_a_get_message_post_start_date() -> Result<Option<i64>, ThisProjectError> {
//     println!("Enter start date for accepting posts (format: YYYY-MM-DD HH:MM:SS or press Enter to skip):");
//     println!("Example: 2024-01-01 00:00:00");

//     let mut input = String::new();
//     io::stdout().flush()?;
//     io::stdin().read_line(&mut input)?;

//     let input = input.trim();
//     if input.is_empty() {
//         return Ok(None);
//     }

//     // Parse the date string into a timestamp
//     // This is a simplified example - you might want to use a proper date parsing library
//     // For now, let's accept a Unix timestamp directly
//     println!("For now, please enter a Unix timestamp (seconds since 1970-01-01):");
//     let mut timestamp_input = String::new();
//     io::stdin().read_line(&mut timestamp_input)?;

//     let timestamp = timestamp_input.trim().parse::<i64>()
//         .map_err(|_| ThisProjectError::InvalidInput(format!("Invalid timestamp: {}", timestamp_input.trim())))?;

//     Ok(Some(timestamp))
// }

// WRONG!!!! THIS USES TOML CRATE!!!!
// /// Vanilla-Rust File Deserialization
// /// Toml Deserialization: Reads collaborator setup data from TOML files in a specified directory.
// ///
// /// # Requires:
// /// the toml crate (use a current version)
// ///
// /// [dependencies]
// /// toml = "0.8"
// ///
// /// # Terms:
// /// Serialization: The process of converting a data structure (like your CollaboratorTomlData struct) into a textual representation (like a TOML file).
// ///
// /// Deserialization: The process of converting a textual representation (like a TOML file) into a data structure (like your CollaboratorTomlData struct).
// ///
// /// This function reads and parses TOML files located in the directory
// /// `COLLABORATOR_ADDRESSBOOK_PATH_STR`. Each file is expected to
// /// contain data for a single collaborator in a structure that can be mapped to
// /// the `CollaboratorTomlData` struct.
// ///
// /// # No `serde` Crate
// ///
// /// This function implements TOML parsing *without* using the `serde` crate.
// /// It manually extracts values from the TOML data using the `toml` crate's
// /// `Value` enum and pattern matching.
// ///
// /// This approach is taken to avoid the dependency on the `serde` crate
// /// while still providing a way to parse TOML files.
// ///
// /// # Data Extraction
// ///
// /// The function extracts the following fields from one TOML file:
// ///
// /// - `user_name` (String)
// /// - `user_salt_list` (Vec<u128>): Stored as hexadecimal strings in the TOML file.
// /// - `ipv4_addresses` (Option<Vec<Ipv4Addr>>): Stored as strings in the TOML file.
// /// - `ipv6_addresses` (Option<Vec<Ipv6Addr>>): Stored as strings in the TOML file.
// /// - `gpg_key_public` (String)
// /// - `sync_interval` (u64)
// /// - `updated_at_timestamp` (u64)
// ///
// /// # Helper Functions
// ///
// /// The following helper functions are used to extract and parse specific data types:
// ///
// /// - `extract_ipv4_addresses`: Parses a string array into `Option<Vec<Ipv4Addr>>`.
// /// - `extract_ipv6_addresses`: Parses a string array into `Option<Vec<Ipv6Addr>>`.
// /// - `extract_u64`: Parses a TOML integer into a `u64` value, handling potential errors.
// ///
// /// Reads collaborator setup data from a TOML file for a specific user.
// ///
// /// This function reads and parses a TOML file located at
// /// `COLLABORATOR_ADDRESSBOOK_PATH_STR/{collaborator_name}__collaborator.toml`.
// /// The file is expected to contain data for a single collaborator in a structure that
// /// can be mapped to the `CollaboratorTomlData` struct.
// ///
// /// # Error Handling
// ///
// /// This function uses a centralized error handling approach. If any error occurs during:
// ///
// /// - File reading (e.g., file not found)
// /// - TOML parsing (e.g., invalid TOML syntax)
// /// - Data extraction (e.g., missing required fields, invalid data formats)
// ///
// /// The function will immediately return an `Err` containing a `ThisProjectError` that describes the error.
// ///
// /// This approach simplifies error propagation and allows for early exit on error.
// /// If any part of the parsing or data extraction process fails, the function will stop
// /// and return the error without attempting to process the rest of the file.
// ///
// /// # Example
// ///
// /// ```
// /// let collaborator_data = read_one_collaborator_addressbook_toml("alice");
// ///
// /// match collaborator_data {
// ///     Ok(data) => { /* ... process the collaborator data */ },
// ///     Err(e) => { /* ... handle the error */ },
// /// }
// /// ```
// ///
// /// # Example TOML File
// ///
// /// ```toml
// /// user_name = "Alice"
// /// user_salt_list = ["0x11111111111111111111111111111111", "0x11111111111111111111111111111112"]
// /// ipv4_addresses = ["192.168.1.1", "10.0.0.1"]
// /// ipv6_addresses = ["fe80::1", "::1"]
// /// gpg_key_public = """-----BEGIN PGP PUBLIC KEY BLOCK----- ..."""
// /// sync_interval = 60
// /// updated_at_timestamp = 1728307160
// /// ```
// ///
// /// # Returns
// ///
// /// Returns a `Result` containing:
// /// - `Ok`: A tuple with:
// ///     - A vector of successfully parsed `CollaboratorTomlData` instances.
// ///     - A vector of any `ThisProjectError` encountered during parsing.
// /// - `Err`: A `ThisProjectError` if there was an error reading the directory or any file.
// ///
// /// This was developed for the UMA project, as the naming reflects:
// /// https://github.com/lineality/uma_productivity_collaboration_tool
// ///
// /// # Use with:
// /// // Specify the username of the collaborator to read
// /// let username = "alice";
// ///
// /// /// Read the collaborator data from the TOML file
// /// match read_one_collaborator_addressbook_toml(username) {
// ///     Ok(collaborator) => {
// ///         // Print the collaborator data
// ///         println!("Collaborator Data for {}:", username);
// ///         println!("{:#?}", collaborator); /// Use {:#?} for pretty-printing
// ///     }
// ///     Err(e) => {
// ///         // Print an error message if there was an error reading or parsing the TOML file
// ///         println!("Error reading collaborator data for {}: {}", username, e);
// ///     }
// /// }
// fn read_one_collaborator_addressbook_toml(collaborator_name: &str) -> Result<CollaboratorTomlData, ThisProjectError> {
//     debug_log("Starting ROCST: read_one_collaborator_addressbook_toml()");

//     // 1. Construct File Path
//     let relative_file_path = Path::new(COLLABORATOR_ADDRESSBOOK_PATH_STR)
//         .join(format!("{}__collaborator.toml", collaborator_name));

//     // Get the executable-relative base directory path
//     let abs_file_path = match make_input_path_name_abs_executabledirectoryrelative_nocheck(
//         relative_file_path
//     ) {
//         Ok(path) => path,
//         Err(e) => {
//             debug_log!("ROCST: Failed to resolve collaborator directory path: {}", e);
//             return Err(ThisProjectError::IoError(e));
//         }
//     };

//     debug_log!("ROCST: read_one_collaborator_addressbook_toml(), abs_file_path (executable-relative) -> {:?}", abs_file_path);

//     // 2. Read TOML File
//     let toml_string = fs::read_to_string(&abs_file_path)?;

//     // 3. Parse TOML Data
//     let toml_value = match toml::from_str::<Value>(&toml_string) {
//         Ok(value) => value,
//         Err(e) => return Err(ThisProjectError::TomlVanillaDeserialStrError(e.to_string())),
//     };

//     // 4. Extract Data from TOML Value (similar to your previous code)
//     if let Value::Table(table) = toml_value {

//         // Extract user_name
//         let user_name = if let Some(Value::String(s)) = table.get("user_name") {
//             s.clone()
//         } else {
//             return Err(ThisProjectError::TomlVanillaDeserialStrError("ROCST: Missing user_name".into()));
//         };

//         // Extract user_salt_list
//         let user_salt_list = if let Some(Value::Array(arr)) = table.get("user_salt_list") {
//             arr.iter()
//                 .map(|val| {
//                     if let Value::String(s) = val {
//                         u128::from_str_radix(s.trim_start_matches("0x"), 16)
//                             .map_err(|e| ThisProjectError::ParseIntError(e))
//                     } else {
//                         Err(ThisProjectError::TomlVanillaDeserialStrError("ROCST: Invalid salt format: Expected string".into()))
//                     }
//                 })
//                 .collect::<Result<Vec<u128>, ThisProjectError>>()?
//         } else {
//             return Err(ThisProjectError::TomlVanillaDeserialStrError("ROCST: Missing user_salt_list".into()));
//         };

//         // Extract ipv4_addresses
//         let ipv4_addresses = extract_ipv4_addresses(&table, "ipv4_addresses")?;

//         // Extract ipv6_addresses
//         let ipv6_addresses = extract_ipv6_addresses(&table, "ipv6_addresses")?;

//         // Extract gpg_publickey_id
//         let gpg_publickey_id = if let Some(Value::String(s)) = table.get("gpg_publickey_id") {
//             s.clone()
//         } else {
//             return Err(ThisProjectError::TomlVanillaDeserialStrError("ROCST: Missing or invalid gpg_publickey_id".into()));
//         };

//         // Extract gpg_key_public
//         let gpg_key_public = if let Some(Value::String(s)) = table.get("gpg_key_public") {
//             s.clone()
//         } else {
//             return Err(ThisProjectError::TomlVanillaDeserialStrError("Missing or invalid gpg_key_public".into()));
//         };

//         // Extract sync_interval
//         let sync_interval = extract_u64(&table, "sync_interval")?;

//         // Extract updated_at_timestamp
//         let updated_at_timestamp = extract_u64(&table, "updated_at_timestamp")?;

//         // 5. Return CollaboratorTomlData
//         Ok(CollaboratorTomlData {
//             user_name,
//             user_salt_list,
//             ipv4_addresses,
//             ipv6_addresses,
//             gpg_publickey_id,
//             gpg_key_public,
//             sync_interval,
//             updated_at_timestamp,
//         })
//     } else {
//         Err(ThisProjectError::TomlVanillaDeserialStrError("Invalid TOML structure: Expected a table".into()))
//     }
// }






// /// Reads IP addresses from a collaborator's TOML file.
// ///
// /// # Purpose
// /// This function securely retrieves IPv4 and IPv6 addresses from a collaborator's
// /// configuration file. It ensures paths are correctly resolved relative to the
// /// executable's location and handles both regular and clearsigned TOML files.
// ///
// /// # Process
// /// 1. Constructs an absolute path to the collaborator file based on the executable's location
// /// 2. Reads IP address arrays from the TOML file
// /// 3. Parses string values into typed IP address objects
// /// 4. Returns structured collections of IPv4 and IPv6 addresses
// ///
// /// # Arguments
// /// * `owner` - Name of the collaborator (used to construct the filename)
// /// * `use_clearsign` - Whether to use clearsigned verification (true) or plain TOML reading (false)
// ///
// /// # Returns
// /// * `Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), String>` - A tuple containing:
// ///   - Vector of IPv4 addresses
// ///   - Vector of IPv6 addresses
// ///   Or an error message if any step fails
// ///
// /// # Example
// /// ```
// /// match get_collaborator_ip_addresses("alice", true) {
// ///     Ok((ipv4_addrs, ipv6_addrs)) => {
// ///         println!("IPv4 addresses: {:?}", ipv4_addrs);
// ///         println!("IPv6 addresses: {:?}", ipv6_addrs);
// ///     },
// ///     Err(e) => eprintln!("Error: {}", e)
// /// }
// /// ```
// pub fn get_collaborator_ip_addresses(
//     owner: &str,
//     use_clearsign: bool
// ) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), String> {
//     // Step 1: Construct the relative path to the collaborator file
//     let relative_path = format!(
//         "project_graph_data/collaborator_files_address_book/{}__collaborator.toml",
//         owner
//     );

//     // Step 2: Convert to an absolute path based on executable location
//     let absolute_path = gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck(&relative_path)
//         .map_err(|e| format!("Failed to resolve path for collaborator '{}': {}", owner, e))?
//         .to_string_lossy()
//         .to_string();

//     // Step 3: Read the IPv4 and IPv6 address arrays from the TOML file
//     let ipv4_strings: Vec<String>;
//     let ipv6_strings: Vec<String>;

//     if use_clearsign {
//         // Read from clearsigned TOML file
//         ipv4_strings = match read_str_array_field_clearsigntoml(&absolute_path, "ipv4_addresses") {
//             Ok(addresses) => addresses,
//             Err(e) => {
//                 println!("Warning: Could not read IPv4 addresses from clearsigned file: {}", e);
//                 Vec::new()
//             }
//         };

//         ipv6_strings = match read_str_array_field_clearsigntoml(&absolute_path, "ipv6_addresses") {
//             Ok(addresses) => addresses,
//             Err(e) => {
//                 println!("Warning: Could not read IPv6 addresses from clearsigned file: {}", e);
//                 Vec::new()
//             }
//         };
//     } else {
//         // Read from regular TOML file
//         ipv4_strings = match read_string_array_field_from_toml(&absolute_path, "ipv4_addresses") {
//             Ok(addresses) => addresses,
//             Err(e) => {
//                 println!("Warning: Could not read IPv4 addresses: {}", e);
//                 Vec::new()
//             }
//         };

//         ipv6_strings = match read_string_array_field_from_toml(&absolute_path, "ipv6_addresses") {
//             Ok(addresses) => addresses,
//             Err(e) => {
//                 println!("Warning: Could not read IPv6 addresses: {}", e);
//                 Vec::new()
//             }
//         };
//     }

//     // Step 4: Parse the string values into IP address types
//     let mut ipv4_addresses = Vec::new();
//     for ip_str in ipv4_strings {
//         match ip_str.parse::<Ipv4Addr>() {
//             Ok(addr) => ipv4_addresses.push(addr),
//             Err(e) => println!("Warning: Invalid IPv4 address '{}': {}", ip_str, e),
//         }
//     }

//     let mut ipv6_addresses = Vec::new();
//     for ip_str in ipv6_strings {
//         match ip_str.parse::<Ipv6Addr>() {
//             Ok(addr) => ipv6_addresses.push(addr),
//             Err(e) => println!("Warning: Invalid IPv6 address '{}': {}", ip_str, e),
//         }
//     }

//     // Step 5: Return the parsed IP addresses
//     Ok((ipv4_addresses, ipv6_addresses))
// }

// /// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
// ///
// /// This function reads the collaborator file for the given `owner` and extracts the
// /// `ipv4_addresses` and `ipv6_addresses` fields. It handles missing fields by returning empty vectors.
// ///
// /// # Arguments
// ///
// /// * `owner`: The username of the local user.
// ///
// /// # Returns
// ///
// /// * `Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError>`: A tuple containing the IPv4 and IPv6 address lists, or a `ThisProjectError` if an error occurs.
// fn load_local_ip_lists_to_ipvec(owner: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError> {

//     /*
//     1. make path to clearsign toml
//     2. read array values... get needed when needed

//     (old code is wrong to:
//         1. use local path
//         2. load the whole file, bad
//         )
//     */
//     let toml_path = format!("project_graph_data/collaborator_files_address_book/{}__collaborator.toml", owner);
//     let toml_string = std::fs::read_to_string(toml_path)?;
//     let toml_value: toml::Value = toml::from_str(&toml_string)?;

//     // Extract IPv4 addresses (handling missing/invalid data):
//     let ipv4_addresses: Vec<Ipv4Addr> = match toml_value.get("ipv4_addresses") {
//         Some(toml::Value::Array(arr)) => arr
//             .iter()
//             .filter_map(|val| val.as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()))
//             .collect(),
//         _ => Vec::new(), // Return empty if no IP list found.
//     };

//     // Extract IPv6 addresses:
//     let ipv6_addresses: Vec<Ipv6Addr> = match toml_value.get("ipv6_addresses") {
//         Some(toml::Value::Array(arr)) => arr
//             .iter()
//             .filter_map(|val| val.as_str().and_then(|s| s.parse::<Ipv6Addr>().ok()))
//             .collect(),
//         _ => Vec::new(), // Return empty on error.
//     };

//     Ok((ipv4_addresses, ipv6_addresses))
// }




// /// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
// ///
// /// This function reads the collaborator file for the given `owner` and extracts the
// /// `ipv4_addresses` and `ipv6_addresses` fields as strings. It ensures security by requiring
// /// clearsigned validation of the TOML file.
// ///
// /// # Security
// /// - REQUIRES cryptographically verified clearsigned TOML files
// /// - Will REJECT files that fail signature verification
// /// - Maintains the integrity of configuration data
// ///
// /// # Arguments
// /// * `owner`: The username of the local user.
// ///
// /// # Returns
// /// * `Result<(Vec<String>, Vec<String>), ThisProjectError>`: A tuple containing the IPv4 and IPv6
// ///   address lists as strings, or a `ThisProjectError` if an error occurs.
// fn load_local_iplists_as_stringtype(
//     owner: &str,
//     full_fingerprint_key_id_string: &str,
//     ) -> Result<(Vec<String>, Vec<String>), ThisProjectError> {

//     /*
//     adding .gpgtoml here:

//     check for .gpgtoml


//     // first check:
//     "project_graph_data/collaborator_files_address_book/{}__collaborator.gpgtoml";


//     */
//     // Construct the relative path to the collaborator file
//     let gpgrelative_path = format!(
//         "{}/{}__collaborator.gpgtoml",
//         COLLABORATOR_ADDRESSBOOK_PATH_STR,
//         owner,
//     );



//     // Convert to an absolute path based on executable location
//     let gpgabsolute_path = match gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck(&gpgrelative_path) {
//         Ok(path) => path.to_string_lossy().to_string(),
//         Err(e) => {
//             return Err(ThisProjectError::IoError(
//                 std::io::Error::new(
//                     std::io::ErrorKind::NotFound,
//                     format!("Failed to resolve path for collaborator '{}': {}", owner, e)
//                 )
//             ));
//         }
//     };

//     // Check if the file exists
//     if !std::path::Path::new(&gpgabsolute_path).exists() {
//         return Err(ThisProjectError::IoError(
//             std::io::Error::new(
//                 std::io::ErrorKind::NotFound,
//                 format!("Collaborator file for '{}' not found at: {}", owner, gpgabsolute_path)
//             )
//         ));
//     }

//     /*
//     first try .gpgtoml, if that does not work, default to .toml

//     1. is .gpgtoml there?
//     2. use parameter full_fingerprint_key_id_string
//     2. extract result to temp dir
//     3. pass path of clearsign-toml to next step

//     gpg decript ... passphrase?
//     maybe into a path to an extracted file
//     run on that extracted file then
//     delete temp extracted file

//     */

//     // Read IP addresses as strings from the clearsigned TOML file
//     // We use our secure verification function that will fail if verification fails
//     let ipv4_addresses = match read_str_array_field_clearsigntoml(&absolute_path, "ipv4_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv4 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };

//     let ipv6_addresses = match read_str_array_field_clearsigntoml(&absolute_path, "ipv6_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv6 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };





//     /*
//     if that doesn't work, do this:
//     */

//     // Construct the relative path to the collaborator file
//     let relative_path = format!(
//         "{}/{}__collaborator.toml",
//         COLLABORATOR_ADDRESSBOOK_PATH_STR,
//         owner,
//     );



//     // Convert to an absolute path based on executable location
//     let absolute_path = match gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck(&relative_path) {
//         Ok(path) => path.to_string_lossy().to_string(),
//         Err(e) => {
//             return Err(ThisProjectError::IoError(
//                 std::io::Error::new(
//                     std::io::ErrorKind::NotFound,
//                     format!("Failed to resolve path for collaborator '{}': {}", owner, e)
//                 )
//             ));
//         }
//     };

//     // Check if the file exists
//     if !std::path::Path::new(&absolute_path).exists() {
//         return Err(ThisProjectError::IoError(
//             std::io::Error::new(
//                 std::io::ErrorKind::NotFound,
//                 format!("Collaborator file for '{}' not found at: {}", owner, absolute_path)
//             )
//         ));
//     }




//     // Read IP addresses as strings from the clearsigned TOML file
//     // We use our secure verification function that will fail if verification fails
//     let ipv4_addresses = match read_str_array_field_clearsigntoml(&absolute_path, "ipv4_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv4 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };

//     let ipv6_addresses = match read_str_array_field_clearsigntoml(&absolute_path, "ipv6_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv6 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };

//     // Return the string representations of the IP addresses directly
//     // No need to parse them into IP address types since we want strings
//     Ok((ipv4_addresses, ipv6_addresses))
// }



// /// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
// ///
// /// This function reads the collaborator file for the given `owner` and extracts the
// /// `ipv4_addresses` and `ipv6_addresses` fields. It handles missing fields by returning empty vectors.
// ///
// /// # Arguments
// ///
// /// * `owner`: The username of the local user.
// ///
// /// # Returns
// ///
// /// * `Result<(Vec<String>, Vec<String>), ThisProjectError>`: A tuple containing the IPv4 and IPv6 address lists as strings, or a `ThisProjectError` if an error occurs.
// fn load_local_iplists_as_stringtype(owner: &str) -> Result<(Vec<String>, Vec<String>), ThisProjectError> {
//     let toml_path = format!("project_graph_data/collaborator_files_address_book/{}__collaborator.toml", owner);
//     let toml_string = std::fs::read_to_string(toml_path)?;
//     let toml_value: toml::Value = toml::from_str(&toml_string)?;

//     // Extract IPv4 addresses (handling missing/invalid data):
//     let ipv4_addresses: Vec<String> = match toml_value.get("ipv4_addresses") {
//         Some(toml::Value::Array(arr)) => arr
//             .iter()
//             .filter_map(|val| val.as_str().map(|s| s.to_string()))
//             .collect(),
//         _ => Vec::new(), // Return empty if no IP list found.
//     };

//     // Extract IPv6 addresses:
//     let ipv6_addresses: Vec<String> = match toml_value.get("ipv6_addresses") {
//         Some(toml::Value::Array(arr)) => arr
//             .iter()
//             .filter_map(|val| val.as_str().map(|s| s.to_string()))
//             .collect(),
//         _ => Vec::new(), // Return empty on error.
//     };

//     Ok((ipv4_addresses, ipv6_addresses))
// }

// /// Loads the local user's IPv4 and IPv6 addresses from their collaborator TOML file.
// ///
// /// This function reads the collaborator file for the given `owner` and extracts the
// /// `ipv4_addresses` and `ipv6_addresses` fields. It ensures security by requiring
// /// clearsigned validation of the TOML file.
// ///
// /// # Security
// /// - REQUIRES cryptographically verified clearsigned TOML files
// /// - Will REJECT files that fail signature verification
// /// - Will NOT fall back to reading unsigned files
// ///
// /// # Arguments
// /// * `owner`: The username of the local user.
// ///
// /// # Returns
// /// * `Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError>`: A tuple containing the IPv4 and IPv6
// ///   address lists, or a `ThisProjectError` if an error occurs.
// fn load_local_ip_lists_to_ipvec(
//     owner: &str,
//     full_fingerprint_key_id_string: &str,
//     ) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), ThisProjectError> {
//     // Construct the relative path to the collaborator file
//     let relative_path = format!(
//         "{}/{}__collaborator.toml",
//         COLLABORATOR_ADDRESSBOOK_PATH_STR,
//         owner
//     );

//     // Convert to an absolute path based on executable location
//     let absolute_path = match gpg_make_input_path_name_abs_executabledirectoryrelative_nocheck(&relative_path) {
//         Ok(path) => path.to_string_lossy().to_string(),
//         Err(e) => {
//             return Err(ThisProjectError::IoError(
//                 std::io::Error::new(
//                     std::io::ErrorKind::NotFound,
//                     format!("Failed to resolve path for collaborator '{}': {}", owner, e)
//                 )
//             ));
//         }
//     };

//     // Check if the file exists
//     if !std::path::Path::new(&absolute_path).exists() {
//         return Err(ThisProjectError::IoError(
//             std::io::Error::new(
//                 std::io::ErrorKind::NotFound,
//                 format!("Collaborator file for '{}' not found at: {}", owner, absolute_path)
//             )
//         ));
//     }

//     // Read IP addresses from the clearsigned TOML file
//     // This will fail if the file is not clearsigned or fails verification
//     let ipv4_strings = match read_str_array_field_clearsigntoml(&absolute_path, "ipv4_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv4 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };

//     let ipv6_strings = match read_str_array_field_clearsigntoml(&absolute_path, "ipv6_addresses") {
//         Ok(strings) => strings,
//         Err(e) => {
//             return Err(ThisProjectError::GpgError(
//                 format!("Failed to securely read IPv6 addresses from clearsigned file: {}", e)
//             ));
//         }
//     };

//     // Parse the string values into IP address types
//     let mut ipv4_addresses = Vec::new();
//     for ip_str in ipv4_strings {
//         match ip_str.parse::<Ipv4Addr>() {
//             Ok(addr) => ipv4_addresses.push(addr),
//             Err(e) => {
//                 println!("Warning: Invalid IPv4 address '{}': {}", ip_str, e);
//             }
//         }
//     }

//     let mut ipv6_addresses = Vec::new();
//     for ip_str in ipv6_strings {
//         match ip_str.parse::<Ipv6Addr>() {
//             Ok(addr) => ipv6_addresses.push(addr),
//             Err(e) => {
//                 println!("Warning: Invalid IPv6 address '{}': {}", ip_str, e);
//             }
//         }
//     }

//     // Return the collected IP addresses
//     Ok((ipv4_addresses, ipv6_addresses))
// }



   // // 1. Render TUI *before* input:
        // match app.input_mode {
        //     InputMode::MainCommand => tiny_tui::render_list(&app.tui_directory_list, &app.current_path),
        //     InputMode::TaskCommand => app.load_tasks(), // Renders the task table.
        //     InputMode::InsertText => tiny_tui::render_list(&app.tui_textmessage_list, &app.current_path),
        // };

        // let input = tiny_tui::get_input()?;

        // match app.input_mode {
        //     InputMode::MainCommand => {
        //         if handle_command_main_mode(&input, &mut app, &graph_navigation_instance_state)? {
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
        //         } else if handle_command_main_mode(&input, &mut app, &graph_navigation_instance_state)? { // Handle commands like "q"
        //             // Refresh list after leaving task browser (if exiting Uma or team channel)
        //             app.load_tasks(); // Refresh task view.
        //         }
        //     },
        //     InputMode::MainCommand => {
        //         if handle_command_main_mode(&input, &mut app, &graph_navigation_instance_state)? {
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
        //         // app.load_tasks(); // This is already called in handle_command_main_mode("t", ...)
        //         // The table is already rendered within load_tasks, using the new tiny_tui::render_tasks_table
        //          debug_log!("InputMode::TaskCommand. render_tasks_table now used. ");  // Clear the screen

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
            //     // if handle_command_main_mode(&input, &mut app, &mut graph_navigation_instance_state) {
            //     if handle_command_main_mode(&input, &mut app, &mut graph_navigation_instance_state)? {
            //         debug_log("QUIT");
            //         break; // Exit the loop if handle_command_main_mode returns true (e.g., for "q")
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
            //             } else if app.is_in_message_posts_browser_directory() {
            //                 // ... handle other TUI actions ...
            //                 debug_log("else if self.is_in_message_posts_browser_directory()");


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
            //     } else if handle_command_main_mode(&input, &mut app, &graph_navigation_instance_state)? { // Handle other commands, like "q"
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

// // old relative version
// /// set sync_start_ok_flag to true
// /// also use: sync_flag_ok_or_wait(3);
// fn set_sync_start_ok_flag_to_true() {
//     if fs::remove_file(SYNC_START_OK_FLAG_PATH_STR).is_ok() {
//         debug_log("Old 'ok_to_start_sync_flag.txt' file deleted."); // Optional log.
//     }

//     let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH_STR)
//         .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

//     file.write_all(b"1")
//         .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
// }

// // old relative version
// /// initialize sync_start_ok_flag
// /// also use: sync_flag_ok_or_wait(3);
// fn initialize_ok_to_start_sync_flag_to_false() {
//     if fs::remove_file(SYNC_START_OK_FLAG_PATH_STR).is_ok() {
//         debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
//     }

//     let mut file = fs::File::create(SYNC_START_OK_FLAG_PATH_STR)
//         .expect("Failed to create 'ok_to_start_sync_flag.txt' file.");

//     file.write_all(b"0")
//         .expect("Failed to write to 'ok_to_start_sync_flag.txt' file.");
// }


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

// fn update_current_path_and_state(app: &mut App, selected_channel: &str) {
//     app.current_path = app.current_path.join(selected_channel);
//     app.graph_navigation_instance_state.current_full_file_path = app.current_path.clone();
//     app.graph_navigation_instance_state.nav_graph_look_read_node_toml();
//     debug_log!("Updated path and state. New path: {:?}", app.current_path);
// }



// /// set signal to stop whole Uma program with all threads
// fn quit_set_continue_uma_to_false() {
//     if fs::remove_file(CONTINUE_UMA_PATH_STR).is_ok() {
//         debug_log("Old 'continue_uma.txt' file deleted."); // Optional log.
//     }

//     let mut file = fs::File::create(CONTINUE_UMA_PATH_STR)
//         .expect("Failed to create 'continue_uma.txt' file.");

//     file.write_all(b"0")
//         .expect("Failed to write to 'continue_uma.txt' file.");
// }

// /// set signal to stop whole Uma program with all threads
// fn no_restart_set_hard_reset_flag_to_false() {
//     if fs::remove_file(HARD_RESTART_FLAG_PATH_STR).is_ok() {
//         debug_log("Old 'yes_hard_restart_flag.txt' file deleted."); // Optional log.
//     }

//     let mut file = fs::File::create(HARD_RESTART_FLAG_PATH_STR)
//         .expect("Failed to create 'yes_hard_restart_flag.txt' file.");

//     file.write_all(b"0")
//         .expect("Failed to write to 'yes_hard_restart_flag.txt' file.");
// }




