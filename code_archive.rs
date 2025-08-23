
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




