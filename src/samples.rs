/*
Samples
*/


/// exe-parent uma.toml reading (sample)

    debug_log!("___ Step 1: Reading LOCAL OWNER USER's name from uma.toml");
    
    // Get absolute path to uma.toml configuration file
    let relative_uma_toml_path = "uma.toml";
    let absolute_uma_toml_path = make_file_path_abs_executabledirectoryrelative_canonicalized_or_error(relative_uma_toml_path)
        .map_err(|e| {
            let error_msg = format!("___ Failed to locate uma.toml configuration file: {}", e);
            println!("Error: {}", error_msg);
            io::Error::new(io::ErrorKind::InvalidData, error_msg)
        })?;
    
    // Convert PathBuf to string for TOML reading
    let absolute_uma_toml_path_str = absolute_uma_toml_path
        .to_str()
        .ok_or_else(|| {
            let error_msg = "__ Unable to convert UMA TOML path to string".to_string();
            println!("Error: {}", error_msg);
            io::Error::new(io::ErrorKind::InvalidData, error_msg)
        })?;
    
    // Read LOCAL OWNER USER's name from uma.toml
    let local_owner_user_name = read_single_line_string_field_from_toml(
        absolute_uma_toml_path_str, 
        "uma_local_owner_user"
    ).map_err(|e| {
        let error_msg = format!("___ Failed to read LOCAL OWNER USER's name: {}", e);
        println!("Error: {}", error_msg);
        io::Error::new(io::ErrorKind::InvalidData, error_msg)
    })?;
    
    debug_log!("___ LOCAL OWNER USER's name is: {}", local_owner_user_name);



    

// Get absolute path to uma.toml configuration file
let relative_uma_toml_path = "uma.toml";
let absolute_uma_toml_path = make_file_path_abs_executabledirectoryrelative_canonicalized_or_error(relative_uma_toml_path)
    .map_err(|e| {
        let error_msg = format!("___ Failed to locate uma.toml configuration file: {}", e);
        println!("Error: {}", error_msg);
        io::Error::new(io::ErrorKind::InvalidData, error_msg)
    })?;

// Convert PathBuf to string for TOML reading
let absolute_uma_toml_path_str = absolute_uma_toml_path
    .to_str()
    .ok_or_else(|| {
        let error_msg = "__ Unable to convert UMA TOML path to string".to_string();
        println!("Error: {}", error_msg);
        io::Error::new(io::ErrorKind::InvalidData, error_msg)
    })?;
    
    
// Read LOCAL OWNER USER's name from uma.toml
let uma_local_owner_user = read_single_line_string_field_from_toml(
    absolute_uma_toml_path_str, 
    "uma_local_owner_user"
).map_err(|e| {
    let error_msg = format!("WLPL Failed to read LOCAL OWNER USER's name: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;

// u64
let default_im_messages_expiration_days = read_u64_field_from_toml(
    absolute_uma_toml_path_str, 
    "uma_default_im_messages_expiration_days"
).map_err(|e| {
    let error_msg = format!("WLPL Failed to read default_im_messages_expiration_days: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;

// u64
let default_task_nodes_expiration_days = read_u64_field_from_toml(
    absolute_uma_toml_path_str, 
    "uma_default_task_nodes_expiration_days"
).map_err(|e| {
    let error_msg = format!("WLPL Failed to read default_task_nodes_expiration_days: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;

// u8
let tui_height = read_u8_field_from_toml(
    absolute_uma_toml_path_str, 
    "tui_height"
).map_err(|e| {
    let error_msg = format!("WLPL Failed to read tui_height: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;

// u8
let tui_width = read_u8_field_from_toml(
    absolute_uma_toml_path_str, 
    "tui_width"
).map_err(|e| {
    let error_msg = format!("WLPL Failed to read tui_width: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;







// Get absolute path to uma.toml configuration file
let relative_uma_toml_path = "uma.toml";
let absolute_uma_toml_path = make_file_path_abs_executabledirectoryrelative_canonicalized_or_error(relative_uma_toml_path)
    .map_err(|e| {
        let error_msg = format!("___ Failed to locate uma.toml configuration file: {}", e);
        println!("Error: {}", error_msg);
        io::Error::new(io::ErrorKind::InvalidData, error_msg)
    })?;

// Convert PathBuf to string for TOML reading
let absolute_uma_toml_path_str = absolute_uma_toml_path
    .to_str()
    .ok_or_else(|| {
        let error_msg = "__ Unable to convert UMA TOML path to string".to_string();
        println!("Error: {}", error_msg);
        io::Error::new(io::ErrorKind::InvalidData, error_msg)
    })?;
    
    
// Read log_mode_refresh from uma.toml
let log_mode_refresh = read_float_field_from_toml(
    absolute_uma_toml_path_str, 
    "log_mode_refresh"
).map_err(|e| {
    let error_msg = format!(" Failed to read log_mode_refresh: {}", e);
    println!("Error: {}", error_msg);
    io::Error::new(io::ErrorKind::InvalidData, error_msg)
})?;

    

