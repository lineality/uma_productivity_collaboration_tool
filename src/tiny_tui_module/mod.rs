// tiny_tui_module.rs

pub mod tiny_tui {
    use std::io;
    use std::fs;
    use walkdir::WalkDir;
    use std::fs::read_dir;
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
        InstantMessageFile,
        }; 

    pub fn render_list(
        list: &Vec<String>,
        current_path: &Path,
        // 
        // agenda_process: &str,
        // goals_features: &str,
        // scope: &str,
        // schedule_duration_start_end: &Vec<u64>,
        //
        pa1_process: &str,
        pa2_schedule: &Vec<u64>,
        pa3_users: &str,
        pa4_features: &str,
        pa5_mvp: &str,
        pa6_feedback: &str,
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

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
        
        // 2b. Display added core node fields
        println!("\nProcess: {}", pa1_process);

        if pa2_schedule.len() == 2 {
            let start_time = pa2_schedule[0];
            let end_time = pa2_schedule[1];
            let duration_days = (end_time - start_time) / (60 * 60 * 24); 

            let start_date = format_timestamp_to_date(start_time);
            let end_date = format_timestamp_to_date(end_time);
            println!("Schedule: {} - {} ({} days)", start_date, end_date, duration_days);

        }
        else {
            println!("Schedule: (no schedule)");
        }

        println!("Users: {}", pa3_users);
        println!("Features: {}", pa4_features);
        println!("MVP: {}", pa5_mvp);
        println!("Feedback: {}", pa6_feedback);
    }    
    
    /// doc strings needed
    /// I thnk this is for message-mode view
    /// which may work for various text line items
    /// - instand messenger
    /// - votes polls surveys
    ///
    /// switching to absolute paths...the system for getting the
    /// path from home directory may need to change
    /// 
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
        
    /// for passive view mode
    /// this should contain some indication of passive-mode
    pub fn simple_render_list_passive(list: &Vec<String>, current_path: &Path) {
        // Display path
        let path_components: Vec<_> = current_path.components().collect();
        if path_components.len() > 2 {
            let relevant_path = path_components[2..].iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            println!("Current Path: /{}", relevant_path);
        }

        // Display messages
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


    /// for passive view mode
    pub fn passive_display_messages(path: &Path) -> io::Result<()> {
        let mut message_list = Vec::new();
        
        // Walk directory and collect messages
        for entry in WalkDir::new(path).max_depth(1) {
            let entry = entry?;
            if entry.path().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                if file_name != "0.toml" {
                    if let Ok(contents) = fs::read_to_string(entry.path()) {
                        if let Ok(message) = toml::from_str::<InstantMessageFile>(&contents) {
                            message_list.push(format!("{}: {}", message.owner, message.text_message));
                        }
                    }
                }
            }
        }
        
        // Display using modified version of simple_render_list
        simple_render_list_passive(&message_list, path);
        Ok(())
    }



        
    //////////////////
    // Tables, Tasks
    //////////////////

    pub fn render_tasks_table(headers: &[String], data: &[Vec<String>], current_path: &Path) {
        debug_log("starting: render_tasks_list");
        // 1. Display Current Path
        print!("\x1B[2J\x1B[1;1H"); // Clear the screen
        println!("Current Path: {}", current_path.display());
    
        // 2. Display Table (reuse display_tasks_table from tiny_tui_module)
        display_tasks_table(headers, data);
    
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
    
    pub fn display_tasks_table(headers: &[String], data: &[Vec<String>]) {  // Changed header type
        debug_log("tui module: task-mode: start: display_tasks_table()");
        debug_log!(
            "tui module: display_tasks_table(): headers -> {:?} data -> {:?}",
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

    /// Render tasks table for passive view mode
    /// Similar to render_tasks_table but without input prompts
    pub fn render_tasks_table_passive(headers: &[String], data: &[Vec<String>], current_path: &Path) {
        debug_log("starting: render_tasks_table_passive");
        // 1. Display Current Path
        print!("\x1B[2J\x1B[1;1H"); // Clear the screen
        println!("Current Path: {}", current_path.display());

        // 2. Display Table (reuse existing display_tasks_table)
        display_tasks_table(headers, data);

        // 3. No input prompt for passive view
        println!("\nPassive View Mode - Updates Automatically"); 
    }

    /// Display tasks in passive view mode using the existing table infrastructure
    pub fn passive_display_tasks(path: &Path) -> io::Result<()> {
        debug_log!("passive-task-mode: starting passive task display");

        // Use existing update_task_display logic but without app state
        match update_passive_task_display(path) {
            Ok((headers, data)) => {
                if headers.is_empty() {
                    debug_log("Warning: No headers found in passive task display");
                    // tiny_tui::render_tasks_table_passive(
                    render_tasks_table_passive(
                        &["No Tasks".to_string()], 
                        &Vec::new(),
                        path,
                    );
                } else {
                    // tiny_tui::render_tasks_table_passive(
                    render_tasks_table_passive(
                        &headers, 
                        &data, 
                        path,
                    );
                }
                Ok(())
            },
            Err(e) => {
                debug_log(&format!("Error updating passive task display: {}", e));
                // tiny_tui::render_tasks_table_passive(
                render_tasks_table_passive(
                    &["Error".to_string()],
                    &vec![vec![format!("Failed to load tasks: {}", e)]],
                    path
                );
                Err(e)
            }
        }
    }


    /// Update task display data for passive view
    /// Returns headers and data for task table display
    fn update_passive_task_display(path: &Path) -> io::Result<(Vec<String>, Vec<Vec<String>>)> {
        let mut headers = Vec::new();
        let mut task_columns = Vec::new();

        // Read directory entries
        for entry in read_dir(path)? {
            let entry = entry?;
            let file_name = entry.file_name().to_string_lossy().into_owned();
            
            // Parse column directories (e.g., "1_plan") using string operations
            if entry.file_type()?.is_dir() {
                // Split on first underscore
                if let Some(underscore_pos) = file_name.find('_') {
                    if let Ok(column_num) = file_name[..underscore_pos].parse::<usize>() {
                        let header = file_name[underscore_pos + 1..].to_string();
                        
                        // Collect tasks in this column
                        let mut tasks = Vec::new();
                        if let Ok(task_entries) = read_dir(entry.path()) {
                            for (i, task_entry) in task_entries.flatten().enumerate() {
                                if task_entry.file_type()?.is_dir() {
                                    tasks.push(format!("{}. {}", 
                                        i + 1,
                                        task_entry.file_name().to_string_lossy()
                                    ));
                                }
                            }
                        }

                        // Ensure we have space in our vectors
                        while headers.len() <= column_num {
                            headers.push(String::new());
                            task_columns.push(Vec::new());
                        }
                        
                        headers[column_num] = header;
                        task_columns[column_num] = tasks;
                    }
                }
            }
        }

        // Convert to table format
        let data = transpose_table_data(&task_columns);
        
        Ok((headers, data))
    }
}
