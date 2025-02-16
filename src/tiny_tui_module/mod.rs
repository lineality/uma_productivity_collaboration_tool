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
        
    /// for passive view mode
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

