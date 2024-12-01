// tiny_tui_module.rs

pub mod tiny_tui {
    use std::path::Path;
    use crate::{ // Import from the main module
        DEBUG_FLAG,
        debug_log,
        OpenOptions,
        Write,
        }; 

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
            println!("Select a Team-Channel (by number):"); 
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }    
    
    pub fn render_tasks_list(headers: &[String], data: &[Vec<String>], current_path: &Path) {
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
            "tui module: display_table: headers -> {:?} data -> {:?}",
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

