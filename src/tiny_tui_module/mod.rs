// tiny_tui_module.rs

pub mod tiny_tui {
    use crate::{
        // Import from the main module
        DEBUG_FLAG,
        Write,
        debug_log,
        write_formatted_navigation_legend_to_tui,
        write_formatted_taskbored_legend_to_tui,
    };

    use std::fs::read_dir;
    use std::io;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

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
            let relevant_path = path_components[2..]
                .iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");

            let _ = write_formatted_navigation_legend_to_tui();

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
            println!(
                "Schedule: {} - {} ({} days)",
                start_date, end_date, duration_days
            );
        } else {
            println!("Schedule: (no schedule... Oh No! Update this!)");
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

        // this no longer works
        // 2. Display the path, skipping the first two components
        if path_components.len() > 2 {
            let relevant_path = path_components[2..]
                .iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            // let _ = write_formatted_navigation_legend_to_tui();
            // println!("Select a Team-Channel (by number):");
            println!("Current Path: /{}", relevant_path);
        } else {
            println!("Select a Team-Channel (by number):");
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }

    // /// doc strings needed
    // /// I thnk this is for message-mode view
    // /// which may work for various text line items
    // /// - instand messenger
    // /// - votes polls surveys
    // ///
    // /// switching to absolute paths...the system for getting the
    // /// path from home directory may need to change
    // ///
    // pub fn simple_render_list(list: &Vec<String>, current_path: &Path) {
    //     // 1. Get the path components
    //     let path_components: Vec<_> = current_path.components().collect();

    //     // this no longer works
    //     // 2. Display the path, skipping the first two components
    //     if path_components.len() > 2 {
    //         let relevant_path = path_components[2..]
    //             .iter()
    //             .map(|c| c.as_os_str().to_string_lossy())
    //             .collect::<Vec<_>>()
    //             .join("/");
    //         // let _ = write_formatted_navigation_legend_to_tui();
    //         println!("Select a Team-Channel (by number):");
    //         println!("Current Path: /{}", relevant_path);
    //     } else {
    //         println!("Select a Team-Channel (by number):");
    //     }

    //     // 3. Display the list items as before
    //     for (i, item) in list.iter().enumerate() {
    //         println!("{}. {}", i + 1, item);
    //     }
    // }

    // /// for passive view mode
    // /// this should contain some indication of passive-mode
    // pub fn simple_render_list_passive(list: &Vec<String>, current_path: &Path) {
    //     // Display path
    //     let path_components: Vec<_> = current_path.components().collect();
    //     if path_components.len() > 2 {
    //         let relevant_path = path_components[2..]
    //             .iter()
    //             .map(|c| c.as_os_str().to_string_lossy())
    //             .collect::<Vec<_>>()
    //             .join("/");
    //         println!("Current Path: /{}", relevant_path);
    //     }

    //     // Display messages
    //     for (i, item) in list.iter().enumerate() {
    //         println!("{}. {}", i + 1, item);
    //     }
    // }

    /// Render Message List for Passive View with Bottom-Scroll Display
    ///
    /// # Purpose
    ///
    /// Displays a list of messages in passive (read-only) view mode with automatic
    /// bottom-scroll behavior. Shows the most recent N messages (where N=18, the
    /// default POSIX terminal height), simulating a scrolled-down view of a message
    /// feed. This matches the interactive view's default scrolldown position but
    /// without interactive controls.
    ///
    /// # Display Behavior
    ///
    /// **Bottom-Scroll Logic (Scrolldown Default):**
    /// - If total messages ≤ 18: Show all messages from beginning
    /// - If total messages > 18: Show only last 18 messages (most recent)
    ///
    /// This creates a "bottom of the scroll" view where new messages appear
    /// at the bottom and old messages scroll off the top automatically.
    ///
    /// # Display Format
    ///
    /// ```text
    /// Current Path: /team_name/channel_name/message_posts_browser
    /// [Showing last 18 of 42 messages]
    ///
    /// 25. alice: Hello everyone
    /// 26. bob: Hi Alice!
    /// 27. charlie: Good morning
    /// ...
    /// 42. alice: Latest message here
    /// ```
    ///
    /// # Message Numbering
    ///
    /// Messages retain their original sequential numbers from the full list:
    /// - Full list has messages 1-42
    /// - Display shows messages 25-42 (last 18)
    /// - Numbering reflects position in full list, not display position
    ///
    /// This helps users understand:
    /// - How many total messages exist
    /// - Which portion they're viewing
    /// - That older messages exist but aren't shown
    ///
    /// # Height Configuration
    ///
    /// Hard-coded constant for passive view:
    /// - `PASSIVE_VIEW_HEIGHT = 18`
    /// - Based on default POSIX terminal height
    /// - Not configurable in passive mode (unlike interactive mode)
    /// - Ensures consistent display across all passive view instances
    ///
    /// # Path Display
    ///
    /// Shows relevant path components:
    /// - Strips first two components (typically /tmp/uma_* or similar base)
    /// - Shows team/channel/message_posts_browser hierarchy
    /// - Helps user identify which channel they're viewing
    /// - Format: "Current Path: /team/channel/message_posts_browser"
    ///
    /// # Passive Mode Indicators
    ///
    /// Clear visual indicators that this is passive mode:
    /// - Header banner: "PASSIVE VIEW MODE"
    /// - Subtitle: "(Auto-refresh, read-only, no input)"
    /// - Message count indicator when scrolled: "[Showing last N of M messages]"
    ///
    /// These indicators prevent confusion with interactive mode and set
    /// correct user expectations (no input, auto-refresh only).
    ///
    /// # Comparison with Interactive Version
    ///
    /// **Interactive (`render_message_browser_screen`):**
    /// - Shows mode indicator (Refresh/Insert)
    /// - Shows input buffer
    /// - User can scroll with j/k commands
    /// - Variable height (user can adjust)
    /// - Shows pagination controls
    ///
    /// **Passive (this function):**
    /// - Shows passive mode indicator
    /// - No input buffer
    /// - No scroll controls (always bottom-scroll)
    /// - Fixed height (18 lines)
    /// - No pagination controls
    ///
    /// # Empty Channel Handling
    ///
    /// If message list is empty:
    /// - Shows passive mode header
    /// - Shows path
    /// - Shows "(No messages yet)" indicator
    /// - Does not prompt for input (unlike interactive mode)
    ///
    /// # Error Handling
    ///
    /// This function performs display only, no I/O operations:
    /// - No file reading (receives pre-built list)
    /// - No user input (passive mode)
    /// - No network operations
    /// - Cannot fail in normal operation
    ///
    /// Edge cases handled:
    /// - Empty list: Shows empty indicator
    /// - Single message: Shows that one message
    /// - Exactly 18 messages: Shows all (no scroll indicator)
    /// - More than 18: Shows last 18 with scroll indicator
    ///
    /// # Performance Notes
    ///
    /// - Slice operation for bottom N is O(1) reference
    /// - No copying of message data
    /// - Minimal string allocation (only for display formatting)
    /// - Suitable for lists with thousands of messages
    ///
    /// # Parameters
    ///
    /// * `list` - Complete list of formatted messages (format: "owner: text")
    /// * `current_path` - Path to message directory for display
    ///
    /// # Returns
    ///
    /// This function does not return a value (display only).
    ///
    /// # Related Functions
    ///
    /// - `passive_display_messages()` - Builds message list and calls this
    /// - `render_message_browser_screen()` - Interactive equivalent
    /// - `run_passive_message_mode()` - Refresh loop that triggers display
    ///
    /// # Example Usage
    ///
    /// ```no_run
    /// use std::path::Path;
    ///
    /// let messages = vec![
    ///     "alice: Hello".to_string(),
    ///     "bob: Hi there".to_string(),
    ///     // ... many more messages ...
    /// ];
    /// let path = Path::new("/path/to/team/channel/message_posts_browser");
    ///
    /// simple_render_list_passive(&messages, path);
    /// // Displays last 18 messages with passive mode indicator
    /// ```
    ///
    /// # Design Rationale
    ///
    /// **Why bottom-scroll default?**
    /// - Matches chat/messaging UX conventions (newest at bottom)
    /// - Matches interactive view's default position
    /// - Most users want to see recent messages first
    /// - Simulates natural "scrolled down" reading position
    ///
    /// **Why fixed height?**
    /// - Passive mode has no user interaction to adjust height
    /// - Consistent experience across all passive view instances
    /// - Matches standard POSIX terminal default
    /// - Simplifies implementation (no state management)
    ///
    /// **Why show message numbers from full list?**
    /// - User can see total message count
    /// - User can see they're viewing a subset
    /// - Numbers remain stable (don't change when scrolling in interactive)
    /// - Helps identify specific messages when switching between views
    pub fn simple_render_list_passive(list: &Vec<String>, current_path: &Path) {
        // ============================================================
        // CONFIGURATION: Hard-coded height for passive view
        // ============================================================
        const PASSIVE_VIEW_HEIGHT: usize = 17;

        // ============================================================
        // HEADER: Display passive mode indicator
        // ============================================================

        // ============================================================
        // PATH DISPLAY: Show relevant path components
        // ============================================================
        let path_components: Vec<_> = current_path.components().collect();
        if path_components.len() > 2 {
            let relevant_path = path_components[2..]
                .iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            println!("View MessagePosts: /{}", relevant_path);
        } else {
            // Fallback: show full path if structure unexpected
            println!("View MessagePosts: {}", current_path.display());
        }

        // ============================================================
        // EMPTY LIST HANDLING: Show indicator for empty channel
        // ============================================================
        if list.is_empty() {
            println!("(No messages yet)\n");
            return;
        }

        // ============================================================
        // SCROLLDOWN CALCULATION: Determine which messages to display
        // ============================================================
        let total_message_count = list.len();

        // Calculate display range (bottom N messages)
        let (display_start_index, display_messages) = if total_message_count <= PASSIVE_VIEW_HEIGHT
        {
            // Show all messages if list is short enough
            (0, &list[..])
        } else {
            // Show only last N messages (bottom-scroll)
            let start_index = total_message_count - PASSIVE_VIEW_HEIGHT;
            (start_index, &list[start_index..])
        };

        // ============================================================
        // MESSAGE DISPLAY: Render messages with original numbering
        // ============================================================
        for (display_index, message) in display_messages.iter().enumerate() {
            // Calculate original message number (1-indexed from full list)
            let original_message_number = display_start_index + display_index + 1;

            println!("{}. {}", original_message_number, message);
        }

        // ============================================================
        // SCROLL INDICATOR: Show if viewing subset of messages
        // ============================================================
        if total_message_count > PASSIVE_VIEW_HEIGHT {
            println!(
                "Last {}:{} , ctrl+c to close, ctrl+b -> o tmux toggle",
                PASSIVE_VIEW_HEIGHT, total_message_count
            );
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

    // use crate::clearsign_toml_module::read_single_line_string_field_from_toml;

    // /// for passive view mode
    // /// Display instant messages in passive (read-only) view mode
    // ///
    // /// # Purpose
    // ///
    // /// Loads and displays all instant message files from a specified directory
    // /// in read-only mode. Unlike `load_im_messages()`, this function reads plain
    // /// TOML files directly without GPG encryption/signature handling and renders
    // /// them without interactive TUI state.
    // ///
    // /// # Process Flow
    // ///
    // /// 1. Collect all file entries from target directory (max depth 1)
    // /// 2. Sort entries by numeric prefix in filename (1__, 2__, 3__, etc.)
    // /// 3. For each file (excluding 0.toml metadata):
    // ///    - Read owner field from TOML
    // ///    - Read text_message field from TOML
    // ///    - Add formatted message to display list
    // ///    - Skip files with read errors (logged in debug builds)
    // /// 4. Render complete message list in passive view
    // ///
    // /// # Message File Formats
    // ///
    // /// - `.toml` files: Plain TOML format with `owner` and `text_message` fields
    // /// - `0.toml`: Metadata file (excluded from message list)
    // /// - Expected filename format: `<number>__<identifier>.toml` (e.g., `1__alice.toml`)
    // ///
    // /// # Sorting Behavior
    // ///
    // /// Messages are sorted by extracting the numeric prefix before the first `__`
    // /// in the filename:
    // /// - `1__alice.toml` → 1
    // /// - `2__bob.toml` → 2
    // /// - `15__charlie.toml` → 15
    // /// - Files without numeric prefix are placed at the end (sorted as u64::MAX)
    // ///
    // /// # Error Handling
    // ///
    // /// - Individual file read errors are logged (debug builds) and skipped
    // /// - Allows partial message display if some files are malformed
    // /// - Directory traversal errors propagate as `io::Result::Err`
    // ///
    // /// # Parameters
    // ///
    // /// * `path` - Directory path containing message TOML files
    // ///
    // /// # Returns
    // ///
    // /// * `Ok(())` - Messages successfully loaded and displayed
    // /// * `Err(io::Error)` - Directory traversal or access error
    // ///
    // /// # Example
    // ///
    // /// ```no_run
    // /// use std::path::Path;
    // ///
    // /// let channel_path = Path::new("/path/to/channel");
    // /// passive_display_messages(channel_path)?;
    // /// ```
    // pub fn passive_display_messages(path: &Path) -> io::Result<()> {
    //     let mut message_list = Vec::new();

    //     // Collect all entries first
    //     let mut entries: Vec<_> = WalkDir::new(path)
    //         .max_depth(1)
    //         .into_iter()
    //         .filter_map(|entry| entry.ok())
    //         .filter(|entry| entry.path().is_file())
    //         .collect();

    //     // Sort entries by numeric prefix in filename (1__, 2__, 3__, etc.)
    //     entries.sort_by_key(|entry| {
    //         entry
    //             .path()
    //             .file_name()
    //             .and_then(|n| n.to_str())
    //             .and_then(|s| s.split("__").next()) // Get part before "__"
    //             .and_then(|num_str| num_str.parse::<u64>().ok()) // Parse as number
    //             .unwrap_or(u64::MAX) // Put unparseable names at end
    //     });

    //     // Process sorted entries
    //     for entry in entries {
    //         let file_name = entry.file_name().to_string_lossy();
    //         if file_name != "0.toml" {
    //             let owner = match read_single_line_string_field_from_toml(
    //                 &entry.path().to_string_lossy(),
    //                 "owner",
    //             ) {
    //                 Ok(o) => o,
    //                 Err(e) => {
    //                     #[cfg(debug_assertions)]
    //                     debug_log!(
    //                         "PDM: Failed to read owner field from {:?}: {} (skipping)",
    //                         entry.path(),
    //                         e
    //                     );
    //                     continue;
    //                 }
    //             };

    //             let text_message = match read_single_line_string_field_from_toml(
    //                 &entry.path().to_string_lossy(),
    //                 "text_message",
    //             ) {
    //                 Ok(o) => o,
    //                 Err(e) => {
    //                     #[cfg(debug_assertions)]
    //                     debug_log!(
    //                         "PDM: Failed to read text_message field from {:?}: {} (skipping)",
    //                         entry.path(),
    //                         e
    //                     );
    //                     continue;
    //                 }
    //             };

    //             message_list.push(format!("{}: {}", owner, text_message));
    //         }
    //     }

    //     // Display using modified version of simple_render_list
    //     simple_render_list_passive(&message_list, path);
    //     Ok(())
    // }

    //////////////////
    // Tables, Tasks
    //////////////////

    pub fn render_tasks_table(headers: &[String], data: &[Vec<String>], current_path: &Path) {
        debug_log("starting: render_tasks_list");
        // 1. Display Current Path
        print!("\x1B[2J\x1B[1;1H"); // Clear the screen
        let _ = write_formatted_taskbored_legend_to_tui();
        println!("Tasks: {}", current_path.display());

        // 2. Display Table (reuse display_tasks_table from tiny_tui_module)
        display_tasks_table(headers, data);

        // 3. (Optional) Display any other task-specific information or instructions.
        // TODO: why not printing?
        println!("\nSelect Task (by number) > ");
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

    pub fn display_tasks_table(headers: &[String], data: &[Vec<String>]) {
        // Changed header type
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
                if i < max_columns {
                    // Ensure we don't exceed the header count.
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

        let num_rows = data.iter().map(|col| col.len()).max().unwrap_or(0); // Or 0 for an empty table
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
    pub fn render_tasks_table_passive(
        headers: &[String],
        data: &[Vec<String>],
        current_path: &Path,
    ) {
        debug_log("starting: render_tasks_table_passive");
        // 1. Display Current Path
        print!("\x1B[2J\x1B[1;1H"); // Clear the screen
        println!("Tasks Path: {}", current_path.display());

        // 2. Display Table (reuse existing display_tasks_table)
        display_tasks_table(headers, data);

        // 3. No input prompt for passive view
        println!("\nView, ctrl+c to exit, ctrl+b -> o for tmux toggle");
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
                    render_tasks_table_passive(&["No Tasks".to_string()], &Vec::new(), path);
                } else {
                    // tiny_tui::render_tasks_table_passive(
                    render_tasks_table_passive(&headers, &data, path);
                }
                Ok(())
            }
            Err(e) => {
                debug_log(&format!("Error updating passive task display: {}", e));
                // tiny_tui::render_tasks_table_passive(
                render_tasks_table_passive(
                    &["Error".to_string()],
                    &vec![vec![format!("Failed to load tasks: {}", e)]],
                    path,
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
                                    tasks.push(format!(
                                        "{}. {}",
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
