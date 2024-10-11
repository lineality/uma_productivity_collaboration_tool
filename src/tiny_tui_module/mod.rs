// tiny_tui_module.rs

pub mod tiny_tui {
    use std::path::Path;

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
            println!("Select a Team-Channel (by number):"); // Home directory (root) 
        }

        // 3. Display the list items as before
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
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
}
