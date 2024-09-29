// tiny_tui_module.rs

pub mod tiny_tui {
    use std::path::Path;

    pub fn render_list(list: &Vec<String>, current_path: &Path) {
        println!("Current Path: {}", current_path.display());
        for (i, item) in list.iter().enumerate() {
            println!("{}. {}", i + 1, item);
        }
    }

    pub fn get_input() -> Result<String, std::io::Error> {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}
