#[path = "storage_files.rs"]
mod files;
#[path = "storage_swap.rs"]
mod swap;

pub fn file_types_and_temps() {
    files::run();
}

pub fn root_substitution() {
    swap::run();
}
