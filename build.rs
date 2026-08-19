fn main() {
    // Tell Cargo where to find the wpcap.lib file inside the new SDK folder
    println!("cargo:rustc-link-search=native=npcap-sdk/Lib/x64");
}
