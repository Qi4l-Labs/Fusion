const LOGO: &'static str = "
        ┏┓  •
        ┣┓┏┏┓┏┓┏┓
        ┻┗┻┛┗┗┛┛┗";

pub fn banner(mode: &str) {
    println!("");
    println!("{LOGO}");
    
    match mode {
        "server" => { println!("          C2 SERVER"); }
        "client" => { println!("          C2 CLIENT"); }
        _ => {}
    }

    println!("");
}