use colored::{Colorize, CustomColor};

use super::client::Mode;

pub fn set_prompt(mode: &Mode) -> String {
    let name = "Fusion";
    let mark = "➜";
    let color_gray = CustomColor::new(255, 165, 0);

    match mode {
        Mode::Root => {
            format!(" {} \n{} ", name.custom_color(color_gray), mark)
        }
        Mode::Agent(agent_name, _agent_os) => {
            format!("{} [agent: {}] \n{} ", name.custom_color(color_gray), agent_name.cyan(), mark)
        }
    }
}