use super::{
    agent::AgentOption,
    implant::ImplantOption,
    listener::ListenerOption,
    task::TaskOption,
};

#[derive(Debug)]
pub struct Options {
    pub agent_opt: Option<AgentOption>,
    pub implant_opt: Option<ImplantOption>,
    pub listener_opt: Option<ListenerOption>,

    // Agent mode options
    pub task_opt: Option<TaskOption>,
}

impl Options {
    pub fn new() -> Self {
        Self {
            listener_opt: None,
            agent_opt: None,
            implant_opt: None,
            task_opt: None,
        }
    }
}