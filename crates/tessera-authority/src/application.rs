use crate::domain::authority::Authority;

pub struct Application {
    pub authority: Authority,
}

impl Application {
    pub fn new(authority: Authority) -> Self {
        Self { authority }
    }
}
