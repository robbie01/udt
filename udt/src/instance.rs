#[derive(Debug)]
pub struct Instance(());

impl Default for Instance {
    fn default() -> Self {
        unsafe { udt_sys::startup() };
        Self(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        unsafe { udt_sys::cleanup() };
    }
}