#[derive(Debug)]
pub struct Instance(());

impl Default for Instance {
    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn default() -> Self {
        unsafe { udt_sys::startup() };
        Self(())
    }
}

impl Drop for Instance {
    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn drop(&mut self) {
        unsafe { udt_sys::cleanup() };
    }
}