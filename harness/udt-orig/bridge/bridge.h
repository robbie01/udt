// Gives the cxx bridge a name for `void` in the UDT namespace, matching the
// approach in udt-compat/udt-sys/bridge/bridge.h.
namespace UDT {
    using c_void = void;
}
