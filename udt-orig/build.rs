fn main() {
    let mut build = cxx_build::bridge("src/ffi.rs");

    // Same source set as the modified fork, plus the two files it removed:
    // epoll.cpp (replaced there by the Rust RPoll) and md5.cpp (replaced by
    // rutil::compute_md5 over the cxx bridge). Upstream needs both.
    build
        .std("c++17")
        .includes(["upstream", "bridge"])
        .files([
            "upstream/api.cpp",
            "upstream/buffer.cpp",
            "upstream/cache.cpp",
            "upstream/ccc.cpp",
            "upstream/channel.cpp",
            "upstream/core.cpp",
            "upstream/epoll.cpp",
            "upstream/list.cpp",
            "upstream/md5.cpp",
            "upstream/packet.cpp",
            "upstream/queue.cpp",
            "upstream/udtCommon.cpp",
            "upstream/window.cpp",
        ]);

    build.flag_if_supported("-pthread");
    // Vendored third-party code from 2012; it is not warning-clean under a
    // modern toolchain and we do not want to patch it. Silencing keeps the
    // signal in our own build output.
    build.warnings(false);

    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        println!("cargo::rustc-link-lib=pthread");
        println!("cargo::rustc-link-lib=m");
    }

    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86_64" {
        build.define("AMD64", None);
    }

    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if os != "windows" {
        build.flag_if_supported("-fvisibility=hidden");
    }

    if os == "macos" {
        build.define("MACOSX", None);
    } else if os == "linux" {
        build.define("LINUX", None);
        println!("cargo::rustc-link-lib=dl");
    } else if os.contains("bsd") {
        build.define("BSD", None);
    } else if os == "windows" {
        build.define("WINDOWS", None);
        build.define("WINVER", "0x0A00");
        build.define("_WIN32_WINNT", "0x0A00");
        println!("cargo::rustc-link-lib=kernel32");
        println!("cargo::rustc-link-lib=user32");
        println!("cargo::rustc-link-lib=ws2_32");
    } else {
        panic!("unsupported platform");
    }

    // MUST NOT be "udt": udt-compat/udt-sys emits an archive by that name, and
    // two `-l static=udt` with different `-L` paths silently resolve to
    // whichever the linker sees first.
    build.compile("udt_orig");

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=upstream");
    println!("cargo:rerun-if-changed=bridge");
}
