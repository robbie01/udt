fn main() {
    let mut build = cxx_build::bridge("src/lib.rs");

    build
        .std("c++17")
        .includes(["udt", "bridge"])
        .files([
            "udt/api.cpp",
            "udt/buffer.cpp",
            "udt/cache.cpp",
            "udt/ccc.cpp",
            "udt/channel.cpp",
            "udt/core.cpp",
            "udt/list.cpp",
            "udt/packet.cpp",
            "udt/queue.cpp",
            "udt/udtCommon.cpp",
            "udt/window.cpp"
        ]);

    build.flag_if_supported("-pthread");

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

    build.compile("udt");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=udt");
    println!("cargo:rerun-if-changed=bridge");
}