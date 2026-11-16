fn main() {
    println!("cargo:rerun-if-changed=src/ffi.rs");
    csbindgen::Builder::default()
        .input_extern_file("src/ffi.rs")
        .csharp_dll_name("perseus_core")
        .csharp_class_name("NativeMethods")
        .csharp_namespace("Perseus.App.Native")
        .generate_csharp_file("../app/Native/PerseusNative.g.cs")
        .expect("csbindgen");
}
