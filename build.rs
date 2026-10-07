fn main() {
    println!("cargo:rerun-if-changed=ico/ArkIris-Icon.ico");

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();

        // EXE 图标
        res.set_icon("ico/ArkIris-Icon.ico");

        // Windows 文件属性中的版权/作者信息
        res.set("CompanyName", "Arklight Project™");
        res.set("LegalCopyright", "© Arklight Project™");
        res.set("ProductName", "ArkIris");
        res.set("FileDescription", "ArkIris");
        res.set("OriginalFilename", "ArkIris.exe");

        res.compile().expect("failed to compile Windows resources");
    }
}