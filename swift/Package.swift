// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DomScan",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: "DomScan", targets: ["DomScan"])
    ],
    targets: [
        .target(name: "DomScan", path: "Sources")
    ]
)
