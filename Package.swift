// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "GatePolicy", products: [.library(name: "GatePolicy", targets: ["GatePolicy"])], targets: [.target(name: "GatePolicy"), .testTarget(name: "GatePolicyTests", dependencies: ["GatePolicy"])])
