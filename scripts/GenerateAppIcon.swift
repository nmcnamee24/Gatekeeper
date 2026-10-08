import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// Original vector artwork, rendered opaque for Apple's 1024px app icon.
let output = CommandLine.arguments.dropFirst().first ?? "App/Assets.xcassets/AppIcon.appiconset/AppIcon.png"
let size = 1024
let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
let ivory = CGColor(red: 0.96, green: 0.94, blue: 0.89, alpha: 1)
let forest = CGColor(red: 0.13, green: 0.22, blue: 0.19, alpha: 1)
context.setFillColor(forest)
context.fill(CGRect(x: 0, y: 0, width: size, height: size))
context.setFillColor(ivory)
let rook = CGMutablePath()
rook.move(to: CGPoint(x: 292, y: 720))
for p in [CGPoint(x:292,y:802),CGPoint(x:392,y:802),CGPoint(x:392,y:720),CGPoint(x:462,y:720),CGPoint(x:462,y:802),CGPoint(x:562,y:802),CGPoint(x:562,y:720),CGPoint(x:632,y:720),CGPoint(x:632,y:802),CGPoint(x:732,y:802),CGPoint(x:732,y:642),CGPoint(x:670,y:582),CGPoint(x:670,y:318),CGPoint(x:708,y:278),CGPoint(x:708,y:220),CGPoint(x:316,y:220),CGPoint(x:316,y:278),CGPoint(x:354,y:318),CGPoint(x:354,y:582),CGPoint(x:292,y:642)] { rook.addLine(to:p) }
rook.closeSubpath()
context.addPath(rook)
context.fillPath()
context.setFillColor(forest)
let opening = CGMutablePath()
opening.move(to:CGPoint(x:464,y:220));opening.addLine(to:CGPoint(x:464,y:418))
opening.addCurve(to:CGPoint(x:560,y:418),control1:CGPoint(x:464,y:482),control2:CGPoint(x:560,y:482))
opening.addLine(to:CGPoint(x:560,y:220));opening.closeSubpath()
context.addPath(opening);context.fillPath()
let url=URL(fileURLWithPath:output)
try FileManager.default.createDirectory(at:url.deletingLastPathComponent(),withIntermediateDirectories:true)
let destination=CGImageDestinationCreateWithURL(url as CFURL,UTType.png.identifier as CFString,1,nil)!
CGImageDestinationAddImage(destination,context.makeImage()!,nil)
guard CGImageDestinationFinalize(destination) else {fatalError("Could not export icon")}
print("Generated opaque 1024px Rook app icon.")
