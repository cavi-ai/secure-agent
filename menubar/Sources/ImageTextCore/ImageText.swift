import CoreGraphics
import CoreImage
import Foundation
import ImageIO
import Vision

/// The text Vision reads in one view of an image.
public struct ImageTextReading: Codable, Sendable, Equatable {
    /// "full", "<n>px" (long edge after downscaling) or "contrast".
    public let view: String
    public let text: String
}

public enum ImageTextError: Error, CustomStringConvertible {
    case unreadable(String)
    public var description: String {
        switch self {
        case .unreadable(let path): return "cannot decode an image at \(path)"
        }
    }
}

/// Long edges models downscale images to before reading them; text drawn to
/// appear only after such a resize shows up in these views.
public let modelLongEdges = [1568, 768, 512]

/// How strongly the contrast views stretch the range near white or black.
let faintGain = 12.0

/// Reads the text in an image at full size, at each long edge smaller than the
/// image, and with contrast raised (faint text). Views with no text are left out.
public func readImageText(at url: URL, longEdges: [Int] = modelLongEdges) throws -> [ImageTextReading] {
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
        throw ImageTextError.unreadable(url.path)
    }
    let input = CIImage(cgImage: image)
    let context = CIContext()
    var views: [(String, CGImage)] = [("full", image)]
    let longest = max(image.width, image.height)
    for edge in longEdges where edge < longest {
        guard let filter = CIFilter(name: "CILanczosScaleTransform") else { continue }
        filter.setValue(input, forKey: kCIInputImageKey)
        filter.setValue(Double(edge) / Double(longest), forKey: kCIInputScaleKey)
        filter.setValue(1.0, forKey: kCIInputAspectRatioKey)
        if let out = filter.outputImage, let scaled = context.createCGImage(out, from: out.extent) {
            views.append(("\(edge)px", scaled))
        }
    }
    // Faint text: stretch the 1/12 of the range nearest white (light
    // backgrounds) and nearest black (dark backgrounds) to the full range.
    for (name, gain, bias) in [("contrast", faintGain, 1 - faintGain), ("contrast-dark", faintGain, 0.0)] {
        guard let matrix = CIFilter(name: "CIColorMatrix"), let clamp = CIFilter(name: "CIColorClamp") else { continue }
        matrix.setValue(input, forKey: kCIInputImageKey)
        matrix.setValue(CIVector(x: gain, y: 0, z: 0, w: 0), forKey: "inputRVector")
        matrix.setValue(CIVector(x: 0, y: gain, z: 0, w: 0), forKey: "inputGVector")
        matrix.setValue(CIVector(x: 0, y: 0, z: gain, w: 0), forKey: "inputBVector")
        matrix.setValue(CIVector(x: bias, y: bias, z: bias, w: 0), forKey: "inputBiasVector")
        clamp.setValue(matrix.outputImage, forKey: kCIInputImageKey)
        if let out = clamp.outputImage, let stretched = context.createCGImage(out, from: input.extent) {
            views.append((name, stretched))
        }
    }
    return try views.compactMap { name, view in
        let text = try recognizeText(in: view)
        return text.isEmpty ? nil : ImageTextReading(view: name, text: text)
    }
}

func recognizeText(in image: CGImage) throws -> String {
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    try VNImageRequestHandler(cgImage: image).perform([request])
    return (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }.joined(separator: " ")
}
