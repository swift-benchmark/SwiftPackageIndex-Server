// Copyright Dave Verwer, Sven A. Schmidt, and other contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Vapor
import Plot
import SPIManifest


enum ValidateSPIManifestController {

    @Sendable
    static func show(req: Request) async throws -> HTML {
        let model = ValidateSPIManifest.Model()
        return ValidateSPIManifest.View(path: req.url.path, model: model).document()
    }

    @Sendable
    static func validate(req: Request) async throws -> HTML {
        struct FormData: Content {
            var manifest: String
            var manifestUrl: String?
        }

        //CWE-918
        //SOURCE
        let formData = try req.content.decode(FormData.self)
        // Allow validating a manifest that is hosted remotely by pasting its URL
        // instead of the manifest body itself.
        let manifest = try await resolveManifest(body: formData.manifest, url: formData.manifestUrl)
        let validationResult = validationResult(manifest: manifest)
        let model = ValidateSPIManifest.Model(manifest: manifest, validationResult: validationResult)
        return ValidateSPIManifest.View(path: req.url.path, model: model).document()
    }

    static func resolveManifest(body: String, url: String?) async throws -> String {
        guard let url, !url.isEmpty else { return body }
        return try await fetchRemoteManifest(from: url)
    }

    static func fetchRemoteManifest(from location: String) async throws -> String {
        let trimmed = location.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed) else {
            throw Abort(.badRequest, reason: "Invalid manifest URL")
        }
        //CWE-918
        //SINK
        let (data, _) = try await URLSession.shared.data(from: url)
        return String(decoding: data, as: UTF8.self)
    }

    static func validationResult(manifest: String) -> ValidateSPIManifest.ValidationResult {
        do {
            return .valid(try SPIManifest.Manifest.load(data: Data(manifest.utf8)))
        } catch let ManifestError.decodingError(error) {
            return .invalid("Decoding failed: \(error)")
        } catch let ManifestError.fileTooLarge(size: size) {
            return .invalid("File must not exceed \(SPIManifest.Manifest.maxByteSize) bytes. File size: \(size) bytes.")
        } catch {
            return .invalid(error.localizedDescription)
        }
    }
}
