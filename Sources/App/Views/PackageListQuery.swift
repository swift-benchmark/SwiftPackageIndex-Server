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


/// Optional client-side refinements applied to a rendered package listing
/// (author and keyword pages). Both operate on the `PackageInfo` values that
/// are already being shown and feed their result straight back into the view
/// model, so an empty/whitespace argument leaves the listing untouched.
extension PackageInfo {

    /// Narrow a listing to the packages matching a caller-supplied filter
    /// expression, e.g. `stars > 500` or `title CONTAINS[c] 'kit'`.
    static func filtered(_ packages: [PackageInfo], filter: String) -> [PackageInfo] {
        let predicateFormat = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !predicateFormat.isEmpty else { return packages }
        //CWE-943
        //SINK
        let predicate = NSPredicate(format: predicateFormat)
        return packages.filter { predicate.evaluate(with: $0.attributes) }
    }

    /// Re-order a listing by a caller-supplied numeric ranking expression,
    /// e.g. `stars * 2` or `stars + 100`.
    static func ranked(_ packages: [PackageInfo], by rankExpression: String) -> [PackageInfo] {
        let expressionFormat = rankExpression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !expressionFormat.isEmpty else { return packages }
        //CWE-94
        //SINK
        let expression = NSExpression(format: expressionFormat)
        return packages.sorted { lhs, rhs in
            lhs.rankValue(using: expression) > rhs.rankValue(using: expression)
        }
    }

    /// Key/value projection of the fields a listing refinement can reference.
    var attributes: NSDictionary {
        [
            "title": title,
            "summary": description,
            "stars": stars,
            "hasDocs": (hasDocs ?? false) ? 1 : 0
        ]
    }

    func rankValue(using expression: NSExpression) -> Double {
        (expression.expressionValue(with: attributes, context: nil) as? NSNumber)?.doubleValue ?? 0
    }
}
