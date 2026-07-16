import Foundation

enum GlobPattern {
    static func matches(_ string: String, pattern: String) -> Bool {
        if pattern == "*" {
            return true
        }

        var stringIndex = string.startIndex
        var patternIndex = pattern.startIndex
        var starStringIndex = string.endIndex
        var starPatternIndex = pattern.endIndex

        while stringIndex < string.endIndex {
            if patternIndex < pattern.endIndex
                && (pattern[patternIndex] == "?" || pattern[patternIndex] == string[stringIndex])
            {
                stringIndex = string.index(after: stringIndex)
                patternIndex = pattern.index(after: patternIndex)
            } else if patternIndex < pattern.endIndex && pattern[patternIndex] == "*" {
                starPatternIndex = patternIndex
                starStringIndex = stringIndex
                patternIndex = pattern.index(after: patternIndex)
            } else if starPatternIndex != pattern.endIndex {
                patternIndex = pattern.index(after: starPatternIndex)
                starStringIndex = string.index(after: starStringIndex)
                stringIndex = starStringIndex
            } else {
                return false
            }
        }

        while patternIndex < pattern.endIndex && pattern[patternIndex] == "*" {
            patternIndex = pattern.index(after: patternIndex)
        }
        return patternIndex == pattern.endIndex
    }
}
