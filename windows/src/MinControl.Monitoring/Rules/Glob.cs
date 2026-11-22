namespace MinControl.Monitoring.Rules;

/// <summary>
/// Case-insensitive glob with <c>*</c> (any run of characters, including path separators) and
/// <c>?</c> (exactly one character), as defined by <c>common.schema.json#/$defs/glob</c>.
/// '/' and '\' are treated as the same character so policies may use either.
/// </summary>
public static class Glob
{
    public static bool IsMatch(string pattern, string text)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(text);

        // Iterative wildcard matching with single-star backtracking: O(n*m) worst case, no recursion.
        int p = 0, t = 0, starP = -1, starT = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                starP = p++;
                starT = t;
            }
            else if (p < pattern.Length && (pattern[p] == '?' || CharEq(pattern[p], text[t])))
            {
                p++;
                t++;
            }
            else if (starP >= 0)
            {
                p = starP + 1;
                t = ++starT;
            }
            else
            {
                return false;
            }
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }

    public static bool HasWildcards(string pattern) => pattern.AsSpan().IndexOfAny('*', '?') >= 0;

    private static bool CharEq(char a, char b)
    {
        if (a == b) return true;
        if (IsSep(a) && IsSep(b)) return true;
        return char.ToUpperInvariant(a) == char.ToUpperInvariant(b);
    }

    private static bool IsSep(char c) => c is '\\' or '/';
}
