# Lexicographical comparison algorithm

## Instantiation: dates

Goal: Check if date d ≤ date D (lexicographically)

Input: Two dates D and d in YYYY-MM-DD format or any other string format when
dates can be compared lexicographically

Output: Boolean indicating whether d ≤ D

### Algorithm

1. Compare sizes - Check that the two inputs are of the same size: AssertIsEqual(length(d), length(D))
2. Initialize - Set isLarger <- false, isDifferent <- false.
3. Compare all positions - Set n <- length(D). For i = 0, 1, 2, ..., n−1, do steps 4 through 6.
4. Compute differences - Set diff <- (d_i != D_i), isGreater <- (d_i > D_i).
5. Conditional update - Set isLarger <- select(isDifferent, isLarger, isGreater).
  (If isDifferent is true, keep isLarger; otherwise update to isGreater.)
6. Mark difference found - Set isDifferent <- isDifferent || diff.
7. Return result - Return !isLarger.
