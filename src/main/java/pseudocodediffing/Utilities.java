package pseudocodediffing;

import java.util.ArrayList;
import java.util.List;

/**
 * Utilities for computing line-based diffs using different alignment algorithms.
 */
public class Utilities {

    public enum DiffType {
        MATCH,      // Lines are identical
        CHANGED,    // Same alignment slot but different text
        ADDED,      // Present only in the second file
        REMOVED     // Present only in the first file
    }

    public static class LineDiff {
        public String leftLine;   // line from file1 (or empty if ADDED)
        public String rightLine;  // line from file2 (or empty if REMOVED)
        public DiffType diffType;

        public LineDiff(String leftLine, String rightLine, DiffType diffType) {
            this.leftLine = leftLine;
            this.rightLine = rightLine;
            this.diffType = diffType;
        }
    }

    /**
     * A single entry point that picks which algorithm to use, based on a string key.
     */
    public static List<LineDiff> computeDiffs(String code1, String code2, String algorithmKey) {
        switch (algorithmKey) {
            case "Naive":
                return computeNaiveLineDiffs(code1, code2);
            case "LCS":
                return computeLcsLineDiffs(code1, code2);
            case "Levenshtein":
                return computeLevenshteinLineDiffs(code1, code2);
            default:
                // fallback
                return computeNaiveLineDiffs(code1, code2);
        }
    }

    /**
     * 1) Naive line-by-line diff:
     *    - lines are compared strictly by index
     */
    public static List<LineDiff> computeNaiveLineDiffs(String code1, String code2) {
        List<LineDiff> diffs = new ArrayList<>();

        String[] lines1 = (code1 == null ? new String[0] : code1.split("\n"));
        String[] lines2 = (code2 == null ? new String[0] : code2.split("\n"));

        int maxLen = Math.max(lines1.length, lines2.length);

        for (int i = 0; i < maxLen; i++) {
            String leftLine = (i < lines1.length) ? lines1[i] : "";
            String rightLine = (i < lines2.length) ? lines2[i] : "";

            if (i < lines1.length && i < lines2.length) {
                // Both sides have a line at index i
                if (leftLine.trim().equals(rightLine.trim())) {
                    diffs.add(new LineDiff(leftLine, rightLine, DiffType.MATCH));
                } else {
                    diffs.add(new LineDiff(leftLine, rightLine, DiffType.CHANGED));
                }
            }
            else if (i < lines1.length) {
                // Only in file1 => REMOVED
                diffs.add(new LineDiff(leftLine, "", DiffType.REMOVED));
            }
            else {
                // Only in file2 => ADDED
                diffs.add(new LineDiff("", rightLine, DiffType.ADDED));
            }
        }

        return diffs;
    }

    /**
     * 2) LCS line-based diff approach:
     *    - Try to minimize CHANGED lines by realigning via LCS.
     */
    public static List<LineDiff> computeLcsLineDiffs(String code1, String code2) {
        String[] lines1 = (code1 == null ? new String[0] : code1.split("\n"));
        String[] lines2 = (code2 == null ? new String[0] : code2.split("\n"));

        List<String> lcs = getLcs(lines1, lines2);
        List<LineDiff> result = new ArrayList<>();

        int i = 0, j = 0;
        while (i < lines1.length && j < lines2.length) {
            if (lines1[i].trim().equals(lines2[j].trim())) {
                result.add(new LineDiff(lines1[i], lines2[j], DiffType.MATCH));
                i++;
                j++;
            }
            else if (lcs.contains(lines1[i].trim()) && !lcs.contains(lines2[j].trim())) {
                // line2[j] is not in LCS => ADDED
                result.add(new LineDiff("", lines2[j], DiffType.ADDED));
                j++;
            }
            else if (!lcs.contains(lines1[i].trim()) && lcs.contains(lines2[j].trim())) {
                // line1[i] is not in LCS => REMOVED
                result.add(new LineDiff(lines1[i], "", DiffType.REMOVED));
                i++;
            }
            else {
                // both differ, presumably out of alignment => CHANGED
                result.add(new LineDiff(lines1[i], lines2[j], DiffType.CHANGED));
                i++;
                j++;
            }
        }

        // leftover lines in file1 => REMOVED
        while (i < lines1.length) {
            result.add(new LineDiff(lines1[i], "", DiffType.REMOVED));
            i++;
        }
        // leftover lines in file2 => ADDED
        while (j < lines2.length) {
            result.add(new LineDiff("", lines2[j], DiffType.ADDED));
            j++;
        }

        return result;
    }

    /**
     * Return the LCS (list of line strings) between lines1 & lines2 by DP.
     */
    private static List<String> getLcs(String[] lines1, String[] lines2) {
        int m = lines1.length;
        int n = lines2.length;

        @SuppressWarnings("unchecked")
        List<String>[][] dp = new ArrayList[m+1][n+1];
        for (int i = 0; i <= m; i++) {
            for (int j = 0; j <= n; j++) {
                dp[i][j] = new ArrayList<>();
            }
        }

        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (lines1[i-1].trim().equals(lines2[j-1].trim())) {
                    dp[i][j].addAll(dp[i-1][j-1]);
                    dp[i][j].add(lines1[i-1].trim());
                } else {
                    if (dp[i-1][j].size() > dp[i][j-1].size()) {
                        dp[i][j] = new ArrayList<>(dp[i-1][j]);
                    } else {
                        dp[i][j] = new ArrayList<>(dp[i][j-1]);
                    }
                }
            }
        }
        return dp[m][n];
    }

    /**
     * 3) Levenshtein-based line diff approach:
     *    - Minimizes total "edit operations" at line-level.
     */
    public static List<LineDiff> computeLevenshteinLineDiffs(String code1, String code2) {
        String[] lines1 = (code1 == null ? new String[0] : code1.split("\n"));
        String[] lines2 = (code2 == null ? new String[0] : code2.split("\n"));

        int m = lines1.length;
        int n = lines2.length;
        int[][] dp = new int[m+1][n+1];

        for (int i = 0; i <= m; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= n; j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (lines1[i-1].trim().equals(lines2[j-1].trim())) {
                    dp[i][j] = dp[i-1][j-1];
                } else {
                    dp[i][j] = 1 + Math.min(dp[i-1][j],
                                     Math.min(dp[i][j-1], dp[i-1][j-1]));
                }
            }
        }

        // Backtrack
        List<LineDiff> result = new ArrayList<>();
        int i = m, j = n;
        while (i > 0 && j > 0) {
            if (lines1[i-1].trim().equals(lines2[j-1].trim())) {
                result.add(0, new LineDiff(lines1[i-1], lines2[j-1], DiffType.MATCH));
                i--;
                j--;
            } else {
                int remove = dp[i-1][j];
                int insert = dp[i][j-1];
                int replace = dp[i-1][j-1];
                if (dp[i][j] == remove + 1) {
                    result.add(0, new LineDiff(lines1[i-1], "", DiffType.REMOVED));
                    i--;
                } 
                else if (dp[i][j] == insert + 1) {
                    result.add(0, new LineDiff("", lines2[j-1], DiffType.ADDED));
                    j--;
                } 
                else {
                    result.add(0, new LineDiff(lines1[i-1], lines2[j-1], DiffType.CHANGED));
                    i--;
                    j--;
                }
            }
        }
        // leftover
        while (i > 0) {
            result.add(0, new LineDiff(lines1[i-1], "", DiffType.REMOVED));
            i--;
        }
        while (j > 0) {
            result.add(0, new LineDiff("", lines2[j-1], DiffType.ADDED));
            j--;
        }

        return result;
    }
}
