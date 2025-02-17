package pseudocodediffing;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
//import ghidra.util.CancelledException;
import ghidra.util.exception.CancelledException;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import pseudocodediffing.Utilities.LineDiff;

/**
 * The provider that shows:
 * 1) A left JList of matched functions
 * 2) A right tabbed pane with:
 *    - "Pseudocode Diff" (your existing line-based comparison)
 *    - "Flow Graph" (a simple block-based CFG of the selected function)
 */
public class DualFileComponentProvider extends ComponentProvider {

    private JPanel mainPanel;

    // Left side list
    private JList<MatchedFunctionPair> functionList;
    private DefaultListModel<MatchedFunctionPair> functionListModel;

    // Right side components
    private JPanel rightPanel;
    private JTabbedPane tabbedPane;      // For "Diff" vs "Flow Graph"
    private JTextPane leftPane;
    private JTextPane rightPane;
    private JLabel matchPercentageLabel;
    private JComboBox<String> algorithmCombo;
    private JButton prevButton;
    private JButton nextButton;

    // Our "Flow Graph" tab container
    private JPanel flowGraphContainerPanel;

    // Current text code for the pseudocode diff
    private String currentCode1;
    private String currentCode2;

    // The diff lines + difference navigation
    private List<LineDiff> currentDiffs = new ArrayList<>();
    private List<Integer> differenceLineIndices = new ArrayList<>();
    private int currentDiffIndex = -1;

    public DualFileComponentProvider(
        PluginTool tool,
        List<MatchedFunctionPair> matchedFunctions
    ) {
        super(tool, "PseudoDiffing", "DiffDisplay");
        createComponents(matchedFunctions);
    }

    private void createComponents(List<MatchedFunctionPair> matchedFunctions) {
        mainPanel = new JPanel(new BorderLayout());

        // ========== LEFT: Function list ==========
        functionListModel = new DefaultListModel<>();
        for (MatchedFunctionPair pair : matchedFunctions) {
            functionListModel.addElement(pair);
        }
        functionList = new JList<>(functionListModel);
        functionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        functionList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(
                JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus
            ) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof MatchedFunctionPair) {
                    MatchedFunctionPair pair = (MatchedFunctionPair) value;
                    String leftName = pair.functionNameFile1;
                    String rightName = pair.functionNameFile2;
                    if (leftName.equals(rightName)) {
                        setText(leftName);
                    } else {
                        setText(leftName + " -> " + rightName);
                    }
                }
                return this;
            }
        });

        functionList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                MatchedFunctionPair selected = functionList.getSelectedValue();
                if (selected != null) {
                    loadSelectedFunction(selected);
                }
            }
        });

        JScrollPane functionScroll = new JScrollPane(functionList);
        functionScroll.setPreferredSize(new Dimension(220, 600));

        // ========== RIGHT: top panel + tabbedPane ==========
        rightPanel = new JPanel(new BorderLayout());
        JPanel topPanel = new JPanel(new BorderLayout());

        // (A) Algorithm combo + match % on the left
        JPanel algoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        algoPanel.add(new JLabel("Choose Diff Algorithm:"));
        algorithmCombo = new JComboBox<>(new String[] { "Naive", "LCS", "Levenshtein" });
        algoPanel.add(algorithmCombo);

        matchPercentageLabel = new JLabel("Match %: 0.00");
        algoPanel.add(matchPercentageLabel);

        topPanel.add(algoPanel, BorderLayout.WEST);

        // (B) Arrow buttons on the right
        JPanel arrowPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        prevButton = new JButton("\u25B2"); // Up
        nextButton = new JButton("\u25BC"); // Down
        arrowPanel.add(prevButton);
        arrowPanel.add(nextButton);
        topPanel.add(arrowPanel, BorderLayout.EAST);

        rightPanel.add(topPanel, BorderLayout.NORTH);

        // ========== The Tabbed Pane ==========
        tabbedPane = new JTabbedPane();

        // Tab 1: The existing side-by-side code diff
        leftPane = new JTextPane();
        leftPane.setEditable(false);
        JScrollPane leftScroll = new JScrollPane(leftPane);
        leftScroll.setRowHeaderView(new LineNumberGutter(leftPane));

        rightPane = new JTextPane();
        rightPane.setEditable(false);
        JScrollPane rightScroll = new JScrollPane(rightPane);
        rightScroll.setRowHeaderView(new LineNumberGutter(rightPane));

        JSplitPane diffSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightScroll
        );
        diffSplit.setDividerLocation(0.5);

        tabbedPane.addTab("Pseudocode Diff", diffSplit);

        // Tab 2: Flow Graph
        flowGraphContainerPanel = new JPanel(new BorderLayout());
        tabbedPane.addTab("Flow Graph", flowGraphContainerPanel);

        rightPanel.add(tabbedPane, BorderLayout.CENTER);

        // (C) Bottom: color legend
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        legendPanel.add(new JLabel("MATCH (Black) - identical lines"));
        legendPanel.add(new JLabel("CHANGED (Red) - different lines"));
        legendPanel.add(new JLabel("ADDED (Green) - in right file only"));
        legendPanel.add(new JLabel("REMOVED (Orange) - in left file only"));
        rightPanel.add(legendPanel, BorderLayout.SOUTH);

        // Action listeners
        algorithmCombo.addActionListener(e -> refreshDiffDisplay());
        prevButton.addActionListener(e -> goToPreviousDifference());
        nextButton.addActionListener(e -> goToNextDifference());

        // ========== COMBINE LEFT + RIGHT ==========
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, functionScroll, rightPanel
        );
        mainSplit.setDividerLocation(0.28);

        mainPanel.add(mainSplit, BorderLayout.CENTER);

        // auto-select first function if any
        if (!matchedFunctions.isEmpty()) {
            functionList.setSelectedIndex(0);
        }
    }

    /**
     * Called whenever the user selects a function from the list.
     * 1) Load the code into the diff viewer
     * 2) Build the flow graph for that function in file1 (and maybe file2)
     */
    private void loadSelectedFunction(MatchedFunctionPair pair) {
        this.currentCode1 = pair.codeFile1;
        this.currentCode2 = pair.codeFile2;

        // Update the code diff
        refreshDiffDisplay();

        // Build a flow graph for (file1) or both sides if you want
        flowGraphContainerPanel.removeAll();
        try {
            if (pair.program1 != null && pair.entry1 != null) {
                // Build the CFG for file1
                PseudocodeDiffingPlugin plugin = (PseudocodeDiffingPlugin) getTool().getService(
                    PseudocodeDiffingPlugin.class
                );
                if (plugin != null) {
                    FlowGraphData gData = plugin.buildFlowGraph(pair.program1, pair.entry1);
                    FlowGraphPanel gPanel = new FlowGraphPanel(gData);
                    flowGraphContainerPanel.add(new JScrollPane(gPanel), BorderLayout.CENTER);
                }
            } else {
                // no function in file1
                flowGraphContainerPanel.add(new JLabel("No flow graph for file1"), BorderLayout.CENTER);
            }
        } catch (CancelledException e) {
            e.printStackTrace();
        }

        flowGraphContainerPanel.revalidate();
        flowGraphContainerPanel.repaint();
    }

    /**
     * Redo the line-based diff using the chosen algorithm, fill leftPane/rightPane
     */
    private void refreshDiffDisplay() {
        if (currentCode1 == null || currentCode2 == null) {
            leftPane.setText("");
            rightPane.setText("");
            matchPercentageLabel.setText("Match %: 0.00");
            return;
        }

        String algo = (String) algorithmCombo.getSelectedItem();
        currentDiffs = Utilities.computeDiffs(currentCode1, currentCode2, algo);

        differenceLineIndices.clear();
        StyledDocument leftDoc = new DefaultStyledDocument();
        StyledDocument rightDoc = new DefaultStyledDocument();

        StyleContext sc = new StyleContext();
        Style matchStyle = sc.addStyle("MATCH", null);
        StyleConstants.setForeground(matchStyle, Color.BLACK);

        Style changedStyle = sc.addStyle("CHANGED", null);
        StyleConstants.setForeground(changedStyle, Color.RED);

        Style addedStyle = sc.addStyle("ADDED", null);
        StyleConstants.setForeground(addedStyle, new Color(0, 128, 0));

        Style removedStyle = sc.addStyle("REMOVED", null);
        StyleConstants.setForeground(removedStyle, new Color(255, 140, 0));

        int matchCount = 0;
        int totalLines = currentDiffs.size();
        int leftPos = 0;
        int rightPos = 0;

        try {
            for (int i = 0; i < totalLines; i++) {
                LineDiff diff = currentDiffs.get(i);
                Style leftStyle, rightStyle;
                switch (diff.diffType) {
                    case MATCH:
                        leftStyle = matchStyle;
                        rightStyle = matchStyle;
                        matchCount++;
                        break;
                    case CHANGED:
                        leftStyle = changedStyle;
                        rightStyle = changedStyle;
                        differenceLineIndices.add(i);
                        break;
                    case ADDED:
                        leftStyle = sc.addStyle("DISABLED_LEFT", null);
                        StyleConstants.setForeground(leftStyle, Color.GRAY);
                        rightStyle = addedStyle;
                        differenceLineIndices.add(i);
                        break;
                    case REMOVED:
                        leftStyle = removedStyle;
                        rightStyle = sc.addStyle("DISABLED_RIGHT", null);
                        StyleConstants.setForeground(rightStyle, Color.GRAY);
                        differenceLineIndices.add(i);
                        break;
                    default:
                        leftStyle = matchStyle;
                        rightStyle = matchStyle;
                }
                leftDoc.insertString(leftPos, diff.leftLine + "\n", leftStyle);
                rightDoc.insertString(rightPos, diff.rightLine + "\n", rightStyle);

                leftPos += diff.leftLine.length() + 1;
                rightPos += diff.rightLine.length() + 1;
            }
        }
        catch (BadLocationException e) {
            e.printStackTrace();
        }

        leftPane.setDocument(leftDoc);
        rightPane.setDocument(rightDoc);

        double matchPct = 0.0;
        if (totalLines > 0) {
            matchPct = (matchCount / (double)totalLines) * 100.0;
        }
        matchPercentageLabel.setText(String.format("Match %%: %.2f", matchPct));

        if (!differenceLineIndices.isEmpty()) {
            currentDiffIndex = 0;
            highlightDifferenceLine();
        } else {
            currentDiffIndex = -1;
            leftPane.getHighlighter().removeAllHighlights();
            rightPane.getHighlighter().removeAllHighlights();
        }
    }

    private void highlightDifferenceLine() {
        if (currentDiffIndex < 0 || currentDiffIndex >= differenceLineIndices.size()) {
            return;
        }
        int lineIndex = differenceLineIndices.get(currentDiffIndex);
        Highlighter leftHi = leftPane.getHighlighter();
        Highlighter rightHi = rightPane.getHighlighter();
        leftHi.removeAllHighlights();
        rightHi.removeAllHighlights();

        Color highlightColor = new Color(255, 255, 150);
        try {
            int startLeft  = getLineStartOffset(leftPane.getDocument(), lineIndex);
            int endLeft    = getLineEndOffset  (leftPane.getDocument(), lineIndex);
            int startRight = getLineStartOffset(rightPane.getDocument(), lineIndex);
            int endRight   = getLineEndOffset  (rightPane.getDocument(), lineIndex);

            leftHi.addHighlight(startLeft, endLeft,
                new DefaultHighlighter.DefaultHighlightPainter(highlightColor));
            rightHi.addHighlight(startRight, endRight,
                new DefaultHighlighter.DefaultHighlightPainter(highlightColor));

            leftPane.setCaretPosition(startLeft);
            rightPane.setCaretPosition(startRight);
        }
        catch (BadLocationException e) {
            e.printStackTrace();
        }
    }

    private int getLineStartOffset(Document doc, int lineIndex) throws BadLocationException {
        if (lineIndex == 0) return 0;
        String text = doc.getText(0, doc.getLength());
        int count = 0;
        int offset = 0;
        while (count < lineIndex && offset < text.length()) {
            if (text.charAt(offset) == '\n') {
                count++;
            }
            offset++;
        }
        return offset;
    }

    private int getLineEndOffset(Document doc, int lineIndex) throws BadLocationException {
        String text = doc.getText(0, doc.getLength());
        int start = getLineStartOffset(doc, lineIndex);
        int offset = start;
        while (offset < text.length() && text.charAt(offset) != '\n') {
            offset++;
        }
        return offset;
    }

    private void goToPreviousDifference() {
        if (differenceLineIndices.isEmpty()) return;
        currentDiffIndex--;
        if (currentDiffIndex < 0) {
            currentDiffIndex = differenceLineIndices.size() - 1;
        }
        highlightDifferenceLine();
    }

    private void goToNextDifference() {
        if (differenceLineIndices.isEmpty()) return;
        currentDiffIndex++;
        if (currentDiffIndex >= differenceLineIndices.size()) {
            currentDiffIndex = 0;
        }
        highlightDifferenceLine();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    // Now we store addresses + program references so we can build flow graphs
    public static class MatchedFunctionPair {
        public String functionNameFile1;
        public String functionNameFile2;

        public Program program1;
        public Address entry1;
        public Program program2;
        public Address entry2;

        public String codeFile1;
        public String codeFile2;

        public MatchedFunctionPair(
            String fn1, String fn2,
            Program p1, Address a1,
            Program p2, Address a2,
            String code1, String code2
        ) {
            this.functionNameFile1 = fn1;
            this.functionNameFile2 = fn2;
            this.program1 = p1;
            this.entry1   = a1;
            this.program2 = p2;
            this.entry2   = a2;
            this.codeFile1= code1;
            this.codeFile2= code2;
        }
    }
}
