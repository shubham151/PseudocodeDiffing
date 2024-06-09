package pseudocodediffing;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
//import resources.Icons;

import java.awt.BorderLayout;

import javax.swing.*;

public class DualFileComponentProvider extends ComponentProvider {
    private JPanel mainPanel;
    private JTextArea codeArea1;
    private JTextArea codeArea2;

    public DualFileComponentProvider(PluginTool tool, String code1, String code2) {
        super(tool, "File Comparison", "Displays comparison of two files");
        createComponents(code1, code2);
    }

    private void createComponents(String code1, String code2) {
        codeArea1 = new JTextArea(code1);
        codeArea1.setEditable(false);
        codeArea2 = new JTextArea(code2);
        codeArea2.setEditable(false);

        mainPanel = new JPanel(new BorderLayout());
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(codeArea1), new JScrollPane(codeArea2));
        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
