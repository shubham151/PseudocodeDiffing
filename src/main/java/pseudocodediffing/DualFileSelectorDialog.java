package pseudocodediffing;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.File;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import ghidra.framework.plugintool.PluginTool;

/**
 * Custom modal dialog that displays two separate file fields with "Browse" buttons.
 */
public class DualFileSelectorDialog extends JDialog {

    private JTextField file1Field;
    private JTextField file2Field;

    private File file1;
    private File file2;

    private boolean okPressed = false;

    /**
     * Constructs and displays a modal dialog allowing the user
     * to pick exactly 2 files, each in a separate field.
     */
    public DualFileSelectorDialog(PluginTool tool) {
        super(SwingUtilities.windowForComponent(tool.getToolFrame()), 
              "Select Two Files", ModalityType.APPLICATION_MODAL);

        initComponents();
        pack();
        setLocationRelativeTo(tool.getToolFrame()); // center on Ghidra's main window
    }

    private void initComponents() {
        // We'll use a panel in the center with a GridBagLayout
        JPanel centerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Row 1: "File 1" label, textField, "Browse" button
        gbc.gridy = 0;
        gbc.gridx = 0;
        centerPanel.add(new JLabel("File 1:"), gbc);

        file1Field = new JTextField(30);
        gbc.gridx = 1;
        centerPanel.add(file1Field, gbc);

        JButton browseBtn1 = new JButton("Browse...");
        browseBtn1.addActionListener(e -> browseFile(file1Field));
        gbc.gridx = 2;
        centerPanel.add(browseBtn1, gbc);

        // Row 2: "File 2" label, textField, "Browse" button
        gbc.gridy = 1;
        gbc.gridx = 0;
        centerPanel.add(new JLabel("File 2:"), gbc);

        file2Field = new JTextField(30);
        gbc.gridx = 1;
        centerPanel.add(file2Field, gbc);

        JButton browseBtn2 = new JButton("Browse...");
        browseBtn2.addActionListener(e -> browseFile(file2Field));
        gbc.gridx = 2;
        centerPanel.add(browseBtn2, gbc);

        // ---- OK/Cancel Buttons in a separate panel at the bottom ----
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("OK");
        okBtn.addActionListener(this::handleOk);
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(this::handleCancel);

        bottomPanel.add(okBtn);
        bottomPanel.add(cancelBtn);

        // Add panels to the dialog
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(centerPanel, BorderLayout.CENTER);
        getContentPane().add(bottomPanel, BorderLayout.SOUTH);
    }

    /**
     * Pops up a JFileChooser to pick a single file, then updates the given text field with the chosen path.
     */
    private void browseFile(JTextField textField) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // Optionally set up a file filter
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Binary Files", "bin", "exe");
        chooser.setFileFilter(filter);

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File chosen = chooser.getSelectedFile();
            if (chosen != null) {
                textField.setText(chosen.getAbsolutePath());
            }
        }
    }

    private void handleOk(ActionEvent e) {
        // Validate that we have 2 files
        String path1 = file1Field.getText().trim();
        String path2 = file2Field.getText().trim();
        if (path1.isEmpty() || path2.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Please select both files before clicking OK!",
                "Validation Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        file1 = new File(path1);
        file2 = new File(path2);

        if (!file1.exists() || !file2.exists()) {
            JOptionPane.showMessageDialog(this, 
                "One or both files do not exist!\nCheck your file paths.",
                "File Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        okPressed = true;
        dispose();
    }

    private void handleCancel(ActionEvent e) {
        okPressed = false;
        dispose();
    }

    /**
     * After the dialog closes, if OK was pressed and both file paths are valid,
     * this returns a File[] of length 2. Otherwise returns null.
     */
    public File[] getSelectedFiles() {
        if (okPressed) {
            return new File[] { file1, file2 };
        }
        return null;
    }

    // ---------- Static helper method to show the dialog  ----------

    /**
     * Shows the dual-file dialog modally, and returns an array of length 2 if the user pressed OK,
     * or null if canceled or invalid.
     */
    public static File[] showDualFileDialog(PluginTool tool) {
        DualFileSelectorDialog dialog = new DualFileSelectorDialog(tool);
        dialog.setVisible(true); // blocks until user closes
        return dialog.getSelectedFiles(); // either two Files or null
    }
}
