package pseudocodediffing;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import resources.Icons;

import javax.swing.*;

import java.awt.BorderLayout;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class ComponentProviderFactory {

    public static ComponentProvider createFileComponentProvider(PluginTool tool, File file) {
        return new FileComponentProvider(tool, file);
    }

    private static class FileComponentProvider extends ComponentProvider {
        private File file;

        public FileComponentProvider(PluginTool tool, File file) {
            super(tool, file.getName(), "Pseudocode Diffing");
            this.file = file;
            setIcon(Icons.ADD_ICON);
        }

        @Override
        public JComponent getComponent() {
            JTextArea textArea = new JTextArea();
            textArea.setEditable(false);

            // Load and display the content of the file in the component
            textArea.setText(loadFileContent(file));

            JScrollPane scrollPane = new JScrollPane(textArea);
            JPanel panel = new JPanel(new BorderLayout());
            panel.add(scrollPane, BorderLayout.CENTER);

            return panel;
        }

        // Method to load file content
        private String loadFileContent(File file1) {
            try {
                byte[] fileBytes = Files.readAllBytes(file1.toPath());
                // Convert the bytes to a readable format (hexadecimal for binary files)
                StringBuilder sb = new StringBuilder();
                for (byte b : fileBytes) {
                    sb.append(String.format("%02X ", b));
                }
                return sb.toString();
            } catch (IOException e) {
                return "Failed to load file content: " + e.getMessage();
            }
        }
    }
}
