package pseudocodediffing;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.plugintool.PluginTool;

public class GhidraFileChooserDialog {

    /**
     * Provide a static method similar to your original code, but behind the scenes
     * it calls the custom DualFileSelectorDialog. Returns a List<File[]> for
     * compatibility with your existing logic.
     */
    public static List<File[]> selectFiles(PluginTool tool) {
        List<File[]> selectedFilesList = new ArrayList<>();
        File[] twoFiles = DualFileSelectorDialog.showDualFileDialog(tool);
        if (twoFiles != null && twoFiles.length == 2) {
            selectedFilesList.add(twoFiles);
        }
        return selectedFilesList;
    }
}
