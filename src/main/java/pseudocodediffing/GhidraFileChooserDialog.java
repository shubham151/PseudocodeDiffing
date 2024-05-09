package pseudocodediffing;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;

import ghidra.framework.plugintool.PluginTool;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class GhidraFileChooserDialog {
//	public static File[] selectFiles(PluginTool tool) {
//	    JFileChooser fileChooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
//	    
//	    fileChooser.setDialogTitle("Select Binary Files");
//	    FileNameExtensionFilter filter = new FileNameExtensionFilter("Binary Files", "bin", "exe");
//	    fileChooser.addChoosableFileFilter(filter);
//	    int result = fileChooser.showOpenDialog(tool.getToolFrame());
//	    if (result == JFileChooser.APPROVE_OPTION) {
//	        File[] selectedFiles = fileChooser.getSelectedFiles();
//	        return selectedFiles;
//	    }
//	    return null;
//	}
	
	public static List<File[]> selectFiles(PluginTool tool) {
	    JFileChooser fileChooser1 = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
	    JFileChooser fileChooser2 = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
	    
	    fileChooser1.setDialogTitle("Select Binary File 1");
	    FileNameExtensionFilter filter1 = new FileNameExtensionFilter("Binary Files", "bin", "exe");
	    fileChooser1.addChoosableFileFilter(filter1);
	    
	    fileChooser2.setDialogTitle("Select Binary File 2");
	    FileNameExtensionFilter filter2 = new FileNameExtensionFilter("Binary Files", "bin", "exe");
	    fileChooser2.addChoosableFileFilter(filter2);
	    
	    int result1 = fileChooser1.showOpenDialog(tool.getToolFrame());
	    int result2 = fileChooser2.showOpenDialog(tool.getToolFrame());
	    
	    List<File[]> selectedFilesList = new ArrayList<>();
	    
	    if (result1 == JFileChooser.APPROVE_OPTION && result2 == JFileChooser.APPROVE_OPTION) {
	        File[] selectedFiles1 = fileChooser1.getSelectedFiles();
	        File[] selectedFiles2 = fileChooser2.getSelectedFiles();
	        
	        selectedFilesList.add(selectedFiles1);
	        selectedFilesList.add(selectedFiles2);
	    }
	    
	    return selectedFilesList;
	}

	
	





}
