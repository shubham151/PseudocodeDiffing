package pseudocodediffing;

import java.io.File;
import java.util.List;
import java.util.ArrayList;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;



//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)


//@formatter:on
public class PseudocodeDiffingPlugin extends ProgramPlugin {

  private static final String WINDOW_GROUP = "PseudocodeDiffingPlugin";
  private static final String ACTION_NAME = "Pseudocode Diffing";

  public PseudocodeDiffingPlugin(PluginTool tool) {
      super(tool);
  }

  @Override
  protected void init() {
      super.init();
      createActions();
  }

  private void createActions() {
      DockingAction action = new DockingAction(ACTION_NAME, getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
              try {
				selectFiles();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.getStackTrace();
			}
          }
      };
      action.setMenuBarData(new MenuData(new String[] { "Window", "Pseudocode Diffing" }, null, WINDOW_GROUP));
      tool.addAction(action);
  }

  private void selectFiles() throws Exception {
      try {
          List<File[]> selectedFilesList = GhidraFileChooserDialog.selectFiles(tool);
          Msg.info(this, "Selected files list size: " + selectedFilesList.size());

          List<File> absoluteFilePaths = new ArrayList<>();

          for (File[] fileArray : selectedFilesList) {
              for (File file : fileArray) {
                  absoluteFilePaths.add(file.getAbsoluteFile());
                  Msg.info(this, "Selected file: " + file.getAbsolutePath());
              }
          }

          if (selectedFilesList != null && selectedFilesList.size() == 2) {
              if (selectedFilesList.get(0).length > 0 && selectedFilesList.get(1).length > 0) {
                  File file1 = absoluteFilePaths.get(0);
                  File file2 = absoluteFilePaths.get(1);

                  // Decompile the selected files and compare them
                  decompileAndCompareFiles(file1, file2);
              } else {
                  Msg.showError(this, null, "Error", "One or both file selections are empty. Please select exactly two files.");
              }
          } else {
              Msg.showError(this, null, "Error", "Please select exactly two files.");
          }
      } catch (Exception e) {
          Msg.showError(this, null, "Error", "An error occurred while selecting files.", e);
      }
  }



  private void decompileAndCompareFiles(File file1, File file2) throws Exception {
      try {
    	  
          String decompiledCode1 = decompileFile(file1);
          String decompiledCode2 = decompileFile(file2);

          DualFileComponentProvider dualFileProvider = new DualFileComponentProvider(tool, decompiledCode1, decompiledCode2);

          tool.addComponentProvider(dualFileProvider, true);
      } catch (Exception e) {
          Msg.showError(this, null, "Error", "An error occurred during decompilation and comparison.", e);
      }
  }
  private String decompileFile(File file) throws Exception {
	    Program program = openProgram(file);
	    if (program == null) {
	        Msg.showError(this, null, "Error", "Failed to open program: " + file.getName());
	        return "";
	    }

	    StringBuilder decompiledCode = new StringBuilder();

	    try {
	        FlatProgramAPI flatAPI = new FlatProgramAPI(program);
	        FlatDecompilerAPI decompilerAPI = new FlatDecompilerAPI(flatAPI);

	        for (Function function : program.getFunctionManager().getFunctions(true)) {
	            try {
	                String functionDecompiledCode = decompilerAPI.decompile(function, 30);
	                decompiledCode.append("// Function: ").append(function.getName()).append("\n")
	                               .append(functionDecompiledCode).append("\n\n");
	            } catch (Exception e) {
	                Msg.showError(this, null, "Error", "Failed to decompile function: " + function.getName(), e);
	            }
	        }

	        return decompiledCode.toString();
	    } finally {
	        program.release(this);
	    }
	}

  private Program openProgram(File file) {
	    Program program = null;

	    try {
	        Project project = tool.getProject();
	        DomainFolder rootFolder = project.getProjectData().getRootFolder();
	        
	        MessageLog log = new MessageLog();
	        TaskMonitor monitor = new TaskMonitorAdapter();

	        LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(file, project, rootFolder.getPathname(), this, log, monitor);
	        if (loadResults == null || loadResults.getPrimaryDomainObject() == null) {
	            Msg.showError(this, null, "Error", "Failed to import program: " + file.getName());
	            return null;
	        }

	        program = loadResults.getPrimaryDomainObject();
	        if (program == null) {
	            Msg.showError(this, null, "Error", "Failed to open program: " + file.getName());
	        }

	    } catch (Exception e) {
	        Msg.showError(this, null, "Error", "Failed to open program file: " + file.getName(), e);
	    }

	    return program;
	}   
}