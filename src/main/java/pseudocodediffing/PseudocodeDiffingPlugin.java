/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pseudocodediffing;

import java.awt.BorderLayout;
import java.io.File;
import java.util.List;


import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;


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
                selectFiles();
            }
        };
        action.setMenuBarData(new MenuData(new String[] { "Window", "Pseudocode Diffing" }, null, WINDOW_GROUP));
        tool.addAction(action);
    }

    private void selectFiles() {
        // Use file chooser dialog to prompt user to select two files
        List<File[]> selectedFilesList = GhidraFileChooserDialog.selectFiles(tool);
        
        if (selectedFilesList != null && selectedFilesList.size() == 2) {
            File[] selectedFiles1 = selectedFilesList.get(0);
            File[] selectedFiles2 = selectedFilesList.get(1);
            
            System.out.println("Selected both files");
            // processFiles(selectedFiles1[0], selectedFiles2[0]);
        } else {
            Msg.showError(this, null, "Error", "Please select exactly two files.");
        }
    }

}