
package pseudocodediffing;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
//import ghidra.util.CancelledException;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.TaskMonitor;

/**
 * A plugin that imports two files, matches functions by name,
 * and then shows a "BinDiff-like" UI with a function list,
 * side-by-side pseudocode diff, and a flow graph tab.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "PseudocodeDiffing",
    description = "Demonstrates multi-algo side-by-side diff, function-level, plus a flow graph tab."
)
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
                    Msg.showError(this, null, "Error", "Exception thrown while selecting files", e);
                }
            }
        };
        action.setMenuBarData(new MenuData(
            new String[] { "Window", "PseudocodeDiff" }, 
            null, 
            WINDOW_GROUP
        ));
        tool.addAction(action);
    }

    private void selectFiles() throws Exception {
        try {
            List<File[]> selectedFilesList = GhidraFileChooserDialog.selectFiles(tool);
            if (selectedFilesList.size() == 1) {
                File file1 = selectedFilesList.get(0)[0];
                File file2 = selectedFilesList.get(0)[1];
                if (file1 != null && file2 != null) {
                    Program program1 = openProgram(file1);
                    Program program2 = openProgram(file2);
                    if (program1 == null || program2 == null) {
                        Msg.showError(this, null, "Error", "Failed to open programs.");
                        return;
                    }

                    // Gather function pairs, storing addresses
                    List<DualFileComponentProvider.MatchedFunctionPair> pairs =
                        gatherMatchedFunctions(program1, program2);

                    // Show them in the BinDiff-like provider
                    DualFileComponentProvider provider =
                        new DualFileComponentProvider(tool, pairs);
                    tool.addComponentProvider(provider, true);

                    // Keep or release the programs as needed...
                }
                else {
                    Msg.showError(this, null, "Error", "Please select exactly two files.");
                }
            } else {
                Msg.showError(this, null, "Error", "Please select exactly two files.");
            }
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Error while selecting files.", e);
        }
    }

    /**
     * Return a Map name->(code, address) by decompiling each function in the program.
     */
    private Map<String, PairInfo> decompileAllFunctions(Program program) {
        Map<String, PairInfo> result = new HashMap<>();
        FlatProgramAPI flatAPI = new FlatProgramAPI(program);
        FlatDecompilerAPI decompilerAPI = new FlatDecompilerAPI(flatAPI);

        for (Function fn : program.getFunctionManager().getFunctions(true)) {
            try {
                String dec = decompilerAPI.decompile(fn, 30);
                result.put(fn.getName(), new PairInfo(dec, fn.getEntryPoint()));
            }
            catch (Exception e) {
                Msg.warn(this, "Failed to decompile " + fn.getName());
            }
        }
        return result;
    }

    private List<DualFileComponentProvider.MatchedFunctionPair>
        gatherMatchedFunctions(Program program1, Program program2) 
    {
        // Decompile + store (code, address)
        Map<String, PairInfo> map1 = decompileAllFunctions(program1);
        Map<String, PairInfo> map2 = decompileAllFunctions(program2);

        List<DualFileComponentProvider.MatchedFunctionPair> pairs = new ArrayList<>();

        // For each function in file1
        for (String fn1 : map1.keySet()) {
            PairInfo pi1 = map1.get(fn1);
            if (map2.containsKey(fn1)) {
                // matched
                PairInfo pi2 = map2.get(fn1);
                pairs.add(new DualFileComponentProvider.MatchedFunctionPair(
                    fn1,           // file1 name
                    fn1,           // file2 name
                    program1,      // store the Program
                    pi1.entry,     // store the function entry
                    program2,
                    pi2.entry,
                    pi1.decompiled,
                    pi2.decompiled
                ));
            }
            else {
                // in file1 only
                pairs.add(new DualFileComponentProvider.MatchedFunctionPair(
                    fn1,
                    "(unmatched in file2)",
                    program1,
                    pi1.entry,
                    null,
                    null,
                    pi1.decompiled,
                    ""
                ));
            }
        }

        // leftover in file2
        for (String fn2 : map2.keySet()) {
            if (!map1.containsKey(fn2)) {
                PairInfo pi2 = map2.get(fn2);
                pairs.add(new DualFileComponentProvider.MatchedFunctionPair(
                    "(unmatched in file1)",
                    fn2,
                    null,
                    null,
                    program2,
                    pi2.entry,
                    "",
                    pi2.decompiled
                ));
            }
        }

        return pairs;
    }

    private Program openProgram(File file) {
        try {
            Project project = tool.getProject();
            DomainFolder root = project.getProjectData().getRootFolder();
            MessageLog log = new MessageLog();
            TaskMonitor monitor = new TaskMonitorAdapter();
            LoadResults<Program> results =
                AutoImporter.importByUsingBestGuess(
                    file, project, root.getPathname(), this, log, monitor);

            if (results == null || results.getPrimaryDomainObject() == null) {
                Msg.showError(this, null, "Error", 
                    "Failed to import program: " + file.getName());
                return null;
            }
            Program program = results.getPrimaryDomainObject();
            if (program == null) {
                Msg.showError(this, null, "Error", 
                    "Failed to open program: " + file.getName());
            }
            return program;
        }
        catch (Exception e) {
            Msg.showError(this, null, "Error", 
                "Failed to open program: " + file.getName(), e);
            return null;
        }
    }

    /**
     * Build a FlowGraphData for the function at the given address in the given program.
     */
    public FlowGraphData buildFlowGraph(Program program, Address funcEntry) throws CancelledException {
        FlowGraphData gData = new FlowGraphData();
        if (program == null || funcEntry == null) {
            return gData; // empty
        }
        BasicBlockModel bbm = new BasicBlockModel(program);
        Function f = program.getFunctionManager().getFunctionAt(funcEntry);
        if (f == null) {
            return gData;
        }
        CodeBlockIterator iter = bbm.getCodeBlocksContaining(f.getBody(), new TaskMonitorAdapter());
        Map<CodeBlock, String> blockToId = new HashMap<>();
        int blockCount = 0;

        // gather blocks
        while (iter.hasNext()) {
            CodeBlock block = iter.next();
            String blockId = "B" + (blockCount++);
            FlowGraphData.Node node = new FlowGraphData.Node();
            node.id = blockId;
            node.start = block.getMinAddress();
            node.end   = block.getMaxAddress();
            gData.nodes.add(node);
            blockToId.put(block, blockId);
        }

        // gather edges
        // reset the iterator
        iter = bbm.getCodeBlocksContaining(f.getBody(), new TaskMonitorAdapter());
        while (iter.hasNext()) {
            CodeBlock block = iter.next();
            String fromId = blockToId.get(block);
            CodeBlockReferenceIterator dests = block.getDestinations(new TaskMonitorAdapter());
            while (dests.hasNext()) {
                CodeBlockReference ref = dests.next();
                CodeBlock destBlock = ref.getDestinationBlock();
                String toId = blockToId.get(destBlock);
                if (toId != null) {
                    FlowGraphData.Edge edge = new FlowGraphData.Edge();
                    edge.fromId = fromId;
                    edge.toId   = toId;
                    gData.edges.add(edge);
                }
            }
        }

        return gData;
    }

    // store a small record of (decompiled text, function entry address)
    private static class PairInfo {
        String decompiled;
        Address entry;
        PairInfo(String dec, Address entry) {
            this.decompiled = dec;
            this.entry = entry;
        }
    }
}

