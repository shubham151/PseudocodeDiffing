package pseudocodediffing;

import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.List;

/**
 * A container holding nodes/edges of a function's flow graph.
 */
public class FlowGraphData {

    public static class Node {
        public String id;        // an identifier like "Block_0", "Block_1"
        public Address start;    // the block's start address
        public Address end;      // the block's end address
    }

    public static class Edge {
        public String fromId;
        public String toId;
    }

    public List<Node> nodes = new ArrayList<>();
    public List<Edge> edges = new ArrayList<>();
}
