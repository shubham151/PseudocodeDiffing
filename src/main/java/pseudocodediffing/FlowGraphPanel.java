package pseudocodediffing;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * A simple Swing panel that draws a naive node-link diagram
 * for a given FlowGraphData. Real-world usage would do a more
 * advanced layout algorithm or library.
 */
public class FlowGraphPanel extends JPanel {

    private FlowGraphData graphData;
    private Map<String, Point> nodePositions = new HashMap<>();

    public FlowGraphPanel(FlowGraphData graphData) {
        this.graphData = graphData;
        setPreferredSize(new Dimension(600, 600));
        doSimpleLayout();
    }

    /**
     * Just stack each block vertically for demonstration.
     */
    private void doSimpleLayout() {
        int x = 100;
        int y = 60;
        int yGap = 80;

        int index = 0;
        for (FlowGraphData.Node node : graphData.nodes) {
            nodePositions.put(node.id, new Point(x, y + index * yGap));
            index++;
        }
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);

        // Draw edges first
        g.setColor(Color.BLACK);
        for (FlowGraphData.Edge e : graphData.edges) {
            Point p1 = nodePositions.get(e.fromId);
            Point p2 = nodePositions.get(e.toId);
            if (p1 != null && p2 != null) {
                g.drawLine(p1.x, p1.y, p2.x, p2.y);
            }
        }

        // Draw nodes
        for (FlowGraphData.Node n : graphData.nodes) {
            Point pt = nodePositions.get(n.id);
            if (pt == null) continue;

            // rectangle
            int w = 80, h = 40;
            int left = pt.x - w / 2;
            int top  = pt.y - h / 2;

            g.setColor(Color.LIGHT_GRAY);
            g.fillRect(left, top, w, h);
            g.setColor(Color.BLACK);
            g.drawRect(left, top, w, h);

            // Label with the block's start address or ID
            String label = n.start != null ? n.start.toString() : n.id;
            g.drawString(label, left + 5, top + 20);
        }
    }
}
