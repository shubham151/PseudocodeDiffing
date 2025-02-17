package pseudocodediffing;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;

/**
 * A simple line-number gutter for a text component (like JTextPane or JTextArea).
 * We attach it to the row header of the JScrollPane.
 */
public class LineNumberGutter extends JComponent {
    private static final long serialVersionUID = 1L;

    private final JTextComponent textComponent;
    private final FontMetrics fontMetrics;
    private final int lineHeight;

    public LineNumberGutter(JTextComponent textComponent) {
        this.textComponent = textComponent;
        setFont(textComponent.getFont());
        fontMetrics = getFontMetrics(getFont());
        lineHeight = fontMetrics.getHeight();
        setPreferredSize(new Dimension(40, Integer.MAX_VALUE));
        setForeground(Color.GRAY);
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Rectangle visibleRect = textComponent.getVisibleRect(); 
        int startOffset = visibleRect.y;
        int startLine = startOffset / lineHeight;

        // Count total lines by scanning for '\n' or via doc structure
        int totalLines = getTotalLines();
        int endLine = Math.min(totalLines, 
                        (visibleRect.y + visibleRect.height) / lineHeight + 1);

        // Baseline offset so first visible line is drawn in the correct place
        int y = -(startOffset % lineHeight) + lineHeight; 

        for (int lineIndex = startLine; lineIndex < endLine; lineIndex++) {
            String lineStr = String.valueOf(lineIndex + 1);
            int x = getWidth() - fontMetrics.stringWidth(lineStr) - 5;
            g.drawString(lineStr, x, y - 3); 
            y += lineHeight;
        }
    }

    private int getTotalLines() {
        try {
            String text = textComponent.getDocument().getText(0, 
                                     textComponent.getDocument().getLength());
            int lines = 1;
            for (int i = 0; i < text.length(); i++) {
                if (text.charAt(i) == '\n') {
                    lines++;
                }
            }
            return lines;
        } catch (BadLocationException e) {
            e.printStackTrace();
            return 1;
        }
    }
}
