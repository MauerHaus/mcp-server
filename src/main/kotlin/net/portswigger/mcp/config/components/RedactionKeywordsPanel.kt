package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.*
import net.portswigger.mcp.security.findBurpFrame
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.*
import javax.swing.*
import javax.swing.JOptionPane.*

class RedactionKeywordsPanel(private val config: McpConfig) : JPanel() {

    private var listenerHandle: ListenerHandle? = null
    private var refreshListener: (() -> Unit)? = null

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Custom Redaction Keywords"))
        add(Box.createVerticalStrut(Design.Spacing.MD))

        val descLabel = JLabel("Specify keywords to redact from HTTP and WebSocket messages.").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)
        }
        val examplesLabel = JLabel("Examples: api-key, secret-token, internal-domain.com").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
        }
        add(descLabel)
        add(examplesLabel)

        val listModel = DefaultListModel<String>()
        val keywordsList = createKeywordsList(listModel)
        updateKeywordsList(listModel)

        refreshListener = {
            SwingUtilities.invokeLater {
                updateKeywordsList(listModel)
            }
        }
        listenerHandle = config.addRedactionKeywordsChangeListener(refreshListener!!)

        val scrollPane = createScrollPane(keywordsList)
        val tableContainer = createTableContainer(scrollPane)
        add(tableContainer)

        val buttonsPanel = createButtonsPanel(keywordsList, listModel)
        add(buttonsPanel)
    }

    private fun createKeywordsList(listModel: DefaultListModel<String>): JList<String> {
        return object : JList<String>(listModel) {
            private var rolloverIndex = -1

            init {
                selectionMode = ListSelectionModel.SINGLE_SELECTION
                visibleRowCount = 5
                font = Design.Typography.bodyMedium
                background = Design.Colors.listBackground
                foreground = Design.Colors.onSurface
                border = BorderFactory.createEmptyBorder(
                    Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD
                )
                cellRenderer = createCellRenderer()
                addMouseMotionListener(createMouseMotionListener())
                addMouseListener(createMouseListener())
                addKeyListener(createKeyListener(listModel))
                isFocusable = true
            }

            private fun createCellRenderer() = object : DefaultListCellRenderer() {
                override fun getListCellRendererComponent(
                    list: JList<*>, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean
                ): Component {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                    border = BorderFactory.createEmptyBorder(
                        Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD
                    )

                    val isRollover = index == rolloverIndex && !isSelected

                    when {
                        isSelected -> {
                            background = Design.Colors.listSelectionBackground
                            foreground = Design.Colors.listSelectionForeground
                        }

                        isRollover -> {
                            background = Design.Colors.listHoverBackground
                            foreground = Design.Colors.onSurface
                        }

                        else -> {
                            background =
                                if (index % 2 == 0) Design.Colors.listBackground else Design.Colors.listAlternatingBackground
                            foreground = Design.Colors.onSurface
                        }
                    }
                    return this
                }
            }

            private fun createMouseMotionListener() = object : MouseMotionAdapter() {
                override fun mouseMoved(e: MouseEvent) {
                    try {
                        val index = locationToIndex(e.point)
                        val newRolloverIndex = if (index >= 0 && index < model.size && getCellBounds(
                                index, index
                            )?.contains(e.point) == true
                        ) {
                            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                            index
                        } else {
                            cursor = Cursor.getDefaultCursor()
                            -1
                        }

                        if (rolloverIndex != newRolloverIndex) {
                            rolloverIndex = newRolloverIndex
                            repaint()
                        }
                    } catch (_: Exception) {
                        rolloverIndex = -1
                        cursor = Cursor.getDefaultCursor()
                    }
                }
            }

            private fun createMouseListener() = object : MouseAdapter() {
                override fun mouseExited(e: MouseEvent) {
                    if (rolloverIndex != -1) {
                        rolloverIndex = -1
                        cursor = Cursor.getDefaultCursor()
                        repaint()
                    }
                }
            }

            private fun createKeyListener(listModel: DefaultListModel<String>) = object : KeyAdapter() {
                override fun keyPressed(e: KeyEvent) {
                    when (e.keyCode) {
                        KeyEvent.VK_DELETE, KeyEvent.VK_BACK_SPACE -> {
                            if (selectedIndex >= 0 && selectedIndex < model.size) {
                                try {
                                    removeKeyword(selectedIndex, listModel)
                                    e.consume()
                                } catch (ex: Exception) {
                                    ex.printStackTrace()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun createScrollPane(keywordsList: JList<String>): JScrollPane {
        return JScrollPane(keywordsList).apply {
            val baseHeight = 220
            val baseWidth = 400
            val scaleFactor = Design.Spacing.MD / 16f
            val responsiveHeight = (baseHeight * scaleFactor).toInt().coerceAtLeast(150)
            val responsiveWidth = (baseWidth * scaleFactor).toInt().coerceAtLeast(250)

            maximumSize = Dimension(Int.MAX_VALUE, responsiveHeight)
            preferredSize = Dimension(responsiveWidth, responsiveHeight)
            minimumSize = Dimension((responsiveWidth * 0.625f).toInt(), (responsiveHeight * 0.68f).toInt())
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.listBorder, 1), BorderFactory.createEmptyBorder(1, 1, 1, 1)
            )
            background = Design.Colors.listBackground
            viewport.background = Design.Colors.listBackground
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }
    }

    private fun createTableContainer(scrollPane: JScrollPane): JPanel {
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
            add(scrollPane)
        }
    }

    private fun createButtonsPanel(keywordsList: JList<String>, listModel: DefaultListModel<String>): JPanel {
        val buttonsPanel = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, Design.Spacing.SM)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(Design.Spacing.SM, 0, 0, 0)
        }

        val addButton = Design.createFilledButton("Add").apply {
            addActionListener {
                val input = Dialogs.showInputDialog(
                    findBurpFrame(),
                    "Enter keyword to redact:\nExamples: api-key, secret-token, internal-domain.com"
                )

                if (!input.isNullOrBlank()) {
                    val trimmed = input.trim()
                    if (trimmed.isNotEmpty()) {
                        addKeyword(trimmed, listModel)
                    } else {
                        Dialogs.showMessageDialog(
                            findBurpFrame(),
                            "Keyword cannot be empty",
                            ERROR_MESSAGE
                        )
                    }
                }
            }
        }

        val removeButton = Design.createOutlinedButton("Remove").apply {
            addActionListener {
                val selectedIndex = keywordsList.selectedIndex
                if (selectedIndex >= 0) {
                    removeKeyword(selectedIndex, listModel)
                }
            }
        }

        val clearButton = Design.createOutlinedButton("Clear All").apply {
            addActionListener {
                val result = Dialogs.showConfirmDialog(
                    findBurpFrame(), "Remove all custom redaction keywords?", YES_NO_OPTION
                )

                if (result == YES_OPTION) {
                    clearAllKeywords(listModel)
                }
            }
        }

        buttonsPanel.add(addButton)
        buttonsPanel.add(removeButton)
        buttonsPanel.add(clearButton)

        return buttonsPanel
    }

    private fun updateKeywordsList(listModel: DefaultListModel<String>) {
        listModel.clear()
        config.getCustomRedactionKeywordsList().forEach {
            listModel.addElement(it)
        }
    }

    private fun addKeyword(keyword: String, listModel: DefaultListModel<String>) {
        val added = config.addCustomRedactionKeyword(keyword)
        if (added) {
            updateKeywordsList(listModel)
        } else {
            Dialogs.showMessageDialog(
                findBurpFrame(),
                "Keyword already exists or is invalid",
                INFORMATION_MESSAGE
            )
        }
    }

    private fun removeKeyword(index: Int, listModel: DefaultListModel<String>) {
        if (index >= 0 && index < listModel.size()) {
            val keyword = listModel.getElementAt(index)
            config.removeCustomRedactionKeyword(keyword)
            updateKeywordsList(listModel)
        }
    }

    private fun clearAllKeywords(listModel: DefaultListModel<String>) {
        config.clearCustomRedactionKeywords()
        updateKeywordsList(listModel)
    }

    fun cleanup() {
        listenerHandle?.remove()
        listenerHandle = null
        refreshListener = null
    }
}
