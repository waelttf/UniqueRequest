# -*- coding: utf-8 -*-
"""
Burp Suite extension that helps identify unique requests by normalizing paths and handling GraphQL operations.
Provides two modes: Normal Request mode for standard HTTP requests and GraphQL mode for GraphQL operations.
"""

from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JSplitPane,
    JPopupMenu, JMenuItem, JTextField, JLabel, JOptionPane,
    JCheckBoxMenuItem, JToggleButton, ButtonGroup, Box, Timer
)
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing import RowFilter, SortOrder
from java.awt import BorderLayout, Dimension, GridLayout
from java.awt.event import MouseAdapter, ActionListener
from java.util import Comparator
import hashlib
import re
import json


class NumericComparator(Comparator):
    """Comparator for numeric sorting in table columns."""
    def compare(self, a, b):
        try:
            return int(a) - int(b)
        except:
            return 0


class BurpExtender(IBurpExtender, ITab, IMessageEditorController):
    """Main extension class implementing the unique request analyzer functionality."""

    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension with Burp Suite callbacks."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("UniqueRequest")

        # Initialize data stores
        self.normal_requests = []
        self.graphql_requests = []
        self.current_mode = "normal"
        self._current_request = None
        self._current_response = None
        self._current_service = None

        # Initialize UI components
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        self._setup_ui()
        callbacks.addSuiteTab(self)

    def _setup_ui(self):
        """Set up the main UI components and layout."""
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setPreferredSize(Dimension(800, 600))

        # Mode toggle panel
        mode_panel = JPanel()
        self._normal_mode_btn = JToggleButton("Normal Requests", True, actionPerformed=self._switch_mode)
        self._graphql_mode_btn = JToggleButton("GraphQL Requests", False, actionPerformed=self._switch_mode)
        
        btn_group = ButtonGroup()
        btn_group.add(self._normal_mode_btn)
        btn_group.add(self._graphql_mode_btn)
        
        mode_panel.add(self._normal_mode_btn)
        mode_panel.add(self._graphql_mode_btn)
        self._main_panel.add(mode_panel, BorderLayout.NORTH)

        # Create shared viewer split pane
        self._viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._viewer_split.setLeftComponent(self._requestViewer.getComponent())
        self._viewer_split.setRightComponent(self._responseViewer.getComponent())
        self._viewer_split.setDividerLocation(0.4)

        # Central panel for mode-specific content
        self._central_panel = JPanel(BorderLayout())
        self._main_panel.add(self._central_panel, BorderLayout.CENTER)

        # Initialize both modes' UIs
        self._init_normal_ui()
        self._init_graphql_ui()
        
        # Start with normal mode visible
        self._switch_to_mode("normal")

    def _init_normal_ui(self):
        """Initialize the normal request mode UI components."""
        self._normal_panel = JPanel(BorderLayout())

        # Top controls
        top_panel = JPanel()
        self._normal_start_btn = JButton("Start", actionPerformed=self._run_normal_analysis)
        self._normal_clear_btn = JButton("Clear All", actionPerformed=self._clear_normal_all)
        self._normal_search_field = JTextField(25)
        self._normal_search_field.getDocument().addDocumentListener(SearchListener(self, "normal"))
        
        self._normal_filter_btn = JButton("Filter", actionPerformed=self._show_normal_filter_menu)

        # Filter menu
        self._normal_filter_menu = JPopupMenu()
        self._normal_filter_post = JCheckBoxMenuItem("Post")
        self._normal_filter_get = JCheckBoxMenuItem("Get")
        self._normal_filter_no_ext = JCheckBoxMenuItem("No extensions")

        for item in [self._normal_filter_post, self._normal_filter_get, self._normal_filter_no_ext]:
            item.addActionListener(self._on_normal_filter_change)
            self._normal_filter_menu.add(item)

        top_panel.add(self._normal_start_btn)
        top_panel.add(self._normal_clear_btn)
        top_panel.add(JLabel("Search Normalized:"))
        top_panel.add(self._normal_search_field)
        top_panel.add(self._normal_filter_btn)

        self._normal_panel.add(top_panel, BorderLayout.NORTH)

        # Table setup
        self._normal_column_names = ["ID", "Method", "Host", "Normalized"]
        self._normal_table_model = self._create_table_model(self._normal_column_names)
        self._normal_table = JTable(self._normal_table_model)
        self._normal_table.setPreferredScrollableViewportSize(Dimension(750, 300))

        self._normal_sorter = TableRowSorter(self._normal_table_model)
        self._normal_sorter.setComparator(0, NumericComparator())
        self._normal_table.setRowSorter(self._normal_sorter)
        self._normal_sorter.setSortKeys([TableRowSorter.SortKey(0, SortOrder.ASCENDING)])

        self._normal_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_select(e, "normal"))

        # Popup menu
        self._normal_popup_menu = JPopupMenu()
        self._normal_popup_menu.add(
            JMenuItem("Send to Repeater", 
                     actionPerformed=lambda e: self._send_to_repeater(e, "normal")))
        self._normal_popup_menu.add(
            JMenuItem("Clear Row", 
                     actionPerformed=lambda e: self._clear_selected_row(e, "normal")))

        self._normal_table.addMouseListener(TableMouseAdapter(self._normal_table, self._normal_popup_menu))

        # Create split pane with table and shared viewer
        self._normal_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._normal_split_pane.setTopComponent(JScrollPane(self._normal_table))
        self._normal_split_pane.setBottomComponent(self._viewer_split)
        self._normal_split_pane.setDividerLocation(0.4)

        self._normal_panel.add(self._normal_split_pane, BorderLayout.CENTER)

    def _init_graphql_ui(self):
        """Initialize the GraphQL mode UI components."""
        self._graphql_panel = JPanel(BorderLayout())

        # Top controls
        top_panel = JPanel()
        self._graphql_start_btn = JButton("Start", actionPerformed=self._run_graphql_analysis)
        self._graphql_clear_btn = JButton("Clear All", actionPerformed=self._clear_graphql_all)
        self._graphql_search_field = JTextField(25)
        self._graphql_search_field.getDocument().addDocumentListener(SearchListener(self, "graphql"))

        top_panel.add(self._graphql_start_btn)
        top_panel.add(self._graphql_clear_btn)
        top_panel.add(JLabel("Search Operation:"))
        top_panel.add(self._graphql_search_field)

        self._graphql_panel.add(top_panel, BorderLayout.NORTH)

        # Table setup
        self._graphql_column_names = ["ID", "Method", "URL", "Operation"]
        self._graphql_table_model = self._create_table_model(self._graphql_column_names)
        self._graphql_table = JTable(self._graphql_table_model)
        self._graphql_table.setPreferredScrollableViewportSize(Dimension(750, 300))

        self._graphql_sorter = TableRowSorter(self._graphql_table_model)
        self._graphql_sorter.setComparator(0, NumericComparator())
        self._graphql_table.setRowSorter(self._graphql_sorter)
        self._graphql_sorter.setSortKeys([TableRowSorter.SortKey(0, SortOrder.ASCENDING)])

        self._graphql_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_select(e, "graphql"))

        # Popup menu
        self._graphql_popup_menu = JPopupMenu()
        self._graphql_popup_menu.add(
            JMenuItem("Send to Repeater", 
                     actionPerformed=lambda e: self._send_to_repeater(e, "graphql")))
        self._graphql_popup_menu.add(
            JMenuItem("Clear Row", 
                     actionPerformed=lambda e: self._clear_selected_row(e, "graphql")))

        self._graphql_table.addMouseListener(TableMouseAdapter(self._graphql_table, self._graphql_popup_menu))

        # Create split pane with table and shared viewer
        self._graphql_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._graphql_split_pane.setTopComponent(JScrollPane(self._graphql_table))
        self._graphql_split_pane.setBottomComponent(self._viewer_split)
        self._graphql_split_pane.setDividerLocation(0.4)

        self._graphql_panel.add(self._graphql_split_pane, BorderLayout.CENTER)

    def _switch_mode(self, event):
        """Handle mode switching between normal and GraphQL views."""
        if self._normal_mode_btn.isSelected():
            self._switch_to_mode("normal")
        else:
            self._switch_to_mode("graphql")

    def _switch_to_mode(self, mode):
        """Switch to the specified mode and update UI accordingly."""
        self.current_mode = mode
        self._central_panel.removeAll()
        
        if mode == "normal":
            self._normal_split_pane.setBottomComponent(self._viewer_split)
            self._normal_split_pane.setDividerLocation(0.4)
            self._central_panel.add(self._normal_panel)
        else:
            self._graphql_split_pane.setBottomComponent(self._viewer_split)
            self._graphql_split_pane.revalidate()
            self._graphql_split_pane.repaint()
            self._graphql_split_pane.setDividerLocation(0.4)
            self._central_panel.add(self._graphql_panel)
            
        self._viewer_split.setDividerLocation(0.4)
        
        # Force the split panes to update their layouts
        self._normal_split_pane.revalidate()
        self._normal_split_pane.repaint()
        self._graphql_split_pane.revalidate()
        self._graphql_split_pane.repaint()
        
        self._central_panel.revalidate()
        self._central_panel.repaint()

        # Additional update after a short delay to ensure proper layout
        def delayed_update():
            if mode == "normal":
                self._normal_split_pane.setDividerLocation(0.4)
            else:
                self._graphql_split_pane.setDividerLocation(0.4)
            self._viewer_split.setDividerLocation(0.4)
            
        class DelayedUpdateListener(ActionListener):
            def actionPerformed(self, event):
                delayed_update()
                
        timer = Timer(100, DelayedUpdateListener())
        timer.setRepeats(False)
        timer.start()

    def _run_normal_analysis(self, event):
        """Analyze and display unique normal requests."""
        self.normal_requests = []
        self._normal_table_model.setRowCount(0)
        seen_hashes = set()
        http_items = self._callbacks.getProxyHistory()

        filter_post = self._normal_filter_post.isSelected()
        filter_get = self._normal_filter_get.isSelected()
        filter_no_ext = self._normal_filter_no_ext.isSelected()

        for item in http_items:
            request_info = self._helpers.analyzeRequest(item)
            method = request_info.getMethod()
            url = request_info.getUrl()
            host = url.getHost()
            path = url.getPath()

            if "graphql" in path.lower():
                continue

            if filter_post and not filter_get:
                if method.upper() != "POST":
                    continue
            elif filter_get and not filter_post:
                if method.upper() != "GET":
                    continue

            if filter_no_ext:
                if re.search(r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|json)$", path, re.IGNORECASE):
                    continue

            normalized = self._normalize_path(path)
            key = "{}:{}:{}".format(method, host, normalized)

            if key not in seen_hashes:
                seen_hashes.add(key)
                self.normal_requests.append((item, {
                    "id": len(self.normal_requests) + 1,
                    "method": method,
                    "host": host,
                    "normalized": normalized
                }))

        for _, meta in self.normal_requests:
            self._normal_table_model.addRow([
                meta["id"],
                meta["method"],
                meta["host"],
                meta["normalized"]
            ])

        self._normal_sorter.setSortKeys([TableRowSorter.SortKey(0, SortOrder.ASCENDING)])

    def _normalize_path(self, path):
        """Normalize the request path by replacing dynamic values with placeholders."""
        path = re.sub(r"/\d+", "/{id}", path)
        path = re.sub(r"/[a-f0-9]{32,}", "/{hash}", path)
        path = re.sub(r"id=\d+", "id={id}", path)
        return path

    def _show_normal_filter_menu(self, event):
        """Show the filter menu for normal requests."""
        self._normal_filter_menu.show(self._normal_filter_btn, 0, self._normal_filter_btn.getHeight())

    def _on_normal_filter_change(self, event):
        """Handle changes in normal request filters."""
        self._run_normal_analysis(None)

    def _run_graphql_analysis(self, event):
        """Analyze and display unique GraphQL requests."""
        self.graphql_requests = []
        self._graphql_table_model.setRowCount(0)
        seen_hashes = set()
        http_items = self._callbacks.getProxyHistory()

        for idx, item in enumerate(http_items, 1):
            request_info = self._helpers.analyzeRequest(item)
            url_obj = request_info.getUrl()
            path = url_obj.getPath()
            url = url_obj.toString()

            if "graphql" in path.lower():
                body_offset = request_info.getBodyOffset()
                body_bytes = item.getRequest()[body_offset:]
                body_str = self._helpers.bytesToString(body_bytes)

                try:
                    json_body = json.loads(body_str)
                    query = json_body.get("query")
                    query_hash = json_body.get("queryHash")
                    op_name = json_body.get("operationName", "Unnamed")

                    if query:
                        key = hashlib.sha256(query.encode()).hexdigest()
                    elif query_hash:
                        key = query_hash
                    else:
                        continue

                    if key not in seen_hashes:
                        seen_hashes.add(key)
                        self.graphql_requests.append((item, {
                            "id": len(self.graphql_requests) + 1,
                            "method": request_info.getMethod(),
                            "url": url,
                            "operation": op_name
                        }))
                except:
                    continue

        for _, meta in self.graphql_requests:
            self._graphql_table_model.addRow([
                meta["id"],
                meta["method"],
                meta["url"],
                meta["operation"]
            ])

        self._graphql_sorter.setSortKeys([TableRowSorter.SortKey(0, SortOrder.ASCENDING)])

    def _create_table_model(self, column_names):
        """Create a non-editable table model with the specified columns."""
        class NonEditableModel(DefaultTableModel):
            def isCellEditable(self, row, col):
                return False
        return NonEditableModel([], column_names)

    def _on_row_select(self, event, mode):
        """Handle row selection in either mode."""
        if not event.getValueIsAdjusting():
            if mode == "normal":
                table = self._normal_table
                data = self.normal_requests
            else:
                table = self._graphql_table
                data = self.graphql_requests

            row = table.getSelectedRow()
            if row >= 0:
                model_index = table.getRowSorter().convertRowIndexToModel(row)
                item = data[model_index][0]
                self._current_request = item.getRequest()
                self._current_response = item.getResponse()
                self._current_service = item.getHttpService()
                self._requestViewer.setMessage(self._current_request, False)
                if self._current_response:
                    self._responseViewer.setMessage(self._current_response, True)
                else:
                    self._responseViewer.setMessage(b"", True)
                self._viewer_split.setDividerLocation(0.4)

    def _send_to_repeater(self, event, mode):
        """Send the selected request to Burp's Repeater tool."""
        if mode == "normal":
            table = self._normal_table
            data = self.normal_requests
            tag = "NormalReq"
        else:
            table = self._graphql_table
            data = self.graphql_requests
            tag = "GraphQL-Op"

        row = table.getSelectedRow()
        if row >= 0:
            model_index = table.getRowSorter().convertRowIndexToModel(row)
            item = data[model_index][0]
            service = item.getHttpService()
            req_bytes = item.getRequest()

            self._callbacks.sendToRepeater(
                service.getHost(),
                service.getPort(),
                service.getProtocol() == "https",
                req_bytes,
                tag
            )

    def _clear_selected_row(self, event, mode):
        """Clear the selected row from the table."""
        if mode == "normal":
            table = self._normal_table
            data = self.normal_requests
            model = self._normal_table_model
        else:
            table = self._graphql_table
            data = self.graphql_requests
            model = self._graphql_table_model

        row = table.getSelectedRow()
        if row >= 0:
            model_index = table.getRowSorter().convertRowIndexToModel(row)

            confirm = JOptionPane.showConfirmDialog(
                None,
                "Are you sure you want to remove the selected row?",
                "Confirm Row Removal",
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                del data[model_index]
                model.removeRow(model_index)
                if table.getRowCount() == 0:
                    self._requestViewer.setMessage(b"", True)
                    self._responseViewer.setMessage(b"", False)

    def _clear_normal_all(self, event):
        """Clear all normal request entries."""
        confirm = JOptionPane.showConfirmDialog(
            None,
            "Are you sure you want to clear all entries?",
            "Confirm Clear All",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.normal_requests = []
            self._normal_table_model.setRowCount(0)
            self._requestViewer.setMessage(b"", False)
            self._responseViewer.setMessage(b"", True)

    def _clear_graphql_all(self, event):
        """Clear all GraphQL request entries."""
        confirm = JOptionPane.showConfirmDialog(
            None,
            "Are you sure you want to clear all entries?",
            "Confirm Clear All",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.graphql_requests = []
            self._graphql_table_model.setRowCount(0)
            self._requestViewer.setMessage(b"", False)
            self._responseViewer.setMessage(b"", True)

    # IMessageEditorController methods
    def getHttpService(self):
        """Return the current HTTP service for the message editor."""
        if hasattr(self, '_current_service') and self._current_service:
            return self._current_service
        return None

    def getRequest(self):
        """Return the current request for the message editor."""
        return self._current_request

    def getResponse(self):
        """Return the current response for the message editor."""
        return self._current_response

    # ITab methods
    def getTabCaption(self):
        """Return the tab caption for the extension."""
        return "UniqueRequest"

    def getUiComponent(self):
        """Return the main UI component for the extension."""
        return self._main_panel


class TableMouseAdapter(MouseAdapter):
    """Mouse adapter for handling table row selection and context menu."""
    def __init__(self, table, popup_menu):
        self.table = table
        self.popup_menu = popup_menu

    def mousePressed(self, evt): 
        if evt.isPopupTrigger():
            row = self.table.rowAtPoint(evt.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                self.popup_menu.show(self.table, evt.getX(), evt.getY())
        self._show_popup(evt)

    def mouseReleased(self, evt): 
        if evt.isPopupTrigger():
            row = self.table.rowAtPoint(evt.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                self.popup_menu.show(self.table, evt.getX(), evt.getY())
        self._show_popup(evt)

    def _show_popup(self, evt):
        if evt.isPopupTrigger():
            row = self.table.rowAtPoint(evt.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                self.popup_menu.show(self.table, evt.getX(), evt.getY())


class SearchListener(DocumentListener):
    """Document listener for handling search field updates."""
    def __init__(self, extender, mode):
        self.extender = extender
        self.mode = mode

    def insertUpdate(self, e): self._filter()
    def removeUpdate(self, e): self._filter()
    def changedUpdate(self, e): self._filter()

    def _filter(self):
        """Apply the search filter to the table."""
        if self.mode == "normal":
            text = self.extender._normal_search_field.getText().strip()
            sorter = self.extender._normal_sorter
            col_idx = 3  # Normalized column
        else:
            text = self.extender._graphql_search_field.getText().strip()
            sorter = self.extender._graphql_sorter
            col_idx = 3  # Operation column

        if text == "":
            sorter.setRowFilter(None)
        else:
            try:
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text, col_idx))
            except:
                sorter.setRowFilter(None)
