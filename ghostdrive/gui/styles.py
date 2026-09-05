"""
styles.py -- QSS Stylesheets and theme definitions for GhostDrive.
"""

import re
from typing import Dict

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QLayout, QTableWidget, QDialog

# Curated palettes
THEME_PALETTES: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg_main": "#121214",         # Deep charcoal
        "bg_card": "#1a1a1e",         # Card panel
        "bg_input": "#24242a",        # Inputs
        "bg_hover": "#2d2d34",        # Button hovers
        "border": "#27272a",          # Muted border
        "text_main": "#f4f4f5",        # High contrast white
        "text_muted": "#9ca3af",       # Muted gray
        "accent_primary": "#8b5cf6",   # Neon Violet
        "accent_secondary": "#06b6d4", # Electric Cyan
        "status_success": "#10b981",   # Emerald Green
        "status_warning": "#f59e0b",   # Amber
        "status_error": "#ef4444",     # Crimson Red
    },
    "light": {
        "bg_main": "#f4f4f5",         # Crisp light gray
        "bg_card": "#ffffff",         # Card panel
        "bg_input": "#f4f4f5",        # Inputs
        "bg_hover": "#e4e4e7",        # Button hovers
        "border": "#e4e4e7",          # Muted border
        "text_main": "#18181b",        # Dark gray
        "text_muted": "#71717a",       # Muted gray
        "accent_primary": "#7c3aed",   # Violet
        "accent_secondary": "#0891b2", # Cyan
        "status_success": "#059669",   # Green
        "status_warning": "#d97706",   # Amber
        "status_error": "#dc2626",     # Red
    }
}


def adjust_hex_color(hex_str: str, factor: float) -> str:
    """Adjust the brightness of a hex color. factor > 1.0 lightens, < 1.0 darkens."""
    hex_str = hex_str.lstrip('#')
    if len(hex_str) != 6:
        return f"#{hex_str}"
    try:
        r = int(hex_str[0:2], 16)
        g = int(hex_str[2:4], 16)
        b = int(hex_str[4:6], 16)
        
        # Adjust brightness
        r = min(255, max(0, int(r * factor)))
        g = min(255, max(0, int(g * factor)))
        b = min(255, max(0, int(b * factor)))
        
        return f"#{r:02x}{g:02x}{b:02x}"
    except Exception:
        return f"#{hex_str}"


def hex_to_rgba(hex_str: str, alpha: float) -> str:
    """Convert hex color to rgba string with specified alpha."""
    hex_str = hex_str.lstrip('#')
    if len(hex_str) != 6:
        return f"rgba(139, 92, 246, {alpha})"
    try:
        r = int(hex_str[0:2], 16)
        g = int(hex_str[2:4], 16)
        b = int(hex_str[4:6], 16)
        return f"rgba({r}, {g}, {b}, {alpha})"
    except Exception:
        return f"rgba(139, 92, 246, {alpha})"


def get_stylesheet(theme: str = "dark", accent_color: str = None) -> str:
    """Return the global QSS stylesheet for the selected theme and custom accent."""
    palette = THEME_PALETTES.get(theme, THEME_PALETTES["dark"]).copy()
    if accent_color:
        palette["accent_primary"] = accent_color
    
    accent = palette["accent_primary"]
    # Compute dynamic gradient stops, shadows, and highlights based on the active accent color
    accent_dark = adjust_hex_color(accent, 0.78)
    accent_light = adjust_hex_color(accent, 1.22)
    accent_rgba_15 = hex_to_rgba(accent, 0.15)
    accent_rgba_10 = hex_to_rgba(accent, 0.10)
    secondary_rgba_12 = hex_to_rgba(palette['accent_secondary'], 0.12)
    
    qss = f"""
    /* Global Settings */
    QWidget {{
        background-color: {palette['bg_main']};
        color: {palette['text_main']};
        font-family: "Plus Jakarta Sans", "Inter", "Segoe UI", -apple-system, Roboto, Helvetica, Arial, sans-serif;
        font-size: 13px;
    }}
    
    /* Main Windows and Cards */
    QMainWindow, QDialog {{
        background-color: {palette['bg_main']};
    }}
    
    QFrame#GlassCard {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {palette['bg_card']}, stop:1 {palette['bg_input']});
        border: 1.5px solid {palette['border']};
        border-radius: 12px;
    }}
    
    QFrame#Sidebar {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {palette['bg_card']}, stop:1 {palette['bg_main']});
        border: none;
        border-right: 1.5px solid {palette['border']};
    }}
    
    /* Labels */
    QLabel {{
        background-color: transparent;
    }}
    
    QLabel#Heading {{
        font-size: 20px;
        font-weight: 800;
        letter-spacing: 0.5px;
        color: {palette['text_main']};
    }}
    
    QLabel#SubHeading {{
        font-size: 14px;
        font-weight: 600;
        letter-spacing: 0.25px;
        color: {accent};
    }}
    
    QLabel#MutedLabel {{
        color: {palette['text_muted']};
        font-size: 11px;
        font-weight: 400;
    }}
    
    /* Inputs */
    QLineEdit, StyledLineEdit, PasswordLineEdit, QTextEdit {{
        background-color: {palette['bg_input']};
        color: {palette['text_main']};
        border: 1px solid {palette['border']};
        border-radius: 8px;
        padding: 10px 14px;
    }}
    
    QLineEdit:hover, StyledLineEdit:hover, PasswordLineEdit:hover, QTextEdit:hover {{
        border: 1px solid {palette['text_muted']};
    }}
    
    QLineEdit:focus, StyledLineEdit:focus, PasswordLineEdit:focus, QTextEdit:focus {{
        border: 1.5px solid {accent};
        background-color: {palette['bg_card']};
    }}
    
    PasswordLineEdit {{
        padding-right: 36px;
    }}
    
    /* Comboboxes */
    QComboBox, StyledComboBox {{
        background-color: {palette['bg_input']};
        color: {palette['text_main']};
        border: 1px solid {palette['border']};
        border-radius: 8px;
        padding: 8px 12px;
        min-width: 100px;
    }}
    
    QComboBox:hover, StyledComboBox:hover {{
        border: 1px solid {palette['text_muted']};
    }}
    
    QComboBox:focus, StyledComboBox:focus {{
        border: 1.5px solid {accent};
    }}
    
    QComboBox::drop-down, StyledComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 30px;
        border-left: none;
    }}
    
    QComboBox QAbstractItemView, QComboBox QListView,
    StyledComboBox QAbstractItemView, StyledComboBox QListView {{
        background-color: {palette['bg_card']};
        color: {palette['text_main']};
        border: 1.5px solid {palette['border']};
        border-radius: 8px;
        selection-background-color: {palette['bg_hover']};
        selection-color: {accent};
        outline: none;
    }}
    
    QComboBox QAbstractItemView::item, QComboBox QListView::item,
    StyledComboBox QAbstractItemView::item, StyledComboBox QListView::item {{
        background-color: {palette['bg_card']};
        color: {palette['text_main']};
        padding: 8px 12px;
    }}
    
    QComboBox QAbstractItemView::item:hover, QComboBox QAbstractItemView::item:selected,
    QComboBox QListView::item:hover, QComboBox QListView::item:selected,
    StyledComboBox QAbstractItemView::item:hover, StyledComboBox QAbstractItemView::item:selected,
    StyledComboBox QListView::item:hover, StyledComboBox QListView::item:selected {{
        background-color: {palette['bg_hover']};
        color: {accent};
    }}
    
    /* Checkboxes & Radio Buttons */
    QCheckBox {{
        spacing: 8px;
        background-color: transparent;
    }}
    
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 1.5px solid {palette['border']};
        border-radius: 5px;
        background-color: {palette['bg_input']};
    }}
    
    QCheckBox::indicator:hover {{
        border-color: {palette['text_muted']};
    }}
    
    QCheckBox::indicator:checked {{
        background-color: {accent};
        border-color: {accent};
    }}
    
    /* Buttons */
    QPushButton {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {palette['bg_input']}, stop:1 {palette['bg_card']});
        border: 1.5px solid {palette['border']};
        border-radius: 8px;
        padding: 9px 16px;
        font-weight: 600;
        font-size: 12px;
    }}
    
    QPushButton:hover {{
        background-color: {palette['bg_hover']};
        border-color: {accent};
    }}
    
    QPushButton:pressed {{
        background-color: {palette['border']};
    }}
    
    QPushButton[theme="primary"], QPushButton#PrimaryButton {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {accent}, stop:1 {accent_dark});
        color: #ffffff;
        border: none;
    }}
    
    QPushButton[theme="primary"]:hover, QPushButton#PrimaryButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {accent_light}, stop:1 {accent});
    }}
    
    QPushButton[theme="secondary"], QPushButton#SecondaryButton {{
        background-color: transparent;
        color: {palette['accent_secondary']};
        border: 1.5px solid {palette['accent_secondary']};
    }}
    
    QPushButton[theme="secondary"]:hover, QPushButton#SecondaryButton:hover {{
        background-color: {secondary_rgba_12};
        border-color: {palette['accent_secondary']};
    }}
    
    QPushButton[theme="danger"], QPushButton#DangerButton {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette['status_error']}, stop:1 #b91c1c);
        color: #ffffff;
        border: none;
    }}
    
    QPushButton[theme="danger"]:hover, QPushButton#DangerButton:hover {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f87171, stop:1 {palette['status_error']});
    }}
    
    /* Navigation Sidebar Items (Buttons) */
    QPushButton[navBtn="true"] {{
        background-color: transparent;
        border: none;
        border-radius: 10px;
        min-height: 50px;
        padding: 0px 12px;
        text-align: left;
        color: {palette['text_muted']};
        font-weight: 600;
        font-size: 18px;
    }}
    
    QPushButton[navBtn="true"]:hover {{
        background-color: rgba(255, 255, 255, 0.03);
        color: {palette['text_main']};
    }}
    
    QPushButton[navBtn="true"]:checked {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {accent_rgba_15}, stop:1 transparent);
        color: {accent};
        border-left: 3px solid {accent};
        font-weight: bold;
    }}
    
    /* Lists and Tables */
    QTableWidget, QListWidget {{
        background-color: {palette['bg_card']};
        border: 1.5px solid {palette['border']};
        border-radius: 12px;
        gridline-color: {palette['border']};
        outline: none;
    }}
    
    QTableWidget::item, QListWidget::item {{
        padding: 10px;
        border-bottom: 1px solid {palette['border']};
    }}
    
    QTableWidget::item:selected, QListWidget::item:selected {{
        background-color: {accent_rgba_10};
        color: {palette['text_main']};
    }}
    
    QHeaderView::section {{
        background-color: {palette['bg_input']};
        color: {palette['text_muted']};
        border: none;
        border-bottom: 1.5px solid {palette['border']};
        font-weight: 700;
        font-size: 11px;
    }}
    
    /* Scrollbars */
    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 0px;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {palette['border']};
        min-height: 20px;
        border-radius: 4px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {palette['text_muted']};
    }}
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        border: none;
        background: none;
        height: 0px;
        width: 0px;
    }}
    
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
    }}
    
    QScrollBar:horizontal {{
        background: transparent;
        height: 8px;
        margin: 0px;
    }}
    
    QScrollBar::handle:horizontal {{
        background-color: {palette['border']};
        min-width: 20px;
        border-radius: 4px;
    }}
    
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        border: none;
        background: none;
        height: 0px;
        width: 0px;
    }}
    
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
        background: none;
    }}
    
    /* Tab Headers */
    QTabBar::tab {{
        background-color: {palette['bg_card']};
        border: 1.5px solid {palette['border']};
        border-bottom-color: transparent;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 20px;
        margin-right: 4px;
        color: {palette['text_muted']};
        font-weight: 600;
    }}
    
    QTabBar::tab:hover {{
        background-color: {palette['bg_hover']};
    }}
    
    QTabBar::tab:selected {{
        background-color: {palette['bg_main']};
        border-color: {palette['border']};
        border-bottom-color: {palette['bg_main']};
        color: {accent};
        font-weight: 700;
    }}
    
    /* Progress Bars */
    QProgressBar {{
        background-color: {palette['bg_input']};
        border: 1.5px solid {palette['border']};
        border-radius: 8px;
        text-align: center;
        font-weight: 700;
        color: {palette['text_main']};
    }}
    
    QProgressBar::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {accent}, stop:1 {palette['accent_secondary']});
        border-radius: 6px;
    }}
    
    /* Tooltips */
    QToolTip {{
        background-color: {palette['bg_card']};
        color: {palette['text_main']};
        border: 1.5px solid {palette['border']};
        border-radius: 6px;
        padding: 6px;
    }}
    """
    return qss




def scale_qss(qss: str, scale_factor: float) -> str:
    """Scale all px values in a QSS string by scale_factor."""
    if not qss:
        return ""
    def repl(match):
        val = int(match.group(1))
        # Keep border widths of 1px or 2px, but scale larger px values.
        if val <= 2:
            return f"{val}px"
        scaled = max(6, int(val * scale_factor))
        return f"{scaled}px"
    return re.sub(r'(\d+)px', repl, qss)

def get_widget_layout(widget: QWidget):
    """Retrieve layout of a QWidget safely, handling masked layout attributes."""
    if not isinstance(widget, QWidget):
        return None
    try:
        prop = getattr(QWidget, "layout", None)
        if prop and hasattr(prop, "fget"):
            layout_obj = prop.fget(widget)
            if layout_obj is not None:
                return layout_obj
    except Exception:
        pass
    layout_obj = getattr(widget, "layout", None)
    if layout_obj is not None:
        if isinstance(layout_obj, QLayout):
            return layout_obj
        if callable(layout_obj):
            try:
                res = layout_obj()
                if isinstance(res, QLayout):
                    return res
            except Exception:
                pass
    return None

def store_original_layout_metrics(widget: QWidget) -> None:
    """Store the initial content margins and spacing of layouts in a widget hierarchy."""
    # Handle the layout of the widget itself
    w_lay = get_widget_layout(widget)
    if w_lay and not hasattr(w_lay, "_orig_margins"):
        m = w_lay.contentsMargins()
        w_lay._orig_margins = (m.left(), m.top(), m.right(), m.bottom())
        if hasattr(w_lay, "spacing"):
            w_lay._orig_spacing = w_lay.spacing()
        if hasattr(w_lay, "horizontalSpacing") and hasattr(w_lay, "verticalSpacing"):
            w_lay._orig_h_spacing = w_lay.horizontalSpacing()
            w_lay._orig_v_spacing = w_lay.verticalSpacing()

    # Handle all nested layouts in child widgets
    for child in widget.findChildren(QWidget):
        c_lay = get_widget_layout(child)
        if c_lay and not hasattr(c_lay, "_orig_margins"):
            m = c_lay.contentsMargins()
            c_lay._orig_margins = (m.left(), m.top(), m.right(), m.bottom())
            if hasattr(c_lay, "spacing"):
                c_lay._orig_spacing = c_lay.spacing()
            if hasattr(c_lay, "horizontalSpacing") and hasattr(c_lay, "verticalSpacing"):
                c_lay._orig_h_spacing = c_lay.horizontalSpacing()
                c_lay._orig_v_spacing = c_lay.verticalSpacing()

def apply_layout_scaling(widget: QWidget, scale_factor: float) -> None:
    """Scale layout margins and spacing based on stored metrics."""
    # Scale widget's own layout
    w_lay = get_widget_layout(widget)
    if w_lay and hasattr(w_lay, "_orig_margins"):
        m = w_lay._orig_margins
        w_lay.setContentsMargins(
            int(m[0] * scale_factor),
            int(m[1] * scale_factor),
            int(m[2] * scale_factor),
            int(m[3] * scale_factor)
        )
        if hasattr(w_lay, "_orig_spacing") and w_lay._orig_spacing is not None:
            w_lay.setSpacing(int(w_lay._orig_spacing * scale_factor))
        if hasattr(w_lay, "_orig_h_spacing") and w_lay._orig_h_spacing is not None:
            w_lay.setHorizontalSpacing(int(w_lay._orig_h_spacing * scale_factor))
        if hasattr(w_lay, "_orig_v_spacing") and w_lay._orig_v_spacing is not None:
            w_lay.setVerticalSpacing(int(w_lay._orig_v_spacing * scale_factor))

    # Scale child layouts
    for child in widget.findChildren(QWidget):
        c_lay = get_widget_layout(child)
        if c_lay and hasattr(c_lay, "_orig_margins"):
            m = c_lay._orig_margins
            c_lay.setContentsMargins(
                int(m[0] * scale_factor),
                int(m[1] * scale_factor),
                int(m[2] * scale_factor),
                int(m[3] * scale_factor)
            )
            if hasattr(c_lay, "_orig_spacing") and c_lay._orig_spacing is not None:
                c_lay.setSpacing(int(c_lay._orig_spacing * scale_factor))
            if hasattr(c_lay, "_orig_h_spacing") and c_lay._orig_h_spacing is not None:
                c_lay.setHorizontalSpacing(int(c_lay._orig_h_spacing * scale_factor))
            if hasattr(c_lay, "_orig_v_spacing") and c_lay._orig_v_spacing is not None:
                c_lay.setVerticalSpacing(int(c_lay._orig_v_spacing * scale_factor))

def store_original_widget_stylesheets(widget: QWidget) -> None:
    """Store inline stylesheets for all child widgets of the widget."""
    for child in widget.findChildren(QWidget):
        if child.styleSheet() and not hasattr(child, "_orig_stylesheet"):
            child._orig_stylesheet = child.styleSheet()

def apply_widget_stylesheet_scaling(widget: QWidget, scale_factor: float) -> None:
    """Apply scaled stylesheets based on stored inline styles of child widgets."""
    for child in widget.findChildren(QWidget):
        if hasattr(child, "_orig_stylesheet"):
            child.setStyleSheet(scale_qss(child._orig_stylesheet, scale_factor))

def apply_table_row_scaling(widget: QWidget, scale_factor: float) -> None:
    """Scale row and column header default sizes for table widgets."""
    for table in widget.findChildren(QTableWidget):
        if not hasattr(table, "_orig_row_height"):
            table._orig_row_height = table.verticalHeader().defaultSectionSize()
        table.verticalHeader().setDefaultSectionSize(int(table._orig_row_height * scale_factor))

def apply_stylesheet_scaling(widget: QWidget, theme: str = "dark", accent_color: str = None, scale_factor: float = 1.0) -> None:
    """Apply scaled global stylesheet to the widget."""
    base_qss = get_stylesheet(theme, accent_color)
    scaled_qss = scale_qss(base_qss, scale_factor)
    widget.setStyleSheet(scaled_qss)

class ResizingResilientMixin:
    """Mixin to add dynamic font, layout, and stylesheet scaling to widgets."""
    def init_resizing_resiliency(self, base_width: int, base_height: int, theme: str = "dark", accent_color: str = None) -> None:
        self._base_width = base_width
        self._base_height = base_height
        self._theme = theme
        self._accent_color = accent_color
        self._scale_factor = 1.0
        self._last_applied_scale = 1.0
        
        # Debounce timer
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._do_resizing_update)
        
        # Capture metrics
        store_original_layout_metrics(self)
        store_original_widget_stylesheets(self)
        
        # Initial apply
        self._do_resizing_update()

    def handle_resize_event(self) -> None:
        if not hasattr(self, "_base_width") or self._base_width <= 0 or self._base_height <= 0:
            return
        # Calculate current scale factor
        w_scale = self.width() / self._base_width
        h_scale = self.height() / self._base_height
        current_scale = min(w_scale, h_scale)
        
        # Trigger immediately if changed significantly, otherwise debounce
        if abs(current_scale - self._last_applied_scale) > 0.05:
            self._do_resizing_update()
        else:
            self._resize_timer.start(30)

    def _do_resizing_update(self) -> None:
        if not hasattr(self, "_base_width") or self._base_width <= 0 or self._base_height <= 0:
            return
        w_scale = self.width() / self._base_width
        h_scale = self.height() / self._base_height
        self._scale_factor = min(w_scale, h_scale)
        self._last_applied_scale = self._scale_factor
        
        # Update layout metrics and inline styles in case children were added
        store_original_layout_metrics(self)
        store_original_widget_stylesheets(self)
        
        apply_stylesheet_scaling(self, self._theme, self._accent_color, self._scale_factor)
        apply_widget_stylesheet_scaling(self, self._scale_factor)
        apply_layout_scaling(self, self._scale_factor)
        apply_table_row_scaling(self, self._scale_factor)

class ResilientDialog(QDialog, ResizingResilientMixin):
    """A standard, platform-agnostic QDialog preconfigured with resizing resiliency."""
    def __init__(self, parent=None, base_width=400, base_height=300, theme="dark", accent_color=None) -> None:
        super().__init__(parent)
        self._base_w = base_width
        self._base_h = base_height
        self._theme = theme
        self._accent_color = accent_color
        self.setMinimumSize(base_width, base_height)
        self.resize(base_width, base_height)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.init_resizing_resiliency(self._base_w, self._base_h, self._theme, self._accent_color)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.handle_resize_event()

