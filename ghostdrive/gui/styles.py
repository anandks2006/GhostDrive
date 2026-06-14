"""
styles.py -- QSS Stylesheets and theme definitions for GhostDrive.
"""

from typing import Dict

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


def get_stylesheet(theme: str = "dark", accent_color: str = None) -> str:
    """Return the global QSS stylesheet for the selected theme and custom accent."""
    palette = THEME_PALETTES.get(theme, THEME_PALETTES["dark"]).copy()
    if accent_color:
        palette["accent_primary"] = accent_color
    
    qss = f"""
    /* Global Settings */
    QWidget {{
        background-color: {palette['bg_main']};
        color: {palette['text_main']};
        font-family: "Segoe UI", -apple-system, Roboto, Helvetica, Arial, sans-serif;
        font-size: 13px;
    }}
    
    /* Main Windows and Cards */
    QMainWindow, QDialog {{
        background-color: {palette['bg_main']};
    }}
    
    QFrame#GlassCard {{
        background-color: {palette['bg_card']};
        border: 1px solid {palette['border']};
        border-radius: 8px;
    }}
    
    QFrame#Sidebar {{
        background-color: {palette['bg_card']};
        border-right: 1px solid {palette['border']};
    }}
    
    /* Labels */
    QLabel {{
        background-color: transparent;
    }}
    
    QLabel#Heading {{
        font-size: 18px;
        font-weight: bold;
        color: {palette['text_main']};
    }}
    
    QLabel#SubHeading {{
        font-size: 14px;
        font-weight: 500;
        color: {palette['text_muted']};
    }}
    
    QLabel#MutedLabel {{
        color: {palette['text_muted']};
        font-size: 11px;
    }}
    
    /* Inputs */
    QLineEdit, QTextEdit {{
        background-color: {palette['bg_input']};
        color: {palette['text_main']};
        border: 1px solid {palette['border']};
        border-radius: 6px;
        padding: 8px 12px;
    }}
    
    QLineEdit:focus, QTextEdit:focus {{
        border: 1.5px solid {palette['accent_primary']};
    }}
    
    PasswordLineEdit {{
        padding-right: 30px;
    }}
    
    /* Buttons */
    QPushButton {{
        background-color: {palette['bg_card']};
        border: 1px solid {palette['border']};
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 500;
    }}
    
    QPushButton:hover {{
        background-color: {palette['bg_hover']};
        border-color: {palette['text_muted']};
    }}
    
    QPushButton:pressed {{
        background-color: {palette['border']};
    }}
    
    QPushButton#PrimaryButton {{
        background-color: {palette['accent_primary']};
        color: #ffffff;
        border: none;
    }}
    
    QPushButton#PrimaryButton:hover {{
        background-color: #7c3aed;  /* Darker violet */
    }}
    
    QPushButton#SecondaryButton {{
        background-color: transparent;
        color: {palette['accent_secondary']};
        border: 1px solid {palette['accent_secondary']};
    }}
    
    QPushButton#SecondaryButton:hover {{
        background-color: rgba(6, 182, 212, 0.1);
    }}
    
    QPushButton#DangerButton {{
        background-color: {palette['status_error']};
        color: #ffffff;
        border: none;
    }}
    
    QPushButton#DangerButton:hover {{
        background-color: #dc2626;
    }}
    
    /* Navigation Sidebar Items */
    QListWidget#NavList {{
        background-color: transparent;
        border: none;
        outline: none;
    }}
    
    QListWidget#NavList::item {{
        background-color: transparent;
        border-radius: 6px;
        padding: 10px 15px;
        margin-bottom: 4px;
        color: {palette['text_muted']};
    }}
    
    QListWidget#NavList::item:hover {{
        background-color: {palette['bg_hover']};
        color: {palette['text_main']};
    }}
    
    QListWidget#NavList::item:selected {{
        background-color: rgba(139, 92, 246, 0.15); /* Muted violet overlay */
        color: {palette['accent_primary']};
        font-weight: bold;
    }}
    
    /* Lists and Tables */
    QTableWidget, QListWidget {{
        background-color: {palette['bg_card']};
        border: 1px solid {palette['border']};
        border-radius: 8px;
        outline: none;
    }}
    
    QTableWidget::item, QListWidget::item {{
        padding: 8px;
    }}
    
    QHeaderView::section {{
        background-color: {palette['bg_input']};
        color: {palette['text_muted']};
        padding: 8px;
        border: none;
        border-bottom: 1px solid {palette['border']};
        font-weight: bold;
    }}
    
    /* Scrollbars */
    QScrollBar:vertical {{
        border: none;
        background-color: transparent;
        width: 10px;
        margin: 0px;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {palette['border']};
        min-height: 20px;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {palette['text_muted']};
    }}
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        border: none;
        background: none;
    }}
    
    QScrollBar:horizontal {{
        border: none;
        background-color: transparent;
        height: 10px;
        margin: 0px;
    }}
    
    QScrollBar::handle:horizontal {{
        background-color: {palette['border']};
        min-width: 20px;
        border-radius: 5px;
    }}
    
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        border: none;
        background: none;
    }}
    
    /* Tab Headers */
    QTabBar::tab {{
        background-color: {palette['bg_card']};
        border: 1px solid {palette['border']};
        border-bottom-color: transparent;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        padding: 8px 16px;
        margin-right: 2px;
        color: {palette['text_muted']};
    }}
    
    QTabBar::tab:hover {{
        background-color: {palette['bg_hover']};
    }}
    
    QTabBar::tab:selected {{
        background-color: {palette['bg_main']};
        border-color: {palette['border']};
        border-bottom-color: {palette['bg_main']};
        color: {palette['accent_primary']};
        font-weight: bold;
    }}
    
    /* Progress Bars */
    QProgressBar {{
        background-color: {palette['bg_input']};
        border: 1px solid {palette['border']};
        border-radius: 6px;
        text-align: center;
        font-weight: bold;
    }}
    
    QProgressBar::chunk {{
        background-color: {palette['accent_primary']};
        border-radius: 5px;
    }}
    
    /* Tooltips */
    QToolTip {{
        background-color: {palette['bg_card']};
        color: {palette['text_main']};
        border: 1px solid {palette['border']};
        border-radius: 4px;
        padding: 4px;
    }}
    """
    return qss


import re
from PyQt6.QtCore import QTimer, QSize
from PyQt6.QtWidgets import QWidget, QLayout, QTableWidget, QDialog

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
            l = prop.fget(widget)
            if l is not None:
                return l
    except Exception:
        pass
    l = getattr(widget, "layout", None)
    if l is not None:
        if isinstance(l, QLayout):
            return l
        if callable(l):
            try:
                res = l()
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

