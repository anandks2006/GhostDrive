"""
settings.py -- Application preferences, theme, autostart, proxy, and log sanitizer settings.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from ghostdrive.web.state import state

router = APIRouter(prefix="/api/settings", tags=["settings"])

class SettingsUpdateModel(BaseModel):
    theme: str = "dark"
    accent_color: str = "#8b5cf6"
    autostart: bool = False
    desktop_notifications: bool = True
    log_level: str = "INFO"
    proxy_type: str = "none"
    proxy_host: str = ""
    proxy_port: int = 0

@router.get("/")
def get_settings() -> dict:
    return state.settings

@router.post("/")
def update_settings(req: SettingsUpdateModel) -> dict:
    state.settings.update(req.model_dump())
    
    # Handle autostart platform update if requested
    if req.autostart:
        try:
            from ghostdrive.platform.autostart import set_autostart
            set_autostart(True)
        except Exception:
            pass
    else:
        try:
            from ghostdrive.platform.autostart import set_autostart
            set_autostart(False)
        except Exception:
            pass

    return {
        "status": "success",
        "settings": state.settings,
        "message": "Application settings saved."
    }
