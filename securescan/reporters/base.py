"""
Base reporter class for all report generators
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..models import ScanResult


class BaseReporter(ABC):
    """Abstract base class for all reporters"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    @abstractmethod
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate report and return the file path"""
        pass
    
    @abstractmethod
    def get_format_name(self) -> str:
        """Return the format name"""
        pass
    
    def get_output_path(self, filename: str, extension: str) -> Path:
        """Get the full output path for a report file"""
        if not filename.endswith(extension):
            filename = f"{filename}.{extension}"
        return self.output_dir / filename
