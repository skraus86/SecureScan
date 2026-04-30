"""
Base scanner class for all security scanners
"""

from abc import ABC, abstractmethod
from typing import List, Generator
from pathlib import Path
import os

from ..models import Finding, ScanResult
from ..config import ScanConfig, EXCLUDED_DIRS


class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
    
    @abstractmethod
    def scan(self, target_path: str) -> List[Finding]:
        """Execute the scan and return findings"""
        pass
    
    @abstractmethod
    def get_scanner_name(self) -> str:
        """Return the name of the scanner"""
        pass
    
    def get_files(self, target_path: str, extensions: List[str] = None) -> Generator[Path, None, None]:
        """
        Recursively get all files in target path, optionally filtered by extension
        """
        target = Path(target_path)
        
        if target.is_file():
            if extensions is None or target.suffix in extensions:
                yield target
            return
        
        for root, dirs, files in os.walk(target):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                if extensions is None or file_path.suffix in extensions:
                    yield file_path
    
    def read_file_content(self, file_path: Path) -> str:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""
    
    def get_line_content(self, file_path: Path, line_number: int, context_lines: int = 2) -> str:
        """Get content around a specific line"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                start = max(0, line_number - context_lines - 1)
                end = min(len(lines), line_number + context_lines)
                return ''.join(lines[start:end])
        except Exception:
            return ""
