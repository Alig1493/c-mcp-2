"""MCP Tool Detection Module.

Detects and extracts tool definitions from MCP server codebases.
Extensible architecture with language-specific detectors.
"""
import asyncio
import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class MCPTool:
    """Represents an MCP tool."""

    def __init__(self, name: str, file_path: str, description: str = '', line_number: int = 0, language: str = ''):
        self.name = name
        self.file_path = file_path
        self.description = description
        self.line_number = line_number
        self.language = language

    def __repr__(self) -> str:
        return f"MCPTool(name='{self.name}', file='{self.file_path}', language='{self.language}')"

    def to_dict(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'file_path': self.file_path,
            'description': self.description,
            'line_number': self.line_number,
            'language': self.language,
        }


class BaseLanguageDetector(ABC):
    """Base class for language-specific MCP tool detectors."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @property
    @abstractmethod
    def language_name(self) -> str:
        """Return the language name (e.g., 'python', 'typescript')."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """Return list of file extensions to scan (e.g., ['.py', '.pyi'])."""
        pass

    @abstractmethod
    def detect_tools_in_file(self, file_path: Path) -> list[MCPTool]:
        """Detect MCP tools in a specific file."""
        pass

    @abstractmethod
    def is_mcp_server(self) -> bool:
        """Check if repository contains MCP server for this language."""
        pass

    def detect_all_tools(self) -> list[MCPTool]:
        """Detect all tools in repository for this language."""
        tools = []

        # Find all relevant files
        for ext in self.file_extensions:
            files = list(self.repo_path.rglob(f'*{ext}'))
            for file_path in files:
                # Skip common non-source directories
                if any(skip in file_path.parts for skip in ['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'vendor', 'dist', 'build']):
                    continue

                tools.extend(self.detect_tools_in_file(file_path))

        return tools


class PythonToolDetector(BaseLanguageDetector):
    """Detects MCP tools in Python code (FastMCP, official SDK)."""

    # Python patterns for tool decorators
    TOOL_PATTERNS = [
        # @mcp.tool() or @server.tool() (allows newlines between decorator and def)
        re.compile(r'@(?:mcp|server)\.tool\(\s*(?:name=[\"\']([^\"\']+)[\"\'])?\s*\)\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE),
        # @tool decorator (from fastmcp) (allows newlines between decorator and def)
        re.compile(r'@tool\(\s*(?:name=[\"\']([^\"\']+)[\"\'])?\s*\)\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE),
    ]

    @property
    def language_name(self) -> str:
        return 'python'

    @property
    def file_extensions(self) -> list[str]:
        return ['.py']

    def detect_tools_in_file(self, file_path: Path) -> list[MCPTool]:
        """Detect tools from Python files."""
        tools = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Extract docstrings for descriptions
            docstrings = {}
            docstring_pattern = re.compile(r'def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*"""([^"]+)"""', re.MULTILINE | re.DOTALL)
            for match in docstring_pattern.finditer(content):
                func_name, docstring = match.groups()
                docstrings[func_name] = docstring.strip().split('\n')[0]  # First line only

            # Find tool decorators
            for pattern in self.TOOL_PATTERNS:
                for match in pattern.finditer(content):
                    # Pattern can match (name, func_name) or just (func_name,)
                    groups = match.groups()
                    if len(groups) == 2 and groups[0]:
                        tool_name = groups[0]  # Explicit name in decorator
                        func_name = groups[1]
                    else:
                        tool_name = groups[-1]  # Use function name
                        func_name = groups[-1]

                    # Get line number
                    line_number = content[:match.start()].count('\n') + 1

                    # Get description
                    description = docstrings.get(func_name, '')

                    relative_path = str(file_path.relative_to(self.repo_path))

                    tools.append(MCPTool(
                        name=tool_name,
                        file_path=relative_path,
                        description=description,
                        line_number=line_number,
                        language=self.language_name
                    ))

        except Exception:
            # Skip files that can't be read
            pass

        return tools

    def is_mcp_server(self) -> bool:
        """Check if repository contains Python MCP server dependencies."""
        dep_files = ['requirements.txt', 'pyproject.toml', 'Pipfile']
        for dep_file in dep_files:
            file_path = self.repo_path / dep_file
            if file_path.exists():
                try:
                    content = file_path.read_text(errors='ignore')
                    if 'mcp' in content or 'fastmcp' in content:
                        return True
                except Exception:
                    pass
        return False


class TypeScriptToolDetector(BaseLanguageDetector):
    """Detects MCP tools in TypeScript/JavaScript code."""

    # TypeScript patterns for tool decorators
    TOOL_PATTERNS = [
        # @Tool({ ... }) decorator
        re.compile(r'@Tool\({[^}]*}\)\s*(?:async\s+)?(?:function\s+)?(\w+)', re.MULTILINE),
        # server.setRequestHandler(ListToolsRequestSchema, ...)
        re.compile(r'setRequestHandler\s*\(\s*ListToolsRequestSchema[^)]*\)\s*.*?name:\s*[\"\']([^\"\']+)[\"\']', re.MULTILINE | re.DOTALL),
    ]

    @property
    def language_name(self) -> str:
        return 'typescript'

    @property
    def file_extensions(self) -> list[str]:
        return ['.ts', '.tsx', '.js', '.jsx']

    def detect_tools_in_file(self, file_path: Path) -> list[MCPTool]:
        """Detect tools from TypeScript/JavaScript files."""
        tools = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Find tool decorators
            for pattern in self.TOOL_PATTERNS:
                for match in pattern.finditer(content):
                    tool_name = match.group(1)

                    # Get line number
                    line_number = content[:match.start()].count('\n') + 1

                    # Try to extract description from decorator
                    description = ''
                    decorator_match = re.search(
                        rf'@Tool\({{[^}}]*description:\s*[\"\']([^\"\']+)[\"\'][^}}]*}}\)\s*(?:async\s+)?(?:function\s+)?{re.escape(tool_name)}',
                        content
                    )
                    if decorator_match:
                        description = decorator_match.group(1)

                    relative_path = str(file_path.relative_to(self.repo_path))

                    tools.append(MCPTool(
                        name=tool_name,
                        file_path=relative_path,
                        description=description,
                        line_number=line_number,
                        language=self.language_name
                    ))

        except Exception:
            pass

        return tools

    def is_mcp_server(self) -> bool:
        """Check if repository contains TypeScript MCP server dependencies."""
        package_json = self.repo_path / 'package.json'
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text())
                dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                if any('modelcontextprotocol' in dep or 'mcp' in dep.lower() for dep in dependencies.keys()):
                    return True
            except Exception:
                pass
        return False


class ToolDetector:
    """Main MCP tool detector that coordinates all language-specific detectors."""

    # Registry of all available language detectors
    DETECTOR_CLASSES = [
        PythonToolDetector,
        TypeScriptToolDetector,
        # Add new language detectors here
    ]

    def __init__(self, repo_path: str, use_runtime_detection: bool = True):
        self.repo_path = Path(repo_path)
        self.tools: list[MCPTool] = []
        self.detectors: list[BaseLanguageDetector] = []
        self.use_runtime_detection = use_runtime_detection

        # Initialize all detectors
        for detector_class in self.DETECTOR_CLASSES:
            self.detectors.append(detector_class(self.repo_path))

    def detect_tools(self) -> list[MCPTool]:
        """
        Detect all tools in the repository.

        Uses hybrid approach:
        1. Try runtime detection first (more accurate)
        2. Fall back to static detection if runtime fails
        """
        self.tools = []

        # Try runtime detection first
        if self.use_runtime_detection:
            print("🔍 Attempting runtime tool detection...")
            try:
                # Import here to avoid circular dependency
                from vmcp.utils.runtime_tool_detector import detect_tools_runtime

                # Check if there's already an event loop running
                try:
                    loop = asyncio.get_running_loop()
                    # If we get here, there's already a loop running
                    # We can't use asyncio.run(), so skip runtime detection
                    print("⚠️  Event loop already running, skipping runtime detection")
                    print("   Falling back to static analysis...")
                except RuntimeError:
                    # No event loop running, safe to use asyncio.run()
                    runtime_tools = asyncio.run(detect_tools_runtime(str(self.repo_path)))

                    if runtime_tools:
                        self.tools = runtime_tools
                        print(f"✅ Runtime detection found {len(runtime_tools)} tools")
                        return self.tools
                    else:
                        print("⚠️  Runtime detection returned no tools, falling back to static analysis")
            except Exception as e:
                print(f"⚠️  Runtime detection failed: {e}")
                print("   Falling back to static analysis...")

        # Fall back to static detection
        print("🔍 Running static tool detection...")
        for detector in self.detectors:
            detected_tools = detector.detect_all_tools()
            self.tools.extend(detected_tools)

        if self.tools:
            print(f"✅ Static detection found {len(self.tools)} tools")

        # If no tools found, check if this is an MCP server and create a default tool
        if not self.tools and self._is_any_mcp_server():
            print("⚠️  No tools detected, but repository appears to be an MCP server")
            self.tools.append(MCPTool(
                name='unknown',
                file_path=str(self.repo_path),
                description='MCP server with undetected tools',
                language='unknown'
            ))

        return self.tools

    def _is_any_mcp_server(self) -> bool:
        """Check if repository is an MCP server in any supported language."""
        for detector in self.detectors:
            if detector.is_mcp_server():
                return True
        return False

    def get_tools_by_file(self) -> dict[str, list[MCPTool]]:
        """Group tools by their source file."""
        tools_by_file: dict[str, list[MCPTool]] = {}
        for tool in self.tools:
            if tool.file_path not in tools_by_file:
                tools_by_file[tool.file_path] = []
            tools_by_file[tool.file_path].append(tool)
        return tools_by_file

    def get_tools_by_language(self) -> dict[str, list[MCPTool]]:
        """Group tools by programming language."""
        tools_by_lang: dict[str, list[MCPTool]] = {}
        for tool in self.tools:
            if tool.language not in tools_by_lang:
                tools_by_lang[tool.language] = []
            tools_by_lang[tool.language].append(tool)
        return tools_by_lang


def detect_tools_in_repo(repo_path: str) -> list[MCPTool]:
    """Convenience function to detect tools in a repository."""
    detector = ToolDetector(repo_path)
    return detector.detect_tools()
