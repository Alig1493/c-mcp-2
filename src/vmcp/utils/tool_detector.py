"""MCP Tool Detection Module.

Detects and extracts tool definitions from MCP server codebases.
Supports Python (FastMCP, official SDK) and TypeScript implementations.
"""
import json
import re
from pathlib import Path
from typing import Any


class MCPTool:
    """Represents an MCP tool."""

    def __init__(self, name: str, file_path: str, description: str = '', line_number: int = 0):
        self.name = name
        self.file_path = file_path
        self.description = description
        self.line_number = line_number

    def __repr__(self) -> str:
        return f"MCPTool(name='{self.name}', file='{self.file_path}')"

    def to_dict(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'file_path': self.file_path,
            'description': self.description,
            'line_number': self.line_number,
        }


class ToolDetector:
    """Detects MCP tools from repository code."""

    # Python patterns for tool decorators
    PYTHON_TOOL_PATTERNS = [
        # @mcp.tool() or @server.tool()
        re.compile(r'@(?:mcp|server)\.tool\(\s*(?:name=[\"\']([^\"\']+)[\"\'])?\s*\)\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE),
        # @tool decorator (from fastmcp)
        re.compile(r'@tool\(\s*(?:name=[\"\']([^\"\']+)[\"\'])?\s*\)\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE),
    ]

    # TypeScript patterns for tool decorators
    TYPESCRIPT_TOOL_PATTERNS = [
        # @Tool({ ... }) decorator
        re.compile(r'@Tool\({[^}]*}\)\s*(?:async\s+)?(?:function\s+)?(\w+)', re.MULTILINE),
        # server.setRequestHandler(ListToolsRequestSchema, ...)
        re.compile(r'setRequestHandler\s*\(\s*ListToolsRequestSchema[^)]*\)\s*.*?name:\s*[\"\']([^\"\']+)[\"\']', re.MULTILINE | re.DOTALL),
    ]

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.tools: list[MCPTool] = []

    def detect_tools(self) -> list[MCPTool]:
        """Detect all tools in the repository."""
        self.tools = []

        # Detect Python tools
        python_files = list(self.repo_path.rglob('*.py'))
        for file_path in python_files:
            self._detect_python_tools(file_path)

        # Detect TypeScript tools
        ts_files = list(self.repo_path.rglob('*.ts')) + list(self.repo_path.rglob('*.tsx'))
        for file_path in ts_files:
            self._detect_typescript_tools(file_path)

        # If no tools found, check if this is an MCP server and create a default tool
        if not self.tools and self._is_mcp_server():
            self.tools.append(MCPTool(
                name='unknown',
                file_path=str(self.repo_path),
                description='MCP server with undetected tools'
            ))

        return self.tools

    def _detect_python_tools(self, file_path: Path) -> None:
        """Detect tools from Python files."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Extract docstrings for descriptions
            docstrings = {}
            docstring_pattern = re.compile(r'def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*"""([^"]+)"""', re.MULTILINE | re.DOTALL)
            for match in docstring_pattern.finditer(content):
                func_name, docstring = match.groups()
                docstrings[func_name] = docstring.strip().split('\n')[0]  # First line only

            # Find tool decorators
            for pattern in self.PYTHON_TOOL_PATTERNS:
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

                    self.tools.append(MCPTool(
                        name=tool_name,
                        file_path=relative_path,
                        description=description,
                        line_number=line_number
                    ))

        except Exception as e:
            # Skip files that can't be read
            pass

    def _detect_typescript_tools(self, file_path: Path) -> None:
        """Detect tools from TypeScript files."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Find tool decorators
            for pattern in self.TYPESCRIPT_TOOL_PATTERNS:
                for match in pattern.finditer(content):
                    tool_name = match.group(1)

                    # Get line number
                    line_number = content[:match.start()].count('\n') + 1

                    # Try to extract description from decorator
                    description = ''
                    decorator_match = re.search(rf'@Tool\({{[^}}]*description:\s*[\"\']([^\"\']+)[\"\'][^}}]*}}\)\s*(?:async\s+)?(?:function\s+)?{re.escape(tool_name)}', content)
                    if decorator_match:
                        description = decorator_match.group(1)

                    relative_path = str(file_path.relative_to(self.repo_path))

                    self.tools.append(MCPTool(
                        name=tool_name,
                        file_path=relative_path,
                        description=description,
                        line_number=line_number
                    ))

        except Exception:
            pass

    def _is_mcp_server(self) -> bool:
        """Check if repository is an MCP server by looking for MCP dependencies."""
        # Check Python dependencies
        python_dep_files = ['requirements.txt', 'pyproject.toml', 'Pipfile']
        for dep_file in python_dep_files:
            file_path = self.repo_path / dep_file
            if file_path.exists():
                content = file_path.read_text(errors='ignore')
                if 'mcp' in content or 'fastmcp' in content:
                    return True

        # Check TypeScript dependencies
        package_json = self.repo_path / 'package.json'
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text())
                dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                if any('modelcontextprotocol' in dep or 'mcp' in dep for dep in dependencies.keys()):
                    return True
            except Exception:
                pass

        return False

    def get_tools_by_file(self) -> dict[str, list[MCPTool]]:
        """Group tools by their source file."""
        tools_by_file: dict[str, list[MCPTool]] = {}
        for tool in self.tools:
            if tool.file_path not in tools_by_file:
                tools_by_file[tool.file_path] = []
            tools_by_file[tool.file_path].append(tool)
        return tools_by_file


def detect_tools_in_repo(repo_path: str) -> list[MCPTool]:
    """Convenience function to detect tools in a repository."""
    detector = ToolDetector(repo_path)
    return detector.detect_tools()
