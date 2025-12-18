# Adding New Language Detectors

This guide explains how to add support for new programming languages to the MCP tool detection system.

## Architecture Overview

The tool detection system uses an extensible class hierarchy:

```
BaseLanguageDetector (ABC)
├── PythonToolDetector
├── TypeScriptToolDetector
└── YourNewDetector  ← Add here
```

The main `ToolDetector` class coordinates all language-specific detectors via a registry pattern.

## Step-by-Step Guide

### 1. Create Your Detector Class

Create a new class that extends `BaseLanguageDetector` in `src/vmcp/utils/tool_detector.py`:

```python
class GoToolDetector(BaseLanguageDetector):
    """Detects MCP tools in Go code."""

    # Define patterns for detecting tool definitions
    TOOL_PATTERNS = [
        re.compile(r'pattern_for_go_mcp_tools', re.MULTILINE),
    ]

    @property
    def language_name(self) -> str:
        return 'go'

    @property
    def file_extensions(self) -> list[str]:
        return ['.go']

    def detect_tools_in_file(self, file_path: Path) -> list[MCPTool]:
        """Detect tools from Go files."""
        tools = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Your detection logic here
            for pattern in self.TOOL_PATTERNS:
                for match in pattern.finditer(content):
                    tool_name = match.group(1)
                    line_number = content[:match.start()].count('\n') + 1

                    tools.append(MCPTool(
                        name=tool_name,
                        file_path=str(file_path.relative_to(self.repo_path)),
                        description='',  # Extract if possible
                        line_number=line_number,
                        language=self.language_name
                    ))

        except Exception:
            pass

        return tools

    def is_mcp_server(self) -> bool:
        """Check if repository contains Go MCP server dependencies."""
        go_mod = self.repo_path / 'go.mod'
        if go_mod.exists():
            try:
                content = go_mod.read_text(errors='ignore')
                # Check for MCP-related dependencies
                if 'mcp' in content.lower():
                    return True
            except Exception:
                pass
        return False
```

### 2. Register Your Detector

Add your detector to the `DETECTOR_CLASSES` registry in the `ToolDetector` class:

```python
class ToolDetector:
    """Main MCP tool detector that coordinates all language-specific detectors."""

    # Registry of all available language detectors
    DETECTOR_CLASSES = [
        PythonToolDetector,
        TypeScriptToolDetector,
        GoToolDetector,  # ← Add your detector here
        # Add more language detectors here
    ]
```

That's it! The system will automatically use your detector when scanning repositories.

## Abstract Methods to Implement

### Required Properties

#### `language_name` → str
Return the language identifier (e.g., 'python', 'typescript', 'go', 'rust').

```python
@property
def language_name(self) -> str:
    return 'rust'
```

#### `file_extensions` → list[str]
Return list of file extensions to scan (e.g., `['.rs', '.rust']`).

```python
@property
def file_extensions(self) -> list[str]:
    return ['.rs']
```

### Required Methods

#### `detect_tools_in_file(file_path: Path) → list[MCPTool]`
Scan a single file and return all detected MCP tools.

**Implementation tips:**
- Read file with UTF-8 encoding
- Use regex patterns to find tool definitions
- Extract tool name, description, line number
- Return empty list on error
- Always set `language=self.language_name`

#### `is_mcp_server() → bool`
Check if the repository contains MCP server dependencies for your language.

**Implementation tips:**
- Check package/dependency files (package.json, go.mod, Cargo.toml, etc.)
- Look for MCP-related dependencies
- Return `False` if unsure

## Pattern Detection Tips

### Finding Tool Definitions

Different MCP frameworks use different patterns:

**Python (FastMCP):**
```python
@mcp.tool()
def my_tool(param: str) -> str:
    """Tool description"""
    return result
```

**TypeScript:**
```typescript
@Tool({ description: 'Tool description' })
async function my_tool(args: Input): Promise<Output> {
    // implementation
}
```

**Your Language:**
- Study MCP SDK/framework for your language
- Identify decorator/annotation patterns
- Write regex to match tool definitions

### Regex Pattern Best Practices

```python
# Capture tool names with optional explicit naming
re.compile(r'@tool\(\s*(?:name=[\"\']([^\"\']+)[\"\'])?\s*\)\s*def\s+(\w+)', re.MULTILINE)

# Multiline patterns for complex definitions
re.compile(r'@Tool\({[^}]*}\)\s*async\s+function\s+(\w+)', re.MULTILINE)
```

## Example: Rust Detector

Here's a complete example for Rust:

```python
class RustToolDetector(BaseLanguageDetector):
    """Detects MCP tools in Rust code."""

    TOOL_PATTERNS = [
        # #[tool] attribute macro
        re.compile(r'#\[tool\]\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)', re.MULTILINE),
    ]

    @property
    def language_name(self) -> str:
        return 'rust'

    @property
    def file_extensions(self) -> list[str]:
        return ['.rs']

    def detect_tools_in_file(self, file_path: Path) -> list[MCPTool]:
        tools = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            for pattern in self.TOOL_PATTERNS:
                for match in pattern.finditer(content):
                    tool_name = match.group(1)
                    line_number = content[:match.start()].count('\n') + 1

                    # Try to extract doc comment
                    description = ''
                    doc_match = re.search(
                        rf'///\s*([^\n]+)\s*#\[tool\]\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(tool_name)}',
                        content
                    )
                    if doc_match:
                        description = doc_match.group(1).strip()

                    tools.append(MCPTool(
                        name=tool_name,
                        file_path=str(file_path.relative_to(self.repo_path)),
                        description=description,
                        line_number=line_number,
                        language=self.language_name
                    ))

        except Exception:
            pass

        return tools

    def is_mcp_server(self) -> bool:
        cargo_toml = self.repo_path / 'Cargo.toml'
        if cargo_toml.exists():
            try:
                content = cargo_toml.read_text(errors='ignore')
                if 'mcp' in content or 'model-context-protocol' in content:
                    return True
            except Exception:
                pass
        return False
```

Then register it:

```python
class ToolDetector:
    DETECTOR_CLASSES = [
        PythonToolDetector,
        TypeScriptToolDetector,
        RustToolDetector,  # ← Added
    ]
```

## Testing Your Detector

### Manual Testing

```bash
# Scan a repository in your language
uv run python -m vmcp.cli scan-tool https://github.com/org/rust-mcp-server --scanners yara

# Check the generated tools metadata
cat results_tools/org-rust-mcp-server-tools.json
```

### Verify Output

The tools metadata should include your language:

```json
[
  {
    "name": "example_tool",
    "file_path": "src/tools.rs",
    "description": "Example tool description",
    "line_number": 42,
    "language": "rust"  ← Your language
  }
]
```

## Benefits of This Architecture

1. **Easy Extension**: Add new languages without modifying existing code
2. **Language Isolation**: Each detector has its own patterns and logic
3. **Automatic Registration**: Just add to the registry list
4. **Language Tracking**: Tools automatically tagged with language
5. **Flexible**: Each detector can have unique implementation details

## Common Patterns to Detect

When implementing a new detector, look for:

- **Decorators/Attributes**: `@tool`, `#[tool]`, `@Tool`
- **Function Definitions**: `def tool_name`, `fn tool_name`, `function tool_name`
- **Registration Calls**: `server.register_tool("name", ...)`
- **Tool Classes**: `class MyTool implements Tool`

## Need Help?

- Check existing detectors for reference (`PythonToolDetector`, `TypeScriptToolDetector`)
- Test patterns at [regex101.com](https://regex101.com/)
- Review MCP SDK documentation for your language
- Look at example MCP servers in that language
