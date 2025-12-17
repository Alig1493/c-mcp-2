"""Detect repository languages and select appropriate scanners."""
import json
import os
import subprocess
import sys
from pathlib import Path


def detect_languages(repo_path: str) -> dict[str, int]:
    """Detect languages in repository using GitHub Linguist approach."""
    languages = {}

    # Common language file extensions
    extensions_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.go': 'go',
        '.java': 'java',
        '.rb': 'ruby',
        '.rs': 'rust',
        '.php': 'php',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
    }

    for root, _, files in os.walk(repo_path):
        # Skip common non-source directories
        if any(skip in root for skip in ['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'vendor']):
            continue

        for file in files:
            ext = Path(file).suffix.lower()
            if ext in extensions_map:
                lang = extensions_map[ext]
                languages[lang] = languages.get(lang, 0) + 1

    return languages


def select_scanners(languages: dict[str, int]) -> list[str]:
    """Select scanners based on detected languages."""
    scanners = set()

    # Language-specific scanners
    language_scanners = {
        'python': ['trivy', 'semgrep', 'yara'],
        'javascript': ['trivy', 'semgrep', 'npm-audit', 'yara'],
        'typescript': ['trivy', 'semgrep', 'yara'],
        'go': ['trivy', 'gosec', 'yara'],
        'java': ['trivy', 'semgrep', 'yara'],
        'ruby': ['trivy', 'bundler-audit', 'yara'],
        'rust': ['trivy', 'cargo-audit', 'yara'],
        'php': ['trivy', 'semgrep', 'yara'],
        'csharp': ['trivy', 'semgrep', 'yara'],
        'cpp': ['trivy', 'semgrep', 'yara'],
        'c': ['trivy', 'semgrep', 'yara'],
    }

    # Add language-specific scanners
    for lang in languages:
        if lang in language_scanners:
            scanners.update(language_scanners[lang])

    # Always include general scanners
    scanners.add('trivy')
    scanners.add('osv-scanner')
    scanners.add('yara')

    return sorted(list(scanners))


def check_dependencies(repo_path: str) -> list[str]:
    """Check for dependency files and add appropriate scanners."""
    additional_scanners = []

    dependency_files = {
        'package.json': 'npm-audit',
        'package-lock.json': 'npm-audit',
        'Gemfile': 'bundler-audit',
        'Cargo.toml': 'cargo-audit',
        'go.mod': 'gosec',
        'requirements.txt': 'safety',
        'Pipfile': 'safety',
    }

    for dep_file, scanner in dependency_files.items():
        if os.path.exists(os.path.join(repo_path, dep_file)):
            additional_scanners.append(scanner)

    return additional_scanners


def main():
    if len(sys.argv) < 2:
        print("Usage: python detect_language.py <repo_path>")
        sys.exit(1)

    repo_path = sys.argv[1]

    if not os.path.exists(repo_path):
        print(f"Error: Repository path {repo_path} does not exist")
        sys.exit(1)

    # Detect languages
    languages = detect_languages(repo_path)

    # Select scanners
    scanners = select_scanners(languages)

    # Check for dependency files
    dep_scanners = check_dependencies(repo_path)
    scanners.extend([s for s in dep_scanners if s not in scanners])

    # Output results
    result = {
        'languages': languages,
        'scanners': scanners
    }

    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
