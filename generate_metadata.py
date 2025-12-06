#!/usr/bin/env python3
"""
Generate binary metadata (JSON and Markdown) for multi-platform builds.
Organizes binaries into bin/{os}/{variant}/ and creates manifest files.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import quote

# GitHub repository information
GITHUB_REPO = "QudsLab/Proof-of-work"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main"


def main():
    """Generate metadata for downloaded binaries."""
    artifacts_dir = Path('downloaded-artifacts')
    bin_dir = Path('bin')
    bin_dir.mkdir(exist_ok=True)
    
    # Map build names to platform/variant paths
    platform_map = {
        'windows': {'x64': '64', 'x86': '32'},
        'linux': {'x86_64': '64', 'aarch64': 'arm64'},
        'macos': {'x86_64': '64', 'arm64': 'arm64'},
        'android': {
            'armeabi-v7a': 'armv7',
            'arm64-v8a': 'arm64',
            'x86': 'x86',
            'x86_64': 'x86_64'
        },
        'wasm': {'wasm': 'wasm'}
    }
    
    binary_info = {}
    
    # Process each artifact directory
    for artifact_dir in sorted(artifacts_dir.glob('binaries-*')):
        if not artifact_dir.is_dir():
            continue
        
        # Parse artifact name: binaries-{os}-{arch} or binaries-wasm
        name_parts = artifact_dir.name.replace('binaries-', '').split('-')
        os_name = name_parts[0]
        
        # Handle WASM special case (no arch suffix)
        if os_name == 'wasm':
            arch = 'wasm'
        else:
            arch = '-'.join(name_parts[1:])
        
        # Get variant from platform map
        if os_name not in platform_map or arch not in platform_map[os_name]:
            print(f"⚠ Unknown platform/arch: {os_name}/{arch}")
            continue
        
        variant = platform_map[os_name][arch]
        
        # Determine target directory based on OS
        if os_name == 'windows':
            target_dir = bin_dir / 'win' / variant
        elif os_name == 'wasm':
            target_dir = bin_dir / 'wasm'
        else:
            target_dir = bin_dir / os_name / variant
        
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy files and collect hashes
        platform_key = f"{os_name}/{variant}"
        if platform_key not in binary_info:
            binary_info[platform_key] = []
        
        for file_path in artifact_dir.rglob('*'):
            if not file_path.is_file():
                continue
            
            rel_path = file_path.relative_to(artifact_dir)
            dest_path = target_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            file_content = file_path.read_bytes()
            dest_path.write_bytes(file_content)
            
            # Calculate hashes
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            # Generate GitHub raw URL
            if os_name == 'windows':
                github_path = f"bin/win/{variant}/{rel_path.as_posix()}"
            elif os_name == 'wasm':
                github_path = f"bin/wasm/{rel_path.as_posix()}"
            else:
                github_path = f"bin/{os_name}/{variant}/{rel_path.as_posix()}"
            
            github_url = f"{GITHUB_RAW_BASE}/{quote(github_path)}"
            
            # Determine file category
            file_category = "runtime"
            if "c_lib" in str(rel_path):
                file_category = "c_development"
            elif "include" in str(rel_path):
                file_category = "headers"
            elif file_path.suffix in ['.js']:
                file_category = "javascript"
            
            binary_info[platform_key].append({
                'filename': file_path.name,
                'category': file_category,
                'path': str(rel_path),
                'size': len(file_content),
                'url': github_url,
                'hashes': {
                    'md5': md5_hash,
                    'sha256': sha256_hash
                }
            })
    
    # Generate binaries.json
    metadata = {
        'version': '1.0.0',
        'repository': f"https://github.com/{GITHUB_REPO}",
        'generated': datetime.utcnow().isoformat() + 'Z',
        'platforms': {}
    }
    
    # Organize by platform
    for platform_key in sorted(binary_info.keys()):
        os_name, variant = platform_key.split('/')
        
        if os_name not in metadata['platforms']:
            metadata['platforms'][os_name] = {}
        
        metadata['platforms'][os_name][variant] = {
            'files': binary_info[platform_key],
            'count': len(binary_info[platform_key])
        }
    
    json_path = bin_dir / 'binaries.json'
    json_path.write_text(json.dumps(metadata, indent=2, sort_keys=False))
    total_files = sum(len(files) for files in binary_info.values())
    print(f"✓ Generated {json_path} with {total_files} entries")
    
    # Generate README.md
    readme_lines = [
        "# Proof-of-Work Binaries",
        "",
        f"**Repository**: [{GITHUB_REPO}](https://github.com/{GITHUB_REPO})",
        f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "This directory contains pre-built binaries for multiple platforms.",
        ""
    ]
    
    # Summary table
    readme_lines.append("## Summary")
    readme_lines.append("")
    readme_lines.append("| Platform | Variant | Files |")
    readme_lines.append("|----------|---------|-------|")
    
    for os_name in ['windows', 'linux', 'macos', 'android', 'wasm']:
        platforms = sorted([k for k in binary_info.keys() if k.startswith(os_name)])
        for platform_key in platforms:
            variant = platform_key.split('/')[1]
            file_count = len(binary_info[platform_key])
            readme_lines.append(f"| {os_name.title()} | {variant} | {file_count} |")
    
    readme_lines.append("")
    readme_lines.append("## Download Links & Checksums")
    readme_lines.append("")
    
    # Detailed sections with download links
    for os_name in ['windows', 'linux', 'macos', 'android', 'wasm']:
        platforms = sorted([k for k in binary_info.keys() if k.startswith(os_name)])
        if platforms:
            readme_lines.append(f"### {os_name.title()}")
            readme_lines.append("")
            
            for platform_key in platforms:
                variant = platform_key.split('/')[1]
                readme_lines.append(f"#### {variant}")
                readme_lines.append("")
                
                for file_info in binary_info[platform_key]:
                    filename = file_info['filename']
                    url = file_info['url']
                    sha256 = file_info['hashes']['sha256']
                    md5 = file_info['hashes']['md5']
                    size = file_info['size']
                    
                    readme_lines.append(f"- **[{filename}]({url})** ({size:,} bytes)")
                    readme_lines.append(f"  - SHA256: `{sha256}`")
                    readme_lines.append(f"  - MD5: `{md5}`")
                    readme_lines.append("")
    
    # Usage instructions
    readme_lines.extend([
        "## Usage",
        "",
        "### Download via curl",
        "```bash",
        "# Example: Download Windows x64 client DLL",
        f"curl -O {GITHUB_RAW_BASE}/bin/win/64/dll/client.dll",
        "```",
        "",
        "### Download via wget",
        "```bash",
        "# Example: Download Linux x64 client library",
        f"wget {GITHUB_RAW_BASE}/bin/linux/64/lib/libclient.so",
        "```",
        "",
        "### Verify checksums",
        "```bash",
        "# Linux/macOS",
        "sha256sum client.dll",
        "md5sum client.dll",
        "",
        "# Windows PowerShell",
        "Get-FileHash client.dll -Algorithm SHA256",
        "Get-FileHash client.dll -Algorithm MD5",
        "```",
        ""
    ])
    
    readme_path = bin_dir / 'README.md'
    readme_path.write_text('\n'.join(readme_lines))
    print(f"✓ Generated {readme_path}")


if __name__ == '__main__':
    main()
