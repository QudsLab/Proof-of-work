#!/usr/bin/env python3
"""
Generate binary metadata (JSON and Markdown) for multi-platform builds.
Organizes binaries into bin/{os}/{variant}/client/ and bin/{os}/{variant}/server/
Creates separate binaries.json (runtime) and c_lib.json (development libs).
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
    
    runtime_binaries = {}
    c_lib_binaries = {}
    
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
        
        # Copy files and collect metadata
        platform_key = f"{os_name}/{variant}"
        if platform_key not in runtime_binaries:
            runtime_binaries[platform_key] = {'client': [], 'server': []}
            c_lib_binaries[platform_key] = {'client': [], 'server': []}
        
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
            
            # Determine if c_lib or runtime
            is_c_lib = "c_lib" in str(rel_path)
            
            # Determine client or server based on filename
            filename_lower = file_path.name.lower()
            if 'client' in filename_lower:
                target_type = 'client'
            elif 'server' in filename_lower:
                target_type = 'server'
            else:
                # For other files like headers or JS glue, skip for now
                continue
            
            # Compact metadata format (no filename, category, or path)
            file_metadata = {
                'size': len(file_content),
                'url': github_url,
                'hashes': {
                    'md5': md5_hash,
                    'sha256': sha256_hash
                }
            }
            
            if is_c_lib:
                c_lib_binaries[platform_key][target_type].append(file_metadata)
            else:
                runtime_binaries[platform_key][target_type].append(file_metadata)
    
    # Generate binaries.json (runtime libraries)
    runtime_metadata = {
        'version': '1.0.0',
        'repository': f"https://github.com/{GITHUB_REPO}",
        'generated': datetime.utcnow().isoformat() + 'Z',
        'platforms': {}
    }
    
    # Organize by platform
    for platform_key in sorted(runtime_binaries.keys()):
        os_name, variant = platform_key.split('/')
        
        if os_name not in runtime_metadata['platforms']:
            runtime_metadata['platforms'][os_name] = {}
        
        runtime_metadata['platforms'][os_name][variant] = runtime_binaries[platform_key]
    
    json_path = bin_dir / 'binaries.json'
    json_path.write_text(json.dumps(runtime_metadata, indent=2, sort_keys=False))
    runtime_count = sum(len(v['client']) + len(v['server']) for v in runtime_binaries.values())
    print(f"✓ Generated {json_path} with {runtime_count} runtime binaries")
    
    # Generate c_lib.json (development libraries - rare cases)
    c_lib_metadata = {
        'version': '1.0.0',
        'repository': f"https://github.com/{GITHUB_REPO}",
        'generated': datetime.utcnow().isoformat() + 'Z',
        'note': 'Development libraries for rare cases where static linking is needed',
        'platforms': {}
    }
    
    # Organize by platform
    for platform_key in sorted(c_lib_binaries.keys()):
        os_name, variant = platform_key.split('/')
        
        if os_name not in c_lib_metadata['platforms']:
            c_lib_metadata['platforms'][os_name] = {}
        
        # Only add if c_lib files exist
        if c_lib_binaries[platform_key]['client'] or c_lib_binaries[platform_key]['server']:
            c_lib_metadata['platforms'][os_name][variant] = c_lib_binaries[platform_key]
    
    c_lib_json_path = bin_dir / 'c_lib.json'
    c_lib_json_path.write_text(json.dumps(c_lib_metadata, indent=2, sort_keys=False))
    c_lib_count = sum(len(v['client']) + len(v['server']) for v in c_lib_binaries.values())
    print(f"✓ Generated {c_lib_json_path} with {c_lib_count} development libraries")
    
    # Generate README.md
    readme_lines = [
        "# Proof-of-Work Binaries",
        "",
        f"**Repository**: [{GITHUB_REPO}](https://github.com/{GITHUB_REPO})",
        f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "This directory contains pre-built binaries for multiple platforms.",
        "",
        "## Metadata Files",
        "",
        "- `binaries.json` - Runtime binaries (DLLs, .so, .dylib, .wasm)",
        "- `c_lib.json` - Development libraries (for C/C++ linking)",
        ""
    ]
    
    # Summary table
    readme_lines.append("## Summary")
    readme_lines.append("")
    readme_lines.append("| Platform | Variant | Client | Server |")
    readme_lines.append("|----------|---------|--------|--------|")
    
    for os_name in ['windows', 'linux', 'macos', 'android', 'wasm']:
        platforms = sorted([k for k in runtime_binaries.keys() if k.startswith(os_name)])
        for platform_key in platforms:
            variant = platform_key.split('/')[1]
            client_count = len(runtime_binaries[platform_key]['client'])
            server_count = len(runtime_binaries[platform_key]['server'])
            readme_lines.append(f"| {os_name.title()} | {variant} | {client_count} | {server_count} |")
    
    readme_lines.append("")
    readme_lines.append("## Download Links")
    readme_lines.append("")
    readme_lines.append("All binaries are available via direct GitHub raw URLs.")
    readme_lines.append("See `binaries.json` and `c_lib.json` for complete download links and checksums.")
    readme_lines.append("")
    
    # Usage instructions
    readme_lines.extend([
        "## Usage",
        "",
        "### Download via curl",
        "```bash",
        "# Example: Download Windows x64 client DLL",
        f"curl -O {GITHUB_RAW_BASE}/bin/win/64/client/client.dll",
        "```",
        "",
        "### Download via wget",
        "```bash",
        "# Example: Download Linux x64 client library",
        f"wget {GITHUB_RAW_BASE}/bin/linux/64/client/libclient.so",
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
        "",
        "## Structure",
        "",
        "```",
        "bin/",
        "├── binaries.json (runtime binaries metadata)",
        "├── c_lib.json (development libraries metadata)",
        "├── README.md",
        "└── {os}/",
        "    └── {variant}/",
        "        ├── client/",
        "        │   └── [runtime files]",
        "        └── server/",
        "            └── [runtime files]",
        "```",
        ""
    ])
    
    readme_path = bin_dir / 'README.md'
    readme_path.write_text('\n'.join(readme_lines))
    print(f"✓ Generated {readme_path}")


if __name__ == '__main__':
    main()
