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
        }
    }
    
    binary_info = {}
    
    # Process each artifact directory
    for artifact_dir in sorted(artifacts_dir.glob('binaries-*')):
        if not artifact_dir.is_dir():
            continue
        
        # Parse artifact name: binaries-{os}-{arch}
        name_parts = artifact_dir.name.replace('binaries-', '').split('-')
        os_name = name_parts[0]
        arch = '-'.join(name_parts[1:])
        
        # Get variant from platform map
        if os_name not in platform_map or arch not in platform_map[os_name]:
            print(f"⚠ Unknown platform/arch: {os_name}/{arch}")
            continue
        
        variant = platform_map[os_name][arch]
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
            
            binary_info[platform_key].append({
                'filename': file_path.name,
                'path': str(rel_path),
                'size': len(file_content),
                'hashes': {
                    'md5': md5_hash,
                    'sha256': sha256_hash
                }
            })
    
    # Generate binaries.json
    metadata = {
        'version': '1.0.0',
        'generated': datetime.utcnow().isoformat() + 'Z',
        'binaries': {}
    }
    
    for platform_key in sorted(binary_info.keys()):
        metadata['binaries'][platform_key] = binary_info[platform_key]
    
    json_path = bin_dir / 'binaries.json'
    json_path.write_text(json.dumps(metadata, indent=2))
    total_files = sum(len(files) for files in binary_info.values())
    print(f"✓ Generated {json_path} with {total_files} entries")
    
    # Generate README.md
    readme_lines = [
        "# Proof-of-Work Binaries",
        "",
        f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ""
    ]
    
    # Summary table
    readme_lines.append("## Summary")
    readme_lines.append("")
    readme_lines.append("| Platform | Variant | Files |")
    readme_lines.append("|----------|---------|-------|")
    
    for os_name in ['windows', 'linux', 'macos', 'android']:
        platforms = sorted([k for k in binary_info.keys() if k.startswith(os_name)])
        for platform_key in platforms:
            variant = platform_key.split('/')[1]
            file_count = len(binary_info[platform_key])
            readme_lines.append(f"| {os_name.title()} | {variant} | {file_count} |")
    
    # Checksums section
    readme_lines.append("")
    readme_lines.append("## Checksums")
    readme_lines.append("")
    
    for os_name in ['windows', 'linux', 'macos', 'android']:
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
                    sha256 = file_info['hashes']['sha256']
                    md5 = file_info['hashes']['md5']
                    size = file_info['size']
                    
                    readme_lines.append(
                        f"- **{filename}** ({size:,} bytes)"
                    )
                    readme_lines.append(f"  - SHA256: `{sha256}`")
                    readme_lines.append(f"  - MD5: `{md5}`")
                    readme_lines.append("")
    
    readme_path = bin_dir / 'README.md'
    readme_path.write_text('\n'.join(readme_lines))
    print(f"✓ Generated {readme_path}")


if __name__ == '__main__':
    main()
