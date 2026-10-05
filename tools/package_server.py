#!/usr/bin/env python3
import os
import zipfile
import sys

def package_server(source_dir, output_zip):
    print(f"[Packager] Starting packaging from: {source_dir}")
    print(f"[Packager] Target ZIP: {output_zip}")
    
    # Exclude development caches and VCS, but INCLUDE pure-JS node_modules for zero-install deployment
    exclude_dirs = {'.git', '__pycache__', '.idea', '.vscode'}
    exclude_exts = {'.log', '.tmp'}
    
    file_count = 0
    total_size = 0
    
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in exclude_exts:
                    continue
                
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, source_dir)
                
                # Normalizing zip path to forward slashes for Linux compatibility
                zip_path = rel_path.replace('\\', '/')
                zipf.write(full_path, zip_path)
                file_count += 1
                total_size += os.path.getsize(full_path)
                
    zip_size = os.path.getsize(output_zip)
    print(f"[Packager] Finished successfully!")
    print(f"[Packager] Total files added: {file_count}")
    print(f"[Packager] Raw size: {total_size / 1024:.2f} KB")
    print(f"[Packager] ZIP file size: {zip_size / 1024:.2f} KB ({zip_size} bytes)")

if __name__ == '__main__':
    src = os.path.abspath("d:/iosss/server")
    dst = os.path.abspath("d:/iosss/ios-auth-server-baota-4090.zip")
    package_server(src, dst)
