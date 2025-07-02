#!/usr/bin/env python3
"""
Deployment Verification Script for Secure Cert-Tools v2.4.0

This script verifies:
1. File existence and consistency
2. Docker image functionality
3. Configuration file accuracy
4. Documentation consistency
5. Environment variable handling
"""

import os
import sys
import subprocess
import json
import yaml
from pathlib import Path

def check_file_exists(filepath, description=""):
    """Check if a file exists and return status"""
    exists = Path(filepath).exists()
    status = "[OK]" if exists else "[FAIL]"
    print(f"{status} {filepath} {description}")
    return exists

def run_command(cmd, description="", capture_output=True):
    """Run a command and return result"""
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            success = result.returncode == 0
        else:
            result = subprocess.run(cmd, shell=True)
            success = result.returncode == 0
        
        status = "[OK]" if success else "[FAIL]"
        print(f"{status} {description}")
        
        if capture_output:
            return success, result.stdout, result.stderr
        return success, "", ""
    except Exception as e:
        print(f"[FAIL] {description} - Error: {e}")
        return False, "", str(e)

def verify_docker_setup():
    """Verify Docker setup and image"""
    print("\n=== Docker Verification ===")
    
    # Check Docker is running
    success, _, _ = run_command("docker info", "Docker is running")
    if not success:
        print("[WARN] Docker is not running. Some tests will be skipped.")
        return False
    
    # Check if our image exists
    success, output, _ = run_command("docker images", "Checking Docker images")
    if "secure-cert-tools" in output:
        print("[OK] secure-cert-tools image found")
    else:
        print("[WARN] secure-cert-tools image not found")
    
    return True

def verify_files():
    """Verify all required files exist"""
    print("\n=== File Verification ===")
    
    required_files = [
        ("secure-cert-tools-v2.4.0-complete.tar", "- Complete Docker image with all changes"),
        ("docker-compose.yml", "- Production configuration"),
        ("docker-compose.dev.yml", "- Development configuration"),
        (".env.example", "- Environment template"),
        ("load-and-run.sh", "- Linux/macOS deployment script"),
        ("load-and-run.ps1", "- Windows PowerShell script"),
        ("offline-deployment-guide.md", "- Deployment guide"),
        ("DEPLOYMENT_MODES.md", "- Modes documentation"),
        ("README.md", "- Main documentation"),
        ("Dockerfile", "- Docker build file"),
        ("requirements.txt", "- Python dependencies"),
        ("gunicorn.conf.py", "- Production server config"),
        ("start_server.py", "- Server startup script"),
        ("app.py", "- Flask application"),
        ("csr.py", "- CSR generation logic"),
        ("_version.py", "- Version information")
    ]
    
    missing_files = []
    for filepath, description in required_files:
        if not check_file_exists(filepath, description):
            missing_files.append(filepath)
    
    return len(missing_files) == 0, missing_files

def verify_docker_compose_configs():
    """Verify Docker Compose configurations"""
    print("\n=== Docker Compose Configuration Verification ===")
    
    configs = {
        "docker-compose.yml": "Production",
        "docker-compose.dev.yml": "Development"
    }
    
    for config_file, mode in configs.items():
        if not Path(config_file).exists():
            print(f"[FAIL] {config_file} missing")
            continue
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Check service configuration
            services = config.get('services', {})
            if not services:
                print(f"[FAIL] {config_file}: No services defined")
                continue
            
            # Check main service
            main_service = None
            for service_name, service_config in services.items():
                if 'secure-cert-tools' in service_name:
                    main_service = service_config
                    break
            
            if main_service:
                # Check image
                image = main_service.get('image', '')
                if 'secure-cert-tools:2.4.0' in image:
                    print(f"[OK] {config_file}: Correct image reference")
                else:
                    print(f"[FAIL] {config_file}: Incorrect image reference: {image}")
                
                # Check environment
                env = main_service.get('environment', [])
                if mode == "Production":
                    if any('FLASK_ENV=production' in str(var) for var in env):
                        print(f"[OK] {config_file}: Production environment set")
                    else:
                        print(f"[FAIL] {config_file}: Production environment not set")
                elif mode == "Development":
                    if any('FLASK_ENV=development' in str(var) for var in env):
                        print(f"[OK] {config_file}: Development environment set")
                    else:
                        print(f"[FAIL] {config_file}: Development environment not set")
                
                # Check ports
                ports = main_service.get('ports', [])
                if any('5555' in str(port) for port in ports):
                    print(f"[OK] {config_file}: Port 5555 configured")
                else:
                    print(f"[FAIL] {config_file}: Port 5555 not configured")
            else:
                print(f"[FAIL] {config_file}: Main service not found")
        
        except Exception as e:
            print(f"[FAIL] {config_file}: Parse error - {e}")

def verify_environment_template():
    """Verify .env.example file"""
    print("\n=== Environment Template Verification ===")
    
    if not Path(".env.example").exists():
        print("? .env.example file missing")
        return False
    
    required_vars = [
        "FLASK_ENV",
        "CERT_DOMAIN", 
        "PORT",
        "SECRET_KEY",
        "DEBUG"
    ]
    
    try:
        with open(".env.example", 'r') as f:
            content = f.read()
        
        for var in required_vars:
            if var in content:
                print(f"? {var} variable present")
            else:
                print(f"? {var} variable missing")
        
        # Check for production default
        if "FLASK_ENV=production" in content:
            print("? Production mode set as default")
        else:
            print("??  Production mode not set as default")
            
        return True
        
    except Exception as e:
        print(f"? Error reading .env.example: {e}")
        return False

def verify_scripts():
    """Verify deployment scripts"""
    print("\n=== Deployment Scripts Verification ===")
    
    scripts = {
        "load-and-run.sh": "bash",
        "load-and-run.ps1": "powershell"
    }
    
    for script, script_type in scripts.items():
        if not Path(script).exists():
            print(f"? {script} missing")
            continue
        
        try:
            with open(script, 'r') as f:
                content = f.read()
            
            # Check for correct image reference
            if "secure-cert-tools-v2.4.0-complete.tar" in content:
                print(f"? {script}: Correct image file reference")
            else:
                print(f"? {script}: Incorrect image file reference")
            
            # Check for executable permissions (Linux/macOS only)
            if script.endswith('.sh'):
                stat = Path(script).stat()
                if stat.st_mode & 0o111:
                    print(f"? {script}: Executable permissions set")
                else:
                    print(f"??  {script}: Executable permissions not set")
        
        except Exception as e:
            print(f"? Error checking {script}: {e}")

def verify_documentation_consistency():
    """Verify documentation mentions correct files and versions"""
    print("\n=== Documentation Consistency Verification ===")
    
    docs = [
        "README.md",
        "offline-deployment-guide.md", 
        "DEPLOYMENT_MODES.md"
    ]
    
    for doc in docs:
        if not Path(doc).exists():
            print(f"? {doc} missing")
            continue
        
        try:
            with open(doc, 'r') as f:
                content = f.read()
            
            # Check version references
            if "2.4.0" in content:
                print(f"? {doc}: Version 2.4.0 mentioned")
            else:
                print(f"??  {doc}: Version 2.4.0 not mentioned")
            
            # Check for correct image file reference
            if "secure-cert-tools-v2.4.0-complete.tar" in content:
                print(f"? {doc}: Correct image file reference")
            elif "secure-cert-tools-v2.4.0-stable-fixed.tar" in content or "secure-cert-tools-v2.4.0-stable.tar" in content:
                print(f"? {doc}: Old image file reference")
            
            # Check for Flask/Gunicorn mentions
            if "Gunicorn" in content and "Flask" in content:
                print(f"? {doc}: Both Flask and Gunicorn mentioned")
            else:
                print(f"??  {doc}: Flask/Gunicorn separation not clearly documented")
        
        except Exception as e:
            print(f"? Error checking {doc}: {e}")

def verify_version_consistency():
    """Verify version consistency across files"""
    print("\n=== Version Consistency Verification ===")
    
    version_files = {
        "_version.py": "__version__",
        "Dockerfile": "LABEL version",
        "README.md": "Current version"
    }
    
    versions = {}
    
    for filename, search_term in version_files.items():
        if not Path(filename).exists():
            print(f"? {filename} missing")
            continue
        
        try:
            with open(filename, 'r') as f:
                content = f.read()
            
            if filename == "_version.py":
                # Extract version from Python file
                for line in content.split('\n'):
                    if '__version__' in line and '=' in line:
                        version = line.split('=')[1].strip().strip('"\'')
                        versions[filename] = version
                        break
            elif filename == "Dockerfile":
                # Extract version from Dockerfile LABEL
                for line in content.split('\n'):
                    if 'LABEL version' in line:
                        version = line.split('=')[1].strip().strip('"\'')
                        versions[filename] = version
                        break
            elif "2.4.0" in content:
                versions[filename] = "2.4.0"
        
        except Exception as e:
            print(f"? Error reading {filename}: {e}")
    
    # Check consistency
    unique_versions = set(versions.values())
    if len(unique_versions) == 1:
        version = list(unique_versions)[0]
        print(f"? Version consistency: All files show version {version}")
    else:
        print(f"? Version inconsistency: Found versions {unique_versions}")
        for filename, version in versions.items():
            print(f"   {filename}: {version}")

def main():
    """Main verification function"""
    print("[*] Secure Cert-Tools v2.4.0 Deployment Verification")
    print("=" * 60)
    
    all_checks = []
    
    # Run all verification checks
    docker_ok = verify_docker_setup()
    files_ok, missing_files = verify_files()
    
    verify_docker_compose_configs()
    env_ok = verify_environment_template()
    verify_scripts()
    verify_documentation_consistency()
    verify_version_consistency()
    
    # Summary
    print("\n" + "=" * 60)
    print("?? VERIFICATION SUMMARY")
    print("=" * 60)
    
    if files_ok:
        print("? All required files present")
    else:
        print(f"? Missing files: {', '.join(missing_files)}")
    
    if docker_ok:
        print("? Docker environment ready")
    else:
        print("??  Docker environment issues detected")
    
    if env_ok:
        print("? Environment configuration valid")
    else:
        print("? Environment configuration issues")
    
    print("\n[*] Deployment verification complete!")
    print("\nNext steps:")
    print("1. Load Docker image: docker load -i secure-cert-tools-v2.4.0-complete.tar")
    print("2. Production: docker-compose up -d")
    print("3. Development: docker-compose -f docker-compose.dev.yml up -d")
    print("4. Access: https://localhost:5555")

if __name__ == "__main__":
    main()

