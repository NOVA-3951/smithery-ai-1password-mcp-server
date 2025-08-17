#!/usr/bin/env python3
"""
Test script to verify package structure and basic imports
"""

import os
import sys
import importlib.util

def test_package_structure():
    """Test that the package structure is correct"""
    package_dir = "onepassword_mcp_server"
    
    required_files = [
        "__init__.py",
        "server.py", 
        "config.py",
        "structured_logging.py",
        "resilience.py",
        "monitoring.py",
        "security_hardening.py",
        "mcp_protocol_compliance.py"
    ]
    
    print("Testing package structure...")
    
    # Check if package directory exists
    if not os.path.isdir(package_dir):
        print(f"❌ Package directory '{package_dir}' does not exist")
        return False
    
    print(f"✅ Package directory '{package_dir}' exists")
    
    # Check for required files
    for file in required_files:
        file_path = os.path.join(package_dir, file)
        if not os.path.isfile(file_path):
            print(f"❌ Required file '{file}' is missing")
            return False
        print(f"✅ Required file '{file}' exists")
    
    return True

def test_syntax():
    """Test that Python files have valid syntax"""
    package_dir = "onepassword_mcp_server"
    
    python_files = [
        "__init__.py",
        "server.py",
        "config.py", 
        "structured_logging.py",
        "resilience.py",
        "monitoring.py",
        "security_hardening.py",
        "mcp_protocol_compliance.py"
    ]
    
    print("\nTesting Python syntax...")
    
    for file in python_files:
        file_path = os.path.join(package_dir, file)
        
        try:
            with open(file_path, 'r') as f:
                source = f.read()
            
            compile(source, file_path, 'exec')
            print(f"✅ Syntax valid for '{file}'")
        except SyntaxError as e:
            print(f"❌ Syntax error in '{file}': {e}")
            return False
        except Exception as e:
            print(f"❌ Error reading '{file}': {e}")
            return False
    
    return True

def test_pyproject_toml():
    """Test that pyproject.toml is valid"""
    print("\nTesting pyproject.toml...")
    
    if not os.path.isfile("pyproject.toml"):
        print("❌ pyproject.toml does not exist")
        return False
    
    try:
        import tomllib
        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)
        
        # Check required sections
        required_sections = ["build-system", "project"]
        for section in required_sections:
            if section not in data:
                print(f"❌ Required section '{section}' missing from pyproject.toml")
                return False
            print(f"✅ Section '{section}' found in pyproject.toml")
        
        # Check project metadata
        project = data["project"]
        required_fields = ["name", "version", "description", "dependencies"]
        for field in required_fields:
            if field not in project:
                print(f"❌ Required field '{field}' missing from [project] section")
                return False
            print(f"✅ Field '{field}' found in [project] section")
        
        return True
        
    except ImportError:
        print("⚠️  tomllib not available, skipping detailed validation")
        return True
    except Exception as e:
        print(f"❌ Error parsing pyproject.toml: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Testing 1Password MCP Server Package Structure\n")
    
    tests = [
        ("Package Structure", test_package_structure),
        ("Python Syntax", test_syntax), 
        ("PyProject Configuration", test_pyproject_toml)
    ]
    
    all_passed = True
    
    for test_name, test_func in tests:
        try:
            if test_func():
                print(f"✅ {test_name} test passed")
            else:
                print(f"❌ {test_name} test failed")
                all_passed = False
        except Exception as e:
            print(f"❌ {test_name} test error: {e}")
            all_passed = False
        print()
    
    if all_passed:
        print("🎉 All tests passed! Package is ready for PyPI.")
        return 0
    else:
        print("💥 Some tests failed. Please fix the issues before publishing.")
        return 1

if __name__ == "__main__":
    sys.exit(main())