#!/usr/bin/env python3
"""Simple test to verify everything works"""

def test_basic_imports():
    print("Testing basic imports...")
    try:
        from flask import Flask
        from api.auth import auth_bp, init_auth_module
        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_flask_app():
    print("Testing Flask app creation...")
    try:
        from flask import Flask
        from api.auth import init_auth_module
        
        app = Flask(__name__)
        app.secret_key = 'test-key'
        init_auth_module(app)
        
        print("✅ Flask app created successfully")
        
        # Test basic endpoint
        with app.test_client() as client:
            response = client.get('/api/auth/health')
            print(f"✅ Health endpoint: {response.status_code}")
        
        return True
    except Exception as e:
        print(f"❌ Flask app failed: {e}")
        return False

def main():
    print("=" * 40)
    print("🧪 SIMPLE SETUP TEST")
    print("=" * 40)
    
    tests = [test_basic_imports, test_flask_app]
    passed = 0
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("🎉 ALL TESTS PASSED!")
        print("🚀 Ready to run: python3 app.py")
    else:
        print("❌ Some tests failed")

if __name__ == '__main__':
    main()
