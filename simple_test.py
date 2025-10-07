#!/usr/bin/env python3
"""Simple test to verify everything works"""

def test_basic_imports():
    """Test basic imports"""
    print("Testing basic imports...")
    try:
        from flask import Flask
        print("✅ Flask imported")
        
        from api.auth import auth_bp, init_auth_module
        print("✅ Auth module imported")
        
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_flask_app():
    """Test Flask app creation"""
    print("Testing Flask app creation...")
    try:
        from flask import Flask
        from api.auth import init_auth_module
        
        app = Flask(__name__)
        app.secret_key = 'test-secret-key'
        init_auth_module(app)
        
        print("✅ Flask app created")
        
        with app.test_client() as client:
            response = client.get('/api/auth/health')
            print(f"✅ Health endpoint: status {response.status_code}")
        
        return True
    except Exception as e:
        print(f"❌ Flask test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
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
        print("🚀 Your authentication system is working!")
    else:
        print("❌ Some tests failed")

if __name__ == '__main__':
    main()

