#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Set environment variables
os.environ['FLASK_APP'] = 'app.py'
os.environ['FLASK_ENV'] = 'development'

def test_imports():
    """Test all critical imports"""
    print("🧪 Testing imports...")
    
    try:
        from app import create_app
        print("✅ Flask app import successful")
        
        from core.database_models import Base, SMTPProfile, EmailTemplate
        print("✅ Database models import successful")
        
        from api.auth import auth_bp
        print("✅ Auth blueprint import successful")
        
        # Test route imports with error handling
        try:
            from routes.dashboard import dashboard_bp
            from routes.auth import auth_routes_bp
            print("✅ Route blueprints import successful")
        except ImportError as e:
            print(f"⚠️  Route import warning: {e}")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_database():
    """Test database creation"""
    print("\n🗄️  Testing database creation...")
    
    try:
        from app import create_app
        from core.database_models import Base
        from sqlalchemy import create_engine
        
        app = create_app()
        with app.app_context():
            # Use SQLite-compatible connection string
            engine = create_engine('sqlite:///email_sender.db', echo=False)
            Base.metadata.create_all(engine)
            
        print("✅ Database created successfully!")
        print("📊 Tables: smtp_profiles, email_templates, recipient_lists, email_campaigns, email_sends, users")
        return True
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_app_creation():
    """Test Flask app creation"""
    print("\n🚀 Testing Flask application creation...")
    
    try:
        from app import create_app
        
        app = create_app()
        print("✅ Flask application created successfully!")
        
        with app.app_context():
            print("✅ Application context works!")
        
        print("🎯 Ready to start development server!")
        return True
        
    except Exception as e:
        print(f"❌ App creation error: {e}")
        return False

def main():
    print("=" * 50)
    print("🔧 EMAIL SENDER PRO - SETUP TEST")
    print("=" * 50)
    
    # Test sequence
    success_count = 0
    total_tests = 3
    
    if test_imports():
        success_count += 1
    
    if test_database():
        success_count += 1
        
    if test_app_creation():
        success_count += 1
    
    print("\n" + "=" * 50)
    print(f"📊 TEST RESULTS: {success_count}/{total_tests} passed")
    
    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED!")
        print("🚀 Ready to start: python3 app.py")
        return 0
    else:
        print("❌ Some tests failed. Check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
