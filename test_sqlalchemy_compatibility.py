#!/usr/bin/env python3
"""
Test script to verify SQLAlchemy 2.0 compatibility
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_sqlalchemy_compatibility():
    """Test SQLAlchemy 2.0 compatibility"""
    try:
        print("Testing SQLAlchemy 2.0 compatibility...")
        
        # Test app imports
        from app import create_app, db
        print("✓ App package imported successfully")
        
        # Create app
        app, celery = create_app()
        print("✓ Flask app created successfully")
        
        with app.app_context():
            # Test database connection with SQLAlchemy 2.0 syntax
            with db.engine.connect() as connection:
                result = connection.execute(db.text('SELECT 1 as test'))
                row = result.fetchone()
                if row and row[0] == 1:
                    print("✓ Database connection successful (SQLAlchemy 2.0)")
                else:
                    print("❌ Database query failed")
                    return False
            
            # Test table creation
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Test model creation
            from app.models import Customer, Scan
            print("✓ Database models imported successfully")
            
            # Test basic query (SQLAlchemy 2.0 style)
            from sqlalchemy import select
            stmt = select(Customer)
            result = db.session.execute(stmt)
            customers = result.scalars().all()
            print(f"✓ Query executed successfully (found {len(customers)} customers)")
            
            # Test insert
            test_customer = Customer(
                name="Test Customer",
                email="test@example.com",
                organization="Test Org"
            )
            db.session.add(test_customer)
            db.session.commit()
            print("✓ Database insert successful")
            
            # Test update
            test_customer.name = "Updated Test Customer"
            db.session.commit()
            print("✓ Database update successful")
            
            # Test delete
            db.session.delete(test_customer)
            db.session.commit()
            print("✓ Database delete successful")
        
        print("\n✅ SQLAlchemy 2.0 compatibility test passed!")
        return True
        
    except Exception as e:
        print(f"❌ SQLAlchemy compatibility error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_sqlalchemy_compatibility()
    sys.exit(0 if success else 1)
