#!/usr/bin/env python3
"""
Database Reset Script
Clears the database and creates initial test users
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from zkm.storage.database import Base, User, UserSession, Transaction, Commitment, Nullifier, MerkleRoot, AuditRecord, MixerStatistics
from zkm.security.auth import hash_password
from datetime import datetime

# Database configuration
DATABASE_URL = "sqlite:///./zk_mixer.db"

def reset_database():
    """Reset database and create initial users"""
    print("🔄 Resetting database...")
    
    # Create engine
    engine = create_engine(DATABASE_URL, echo=False)
    
    # Drop all tables
    print("  ⚠️  Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    
    # Create all tables
    print("  ✨ Creating tables...")
    Base.metadata.create_all(bind=engine)
    
    # Create session
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Create test users
        print("  👥 Creating users...")
        
        users_data = [
            {
                "username": "user1",
                "email": "user1@example.com",
                "password": "password1",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "user2",
                "email": "user2@example.com",
                "password": "password2",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "user3",
                "email": "user3@example.com",
                "password": "password3",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "user4",
                "email": "user4@example.com",
                "password": "password4",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "user5",
                "email": "user5@example.com",
                "password": "password5",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "admin",
                "email": "admin@zkmixer.local",
                "password": "admin123",
                "role": "ADMIN",
                "balance": 1000,
                "is_active": True,
                "is_verified": True
            },
            {
                "username": "anonymous",
                "email": "anonymous@zkmixer.local",
                "password": "anonymous123",
                "role": "USER",
                "balance": 0,
                "is_active": True,
                "is_verified": True
            }
        ]
        
        created_users = []
        for user_data in users_data:
            # Hash password
            password = user_data.pop("password")
            password_hash = hash_password(password)
            
            # Create user
            user = User(
                password_hash=password_hash,
                **user_data
            )
            db.add(user)
            created_users.append(user_data["username"])
            print(f"    ✓ Created user: {user_data['username']} ({user_data['email']}) - Role: {user_data['role']}")
        
        # Initialize mixer statistics
        print("  📊 Initializing mixer statistics...")
        stats = MixerStatistics(
            total_deposits=0,
            total_withdrawals=0,
            total_volume=0.0,
            num_commitments=0,
            num_nullifiers=0,
            num_audited=0
        )
        db.add(stats)
        
        # Commit all changes
        db.commit()
        
        print("\n✅ Database reset complete!")
        print(f"\n📋 Created {len(created_users)} users:")
        print("   • user1-5: password is 'password1' through 'password5'")
        print("   • admin: password is 'admin123' (ADMIN role, balance: 1000)")
        print("   • anonymous: password is 'anonymous123'")
        print("\n🔐 You can now login with any of these accounts")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    try:
        reset_database()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
