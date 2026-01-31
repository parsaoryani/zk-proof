"""SQLAlchemy ORM models for persistent transaction storage."""

from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, LargeBinary, Text, Enum as SQLEnum, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import enum
import json

Base = declarative_base()


class UserRole(str, enum.Enum):
    """User role enumeration."""
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"


class TransactionType(str, enum.Enum):
    """Transaction type enumeration."""
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    AUDIT = "audit"


class TransactionStatus(str, enum.Enum):
    """Transaction status enumeration."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    AUDITED = "audited"
    FAILED = "failed"


class User(Base):
    """User account record."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")
    audit_records = relationship("AuditRecord", back_populates="auditor")
    
    def __repr__(self) -> str:
        return f"<User({self.username} - {self.role.value})>"


class Session(Base):
    """User session record."""
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self) -> str:
        return f"<Session(user_id={self.user_id})>"
    
    def is_valid(self) -> bool:
        """Check if session is still valid."""
        return self.expires_at > datetime.utcnow() and self.user.is_active


class Transaction(Base):
    """Base transaction record."""
    __tablename__ = "transactions"
    
    id = Column(Integer, primary_key=True)
    transaction_hash = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tx_type = Column(SQLEnum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="transactions")
    
    def __repr__(self) -> str:
        return f"<Transaction({self.transaction_hash[:8]}... {self.tx_type.value} ${self.amount})>"


class Commitment(Base):
    """Merkle tree commitment record."""
    __tablename__ = "commitments"
    
    id = Column(Integer, primary_key=True)
    commitment_hash = Column(LargeBinary(32), unique=True, nullable=True)
    commitment_index = Column(Integer, nullable=False, index=True)  # Not unique - multiple deposits may use same index
    transaction_hash = Column(String(255), nullable=False, index=True)
    merkle_root = Column(LargeBinary(32), nullable=True)
    
    # Encrypted data (never stored unencrypted)
    encrypted_secret = Column(LargeBinary, nullable=True)
    encrypted_randomness = Column(LargeBinary, nullable=True)
    encrypted_identity = Column(LargeBinary, nullable=True)  # Identity encrypted with auditor key
    
    # Metadata
    amount = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<Commitment(index={self.commitment_index} {self.commitment_hash.hex()[:8] if self.commitment_hash else 'None'}...)>"


class Nullifier(Base):
    """Double-spend prevention record."""
    __tablename__ = "nullifiers"
    
    id = Column(Integer, primary_key=True)
    nullifier_hash = Column(LargeBinary(32), unique=True, nullable=False, index=True)
    commitment_hash = Column(LargeBinary(32), nullable=False, index=True)
    withdrawal_hash = Column(String(255), nullable=True, index=True)
    
    # Usage tracking
    is_spent = Column(Integer, default=0)  # Boolean as integer for SQLite compatibility
    spent_timestamp = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<Nullifier({self.nullifier_hash.hex()[:8]}... spent={bool(self.is_spent)})>"


class AuditRecord(Base):
    """Regulatory audit trail."""
    __tablename__ = "audit_records"
    
    id = Column(Integer, primary_key=True)
    audit_hash = Column(String(255), nullable=False, index=True)  # Allows multiple audits per transaction
    transaction_hash = Column(String(255), nullable=False, index=True)
    auditor_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Decrypted identity (still sensitive - should be encrypted at rest)
    decrypted_identity = Column(String(255), nullable=False, index=True)
    
    # Audit metadata
    auditor_note = Column(Text, nullable=True)
    audit_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    auditor = relationship("User", back_populates="audit_records")
    
    def __repr__(self) -> str:
        return f"<AuditRecord({self.audit_hash[:8]}... {self.decrypted_identity})>"


class MerkleRoot(Base):
    """Merkle tree state snapshots."""
    __tablename__ = "merkle_roots"
    
    id = Column(Integer, primary_key=True)
    root_hash = Column(LargeBinary(32), unique=True, nullable=False, index=True)
    tree_height = Column(Integer, nullable=False)
    num_leaves = Column(Integer, nullable=False)
    
    # Snapshot metadata
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<MerkleRoot({self.root_hash.hex()[:8]}... {self.num_leaves} leaves)>"


class MixerStatistics(Base):
    """Aggregate statistics snapshots."""
    __tablename__ = "mixer_statistics"
    
    id = Column(Integer, primary_key=True)
    
    # Counters
    total_deposits = Column(Integer, default=0)
    total_withdrawals = Column(Integer, default=0)
    total_volume = Column(Float, default=0.0)
    num_commitments = Column(Integer, default=0)
    num_nullifiers = Column(Integer, default=0)
    num_audited = Column(Integer, default=0)
    
    # Snapshot metadata
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<MixerStatistics(deposits={self.total_deposits} withdrawals={self.total_withdrawals})>"


class DatabaseManager:
    """Manages SQLAlchemy database connections and sessions."""
    
    def __init__(self, database_url: str = "sqlite:///zk_mixer.db"):
        """
        Initialize database manager.
        
        Args:
            database_url: SQLAlchemy database URL
                         Default: SQLite in current directory
                         PostgreSQL example: "postgresql://user:password@localhost/zkm"
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=False,  # Set to True for SQL debugging
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
        )
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
    
    def create_tables(self):
        """Create all tables in database."""
        Base.metadata.create_all(self.engine)
    
    def drop_tables(self):
        """Drop all tables (for testing)."""
        Base.metadata.drop_all(self.engine)
    
    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()
    
    # Transaction operations
    def add_transaction(self, session: Session, transaction_hash: str, tx_type: TransactionType,
                       amount: float, user_id: int, status: TransactionStatus = TransactionStatus.CONFIRMED) -> Transaction:
        """Add transaction to database."""
        tx = Transaction(
            transaction_hash=transaction_hash,
            user_id=user_id,
            tx_type=tx_type,
            amount=amount,
            status=status
        )
        session.add(tx)
        session.commit()
        return tx
    
    def get_transaction(self, session: Session, transaction_hash: str) -> Optional[Transaction]:
        """Get transaction by hash."""
        return session.query(Transaction).filter_by(transaction_hash=transaction_hash).first()
    
    def update_transaction_status(self, session: Session, transaction_hash: str,
                                  status: TransactionStatus) -> bool:
        """Update transaction status."""
        tx = session.query(Transaction).filter_by(transaction_hash=transaction_hash).first()
        if tx:
            tx.status = status
            tx.updated_at = datetime.utcnow()
            session.commit()
            return True
        return False
    
    # User management operations
    def create_user(self, session: Session, username: str, password_hash: str, 
                   role: UserRole = UserRole.USER, email: Optional[str] = None) -> User:
        """Create a new user."""
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            is_verified=True  # Set to True for now, can be email-verified later
        )
        session.add(user)
        session.commit()
        return user
    
    def get_user_by_username(self, session: Session, username: str) -> Optional[User]:
        """Get user by username."""
        return session.query(User).filter_by(username=username).first()
    
    def get_user_by_id(self, session: Session, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return session.query(User).filter_by(id=user_id).first()
    
    def get_user_transactions(self, session: Session, user_id: int, limit: int = 20) -> List[Transaction]:
        """Get transactions for a specific user."""
        return session.query(Transaction).filter_by(user_id=user_id).order_by(Transaction.created_at.desc()).limit(limit).all()
    
    def update_user_last_login(self, session: Session, user_id: int) -> bool:
        """Update user's last login timestamp."""
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.last_login = datetime.utcnow()
            session.commit()
            return True
        return False
    
    # Session management operations
    def create_session(self, session: Session, user_id: int, token: str, 
                      ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                      expires_in_hours: int = 24) -> Session:
        """Create a new session."""
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        sess = Session(
            user_id=user_id,
            token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )
        session.add(sess)
        session.commit()
        return sess
    
    def get_session_by_token(self, session: Session, token: str) -> Optional[Session]:
        """Get session by token."""
        return session.query(Session).filter_by(token=token).first()
    
    def invalidate_session(self, session: Session, token: str) -> bool:
        """Invalidate a session by setting expiry to now."""
        sess = session.query(Session).filter_by(token=token).first()
        if sess:
            sess.expires_at = datetime.utcnow()
            session.commit()
            return True
        return False
    
    def invalidate_user_sessions(self, session: Session, user_id: int) -> bool:
        """Invalidate all sessions for a user."""
        sessions = session.query(Session).filter_by(user_id=user_id).all()
        for sess in sessions:
            sess.expires_at = datetime.utcnow()
        session.commit()
        return True
    
    # Commitment operations
    def add_commitment(self, session: Session, commitment_hash: bytes, commitment_index: int,
                      transaction_hash: str, merkle_root: bytes, encrypted_secret: bytes,
                      encrypted_randomness: bytes, amount: float, encrypted_identity: Optional[bytes] = None) -> Commitment:
        """Add commitment to database."""
        commitment = Commitment(
            commitment_hash=commitment_hash,
            commitment_index=commitment_index,
            transaction_hash=transaction_hash,
            merkle_root=merkle_root,
            encrypted_secret=encrypted_secret,
            encrypted_randomness=encrypted_randomness,
            amount=amount,
            encrypted_identity=encrypted_identity
        )
        session.add(commitment)
        session.commit()
        return commitment
    
    def get_commitment_by_index(self, session: Session, commitment_index: int) -> Optional[Commitment]:
        """Get commitment by tree index."""
        return session.query(Commitment).filter_by(commitment_index=commitment_index).first()
    
    def get_commitment_by_hash(self, session: Session, commitment_hash: bytes) -> Optional[Commitment]:
        """Get commitment by hash."""
        return session.query(Commitment).filter_by(commitment_hash=commitment_hash).first()
    
    def get_commitment_by_transaction(self, session: Session, transaction_hash: str) -> Optional[Commitment]:
        """Get commitment by transaction hash."""
        return session.query(Commitment).filter_by(transaction_hash=transaction_hash).first()
    
    # Nullifier operations
    def add_nullifier(self, session: Session, nullifier_hash: bytes, commitment_hash: bytes) -> Nullifier:
        """Add nullifier record."""
        nullifier = Nullifier(
            nullifier_hash=nullifier_hash,
            commitment_hash=commitment_hash,
            is_spent=0
        )
        session.add(nullifier)
        session.commit()
        return nullifier
    
    def mark_nullifier_spent(self, session: Session, nullifier_hash: bytes,
                            withdrawal_hash: str) -> bool:
        """Mark nullifier as spent."""
        nullifier = session.query(Nullifier).filter_by(nullifier_hash=nullifier_hash).first()
        if nullifier and not nullifier.is_spent:
            nullifier.is_spent = 1
            nullifier.spent_timestamp = datetime.utcnow()
            nullifier.withdrawal_hash = withdrawal_hash
            session.commit()
            return True
        return False
    
    def is_nullifier_spent(self, session: Session, nullifier_hash: bytes) -> bool:
        """Check if nullifier has been spent."""
        nullifier = session.query(Nullifier).filter_by(nullifier_hash=nullifier_hash).first()
        return bool(nullifier and nullifier.is_spent)
    
    # Audit operations
    def add_audit_record(self, session: Session, audit_hash: str, transaction_hash: str,
                        decrypted_identity: str, auditor_id: int, auditor_note: Optional[str] = None) -> AuditRecord:
        """Add audit record."""
        audit = AuditRecord(
            audit_hash=audit_hash,
            transaction_hash=transaction_hash,
            decrypted_identity=decrypted_identity,
            auditor_id=auditor_id,
            auditor_note=auditor_note
        )
        session.add(audit)
        session.commit()
        return audit
    
    def get_audit_record(self, session: Session, audit_hash: str) -> Optional[AuditRecord]:
        """Get audit record by hash."""
        return session.query(AuditRecord).filter_by(audit_hash=audit_hash).first()
    
    def get_audits_for_transaction(self, session: Session, transaction_hash: str) -> List[AuditRecord]:
        """Get all audits for a transaction."""
        return session.query(AuditRecord).filter_by(transaction_hash=transaction_hash).all()
    
    # Merkle root operations
    def add_merkle_root(self, session: Session, root_hash: bytes, tree_height: int,
                       num_leaves: int) -> MerkleRoot:
        """Add Merkle root snapshot."""
        root = MerkleRoot(
            root_hash=root_hash,
            tree_height=tree_height,
            num_leaves=num_leaves
        )
        session.add(root)
        session.commit()
        return root
    
    def get_current_root(self, session: Session) -> Optional[MerkleRoot]:
        """Get most recent Merkle root."""
        return session.query(MerkleRoot).order_by(MerkleRoot.created_at.desc()).first()
    
    # Statistics operations
    def save_statistics(self, session: Session, total_deposits: int, total_withdrawals: int,
                       total_volume: float, num_commitments: int, num_nullifiers: int,
                       num_audited: int) -> MixerStatistics:
        """Save statistics snapshot."""
        stats = MixerStatistics(
            total_deposits=total_deposits,
            total_withdrawals=total_withdrawals,
            total_volume=total_volume,
            num_commitments=num_commitments,
            num_nullifiers=num_nullifiers,
            num_audited=num_audited
        )
        session.add(stats)
        session.commit()
        return stats
    
    def get_latest_statistics(self, session: Session) -> Optional[MixerStatistics]:
        """Get most recent statistics."""
        return session.query(MixerStatistics).order_by(MixerStatistics.created_at.desc()).first()
    
    # Aggregate queries
    def get_total_volume(self, session: Session) -> float:
        """Get total volume mixed."""
        result = session.query(Transaction).filter_by(tx_type=TransactionType.DEPOSIT).all()
        return sum(tx.amount for tx in result)
    
    def get_transaction_count(self, session: Session, tx_type: Optional[TransactionType] = None) -> int:
        """Get transaction count."""
        query = session.query(Transaction)
        if tx_type:
            query = query.filter_by(tx_type=tx_type)
        return query.count()
    
    def get_recent_transactions(self, session: Session, limit: int = 10) -> List[Transaction]:
        """Get most recent transactions."""
        return session.query(Transaction).order_by(Transaction.created_at.desc()).limit(limit).all()


# Default database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager(database_url: str = "sqlite:///zk_mixer.db") -> DatabaseManager:
    """Get or create default database manager."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(database_url)
        _db_manager.create_tables()
        _initialize_default_users(_db_manager)
    return _db_manager


def _initialize_default_users(db_manager: DatabaseManager):
    """Create default admin and anonymous users if they don't exist."""
    from zkm.security.auth import hash_password
    
    with db_manager.get_session() as session:
        # Check if admin exists
        admin = session.query(User).filter_by(username="admin").first()
        if not admin:
            # Create default admin user
            admin = User(
                username="admin",
                email="admin@zkmixer.local",
                password_hash=hash_password("admin"),  # Default password: admin
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True
            )
            session.add(admin)
            session.commit()
            print("✓ Created default admin user (username: admin, password: admin)")
        
        # Check if anonymous user exists
        anonymous = session.query(User).filter_by(username="anonymous").first()
        if not anonymous:
            # Create anonymous user for public deposits/withdrawals
            anonymous = User(
                username="anonymous",
                email="anonymous@zkmixer.local",
                password_hash=hash_password("anonymous123"),  # Not meant to be used for login
                role=UserRole.USER,
                is_active=True,
                is_verified=True
            )
            session.add(anonymous)
            session.commit()
            print("✓ Created anonymous user for public transactions")


def reset_db_manager():
    """Reset database manager (for testing)."""
    global _db_manager
    _db_manager = None
