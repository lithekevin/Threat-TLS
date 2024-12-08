from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Server(Base):
    __tablename__ = 'servers'

    id = Column(Integer, primary_key=True)
    ip = Column(String(100), nullable=False)
    port = Column(String(10), nullable=False)
    overall_status = Column(String(20), default='Secure')
    attacks = relationship('AttackResult', back_populates='server')
    cpes = relationship('CPE', back_populates='server', cascade='all, delete-orphan')
    certificate_results = relationship("CertificateResult", back_populates="server")

    def __repr__(self):
        return f"<Server(ip='{self.ip}', port='{self.port}')>"


class AttackResult(Base):
    __tablename__ = 'attack_results'

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey('servers.id'), nullable=False)
    attack_name = Column(String, nullable=False)
    tool = Column(String, nullable=False)
    vulnerable = Column(Boolean, nullable=False)
    log_content = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False)
    processing_time = Column(Float, nullable=True)  # New field for processing time

    server = relationship("Server", back_populates="attacks")


class CPE(Base):
    __tablename__ = 'cpes'

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey('servers.id'), nullable=False)
    cpe_name = Column(String, nullable=False)

    server = relationship("Server", back_populates="cpes")

    def __repr__(self):
        return f"<CPE(server_id='{self.server_id}', cpe_name='{self.cpe_name}')>"


class AttackCPE(Base):
    __tablename__ = 'attack_cpes'

    id = Column(Integer, primary_key=True)
    attack_name = Column(String, nullable=False)
    cve_id = Column(String, nullable=False)
    cpe_name = Column(String, nullable=False)
    version_start_including = Column(String, nullable=True)
    version_end_including = Column(String, nullable=True)
    version_start_excluding = Column(String, nullable=True)
    version_end_excluding = Column(String, nullable=True)


class CertificateResult(Base):
    __tablename__ = 'certificate_results'
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey('servers.id'))
    is_valid = Column(Boolean)
    reason = Column(Text)
    certificate_pem = Column(Text)
    fingerprint = Column(String)
    server = relationship("Server", back_populates="certificate_results")
