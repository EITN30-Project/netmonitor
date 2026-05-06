from sqlalchemy import Column, Integer, String, Boolean
from .database import Base

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    port = Column(String)
    action = Column(String)
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)
    handle = Column(Integer, default=0)
    applied = Column(Boolean, default=False)