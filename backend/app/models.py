from sqlalchemy import Column, Integer, String, Boolean
from .database import Base

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    port = Column(String)
    action = Column(String)
    applied = Column(Boolean, default=False)