from sqlalchemy import Column, Integer, String
from .database import Base

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    port = Column(String)
    action = Column(String)