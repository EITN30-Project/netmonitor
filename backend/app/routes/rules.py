from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from .. import models, database, firewall

router = APIRouter()

class RuleCreate(BaseModel):
    ip: str
    port: str = ""
    action: str


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    return db.query(models.Rule).all()

@router.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    db_rule = models.Rule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    firewall.apply_rule(db_rule)
    return db_rule

@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(models.Rule, rule_id)
    if rule:
        db.delete(rule)
        db.commit()
    return {"ok": True}