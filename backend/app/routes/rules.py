from fastapi import APIRouter, Depends, HTTPException
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


@router.get("/")
def index():
    return {"message": "Welcome to EITN30 Firewall API", "authors": ["Prince", "Naima"]}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    return db.query(models.Rule).all()

@router.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    db_rule = models.Rule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(models.Rule, rule_id)
    if rule:
        db.delete(rule)
        db.commit()
    return {"ok": True}

@router.post("/apply")
def apply_all_rules(db: Session = Depends(get_db)):
    rules = db.query(models.Rule).all()
    try:
        firewall.apply_rules(rules)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to apply rules")
    db.commit()
    return {"status": "applied", "count": len(rules)}


@router.post("/rules/{rule_id}/apply")
def apply_single_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(models.Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule.applied:
        return {"status": "already_applied", "rule": rule}

    try:
        firewall.apply_rule(rule)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to apply rule")
    db.commit()
    db.refresh(rule)
    return {"status": "applied", "rule": rule}
