from fastapi import FastAPI
from .database import Base, engine
from .routes import analysis, rules
from fastapi.middleware.cors import CORSMiddleware

from .analysis_metrics import collector

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(rules.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")


@app.on_event("startup")
def _start_metrics_collector():
    collector.start()