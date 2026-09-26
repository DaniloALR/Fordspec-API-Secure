from typing import Optional
from pydantic import BaseModel


class SpecItem(BaseModel):
    attribute: str
    category: str
    value: str
    unit: Optional[str] = None
    status: str
    source: Optional[str] = None


class SpecSheet(BaseModel):
    id: str
    vehicle: dict
    generated_at: str
    total_attributes: int
    items: list[SpecItem]


class AttributeOut(BaseModel):
    category: str
    name: str
    unit: Optional[str] = None


class VehicleOut(BaseModel):
    brand: str
    model: str
    version: str
