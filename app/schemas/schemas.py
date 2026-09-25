from typing import Optional
from pydantic import BaseModel, Field

class SpecRequestIn(BaseModel):
    brand: str = Field(..., examples=["Ford"])
    model: str = Field(..., examples=["Ranger"])
    version: str = Field(..., examples=["Limited 3.0L V6 26MY"])
    attributes: Optional[list[str]] = Field(
        default=None,
        description="Lista livre de atributos. Se vazia, retorna a ficha completa.",
        examples=[["Potência", "Torque", "Tração"]],
    )


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


class ErrorOut(BaseModel):
    error: str
    message: str
    status: int
