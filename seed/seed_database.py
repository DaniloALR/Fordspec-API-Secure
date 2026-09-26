import json
import os
import secrets
from app.db.database import SessionLocal, Base, engine
from app.db import models
from app.security.auth import ROLES, hash_password

HERE = os.path.dirname(__file__)

UNIT_HINTS = {
    "Potência": ("numeric", "cv"),
    "Torque": ("numeric", "Nm"),
    "Cilindrada": ("numeric", "L"),
    "Economia de Combustível": ("numeric", "km/l"),
    "Polegadas": ("numeric", '"'),
    "Peso em ordem de marchas": ("numeric", "kg"),
    "Quantidade de marchas": ("numeric", "un"),
}


def infer_type_unit(name: str):
    if name in UNIT_HINTS:
        return UNIT_HINTS[name]
    return ("boolean", None)


def seed_users(db):
    for role in ROLES:
        if db.query(models.AppUser).filter_by(username=role).first():
            continue
        senha = os.getenv(f"SEED_PASSWORD_{role.upper()}")
        gerada = senha is None
        if gerada:
            senha = secrets.token_urlsafe(18)
        db.add(models.AppUser(
            username=role, password_hash=hash_password(senha), role=role,
            email=os.getenv(f"SEED_EMAIL_{role.upper()}", f"{role}@fordspec.local"),
        ))
        if gerada:
            print(f"[seed] usuário '{role}' criado. Senha gerada (anote, não será exibida "
                  f"novamente): {senha}")
        else:
            print(f"[seed] usuário '{role}' criado com senha de SEED_PASSWORD_{role.upper()}.")
    db.commit()


def run():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(models.SpecValue).delete()
        db.query(models.VehicleVersion).delete()
        db.query(models.Attribute).delete()
        db.commit()

        with open(os.path.join(HERE, "attributes_dict.json"), encoding="utf-8") as f:
            attrs = json.load(f)
        name_to_id = {}
        for a in attrs:
            dtype, unit = infer_type_unit(a["name"])
            obj = models.Attribute(
                category=a["category"], name=a["name"],
                data_type=dtype, unit=unit, display_order=a["order"],
            )
            db.add(obj)
            db.flush()
            name_to_id[a["name"]] = obj.id
        print(f"[seed] {len(attrs)} atributos inseridos.")

        with open(os.path.join(HERE, "curated_values.json"), encoding="utf-8") as f:
            curated = json.load(f)

        for version_name, values in curated.items():
            vehicle = models.VehicleVersion(
                brand="Ford", model="Ranger", version=version_name
            )
            db.add(vehicle)
            db.flush()
            for attr_name, val in values.items():
                attr_id = name_to_id.get(attr_name)
                if not attr_id:
                    continue
                status = "confirmed" if val not in (None, "") else "not_available"
                db.add(models.SpecValue(
                    vehicle_id=vehicle.id, attribute_id=attr_id,
                    value=val if val else None, status=status,
                    source="Ford data sheet BASE (curado)",
                ))
            print(f"[seed] versão '{version_name}' curada com {len(values)} atributos.")

        db.commit()
        seed_users(db)
        print("[seed] Concluído com sucesso.")
    finally:
        db.close()


if __name__ == "__main__":
    run()
