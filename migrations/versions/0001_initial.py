from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("attribute",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("data_type", sa.String(20)),
        sa.Column("unit", sa.String(20)),
        sa.Column("display_order", sa.Integer),
        sa.UniqueConstraint("category", "name", name="uq_attr_cat_name"),
    )
    op.create_table("vehicle_version",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("brand", sa.String(60), nullable=False),
        sa.Column("model", sa.String(60), nullable=False),
        sa.Column("version", sa.String(160), nullable=False),
        sa.UniqueConstraint("brand", "model", "version", name="uq_vehicle_bmv"),
    )
    op.create_table("spec_value",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("vehicle_id", sa.Integer, sa.ForeignKey("vehicle_version.id", ondelete="CASCADE")),
        sa.Column("attribute_id", sa.Integer, sa.ForeignKey("attribute.id")),
        sa.Column("value", sa.Text),
        sa.Column("status", sa.String(20)),
        sa.Column("source", sa.String(200)),
    )
    op.create_table("spec_request",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("brand", sa.String(60)),
        sa.Column("model", sa.String(60)),
        sa.Column("version", sa.String(160)),
        sa.Column("created_at", sa.DateTime),
    )

def downgrade():
    op.drop_table("spec_request")
    op.drop_table("spec_value")
    op.drop_table("vehicle_version")
    op.drop_table("attribute")
