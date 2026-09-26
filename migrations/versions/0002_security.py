from alembic import op
import sqlalchemy as sa

revision = "0002_security"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("app_user",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(40), nullable=False),
        sa.Column("password_hash", sa.String(100), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("email", sa.Text),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("failed_attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime),
        sa.Column("token_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_app_user_username", "app_user", ["username"], unique=True)

    op.create_table("audit_event",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ts", sa.DateTime, nullable=False),
        sa.Column("actor", sa.String(60), nullable=False),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("resource", sa.String(200), nullable=False),
        sa.Column("ip", sa.String(60)),
        sa.Column("trace_id", sa.String(36)),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_event_ts", "audit_event", ["ts"])
    op.create_index("ix_audit_event_action", "audit_event", ["action"])

    op.add_column("spec_request", sa.Column("requested_by", sa.String(40)))
    op.create_index("ix_spec_request_requested_by", "spec_request", ["requested_by"])


def downgrade():
    op.drop_index("ix_spec_request_requested_by", table_name="spec_request")
    op.drop_column("spec_request", "requested_by")
    op.drop_table("audit_event")
    op.drop_table("app_user")
