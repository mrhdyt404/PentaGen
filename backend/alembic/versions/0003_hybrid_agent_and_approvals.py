"""hybrid_agent_and_approvals

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-15 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003'
down_revision: Union[str, Sequence[str], None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create pairing_tokens
    op.create_table(
        'pairing_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('name_hint', sa.String(length=120), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('pairing_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pairing_tokens_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_pairing_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_pairing_tokens_expires_at'), ['expires_at'], unique=False)

    # 2. Create agent_nodes
    op.create_table(
        'agent_nodes',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=160), nullable=False),
        sa.Column('device_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('shared_secret', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=30), server_default='active', nullable=False),
        sa.Column('platform_info', sa.JSON(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['revoked_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('agent_nodes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_nodes_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_nodes_device_fingerprint'), ['device_fingerprint'], unique=False)

    # 3. Alter approvals table
    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('target_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('envelope_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('risk_assessment_json', sa.JSON(), nullable=False, server_default='{}'))
        batch_op.add_column(sa.Column('decided_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key('fk_approvals_target_id', 'targets', ['target_id'], ['id'])
        batch_op.create_index(batch_op.f('ix_approvals_target_id'), ['target_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approvals_envelope_id'), ['envelope_id'], unique=False)

    # 4. Create agent_job_envelopes
    op.create_table(
        'agent_job_envelopes',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('agent_node_id', sa.String(length=64), nullable=True),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.Integer(), nullable=True),
        sa.Column('approval_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=60), nullable=False),
        sa.Column('payload_json', sa.JSON(), nullable=False),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=30), server_default='pending', nullable=False),
        sa.Column('dispatched_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('result_json', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['agent_node_id'], ['agent_nodes.id']),
        sa.ForeignKeyConstraint(['approval_id'], ['approvals.id']),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id']),
        sa.ForeignKeyConstraint(['task_id'], ['agent_tasks.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('agent_job_envelopes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_job_envelopes_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_job_envelopes_agent_node_id'), ['agent_node_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_job_envelopes_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_job_envelopes_approval_id'), ['approval_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_job_envelopes_task_id'), ['task_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('agent_job_envelopes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_job_envelopes_task_id'))
        batch_op.drop_index(batch_op.f('ix_agent_job_envelopes_approval_id'))
        batch_op.drop_index(batch_op.f('ix_agent_job_envelopes_scan_id'))
        batch_op.drop_index(batch_op.f('ix_agent_job_envelopes_agent_node_id'))
        batch_op.drop_index(batch_op.f('ix_agent_job_envelopes_organization_id'))
    op.drop_table('agent_job_envelopes')

    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_approvals_envelope_id'))
        batch_op.drop_index(batch_op.f('ix_approvals_target_id'))
        batch_op.drop_constraint('fk_approvals_target_id', type_='foreignkey')
        batch_op.drop_column('decided_at')
        batch_op.drop_column('risk_assessment_json')
        batch_op.drop_column('envelope_id')
        batch_op.drop_column('target_id')

    with op.batch_alter_table('agent_nodes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_nodes_device_fingerprint'))
        batch_op.drop_index(batch_op.f('ix_agent_nodes_organization_id'))
    op.drop_table('agent_nodes')

    with op.batch_alter_table('pairing_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pairing_tokens_expires_at'))
        batch_op.drop_index(batch_op.f('ix_pairing_tokens_token_hash'))
        batch_op.drop_index(batch_op.f('ix_pairing_tokens_organization_id'))
    op.drop_table('pairing_tokens')

