from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
post = Table('post', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('subject', String(length=140)),
    Column('body', String(length=140)),
    Column('timestamp', DateTime),
    Column('user_id', Integer),
    Column('language', String(length=5)),
    Column('answered', Boolean),
    Column('answer', String(length=140)),
    Column('answer_time', DateTime),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['post'].columns['answer'].create()
    post_meta.tables['post'].columns['answer_time'].create()
    post_meta.tables['post'].columns['answered'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['post'].columns['answer'].drop()
    post_meta.tables['post'].columns['answer_time'].drop()
    post_meta.tables['post'].columns['answered'].drop()
