# This Software (Dioptra) is being made available as a public service by the
# National Institute of Standards and Technology (NIST), an Agency of the United
# States Department of Commerce. This software was developed in part by employees of
# NIST and in part by NIST contractors. Copyright in portions of this software that
# were developed by NIST contractors has been licensed or assigned to NIST. Pursuant
# to Title 17 United States Code Section 105, works of NIST employees are not
# subject to copyright protection in the United States. However, NIST may hold
# international copyright in software created by its employees and domestic
# copyright (or licensing rights) in portions of software that were assigned or
# licensed to NIST. To the extent that NIST holds copyright in this software, it is
# being made available under the Creative Commons Attribution 4.0 International
# license (CC BY 4.0). The disclaimers of the CC BY 4.0 license apply to all parts
# of the software developed or licensed by NIST.
#
# ACCESS THE FULL CC BY 4.0 LICENSE HERE:
# https://creativecommons.org/licenses/by/4.0/legalcode
from string import Template

from flask_sqlalchemy import SQLAlchemy
from importlib_resources import files
from sqlalchemy import select, text

from dioptra.restapi.db import models

LATEST_SNAPSHOT_SQL_PATH = files("dioptra.restapi.db.views").joinpath(
    "latest_snapshot.sql.template"
)
LATEST_QUEUE_BY_GROUP_AND_NAME_SQL_PATH = files("dioptra.restapi.db.views").joinpath(
    "latest_queue_by_group_and_name.sql.template"
)


def get_latest_queue(db: SQLAlchemy, resource_id: int) -> models.Queue | None:
    """Get the latest queue for a given resource ID.

    Args:
        db: The SQLAlchemy database session.
        resource_id: The ID of the resource.

    Returns:
        The latest queue for the given resource ID, or None if no queue is found.
    """
    sql_template = Template(LATEST_SNAPSHOT_SQL_PATH.read_text())
    sql = sql_template.substitute(resource="queues")

    textual_sql = (
        text(sql)
        .columns(
            models.Queue.resource_snapshot_id,
            models.Queue.resource_id,
            models.Queue.resource_type,
        )
        .bindparams(resource_id=resource_id)
    )
    stmt = select(models.Queue).from_statement(textual_sql)
    return db.session.execute(stmt).scalar()


def get_latest_queue_by_group_and_name(
    db: SQLAlchemy, group_id: int, name: str
) -> models.Queue | None:
    """Get the latest queue for with matching group_id and name.

    Args:
        db: The SQLAlchemy database session.
        group_id: The ID of the owning group.
        name: The name of the queue.

    Returns:
        The latest queue for the given group ID and name, or None if no queue is found.
    """
    sql_template = Template(LATEST_QUEUE_BY_GROUP_AND_NAME_SQL_PATH.read_text())
    sql = sql_template.substitute(resource="queues")

    textual_sql = (
        text(sql)
        .columns(
            models.Queue.resource_snapshot_id,
            models.Queue.resource_id,
            models.Queue.resource_type,
            models.Queue.name,
            models.Resource.group_id,
        )
        .bindparams(group_id=group_id, name=name)
    )
    stmt = select(models.Queue).from_statement(textual_sql)
    return db.session.execute(stmt).scalar()
