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
"""The server-side functions that perform queue endpoint operations."""
from __future__ import annotations

from typing import Any

import structlog
from flask_login import current_user
from injector import inject
from sqlalchemy import func, select
from structlog.stdlib import BoundLogger

from dioptra.restapi.db import db, models, viewsdb

from .errors import QueueAlreadyExistsError, QueueDoesNotExistError

LOGGER: BoundLogger = structlog.stdlib.get_logger()


class QueueService(object):
    """The service methods for registering and managing queues by their unique id."""

    @inject
    def __init__(
        self,
        queue_name_service: QueueNameService,
    ) -> None:
        """Initialize the queue service.

        All arguments are provided via dependency injection.

        Args:
            queue_name_service: A QueueNameService object.
        """
        self._queue_name_service = queue_name_service

    def create(
        self,
        name: str,
        description: str,
        group_id: int,
        **kwargs,
    ) -> models.Queue:
        """Create a new queue.

        Args:
            name: The name of the queue.

        Returns:
            The newly created queue object.

        Raises:
            QueueAlreadyExistsError: If a queue with the given name already exists.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())

        if self._queue_name_service.get(name, log=log) is not None:
            log.error("Queue name already exists", name=name)
            raise QueueAlreadyExistsError

        stmt = select(models.Group).filter_by(group_id=group_id)
        group: models.Group | None = db.session.scalars(stmt).first()

        resource = models.Resource(resource_type="queue", owner=group)
        new_queue = models.Queue(
            name=name, description=description, resource=resource, creator=current_user
        )
        db.session.add(new_queue)
        db.session.commit()
        log.info(
            "Queue registration successful",
            queue_id=new_queue.resource_id,
            name=new_queue.name,
        )
        return new_queue

    def get(
        self,
        search_string: str,
        page_index: int,
        page_length: int,
        **kwargs,
    ) -> Any:
        """Fetch the list of all queues.

        Returns:
            - A list of fetched queues.
            - A count of the total number of queues matching the query
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())
        log.info("Get full list of queues")

        if search_string:
            log.warn("Searching is not implemented", search_string=search_string)

        stmt = (
            select(func.count(models.Queue.resource_id))
            .join(models.Resource)
            .filter_by(is_deleted=False)
        )
        total_num_queues = db.session.scalars(stmt).first()

        if total_num_queues == 0:
            return [], total_num_queues

        stmt = (
            select(models.Queue)  # type: ignore
            .join(models.Resource)
            .filter_by(is_deleted=False)
            .offset(page_index)
            .limit(page_length)
        )
        queues = db.session.scalars(stmt).all()

        queue_snapshots = [
            viewsdb.get_latest_queue(db, resource_id=queue.resource.resource_id)  # type: ignore
            for queue in queues
        ]
        return queue_snapshots, total_num_queues


class QueueIdService(object):
    """The service methods for registering and managing queues by their unique id."""

    @inject
    def __init__(
        self,
        queue_name_service: QueueNameService,
    ) -> None:
        """Initialize the queue service.

        All arguments are provided via dependency injection.

        Args:
            queue_name_service: A QueueNameService object.
        """
        self._queue_name_service = queue_name_service

    def get(
        self,
        queue_id: int,
        error_if_not_found: bool = False,
        **kwargs,
    ) -> models.Queue | None:
        """Fetch a queue by its unique id.

        Args:
            queue_id: The unique id of the queue.
            error_if_not_found: If True, raise an error if the queue is not found.
                Defaults to False.

        Returns:
            The queue object if found, otherwise None.

        Raises:
            QueueDoesNotExistError: If the queue is not found and `error_if_not_found`
                is True.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())
        log.info("Get queue by id", queue_id=queue_id)

        queue = viewsdb.get_latest_queue(db, resource_id=queue_id)

        if queue is None:
            if error_if_not_found:
                log.error("Queue not found", queue_id=queue_id)
                raise QueueDoesNotExistError

            return None

        return queue

    def modify(
        self, queue_id: int, name: str, description: str, **kwargs
    ) -> models.Queue:
        """Rename a queue.

        Args:
            queue_id: The unique id of the queue.
            name: The new name of the queue.
            description: The new description of the queue.

        Returns:
            The updated queue object.

        Raises:
            QueueDoesNotExistError: If the queue is not found.
            QueueAlreadyExistsError: If the queue name already exists
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())

        if self._queue_name_service.get(name, log=log) is not None:
            log.error("Queue name already exists", name=name)
            raise QueueAlreadyExistsError

        queue = viewsdb.get_latest_queue(db, resource_id=queue_id)

        if queue is None:
            raise QueueDoesNotExistError

        new_queue = models.Queue(
            name=name,
            description=description,
            resource=queue.resource,
            creator=current_user,
        )
        db.session.add(new_queue)
        db.session.commit()

        log.info(
            "Queue modified",
            queue_id=queue.resource_id,
            name=name,
            description=description,
        )
        return new_queue

    def delete(self, queue_id: int, **kwargs) -> dict[str, Any]:
        """Delete a queue.

        Args:
            queue_id: The unique id of the queue.

        Returns:
            A dictionary reporting the status of the request.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())

        stmt = select(models.Queue).filter_by(resource_id=queue_id)
        queue: models.Queue | None = db.session.scalars(stmt).first()

        if queue is None:
            raise QueueDoesNotExistError

        deleted_resource_lock = models.ResourceLock(
            resource_lock_type="delete",
            resource=queue.resource,
        )
        db.session.add(deleted_resource_lock)
        db.session.commit()

        log.info("Queue deleted", queue_id=queue_id)

        return {"status": "Success", "queue_id": queue_id}


class QueueNameService(object):
    """The service methods for managing queues by their name."""

    def get(
        self,
        name: str,
        # group_id: int,
        error_if_not_found: bool = False,
        **kwargs,
    ) -> models.Queue | None:
        """Fetch a queue by its name.

        Args:
            name: The name of the queue.
            group_id: The the group id of the queue.
            error_if_not_found: If True, raise an error if the queue is not found.
                Defaults to False.

        Returns:
            The queue object if found, otherwise None.

        Raises:
            QueueDoesNotExistError: If the queue is not found and `error_if_not_found`
                is True.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())
        log.info("Get queue by name", queue_name=name)

        stmt = select(models.Queue).filter_by(name=name)
        resource: models.Queue | None = db.session.scalars(stmt).first()

        if resource is None or resource.resource.is_deleted:
            if error_if_not_found:
                log.error("Queue not found", name=name)
                raise QueueDoesNotExistError

            return None

        queue = viewsdb.get_latest_queue(db, resource_id=resource.resource_id)

        if queue is None:
            if error_if_not_found:
                log.error("Queue not found", name=name)
                raise QueueDoesNotExistError

            return None

        return queue
