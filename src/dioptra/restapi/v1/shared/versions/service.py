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
"""The server-side functions that perform versions sub endpoint operations."""
from __future__ import annotations

from abc import abstractmethod
from typing import Any, Type

import structlog
from sqlalchemy import func, select
from structlog.stdlib import BoundLogger

from dioptra.restapi.db import db, models
from dioptra.restapi.errors import BackendDatabaseError, ResourceDoesNotExistError
from dioptra.restapi.v1.shared.search_parser import construct_sql_query_filters

LOGGER: BoundLogger = structlog.stdlib.get_logger()


class ResourceVersionsService(object):
    @property
    @abstractmethod
    def resource_type(self) -> str: ...  # noqa: E704

    @property
    @abstractmethod
    def searchable_fields(self) -> dict[str, Any]: ...  # noqa: E704

    @property
    @abstractmethod
    def ResourceModel(self) -> Type[models.ResourceSnapshot]: ...  # noqa: E704

    def get(
        self,
        resource_id: int,
        search_string: str,
        page_index: int,
        page_length: int,
        error_if_not_found: bool = False,
        **kwargs,
    ) -> tuple[list[models.ResourceSnapshot], int] | None:
        """Fetch a list of versions of a resource.

        Args:
            resource_id: The unique id of the resource.
            search_string: A search string used to filter results.
            page_index: The index of the first snapshot to be returned.
            page_length: The maximum number of versions to be returned.
            error_if_not_found: If True, raise an error if the resource is not found.
                Defaults to False.

        Returns:
            The list of resource snapshots of the resource object if found, otherwise
                None.

        Raises:
            ResourceDoesNotExistError: If the resource is not found and
                `error_if_not_found` is True.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())
        log.debug("Get resource versions by id", resource_id=resource_id)

        stmt = select(models.Resource).filter_by(
            resource_id=resource_id, resource_type=self.resource_type, is_deleted=False
        )
        resource = db.session.scalars(stmt).first()

        if resource is None:
            if error_if_not_found:
                log.debug("Resource not found", resource_id=resource_id)
                raise ResourceDoesNotExistError

            return None

        filters = construct_sql_query_filters(search_string, self.searchable_fields)

        stmt = (
            select(func.count(self.ResourceModel.resource_id))  # type: ignore
            .join(models.Resource)
            .where(
                filters,
                models.Resource.resource_id == resource_id,
                models.Resource.is_deleted == False,  # noqa: E712
            )
        )
        total_num_versions = db.session.scalars(stmt).first()

        if total_num_versions is None:
            log.error(
                "The database query returned a None when counting the number of "
                "versions when it should return a number.",
                sql=str(stmt),
            )
            raise BackendDatabaseError

        if total_num_versions == 0:
            return [], total_num_versions

        stmt = (
            select(self.ResourceModel)
            .join(models.Resource)
            .where(
                filters,
                models.Resource.resource_id == resource_id,
                models.Resource.is_deleted == False,  # noqa: E712
            )
            .order_by(self.ResourceModel.created_on)
            .offset(page_index)
            .limit(page_length)
        )
        snapshots = list(db.session.scalars(stmt).all())

        return snapshots, total_num_versions


class ResourceVersionsNumberService(object):
    @property
    @abstractmethod
    def resource_type(self) -> str: ...  # noqa: E704

    @property
    @abstractmethod
    def ResourceModel(self) -> Type[models.ResourceSnapshot]: ...  # noqa: E704

    def get(
        self,
        resource_id: int,
        version_number: int,
        error_if_not_found: bool = False,
        **kwargs,
    ) -> list[models.ResourceSnapshot] | None:
        """Fetch a specific version of a resource.

        Args:
            resource_id: The unique id of the resource.
            version_number: A search string used to filter results.
            error_if_not_found: If True, raise an error if the resource is not found.
                Defaults to False.

        Returns:
            The requested version the resource object if found, otherwise None.

        Raises:
            ResourceDoesNotExistError: If the resource is not found and
                `error_if_not_found` is True.
        """
        log: BoundLogger = kwargs.get("log", LOGGER.new())
        log.debug("Get resource versions by id", resource_id=resource_id)

        stmt = select(models.Resource).filter_by(
            resource_id=resource_id, resource_type=self.resource_type, is_deleted=False
        )
        resource = db.session.scalars(stmt).first()

        if resource is None:
            if error_if_not_found:
                log.debug("Resource not found", resource_id=resource_id)
                raise ResourceDoesNotExistError

            return None

        stmt = (
            select(self.ResourceModel)
            .join(models.Resource)
            .where(
                models.Resource.resource_id == resource_id,
                models.Resource.is_deleted == False,  # noqa: E712
            )
            .order_by(self.ResourceModel.created_on)
            .offset(version_number - 1)
            .limit(1)
        )
        snapshot = db.session.scalars(stmt).first()

        if snapshot is None:
            if error_if_not_found:
                log.debug("Resource version not found", version_number=version_number)
                raise ResourceDoesNotExistError

            return None

        return snapshot
