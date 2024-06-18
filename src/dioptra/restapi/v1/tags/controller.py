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
"""The module defining the endpoints for Tag resources."""
from __future__ import annotations

import uuid
from typing import cast

import structlog
from flask import request
from flask_accepts import accepts, responds
from flask_login import login_required
from flask_restx import Namespace, Resource
from injector import inject
from structlog.stdlib import BoundLogger

from dioptra.restapi.db import models
from dioptra.restapi.v1 import utils
from dioptra.restapi.v1.schemas import IdStatusResponseSchema, ResourceUrlsSchema

from .schema import (
    TagGetQueryParameters,
    TagMutableFieldsSchema,
    TagPageSchema,
    TagResourceQueryParameters,
    TagSchema,
)
from .service import TagIdService, TagService

LOGGER: BoundLogger = structlog.stdlib.get_logger()

api: Namespace = Namespace("Tags", description="Tags endpoint")


@api.route("/")
class TagEndpoint(Resource):
    @inject
    def __init__(self, tag_service: TagService, *args, **kwargs) -> None:
        """Initialize the tag resource.

        All arguments are provided via dependency injection.

        Args:
            tag_service: A TagService object.
        """
        self._tag_service = tag_service
        super().__init__(*args, **kwargs)

    @login_required
    @accepts(query_params_schema=TagGetQueryParameters, api=api)
    @responds(schema=TagPageSchema, api=api)
    def get(self):
        """Gets a list of all Tags."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Tag", request_type="GET"
        )
        log.debug("Request received")
        parsed_query_params = request.parsed_query_params  # noqa: F841

        group_id = parsed_query_params["group_id"]
        search_string = parsed_query_params["search"]
        page_index = parsed_query_params["index"]
        page_length = parsed_query_params["page_length"]

        tags, total_num_tags = self._tag_service.get(
            group_id=group_id,
            search_string=search_string,
            page_index=page_index,
            page_length=page_length,
            log=log,
        )
        return utils.build_paging_envelope(
            "tags",
            build_fn=utils.build_tag,
            data=tags,
            query=search_string,
            index=page_index,
            length=page_length,
            total_num_elements=total_num_tags,
        )

    @login_required
    @accepts(schema=TagSchema, api=api)
    @responds(schema=TagSchema, api=api)
    def post(self):
        """Creates a Tag Resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Tag", request_type="POST"
        )
        log.debug("Request received")
        parsed_obj = request.parsed_obj  # noqa: F841

        tag = self._tag_service.create(
            name=parsed_obj["name"],
            description=parsed_obj["description"],
            group_id=parsed_obj["group_id"],
            log=log,
        )
        return utils.build_tag(tag)


@api.route("/<int:id>")
@api.param("id", "ID for the Tag.")
class TagIdEndpoint(Resource):
    @login_required
    @responds(schema=TagSchema, api=api)
    def get(self, id: int):
        """Gets a Tag."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Tag", request_type="GET", id=id
        )
        log.debug("Request received")

    @login_required
    @responds(schema=IdStatusResponseSchema, api=api)
    def delete(self, id: int):
        """Deletes a Tag."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Queue", request_type="DELETE", id=id
        )
        log.debug("Request received")

    @login_required
    @accepts(schema=TagMutableFieldsSchema, api=api)
    @responds(schema=TagSchema, api=api)
    def put(self, id: int):
        """Modifies a Tag."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Tag", request_type="PUT", id=id
        )
        log.debug("Request received")
        parsed_obj = request.parsed_obj  # type: ignore # noqa: F841


@api.route("/<int:id>/resources/")
@api.param("id", "ID for the Tag.")
class TagIdResourceEndpoint(Resource):
    @login_required
    @accepts(query_params_schema=TagResourceQueryParameters, api=api)
    @responds(schema=ResourceUrlsSchema, api=api)
    def get(self, id: int):
        """Gets all Resources labeled with this Tag."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Tag", request_type="GET", id=id
        )
        log.debug("Request received")
        parsed_query_params = request.parsed_query_params  # type: ignore # noqa: F841
