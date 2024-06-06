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
"""The module defining the endpoints for Drafts."""
from __future__ import annotations

import uuid

import structlog
from flask import request
from flask_accepts import accepts, responds
from flask_login import login_required
from flask_restx import Namespace, Resource
from structlog.stdlib import BoundLogger

from dioptra.restapi.v1 import utils
from dioptra.restapi.v1.schemas import (
    IdStatusResponseSchema,
    PagingQueryParametersSchema,
)

from .schema import (
    DraftExistingResourceSchema,
    DraftMutableFieldsSchema,
    DraftNewResourceSchema,
    DraftPageSchema,
)

LOGGER: BoundLogger = structlog.stdlib.get_logger()

api: Namespace = Namespace("Drafts", description="Drafts sub-endpoint")


class ResourcesDraftsEndpoint(Resource):
    @login_required
    @accepts(query_params_schema=PagingQueryParametersSchema, api=api)
    @responds(schema=DraftPageSchema, api=api)
    def get(self):
        """Gets the Drafts for the resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="GET"
        )
        parsed_query_params = request.parsed_query_params  # noqa: F841

        page_index = parsed_query_params["index"]
        page_length = parsed_query_params["page_length"]

        drafts, total_num_drafts = self._draft_service.get(
            page_index, page_length, log=log
        )
        return utils.build_paging_envelope(
            f"{self._resource_name}/drafts",
            build_fn=utils.build_new_resource_draft,
            data=drafts,
            query=None,
            index=page_index,
            length=page_length,
            total_num_elements=total_num_drafts,
        )

    @login_required
    @accepts(schema=DraftNewResourceSchema, api=api)
    @responds(schema=DraftNewResourceSchema, api=api)
    def post(self):
        """Creates a Draft for the resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="POST"
        )
        parsed_obj = request.parsed_obj  # noqa: F841
        draft = self._draft_service.create(
            parsed_obj["group_id"], parsed_obj["payload"], log=log
        )
        return utils.build_new_resource_draft(draft)


class ResourcesDraftsIdEndpoint(Resource):
    @login_required
    @responds(schema=DraftNewResourceSchema, api=api)
    def get(self, draft_id: int):
        """Gets a Draft for the resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="GET"
        )
        draft = self._draft_id_service.get(draft_id, error_if_not_found=True, log=log)
        return utils.build_new_resource_draft(draft)

    @login_required
    @accepts(schema=DraftMutableFieldsSchema, api=api)
    @responds(schema=DraftNewResourceSchema, api=api)
    def put(self, draft_id: int):
        """Modifies a Draft for the resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="POST"
        )
        parsed_obj = request.parsed_obj  # type: ignore
        draft = self._draft_id_service.modify(
            draft_id, payload=parsed_obj["payload"], log=log
        )
        return utils.build_new_resource_draft(draft)

    @login_required
    @responds(schema=IdStatusResponseSchema, api=api)
    def delete(self, draft_id: int):
        """Deletes a Draft for the resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="DELETE"
        )
        return self._draft_id_service.delete(draft_id, log=log)


@api.route("/<int:id>/draft")
@api.param("id", "ID for the resource.")
class ResourcesIdDraftEndpoint(Resource):
    @login_required
    @responds(schema=DraftExistingResourceSchema, api=api)
    def get(self, id: int):
        """Gets the Draft for this resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="GET"
        )
        draft, num_other_drafts = self._id_draft_service.get(
            id, error_if_not_found=True, log=log
        )
        return utils.build_existing_resource_draft(draft, num_other_drafts)

    @login_required
    @accepts(schema=DraftExistingResourceSchema, api=api)
    @responds(schema=DraftExistingResourceSchema, api=api)
    def post(self, id: int):
        """Creates a Draft for this resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="POST"
        )
        parsed_obj = request.parsed_obj  # type: ignore
        draft, num_other_drafts = self._id_draft_service.create(
            id, payload=parsed_obj["payload"], log=log
        )
        return utils.build_existing_resource_draft(draft, num_other_drafts)

    @login_required
    @accepts(schema=DraftMutableFieldsSchema, api=api)
    @responds(schema=DraftExistingResourceSchema, api=api)
    def put(self, id: int):
        """Modifies the Draft for this resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="POST"
        )
        parsed_obj = request.parsed_obj  # type: ignore
        draft, num_other_drafts = self._id_draft_service.modify(
            id, payload=parsed_obj["payload"], error_if_not_found=True, log=log
        )
        log.info("controller", payload=draft.payload)
        return utils.build_existing_resource_draft(draft, num_other_drafts)

    @login_required
    @responds(schema=IdStatusResponseSchema, api=api)
    def delete(self, id: int):
        """Deletes the Draft for this resource."""
        log = LOGGER.new(
            request_id=str(uuid.uuid4()), resource="Draft", request_type="DELETE"
        )
        return self._id_draft_service.delete(id, log=log)
