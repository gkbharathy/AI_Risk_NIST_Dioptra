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
"""The server-side functions that perform experiment endpoint operations."""
from typing import Final

from injector import inject

from dioptra.restapi.v1.groups.service import GroupIdService
from dioptra.restapi.v1.shared.drafts.service import (
    ResourceDraftIdService,
    ResourceDraftService,
    ResourceIdDraftService,
)

RESOURCE_TYPE: Final[str] = "experiment"


class ExperimentDraftService(ResourceDraftService):
    """The service methods for managing experiment drafts."""

    @inject
    def __init__(self, group_id_service: GroupIdService) -> None:
        super().__init__(RESOURCE_TYPE, group_id_service)


class ExperimentDraftIdService(ResourceDraftIdService):
    """The service methods for managing a specific experiment draft."""

    @inject
    def __init__(self) -> None:
        super().__init__(RESOURCE_TYPE)


class ExperimentIdDraftService(ResourceIdDraftService):
    """The service methods for managing the draft for an existing experiment."""

    @inject
    def __init__(self) -> None:
        super().__init__(RESOURCE_TYPE)
