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
"""Utility functions to help in building responses from ORM models"""
from __future__ import annotations

from typing import Any

from dioptra.restapi.db import models


def build_user_ref(user: models.User) -> dict[str, Any]:
    return {
        "id": user.user_id,
        "username": user.username,
        "url": f"/users/{user.user_id}",
    }

def build_user(user: models.User) -> dict[str:Any]:
    return {
        "id": user.user_id,
        "username": user.username,
        "email": user.email_address,
    }

def build_current_user(user: models.User) -> dict[str:Any]:
    member_of = {x.group.group_id: x.group for x in user.group_memberships}
    manager_of = {x.group.group_id: x.group for x in user.group_managementships}
    groups = {**member_of, **manager_of}.values()

    return {
        "id": user.user_id,
        "username": user.username,
        "email": user.email_address,
        "groups": [build_group_ref(group) for group in groups],
        "createdOn": user.created_on,
        "lastModifiedOn": user.last_modified_on,
        "lastLoginOn": user.last_login_on,
        "passwordExpiresOn": user.password_expire_on,
    }


def build_group_ref(group: models.Group) -> dict[str, Any]:
    return {
        "id": group.group_id,
        "name": group.name,
        "url": f"/groups/{group.group_id}",
    }


def build_group(group: models.Group) -> dict[str:Any]:
    members = [
        {
            "user": build_user_ref(member.user),
            "group": build_group_ref(group),
            "permissions": {
                "read": member.read,
                "write": member.write,
                "shareRead": member.share_read,
                "shareWrite": member.share_write,
                "admin": False,
                "owner": False,
            },
        }
        for member in group.members
    ]
    return {
        "id": group.group_ud,
        "name": group.name,
        "user": build_user_ref(group.creator),
        "members": members,
        "createdOn": group.created_on,
        "lastModified_on": group.last_modified_on,
    }

def build_paging_envelope(name, data, query, index, length):
    has_prev = index > 0
    has_next = len(data) > length
    is_complete = not (has_prev or has_next)
    paged_data = {
        "query": query,
        "index": index,
        "is_complete": is_complete,
        "data": data[:length],
    }

    if has_prev:
        prev_index = max(index - length, 0)
        prev_url = build_paging_url("users", query, prev_index, length)
        paged_data.update({"prev": prev_url})

    if has_next:
        next_index = index + length
        next_url = build_paging_url("users", query, next_index, length)
        paged_data.update({"next": next_url})

    return paged_data


def build_paging_url(name: str, search: str, index: int, length: int):
    return f"/{name}/?query={search}&index={index}&pageLength={length}"
