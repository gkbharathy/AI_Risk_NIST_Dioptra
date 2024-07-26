from typing import Any

import importlib
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from werkzeug.test import TestResponse

from ..lib import actions, asserts, helpers

class TestResource(object):

    def __init__(self, client, api_route: str) -> None:
        self.client = client
        self.api_route = api_route


    def modify_resource(
        self, id: int, new_name: str, new_description: str
    ) -> TestResponse:
        payload: dict[str, Any] = {"name": new_name, "description": new_description}
        return self.client.put(
            f"{self.api_route}/{id}",
            json=payload,
            follow_redirects=True,
        )


    def delete_resource(self, id: int) -> TestResponse:
        return self.client.delete(
            f"{self.api_route}/{id}",
            follow_redirects=True,
        )


    def assert_base_response_contents_matches_expectations(
        self,
        expected_keys: set[str],
        response: dict[str, Any], 
        expected_contents: dict[str, Any],
    ) -> None:
        assert set(response.keys()) == expected_keys
        asserts.assert_base_resource_contents_match_expectations(response)
        asserts.assert_user_ref_contents_matches_expectations(
            user=response["user"], expected_user_id=expected_contents["user_id"]
        )
        asserts.assert_group_ref_contents_matches_expectations(
            group=response["group"], expected_group_id=expected_contents["group_id"]
        )
        asserts.assert_tag_ref_contents_matches_expectations(tags=response["tags"])


    def assert_retrieving_by_id_works(self, id: int, expected: dict[str, Any]) -> None:
        response = self.client.get(
            f"{self.api_route}/{id}", follow_redirects=True
        )
        assert response.status_code == 200 and response.get_json() == expected


    def assert_retrieving_all_works(
            self, 
            expected: list[dict[str, Any]],
            group_id: int | None = None,
            search: str | None = None,
            paging_info: dict[str, Any] | None = None,
        ) -> None:
        query_string: dict[str, Any] = {}

        if group_id is not None:
            query_string["groupId"] = group_id

        if search is not None:
            query_string["search"] = search

        if paging_info is not None:
            query_string["index"] = paging_info["index"]
            query_string["pageLength"] = paging_info["page_length"]

        response = self.client.get(
            self.api_route,
            query_string=query_string,
            follow_redirects=True,
        )
        assert response.status_code == 200 and response.get_json()["data"] == expected
    
    def assert_resource_is_not_found(self, ) -> None:
        return


    def register(self, **kwargs) -> None:
        # expected_contents = kwargs
        # register = getattr(actions, f"register_{resource_type}")
        # expected_response = register(
        #     client, name=name, description=description, group_id=group_id
        # ).get_json()

        payload = kwargs
        return self.client.post(
            self.api_route,
            json=payload,
            follow_redirects=True,
        ).get_json

        # assert_queue_response_contents_matches_expectations(
        #     response=expected_response,
        #     expected_contents=expected_contents,
        # )
        # assert_retrieving_queue_by_id_works(
        #     client, queue_id=queue1_expected["id"], expected=queue1_expected
        # )


    def test_get_all(self, ) -> None:
        return
    
    def test_search_query(self, ) -> None:
        return
    
    def test_group_query(self, ) -> None:
        return
    
    def test_get_by_id(self, ) -> None:
        return
    
    def test_delete(self, ) -> None:
        return


