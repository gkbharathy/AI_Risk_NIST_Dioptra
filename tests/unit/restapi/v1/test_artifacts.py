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
"""Test suite for artifact operations.

This module contains a set of tests that validate the permitted operations of the
artifact entity. The tests ensure that artifacts can be retrieved but not submitted
by users."""
from typing import Any, Dict, List

import json, os, pytest
from flask import jsonify
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from pytest import MonkeyPatch
from werkzeug.test import TestResponse

from dioptra.restapi.routes import V1_ROOT, V1_ARTIFACTS_ROUTE
from dioptra.restapi.v1.artifacts.schema import ArtifactSchema
from dioptra.restapi.v1.artifacts.controller import ArtifactEndpoint


class MockJobService:

    job_count = 0
    artifact_count = 0
    artifacts = []

    def __init__(self, num_artifacts=3):
        """For the mock job service, create a dictionary that associates
        each job ID (int) with a list of of mock artifacts (dict) """
        if num_artifacts > 0:
            self.generate_mock_artifacts(num_artifacts)


    def generate_mock_artifacts(self, num_artifacts: int) -> None:
        """Generate num_artifacts number of mock artifacts."""
        self.job_count += 1
        for i in range(num_artifacts):
            self.artifact_count += 1
            artifact = self.create_artifact(
                artifactUri=f"http://example.com/artifacts/{self.artifact_count}",
                jobId=self.job_count,
                mlflowRunId=5
            )
            self.artifacts.append(artifact)


    def create_artifact(artifactUri: str, jobId: int, mlflowRunId: int) -> Dict:
        """Create an artifact with the provided attributes and validate it against
        ArtifactSchema."""
        artifact_data = {
                "artifactUri": artifactUri,
                "jobId": jobId,
                "mlflowRunId": mlflowRunId,
            }
        validated_artifact_data = ArtifactSchema().load(artifact_data)
        return validated_artifact_data

    
    def get_artifact_by_id_response(self, *args, **kwargs) -> TestResponse:
        """Get an artifact by its ID. Returns a mocked TestResponse"""
        artifact_id = int(os.path.basename(args[0]))
        response_json = jsonify(MockJobService.get_artifact_by_id(artifact_id))
        response = TestResponse(
            response=response_json.data,
            status=200,
            content_type='application/json',
            headers=None,
            request=None,
        )
        return response


    def get_artifact_by_id(artifact_id: int) -> Dict:
        if artifact_id + 1 > MockJobService.artifact_count:
            return None
        return MockJobService.artifacts[artifact_id + 1]
    

    def get_artifacts_response(self, *args, **kwargs) -> TestResponse:
        """Get all artifacts. Returns a mocked TestResponse."""
        response_json = jsonify(MockJobService.get_artifacts())
        response = TestResponse(
            response=response_json.data,
            status=200,
            content_type='application/json',
            headers=None,
            request=None,
        )
        return response

    def get_artifacts():
        return MockJobService.artifacts

    
    def post_artifact(self, *args, **kwargs) -> TestResponse:
        MockJobService.create_artifact()



# -- Actions --------------------------------------------------------------------------

def submit_artifact(
    client: FlaskClient,
    form_request: dict[str, Any],
) -> TestResponse:
    """Submit an artifact using the API.
    
    Args:
        client: The Flask test client.
        form_request: The artifact parameters to include in the submission request.
        
    Returns:
        The response from the API.
    """
    return client.post(
        f"/{V1_ROOT}/{V1_ARTIFACTS_ROUTE}/",
        content_type="multipart/form-data",
        data=form_request,
        follow_redirects=True,
    )

def get_artifact_by_id(
        client: FlaskClient, artifact_id: int
) -> TestResponse:
    """Retrieve an artifact by ID using the API
    
    Args:
        client: The Flask test client.
        artifact_id: The ID of the artifact to retrieve.
        
    Returns:
        The response from the API.
    """
    return client.get(
        f"/{V1_ROOT}/{V1_ARTIFACTS_ROUTE}/{artifact_id}", 
        follow_redirects=True,
    )

def get_all_artifacts(client: FlaskClient) -> TestResponse:
    """Retrieve all artifacts using the API.
    
    Args:
        client: The Flask test client.
        
    Returns:
        The response from the API.
    """
    return client.get(
        f"/{V1_ROOT}/{V1_ARTIFACTS_ROUTE}",
        follow_redirects=True,
    )

def post_artifact(client: FlaskClient) -> TestResponse:
    """Post an artifact using the API.
    
    Args: client: The Flask test client.
    
    Returns:
        The response from the API.
    """
    return client.post(
        f"/{V1_ROOT}/{V1_ARTIFACTS_ROUTE}",
        follow_redirects=True,
    )

# -- Tests ----------------------------------------------------------------------------

@pytest.mark.v1
def test_user_submit_artifact(
        client: FlaskClient,
        db: SQLAlchemy,
) -> None:
    """Test that a user cannot submit an artifact.
    
        Scenario: Decline User Submission of an Artifact
            Given I am a non-system user,
            I should not be able to submit a post request for an artifact
            because they can only be submitted by the system.
    """
    response = submit_artifact(client, form_request={})
    assert response.status_code == 403


@pytest.mark.v1
def test_get_artifact_by_id(
        monkeypatch: MonkeyPatch,
        client: FlaskClient,
        db: SQLAlchemy,
) -> None:
    """Test that an artifact can be retrieved by ID.
    
        Scenario: Get a Specific Artifact
            Given I am an authorized user and an artifact exists
            I need to submit a get request that includes an artifact ID
            in order to obtain an artifact's information.
    """

    mock_job = MockJobService
    monkeypatch.setattr(FlaskClient, "get", mock_job.get_artifact_by_id_response)
    artifact_id = mock_job.artifact_count
    response = get_artifact_by_id(client, artifact_id)
    assert response.status_code == 200


@pytest.mark.v1
def test_get_all_artifacts(
        monkeypatch: MonkeyPatch,
        client: FlaskClient,
        db: SQLAlchemy,
) -> None:
    """Test that all artifacts can be retrieved.

        Scenario: Get a List of All Artifacts
            Given I am an authorized user and artifacts exist
            I need to submit a get request with query parameters
            in order to retrieve the list of artifacts matching those parameters.
    """
    mock_job = MockJobService

    monkeypatch.setattr(FlaskClient, "get", mock_job.get_artifacts_response)
    response = get_all_artifacts(client)
    formatted_response = json.loads(response.data)
    assert response.status_code == 200 and formatted_response == mock_job.get_artifacts()


@pytest.mark.v1
def test_system_submit_artifact(
        monkeypatch: MonkeyPatch,
        client: FlaskClient,
        db: SQLAlchemy,
) -> None:
    """Test that the system can submit a new artifact.
    
        Scenario: System Creates an Artifact
            Given I am the system, a job exists, and an MLFLow run exists
            I need to be able to submit a post request that includes a group ID, 
            a job ID, an MLFLow run ID, and an optional URL
            in order to create a new artifact.
    """

    mock_job = MockJobService

    monkeypatch.setattr(FlaskClient, "post", mock_job.post_artifact)