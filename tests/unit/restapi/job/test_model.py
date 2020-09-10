import datetime
from typing import BinaryIO

import pytest
import structlog
from structlog._config import BoundLoggerLazyProxy

from mitre.securingai.restapi.job.model import Job, JobFormData
from mitre.securingai.restapi.shared.job_queue.model import JobQueue, JobStatus

LOGGER: BoundLoggerLazyProxy = structlog.get_logger()


@pytest.fixture
def job() -> Job:
    return Job(
        job_id="4520511d-678b-4966-953e-af2d0edcea32",
        mlflow_run_id=None,
        created_on=datetime.datetime(2020, 8, 17, 18, 46, 28, 717559),
        last_modified=datetime.datetime(2020, 8, 17, 18, 46, 28, 717559),
        queue=JobQueue.tensorflow_cpu,
        timeout="12h",
        workflow_uri="s3://workflow/workflows.tar.gz",
        entry_point="main",
        entry_point_kwargs="-P var1=testing",
        depends_on=None,
        status=JobStatus.queued,
    )


@pytest.fixture
def job_form_data(workflow_tar_gz: BinaryIO) -> JobFormData:
    return JobFormData(
        queue=JobQueue.tensorflow_cpu,
        timeout="12h",
        entry_point="main",
        entry_point_kwargs="-P var1=testing",
        depends_on="0c30644b-df51-4a8b-b745-9db07ce57f72",
        workflow=workflow_tar_gz,
    )


def test_Job_create(job: Job) -> None:
    assert isinstance(job, Job)


def test_JobFormData_create(job_form_data: JobFormData) -> None:
    assert isinstance(job_form_data, dict)