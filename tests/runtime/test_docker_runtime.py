"""Tests for DockerRuntime container startup and auth injection."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from strix.runtime import SandboxInitializationError


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    with patch("docker.from_env") as mock_from_env:
        client = MagicMock()
        mock_from_env.return_value = client
        yield client


@pytest.fixture
def runtime(mock_docker_client):
    """Create a DockerRuntime instance with mocked Docker."""
    from strix.runtime.docker_runtime import DockerRuntime

    return DockerRuntime()


class TestWaitForToolServer:
    """Tests for _wait_for_tool_server container liveness checks."""

    def test_fails_fast_when_container_dead(self, runtime):
        """When the container exits during startup, fail immediately with logs."""
        container = MagicMock()
        container.status = "exited"
        container.logs.return_value = b"ERROR: Tool server failed to become healthy"
        runtime._scan_container = container
        runtime._tool_server_port = 12345

        with patch("time.sleep"), pytest.raises(SandboxInitializationError) as exc_info:
            runtime._wait_for_tool_server(max_retries=6, timeout=1)

        assert "Container exited during initialization" in str(exc_info.value.details)
        assert "Tool server failed to become healthy" in str(exc_info.value.details)

    def test_succeeds_when_healthy(self, runtime):
        """When the health check returns healthy, succeed immediately."""
        container = MagicMock()
        container.status = "running"
        runtime._scan_container = container
        runtime._tool_server_port = 12345

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}

        with (
            patch("time.sleep"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            # Should not raise
            runtime._wait_for_tool_server(max_retries=5, timeout=1)

    def test_timeout_includes_container_logs(self, runtime):
        """When timing out, include container logs in the error details."""
        container = MagicMock()
        container.status = "running"
        container.logs.return_value = b"Waiting for Caido API..."
        runtime._scan_container = container
        runtime._tool_server_port = 12345

        import httpx

        with (
            patch("time.sleep"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ConnectError("refused")
            mock_client_cls.return_value = mock_client

            with pytest.raises(SandboxInitializationError) as exc_info:
                runtime._wait_for_tool_server(max_retries=3, timeout=1)

        assert "Container logs:" in str(exc_info.value.details)


class TestCreateContainerRetry:
    """Tests for _create_container retry logic with SandboxInitializationError."""

    def test_retries_on_tool_server_failure(self, runtime, mock_docker_client):
        """SandboxInitializationError from _wait_for_tool_server triggers retry."""
        from docker.errors import NotFound

        container = MagicMock()
        container.id = "abc123"
        container.status = "running"
        container.logs.return_value = b"some logs"
        mock_docker_client.containers.run.return_value = container
        # containers.get is called in contextlib.suppress(NotFound) to clean up
        mock_docker_client.containers.get.side_effect = NotFound("not found")
        mock_docker_client.images.get.return_value = MagicMock(
            id="img123", attrs={"Size": 100}
        )

        call_count = 0

        def mock_wait(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise SandboxInitializationError(
                    "Tool server failed to start",
                    "Container exited during initialization.",
                )

        with (
            patch.object(runtime, "_wait_for_tool_server", side_effect=mock_wait),
            patch.object(runtime, "_find_available_port", return_value=12345),
            patch.object(runtime, "_start_zap_container"),
            patch.object(runtime, "_inject_auth_files"),
            patch("time.sleep"),
            patch("strix.runtime.docker_runtime.Config") as mock_config,
        ):
            mock_config.get.return_value = "test-image:latest"
            result = runtime._create_container("test-scan", max_retries=2)

        assert result == container
        assert call_count == 2  # Failed once, succeeded on retry


    def test_docker_error_preserved_in_details(self, runtime, mock_docker_client):
        """Docker API errors include the exception type and message in details."""
        from docker.errors import APIError, NotFound

        mock_docker_client.containers.get.side_effect = NotFound("not found")
        mock_docker_client.images.get.return_value = MagicMock(
            id="img123", attrs={"Size": 100}
        )
        mock_docker_client.containers.run.side_effect = APIError(
            "Conflict. The container name is already in use"
        )

        with (
            patch.object(runtime, "_find_available_port", return_value=12345),
            patch.object(runtime, "_start_zap_container"),
            patch("time.sleep"),
            patch("strix.runtime.docker_runtime.Config") as mock_config,
        ):
            mock_config.get.return_value = "test-image:latest"
            with pytest.raises(SandboxInitializationError) as exc_info:
                runtime._create_container("test-scan", max_retries=0)

        assert "Failed to create container" in exc_info.value.message
        assert "APIError" in str(exc_info.value.details)
        assert "Conflict" in str(exc_info.value.details)

    def test_tool_server_error_preserves_original_message(self, runtime, mock_docker_client):
        """When tool server fails on all retries, the original message is preserved."""
        from docker.errors import NotFound

        container = MagicMock()
        container.id = "abc123"
        container.status = "running"
        container.logs.return_value = b"some logs"
        mock_docker_client.containers.run.return_value = container
        mock_docker_client.containers.get.side_effect = NotFound("not found")
        mock_docker_client.images.get.return_value = MagicMock(
            id="img123", attrs={"Size": 100}
        )

        def mock_wait(*args, **kwargs):
            raise SandboxInitializationError(
                "Tool server failed to start",
                "Container exited during initialization.",
            )

        with (
            patch.object(runtime, "_wait_for_tool_server", side_effect=mock_wait),
            patch.object(runtime, "_find_available_port", return_value=12345),
            patch.object(runtime, "_start_zap_container"),
            patch.object(runtime, "_inject_auth_files"),
            patch("time.sleep"),
            patch("strix.runtime.docker_runtime.Config") as mock_config,
        ):
            mock_config.get.return_value = "test-image:latest"
            with pytest.raises(SandboxInitializationError) as exc_info:
                runtime._create_container("test-scan", max_retries=1)

        # Should preserve the original "Tool server failed" message, not generic
        assert "Tool server failed to start" in exc_info.value.message
        assert "Container exited" in str(exc_info.value.details)

    def test_image_not_found_gives_actionable_error(self, runtime, mock_docker_client):
        """Missing Docker image produces an actionable error with pull command."""
        from docker.errors import ImageNotFound

        mock_docker_client.images.get.side_effect = ImageNotFound("not found")

        with (
            patch("time.sleep"),
            patch("strix.runtime.docker_runtime.Config") as mock_config,
        ):
            mock_config.get.return_value = "ghcr.io/usestrix/strix-sandbox:0.1.13"
            with pytest.raises(SandboxInitializationError) as exc_info:
                runtime._create_container("test-scan", max_retries=0)

        assert "Docker image not found" in exc_info.value.message
        assert "docker pull" in str(exc_info.value.details)
        assert "ghcr.io/usestrix/strix-sandbox:0.1.13" in str(exc_info.value.details)


class TestInjectAuthFiles:
    """Tests for _inject_auth_files file-based auth injection."""

    def test_injects_cookies_as_tar(self, runtime):
        """Auth cookies are written as a tar archive into the container."""
        container = MagicMock()
        cookies = [
            {"name": "__Host-at-abc", "value": "x" * 2000},
            {"name": "__Host-rt-abc", "value": "y" * 2000},
        ]
        scan_config = {
            "auth_config": {
                "configured": True,
                "headers": {},
                "cookies": cookies,
            }
        }

        mock_tracer = MagicMock()
        mock_tracer.scan_config = scan_config

        with patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer
        ):
            runtime._inject_auth_files(container)

        container.put_archive.assert_called_once()
        call_args = container.put_archive.call_args
        assert call_args[0][0] == "/app/certs"

        # Verify the tar contains auth_cookies.json
        import tarfile
        from io import BytesIO

        tar_data = call_args[0][1]
        with tarfile.open(fileobj=BytesIO(tar_data), mode="r") as tar:
            names = tar.getnames()
            assert "auth_cookies.json" in names
            member = tar.getmember("auth_cookies.json")
            f = tar.extractfile(member)
            assert f is not None
            data = json.loads(f.read())
            assert len(data) == 2
            assert data[0]["name"] == "__Host-at-abc"

    def test_no_op_without_auth_config(self, runtime):
        """Does nothing when no auth config is present."""
        container = MagicMock()

        mock_tracer = MagicMock()
        mock_tracer.scan_config = {"auth_config": {}}

        with patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer
        ):
            runtime._inject_auth_files(container)

        container.put_archive.assert_not_called()

    def test_handles_missing_tracer_gracefully(self, runtime):
        """Does not raise when tracer is unavailable."""
        container = MagicMock()

        with patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=None
        ):
            # Should not raise
            runtime._inject_auth_files(container)

        container.put_archive.assert_not_called()


class TestGetAuthEnvVars:
    """Tests for _get_auth_env_vars with large cookie payloads."""

    def test_serializes_cookies_to_json(self, runtime):
        """Cookies are serialized as JSON in the env var."""
        cookies = [
            {"name": "__Host-at-abc", "value": "x" * 2000},
        ]
        scan_config = {
            "auth_config": {
                "configured": True,
                "headers": {},
                "cookies": cookies,
            }
        }

        mock_tracer = MagicMock()
        mock_tracer.scan_config = scan_config

        with patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer
        ):
            env_vars = runtime._get_auth_env_vars()

        assert "STRIX_AUTH_COOKIES_JSON" in env_vars
        parsed = json.loads(env_vars["STRIX_AUTH_COOKIES_JSON"])
        assert len(parsed) == 1
        assert parsed[0]["value"] == "x" * 2000

    def test_empty_when_no_auth(self, runtime):
        """Returns empty dict when no auth is configured."""
        mock_tracer = MagicMock()
        mock_tracer.scan_config = {}

        with patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer
        ):
            env_vars = runtime._get_auth_env_vars()

        assert env_vars == {}
