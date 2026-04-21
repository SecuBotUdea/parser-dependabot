from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.routes.webhook.processor import _enqueue_upsert, _send_normalized_alert


async def test_send_normalized_alert_executes_post_with_correct_payload():
    # Arrange
    alert_dict = {
        "alert_id": "dependabot-org-repo-42",
        "source_id": "42",
        "severity": "high",
        "component": "requests",
        "status": "open",
        "signature": "abc123",
        "quality": "good",
        "normalized_payload": {},
    }

    with patch("app.routes.webhook.processor.httpx.AsyncClient") as mock_client:
        mock_response = MagicMock(status_code=200)
        mock_post = AsyncMock(return_value=mock_response)
        mock_instance = AsyncMock()
        mock_instance.post = mock_post
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        # Act
        await _send_normalized_alert(alert_dict, "dependabot")

    # Assert
    mock_post.assert_called_once()
    _, call_kwargs = mock_post.call_args
    assert call_kwargs["json"]["alert_id"] == "dependabot-org-repo-42"
    assert call_kwargs["json"]["severity"] == "high"


async def test_enqueue_upsert_calls_service_when_source_is_dependabot():
    # Arrange
    alert_data = {"number": 42, "state": "open"}
    mock_service = MagicMock()
    mock_service.create_alert_from_dependabot.return_value = None

    # Act
    await _enqueue_upsert(alert_data, mock_service, source="dependabot")

    # Assert
    mock_service.create_alert_from_dependabot.assert_called_once_with(alert_data)
