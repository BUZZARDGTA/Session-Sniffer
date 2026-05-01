"""The package handles interactions with Discord."""

from session_sniffer.discord.webhook import (
    DiscordWebhookPayload,
    DiscordWebhookSender,
    is_valid_webhook_url,
    send_test_message,
)

__all__ = [
    'DiscordWebhookPayload',
    'DiscordWebhookSender',
    'is_valid_webhook_url',
    'send_test_message',
]
