import http.client
import json

from config import  get_logger, SlackAppConfig, SlackWebhookConfig
from dateutil.parser import parse as parse_date
from slack_sdk import WebClient
from typing import Any
from slack_sdk.web.slack_response import SlackResponse

logger = get_logger()



def post_message( # noqa: ANN201
        slack_config: SlackAppConfig | SlackWebhookConfig,
        message: dict,
        account_id: str | None = None,
        thread_ts: str | None = None,
) -> None | SlackResponse:

    if isinstance(slack_config, SlackAppConfig):
        if account_id and slack_config.configuration:
            channel_id = next(
                (cfg["slack_channel_id"] for cfg in slack_config.configuration if account_id in cfg["accounts"]), # noqa: E501
                slack_config.default_channel_id
            )
        else:
            channel_id = slack_config.default_channel_id
        return slack_app_post_message(
            message = message,
            channel_id = channel_id,
            slack_config = slack_config,
            thread_ts = thread_ts,
        )

    if isinstance(slack_config, SlackWebhookConfig):
        if account_id and slack_config.configuration:
            hook_url = next(
                (cfg["slack_hook_url"] for cfg in slack_config.configuration if account_id in cfg["accounts"]), # noqa: E501
                slack_config.default_hook_url
            )
        else:
            hook_url = slack_config.default_hook_url
        webhook_post_message(
            message = message,
            hook_url = hook_url,
        )


def slack_app_post_message( # noqa: ANN201
        message: dict,
        channel_id: str,
        slack_config: SlackAppConfig,
        thread_ts: str | None = None
):
    client = WebClient(token=slack_config.bot_token)
    return client.chat_postMessage(
        channel = channel_id,
        blocks = message["blocks"],
        thread_ts = thread_ts,
        text="New message from CloudTrailToSlack"
    )



# Slack web hook example
# https://hooks.slack.com/services/XXXXXXX/XXXXXXX/XXXXXXXXXX
def webhook_post_message(message: dict, hook_url: str) -> int:
    logger.info({"Sending message to slack": message})
    headers = {"Content-type": "application/json"}
    connection = http.client.HTTPSConnection("hooks.slack.com")
    connection.request("POST",
                       hook_url.replace("https://hooks.slack.com", ""),
                       json.dumps(message),
                       headers)
    response = connection.getresponse()
    logger.info({"Slack response": {"status": response.status, "message": response.read().decode()}})
    return response.status


# Format message
#
# INTUNE PATCH (vendored fork, baseline upstream tag 4.5.0): replaces the upstream
# three-raw-json.dumps formatter with a ClickOps-style layout — header + subtitle, a
# TWO-COLUMN summary (Account Id | Region, IAM Action | Principal) via Slack `fields`,
# and ONLY the requestParameters (the "what changed" detail) as a small code block.
# The full event is omitted (it lives in CloudTrail; S3 path in the footer), keeping
# each alert scannable. Posted via a Slack bot token so it carries its own app
# identity, same as the original ClickOps.
def event_to_slack_message(event:  dict, source_file :str , account_id_from_event: str ) ->  dict[str, Any]:
    event_name    = event["eventName"]
    event_source  = event.get("eventSource", "")
    region        = event.get("awsRegion", "N/A")
    error_code    = event.get("errorCode")
    error_message = event.get("errorMessage")
    event_time    = parse_date(event["eventTime"])
    event_id      = event.get("eventID", "N/A")

    identity = event.get("userIdentity", {})
    # Prefer a human-readable principal: IAM userName, else the full ARN.
    principal = identity.get("userName") or identity.get("arn", "Unknown Identity")
    action    = f"{event_name}:{event_source}" if event_source else event_name

    # Best-effort "what was touched": first resource ARN, else a name-ish request param.
    resource  = ""
    resources = event.get("resources") or []
    if isinstance(resources, list) and resources and isinstance(resources[0], dict) and resources[0].get("ARN"):
        resource = resources[0]["ARN"]
    else:
        rp = event.get("requestParameters") or {}
        if isinstance(rp, dict):
            resource = rp.get("name") or rp.get("functionName") or rp.get("bucketName") or rp.get("groupName") or ""

    blocks = []

    header = ":rotating_light: *ClickOps Alert* :rotating_light:"
    if error_code is not None:
        header = ":warning: *ClickOps Alert* (action failed) :warning:"
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": header}})

    blocks.append({"type": "section", "text": {"type": "mrkdwn",
        "text": "Someone is practicing ClickOps in your AWS Account!"}})

    # Two-column summary — Slack lays `fields` out two-per-row, like ClickOps.
    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"*Account Id*\n{account_id_from_event}"},
            {"type": "mrkdwn", "text": f"*Region*\n{region}"},
            {"type": "mrkdwn", "text": f"*IAM Action*\n{action}"},
            {"type": "mrkdwn", "text": f"*Principal*\n{principal}"},
        ],
    })

    if resource:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Resource*\n`{resource}`"}})

    if error_code is not None:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Failed due to* `{error_code}`"}})

    if error_message is not None:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Error:* {error_message}"}})

    if event_name == "ConsoleLogin" and event.get("additionalEventData", {}).get("MFAUsed") != "Yes":
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ":warning: *Login without MFA!* :warning:"}})

    # Only the request parameters — the "what changed" detail. CloudTrail redacts
    # secret values (e.g. SecureString → HIDDEN_DUE_TO_SECURITY_REASONS) upstream.
    request_parameters = event.get("requestParameters")
    if request_parameters:
        rp_json = json.dumps(request_parameters, indent=2, default=str)
        if len(rp_json) > 1500:
            rp_json = rp_json[:1500] + "\n... (truncated)"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Request parameters*\n```{rp_json}```"}})

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"{event_name} · {event_time} UTC · `{event_id}`"},
            {"type": "mrkdwn", "text": f"Full event in CloudTrail: {source_file}"},
        ],
    })

    blocks.append({"type": "divider"})

    return {"blocks": blocks}


def message_for_slack_error_notification(
        error: Exception,
        s3_notification_event:  dict
) ->  dict:
    object_keys = [record["s3"]["object"]["key"] for record in s3_notification_event["Records"]]
    if len(object_keys) == 1:
        object_key = object_keys[0]
    else:
        object_key = "\n ".join(object_keys)

    title = ":warning: *Failed to process event:*  :warning:"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Error:*"
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"```{error}```"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Object(s):*"
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"{object_key}"
                }
            ]
        }
    ]
    message = {"blocks": blocks}

    return message


def message_for_rule_evaluation_error_notification(
        error: Exception,
        object_key: str,
        rule: str
) ->  dict[str, Any]:
    title = ":warning: *Failed to evaluate rule:*  :warning:"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Rule:* \n```{rule}```"
                }
            ]
        },

        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Error:* \n```{error}```"
                }
            ]
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Object:* \n{object_key}"
                }
            ]
        }
    ]
    message = {"blocks": blocks}

    return message
