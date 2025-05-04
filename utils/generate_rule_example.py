#!/usr/bin/env python3
import sys
import os
import json
import copy
import yaml

# A base CloudTrail log template (adjust as needed).
BASE_LOG = {
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROEXAMPLE",
        "arn": "arn:aws:sts::123456789012:assumed-role/ExampleRole/ExampleUser",
        "accountId": "123456789012",
        "accessKeyId": "ASIAXXXXXX",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROEXAMPLE",
                "arn": "arn:aws:iam::123456789012:role/ExampleRole",
                "accountId": "123456789012",
                "userName": "ExampleUserName"
            },
            "attributes": {
                "creationDate": "2025-03-09T16:39:29Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2025-03-09T16:39:48Z",
    "eventSource": "notifications.amazonaws.com",
    "eventName": "ListNotificationHubs",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "1.2.3.4",
    "userAgent": "ExampleAgent/1.0",
    "requestParameters": None,
    "responseElements": None,
    "requestID": "4c23c774-e2b5-46fe-83b9-EXAMPLE",
    "eventID": "2a9c402c-5df4-4e68-a21f-EXAMPLE",
    "readOnly": True,
    "eventType": "AwsApiCall",
    "managementEvent": True,
    "recipientAccountId": "123456789012",
    "eventCategory": "Management"
}

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_rule_example_json.py <rule.yml>")
        sys.exit(1)

    rule_file = sys.argv[1]
    base, _ = os.path.splitext(rule_file)
    out_file = f"{base}_tests.json"

    with open(rule_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if isinstance(data, list):
        rule = data[0]
    else:
        rule = data

    detection = rule.get("detection", {})
    condition_block = detection.get("condition")
    if not condition_block:
        print("No 'condition' found in the rule's detection. Exiting.")
        return

    selection_block = detection.get(condition_block, {})

    match_log = copy.deepcopy(BASE_LOG)

    event_source = selection_block.get("eventSource")
    if isinstance(event_source, list) and event_source:
        match_log["eventSource"] = event_source[0]
    elif isinstance(event_source, str):
        match_log["eventSource"] = event_source

    event_name = selection_block.get("eventName")
    if isinstance(event_name, list) and event_name:
        match_log["eventName"] = event_name[0]
    elif isinstance(event_name, str):
        match_log["eventName"] = event_name

    nonmatch_log = copy.deepcopy(match_log)

    if event_source:
        current = nonmatch_log["eventSource"]
        if current == "cloudtrail.amazonaws.com":
            nonmatch_log["eventSource"] = "s3.amazonaws.com"
        else:
            nonmatch_log["eventSource"] = "cloudtrail.amazonaws.com"
    elif event_name:
        if isinstance(event_name, list):
            possible = {"CreateUser", "GetSessionToken", "DescribeInstances"}
            not_match = (possible - set(event_name)).pop() if (possible - set(event_name)) else "UnexpectedEvent"
            nonmatch_log["eventName"] = not_match
        else:
            if event_name == "DeleteIdentity":
                nonmatch_log["eventName"] = "CreateUser"
            else:
                nonmatch_log["eventName"] = "DeleteIdentity"

    test_data = {
        "should_match": [match_log],
        "should_not_match": [nonmatch_log]
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(test_data, f, indent=2)

    print(f"Generated {out_file}")
    print("\n[should_match] example log:")
    print(json.dumps(match_log, indent=2))
    print("\n[should_not_match] example log:")
    print(json.dumps(nonmatch_log, indent=2))

if __name__ == "__main__":
    main()