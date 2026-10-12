import os
import sys
import json

INVESTIGATION_DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_DIR = os.path.dirname(INVESTIGATION_DIR)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)

from integrations.servicenow_client import ServiceNowClient


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_records(records):
    print(f"Records retrieved: {len(records)}")

    for index, record in enumerate(records, start=1):
        print(f"\nRecord {index}:")
        print(json.dumps(record, indent=2, ensure_ascii=False))


def main():
    client = None

    try:
        client = ServiceNowClient()

        print_section("SMYD RCA COPILOT - INCIDENT CORRELATION")

        connection = client.test_connection()
        print(f"ServiceNow connection: {connection}")

        if not connection.get("connected"):
            print("Connection failed. Stopping investigation.")
            return

        # --------------------------------------------------
        # 1. Retrieve recent incident email logs
        # --------------------------------------------------

        print_section("RECENT INCIDENT EMAIL LOGS")

        email_logs = client.get_email_logs(
            table_name="incident",
            limit=20,
        )

        print_records(email_logs)

        # --------------------------------------------------
        # 2. Retrieve incident notifications
        # --------------------------------------------------

        print_section("ACTIVE INCIDENT NOTIFICATIONS")

        notifications = client.get_notifications(
            table_name="incident",
            active_only=True,
            limit=50,
        )

        print_records([
            {
                "sys_id": record.get("sys_id"),
                "name": record.get("name"),
                "event_name": record.get("event_name"),
                "condition": record.get("condition"),
                "advanced_condition": record.get(
                    "advanced_condition"
                ),
                "generation_type": record.get("generation_type"),
                "subject": record.get("subject"),
                "action_insert": record.get("action_insert"),
                "action_update": record.get("action_update"),
                "recipient_fields": record.get("recipient_fields"),
            }
            for record in notifications
        ])

        # --------------------------------------------------
        # 3. Retrieve incident business rules
        # --------------------------------------------------

        print_section("ACTIVE INCIDENT BUSINESS RULES")

        business_rules = client.get_business_rules(
            table_name="incident",
            active_only=True,
            limit=50,
        )

        print_records(business_rules)

        # --------------------------------------------------
        # 4. Retrieve recent Flow Designer events
        # --------------------------------------------------

        print_section("RECENT FLOW DESIGNER EVENTS")

        flow_events = client.get_system_events(
            event_name="flow.fire",
            limit=10,
        )

        print_records([
            {
                "sys_id": record.get("sys_id"),
                "name": record.get("name"),
                "table": record.get("table"),
                "uri": record.get("uri"),
                "parm1": record.get("parm1"),
                "parm2": record.get("parm2"),
                "state": record.get("state"),
                "sys_created_on": record.get("sys_created_on"),
            }
            for record in flow_events
        ])

        # --------------------------------------------------
        # 5. Summary
        # --------------------------------------------------

        print_section("INVESTIGATION SUMMARY")

        print(f"Email log records: {len(email_logs)}")
        print(f"Active notifications: {len(notifications)}")
        print(f"Active incident business rules: {len(business_rules)}")
        print(f"Flow events: {len(flow_events)}")

        print(
            "\nThis test collects potential evidence. "
            "It does not independently prove a root cause."
        )

    except Exception as error:
        print(f"Investigation test failed: {type(error).__name__}: {error}")

    finally:
        if client is not None:
            client.close()
            print("\nServiceNow connection closed.")


if __name__ == "__main__":
    main()