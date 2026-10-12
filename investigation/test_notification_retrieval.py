import os
import sys
import json
import traceback

# ==========================================================
# PATH CONFIGURATION
# ==========================================================

INVESTIGATION_DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_DIR = os.path.dirname(INVESTIGATION_DIR)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)


# ==========================================================
# SERVICENOW CLIENT
# ==========================================================

from integrations.servicenow_client import ServiceNowClient


# ==========================================================
# OUTPUT HELPERS
# ==========================================================

def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_records(records, selected_fields=None):
    """Print retrieved records, optionally restricting displayed fields."""

    print(f"Records retrieved: {len(records)}")

    for index, record in enumerate(records, start=1):
        print(f"\nRecord {index}:")

        if selected_fields:
            record = {
                field: record.get(field)
                for field in selected_fields
            }

        print(
            json.dumps(
                record,
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )


def run_test(test_name, retrieve, selected_fields=None):
    """Execute an individual retrieval test without stopping other tests."""

    print_section(test_name)

    try:
        records = retrieve()

        if records is None:
            print("The retrieval method returned None.")
            return

        print_records(records, selected_fields)

    except Exception as error:
        print(f"Test failed: {type(error).__name__}: {error}")
        traceback.print_exc()


# ==========================================================
# MAIN EXECUTION
# ==========================================================

def main():
    client = None

    try:
        client = ServiceNowClient()

        print_section("SMYD RCA COPILOT - NOTIFICATION RETRIEVAL TEST")

        # --------------------------------------------------
        # 1. Test connection
        # --------------------------------------------------

        print("\n1. Testing ServiceNow connection...")

        connection = client.test_connection()
        print(connection)

        if not connection.get("connected", False):
            print(
                "\nServiceNow connection failed. "
                "Check your configuration and credentials."
            )
            return

        # --------------------------------------------------
        # 2. Retrieve active incident notifications
        # --------------------------------------------------

        run_test(
            "ACTIVE INCIDENT NOTIFICATIONS",
            lambda: client.get_notifications(
                table_name="incident",
                active_only=True,
                limit=10,
            ),
            selected_fields=[
                "sys_id",
                "name",
                "active",
                "collection",
                "event_name",
                "condition",
                "advanced_condition",
                "generation_type",
                "subject",
                "action_insert",
                "action_update",
                "recipient_users",
                "recipient_groups",
                "recipient_fields",
            ],
        )

        # --------------------------------------------------
        # 3. Retrieve events without a table filter
        # --------------------------------------------------

        run_test(
            "RECENT SYSTEM EVENTS - NO TABLE FILTER",
            lambda: client.get_system_events(
                limit=10,
            ),
            selected_fields=[
                "sys_id",
                "name",
                "table",
                "uri",
                "parm1",
                "parm2",
                "state",
                "queue",
                "sys_created_on",
                "process_on",
                "processed",
                "processing_duration",
                "user_name",
            ],
        )

        # --------------------------------------------------
        # 4. Retrieve events for the incident table
        # --------------------------------------------------

        run_test(
            "RECENT SYSTEM EVENTS - INCIDENT TABLE FILTER",
            lambda: client.get_system_events(
                table_name="incident",
                limit=10,
            ),
            selected_fields=[
                "sys_id",
                "name",
                "table",
                "uri",
                "parm1",
                "parm2",
                "state",
                "queue",
                "sys_created_on",
                "process_on",
                "processed",
                "processing_duration",
                "user_name",
            ],
        )

        # --------------------------------------------------
        # 5. Retrieve incident email logs
        # --------------------------------------------------

        run_test(
            "INCIDENT EMAIL LOGS",
            lambda: client.get_email_logs(
                table_name="incident",
                limit=10,
            ),
            selected_fields=[
                "sys_id",
                "type",
                "state",
                "status",
                "subject",
                "instance",
                "target_table",
                "recipients",
                "direct",
                "notification_type",
                "sys_created_on",
                "sys_created_by",
                "error_string",
                "message_id",
            ],
        )

        # --------------------------------------------------
        # 6. Completion
        # --------------------------------------------------

        print_section("TEST SUMMARY")

        print("ServiceNow connection: Successful")
        print("Notification, event, and email retrieval tests completed.")
        print(
            "Compare the two system-event tests to determine whether "
            "the incident-table filter is affecting the results."
        )

    except Exception as error:
        print_section("TEST EXECUTION ERROR")
        print(f"{type(error).__name__}: {error}")
        traceback.print_exc()

    finally:
        if client is not None:
            try:
                client.close()
                print("\nServiceNow connection closed.")
            except Exception as error:
                print(f"Error closing client: {error}")


if __name__ == "__main__":
    main()