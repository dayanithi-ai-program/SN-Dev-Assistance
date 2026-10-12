import os
import sys
import json

INVESTIGATION_DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_DIR = os.path.dirname(INVESTIGATION_DIR)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)

from integrations.servicenow_client import ServiceNowClient


def main():
    client = None

    try:
        client = ServiceNowClient()

        print("Testing ServiceNow connection...")
        print(client.test_connection())

        tests = [
            (
                "Recent events without filters",
                lambda: client.get_system_events(limit=10),
            ),
            (
                "Incident events",
                lambda: client.get_system_events(
                    table_name="incident",
                    limit=10,
                ),
            ),
            (
                "Flow events",
                lambda: client.get_system_events(
                    event_name="flow.fire",
                    limit=10,
                ),
            ),
        ]

        for title, retrieve in tests:
            print("\n" + "=" * 60)
            print(title)
            print("=" * 60)

            try:
                records = retrieve()

                print(f"Records retrieved: {len(records)}")

                for record in records:
                    print(
                        json.dumps(
                            record,
                            indent=2,
                            ensure_ascii=False,
                        )
                    )

            except Exception as error:
                print(
                    f"Error: {type(error).__name__}: {error}"
                )

    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    main()