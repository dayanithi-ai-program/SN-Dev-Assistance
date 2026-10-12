import os
import sys
import json

# ==========================================================
# PATH CONFIGURATION
# ==========================================================

# Current file is inside Application/investigation/
INVESTIGATION_DIR = os.path.dirname(os.path.abspath(__file__))

# Parent directory is Application/
APPLICATION_DIR = os.path.dirname(INVESTIGATION_DIR)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)


# ==========================================================
# SERVICENOW CLIENT
# ==========================================================

from integrations.servicenow_client import ServiceNowClient


# ==========================================================
# TABLES TO INSPECT
# ==========================================================

TABLES_TO_INSPECT = [
    "sysevent_email_action",
    "sysevent",
    "sys_email",
]


# ==========================================================
# MAIN EXECUTION
# ==========================================================

def main():

    print("=" * 70)
    print("SMYD RCA COPILOT - INVESTIGATION SCHEMA DISCOVERY")
    print("=" * 70)

    client = None

    try:
        print("\nInitializing ServiceNow connection...")

        client = ServiceNowClient()

        # Test connection
        connection = client.test_connection()

        print("\nServiceNow connection successful!")
        print(f"Connection details: {connection}")

        # Retrieve dictionary metadata
        for table_name in TABLES_TO_INSPECT:

            print("\n" + "=" * 70)
            print(f"TABLE: {table_name}")
            print("=" * 70)

            try:
                fields = client.get_table_schema(table_name)

                if not fields:
                    print(f"No fields returned for {table_name}.")
                    continue

                print(f"\nTotal fields: {len(fields)}\n")

                for field in fields:
                    print(
                        f"Field: {field.get('element', 'N/A')} | "
                        f"Label: {field.get('column_label', 'N/A')} | "
                        f"Type: {field.get('internal_type', 'N/A')} | "
                        f"Reference: {field.get('reference', '')}"
                    )

                print("\nComplete field metadata:")

                print(
                    json.dumps(
                        fields,
                        indent=2,
                        ensure_ascii=False
                    )
                )

            except Exception as error:
                print(
                    f"Failed to inspect {table_name}: "
                    f"{type(error).__name__}: {error}"
                )

        print("\n" + "=" * 70)
        print("SCHEMA DISCOVERY COMPLETED")
        print("=" * 70)

    except Exception as error:
        print(
            f"\nServiceNow integration failed: "
            f"{type(error).__name__}: {error}"
        )

    finally:
        if client is not None:
            client.close()
            print("\nServiceNow connection closed.")


if __name__ == "__main__":
    main()