import os
import re
import requests

from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth


# ==========================================================
# ENVIRONMENT CONFIGURATION
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_PATH)


# ==========================================================
# SERVICENOW CLIENT
# ==========================================================

class ServiceNowClient:
    """
    Read-only ServiceNow integration for SMYD RCA Copilot.

    Capabilities:
        1. Discover ServiceNow tables
        2. Discover table fields
        3. Retrieve developer configuration
        4. Retrieve logs for troubleshooting
    """

    def __init__(self):

        self.instance_url = os.getenv(
            "SERVICENOW_INSTANCE_URL", ""
        ).rstrip("/")

        self.username = os.getenv(
            "SERVICENOW_USERNAME", ""
        )

        self.password = os.getenv(
            "SERVICENOW_PASSWORD", ""
        )

        if not self.instance_url:
            raise ValueError(
                "SERVICENOW_INSTANCE_URL is missing from .env"
            )

        if not self.instance_url.startswith("https://"):
            raise ValueError(
                "ServiceNow instance URL must use HTTPS."
            )

        if not self.username or not self.password:
            raise ValueError(
                "ServiceNow credentials are missing from .env"
            )

        self.session = requests.Session()

        self.session.auth = HTTPBasicAuth(
            self.username,
            self.password,
        )

        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

        self.timeout = 30
        # ======================================================
    # TABLE SCHEMA DISCOVERY
    # ======================================================

    def get_table_schema(self, table_name: str) -> list[dict]:
        """
        Retrieve dictionary metadata for a ServiceNow table.
        """

        self._validate_table_name(table_name)

        return self._get_records(
            table_name="sys_dictionary",
            query=f"name={table_name}^elementISNOTEMPTY",
            limit=1000,
            fields=[
                "sys_id",
                "name",
                "element",
                "internal_type",
                "column_label",
                "reference",
            ],
            order_by="element",
        )

    # ======================================================
    # GENERIC TABLE API
    # ======================================================

    def _get_records(
        self,
        table_name,
        query="",
        limit=100,
        fields=None,
        offset=0,
        order_by=None,
    ):
        """
        Retrieve records from a ServiceNow table.

        Uses read-only GET requests.
        """

        if not re.fullmatch(
            r"[a-zA-Z0-9_]+",
            table_name,
        ):
            raise ValueError(
                f"Invalid table name: {table_name}"
            )

        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError(
                "Limit must be between 1 and 1000."
            )

        if not isinstance(offset, int) or offset < 0:
            raise ValueError(
                "Offset must be a non-negative integer."
            )

        url = (
            f"{self.instance_url}/api/now/table/"
            f"{table_name}"
        )

        params = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
            "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
        }

        if query:
            params["sysparm_query"] = query

        if fields:
            params["sysparm_fields"] = ",".join(fields)

        if order_by:
            params["sysparm_order_by"] = order_by

        response = self.session.get(
            url,
            params=params,
            timeout=self.timeout,
        )

        if response.status_code == 401:
            raise PermissionError(
                "ServiceNow authentication failed. "
                "Check your credentials."
            )

        if response.status_code == 403:
            raise PermissionError(
                f"Access denied to ServiceNow table "
                f"'{table_name}'. Check roles and permissions."
            )

        response.raise_for_status()

        data = response.json()

        return data.get("result", [])

    # ======================================================
    # CONNECTION TEST
    # ======================================================

    def test_connection(self):

        records = self._get_records(
            table_name="sys_user",
            limit=1,
            fields=[
                "sys_id",
                "user_name",
            ],
        )

        return {
            "connected": True,
            "records_returned": len(records),
        }

    # ======================================================
    # TABLE DISCOVERY
    # sys_db_object
    # ======================================================

    def get_all_tables(
        self,
        page_size=100,
        max_tables=10000,
    ):
        """
        Retrieve table definitions using pagination.

        Returns:
            sys_id
            name
            label
            super_class
            is_extendable

        max_tables prevents unexpectedly large retrievals.
        """

        if not 1 <= page_size <= 1000:
            raise ValueError(
                "page_size must be between 1 and 1000."
            )

        if max_tables < 1:
            raise ValueError(
                "max_tables must be greater than zero."
            )

        all_tables = []
        offset = 0

        while len(all_tables) < max_tables:

            current_limit = min(
                page_size,
                max_tables - len(all_tables),
            )

            records = self._get_records(
                table_name="sys_db_object",
                limit=current_limit,
                offset=offset,
                fields=[
                    "sys_id",
                    "name",
                    "label",
                    "super_class",
                    "is_extendable",
                ],
                order_by="name",
            )

            if not records:
                break

            all_tables.extend(records)

            offset += len(records)

            print(
                f"Discovered {len(all_tables)} tables..."
            )

            if len(records) < current_limit:
                break

        return all_tables

    # ======================================================
    # FIELD DISCOVERY
    # sys_dictionary
    # ======================================================

    def get_table_fields(
        self,
        table_name,
        limit=1000,
    ):
        """
        Discover field definitions for a table.

        Includes field name, label, type, mandatory status,
        read-only status, reference and attributes.
        """

        if not re.fullmatch(
            r"[a-zA-Z0-9_]+",
            table_name,
        ):
            raise ValueError(
                "Invalid ServiceNow table name."
            )

        return self._get_records(
            table_name="sys_dictionary",
            query=f"name={table_name}^elementISNOTEMPTY",
            limit=min(limit, 1000),
            fields=[
                "sys_id",
                "name",
                "element",
                "column_label",
                "internal_type",
                "mandatory",
                "read_only",
                "reference",
                "attributes",
            ],
            order_by="element",
        )

    # ======================================================
    # BUSINESS RULES
    # sys_script
    # ======================================================

    def get_business_rules(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):

        query_parts = []

        if table_name:
            self._validate_table_name(table_name)

            query_parts.append(
                f"collection={table_name}"
            )

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sys_script",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "collection",
                "active",
                "when",
                "order",
                "condition",
                "script",
            ],
        )

    def search_business_rules(
        self,
        table_name,
        limit=100,
    ):

        return self.get_business_rules(
            table_name=table_name,
            active_only=True,
            limit=limit,
        )

    # ======================================================
    # CLIENT SCRIPTS
    # sys_script_client
    # ======================================================

    def get_client_scripts(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):

        query_parts = []

        if table_name:
            self._validate_table_name(table_name)

            query_parts.append(
                f"table={table_name}"
            )

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sys_script_client",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "table",
                "type",
                "active",
                "field",
                "condition",
                "script",
            ],
        )

    # ======================================================
    # SCRIPT INCLUDES
    # sys_script_include
    # ======================================================

    def get_script_includes(
        self,
        active_only=True,
        limit=100,
    ):

        query = "active=true" if active_only else ""

        return self._get_records(
            table_name="sys_script_include",
            query=query,
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "api_name",
                "active",
                "client_callable",
                "script",
            ],
        )

    # ======================================================
    # UI POLICIES
    # sys_ui_policy
    # ======================================================

    def get_ui_policies(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):

        query_parts = []

        if table_name:
            self._validate_table_name(table_name)

            query_parts.append(
                f"table={table_name}"
            )

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sys_ui_policy",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id",
                "short_description",
                "table",
                "active",
                "conditions",
                "run_scripts",
                "on_load",
            ],
        )

    # ======================================================
    # UI POLICY ACTIONS
    # sys_ui_policy_action
    # ======================================================

    def get_ui_policy_actions(
        self,
        limit=100,
        policy_sys_ids=None,
    ):
        """Retrieve UI Policy Actions, optionally scoped to parent policies.

        Passing policy_sys_ids avoids scanning the first page of unrelated
        actions. This method performs read-only Table API GET requests only.
        """
        query = ""
        if policy_sys_ids is not None:
            if not isinstance(policy_sys_ids, (list, tuple, set)):
                raise ValueError("policy_sys_ids must be a list, tuple, or set.")

            valid_ids = []
            for value in policy_sys_ids:
                sys_id = str(value or "").strip()
                if not re.fullmatch(r"[a-fA-F0-9]{32}", sys_id):
                    continue
                if sys_id not in valid_ids:
                    valid_ids.append(sys_id)

            if not valid_ids:
                return []

            # ServiceNow encoded query: ui_policy IN <comma-separated sys_ids>
            query = "ui_policyIN" + ",".join(valid_ids)

        return self._get_records(
            table_name="sys_ui_policy_action",
            query=query,
            limit=limit,
            fields=[
                "sys_id",
                "ui_policy",
                "field",
                "mandatory",
                "visible",
                "disabled",
            ],
        )

    # ======================================================
    # DATA POLICIES
    # sys_data_policy2
    # ======================================================

    def get_data_policies(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):

        query_parts = []

        if table_name:
            self._validate_table_name(table_name)

            query_parts.append(
                f"model_table={table_name}"
            )

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sys_data_policy2",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id",
                "short_description",
                "model_table",
                "active",
                "conditions",
                "reverse_if_false",
            ],
        )

    # ======================================================
    # DATA POLICY RULES
    # ======================================================

    def get_data_policy_rules(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sys_data_policy_rule",
            limit=limit,
            fields=[
                "sys_id",
                "sys_name",
                "sys_data_policy",
                "field",
                "mandatory",
                "read_only",
                "active",
            ],
        )

    # ======================================================
    # UI ACTIONS
    # sys_ui_action
    # ======================================================

    def get_ui_actions(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):

        query_parts = []

        if table_name:
            self._validate_table_name(table_name)

            query_parts.append(
                f"table={table_name}"
            )

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sys_ui_action",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "table",
                "active",
                "condition",
                "script",
                "client",
                "action_name",
            ],
        )

    # ======================================================
    # DICTIONARY OVERRIDES
    # sys_dictionary_override
    # ======================================================

    def get_dictionary_overrides(
        self,
        table_name=None,
        limit=100,
    ):

        query = ""

        if table_name:
            self._validate_table_name(table_name)

            query = f"name={table_name}"

        return self._get_records(
            table_name="sys_dictionary_override",
            query=query,
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "element",
                "mandatory",
                "read_only",
                "reference",
                "attributes",
            ],
        )

    # ======================================================
    # FLOWS
    # sys_hub_flow
    # ======================================================

    def get_flows(
        self,
        active_only=True,
        limit=100,
    ):

        query = "active=true" if active_only else ""

        return self._get_records(
            table_name="sys_hub_flow",
            query=query,
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "active",
                "sys_updated_on",
            ],
        )

    # ======================================================
    # SCHEDULED JOBS
    # sysauto
    # ======================================================

    def get_scheduled_jobs(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sysauto",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "sys_class_name",
                "sys_updated_on",
            ],
        )

    # ======================================================
    # SCHEDULED SCRIPT EXECUTIONS
    # sysauto_script
    # ======================================================

    def get_scheduled_script_executions(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sysauto_script",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "active",
                "run_type",
                "script",
                "sys_updated_on",
            ],
        )

    # ======================================================
    # FIX SCRIPTS
    # sys_script_fix
    # ======================================================

    def get_fix_scripts(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sys_script_fix",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "active",
                "script",
                "sys_updated_on",
            ],
        )

    # ======================================================
    # SCRIPT ACTIONS
    # sysevent_script_action
    # ======================================================

    def get_script_actions(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sysevent_script_action",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "active",
                "event_name",
                "script",
            ],
        )

    # ======================================================
    # EVENTS
    # sysevent_register
    # ======================================================

    def get_event_registrations(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sysevent_register",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "table",
                "event_name",
            ],
        )

    # ======================================================
    # TRANSFORM MAPS
    # sys_transform_map
    # ======================================================

    def get_transform_maps(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sys_transform_map",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "source_table",
                "target_table",
                "active",
            ],
        )

    # ======================================================
    # TRANSFORM SCRIPTS
    # sys_transform_script
    # ======================================================

    def get_transform_scripts(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sys_transform_script",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "map",
                "active",
                "script",
            ],
        )

    # ======================================================
    # SYSTEM LOGS
    # syslog
    # ======================================================

    def get_system_logs(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="syslog",
            limit=limit,
            fields=[
                "sys_id",
                "level",
                "message",
                "source",
                "sys_created_on",
            ],
            order_by="sys_created_on",
        )

    # ======================================================
    # SYSTEM PROPERTIES
    # sys_properties
    # ======================================================

    def get_system_properties(
        self,
        limit=100,
    ):

        return self._get_records(
            table_name="sys_properties",
            limit=limit,
            fields=[
                "sys_id",
                "name",
                "type",
                "description",
            ],
        )

    # ======================================================
    # NOTIFICATION CONFIGURATIONS
    # sysevent_email_action
    # ======================================================

    def get_notifications(
        self,
        table_name=None,
        active_only=True,
        limit=100,
    ):
        """Retrieve email notification configurations, optionally by table."""
        query_parts = []

        if table_name:
            self._validate_table_name(table_name)
            query_parts.append(f"collection={table_name}")

        if active_only:
            query_parts.append("active=true")

        return self._get_records(
            table_name="sysevent_email_action",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id", "name", "active", "collection", "event_name",
                "condition", "advanced_condition", "generation_type",
                "action_insert", "action_update", "subject", "message",
                "message_html", "message_text", "recipient_users",
                "recipient_groups", "recipient_fields",
            ],
            order_by="name",
        )

    # ======================================================
    # SYSTEM EVENTS
    # sysevent
    # ======================================================

    def get_system_events(
        self,
        table_name=None,
        record_sys_id=None,
        event_name=None,
        limit=100,
    ):
        """Retrieve queued/processed system events with optional filters."""
        query_parts = []

        if table_name:
            self._validate_table_name(table_name)
            query_parts.append(f"table={table_name}")

        if record_sys_id:
            if not re.fullmatch(r"[a-fA-F0-9]{32}", record_sys_id):
                raise ValueError("record_sys_id must be a 32-character sys_id.")
            # Event URI formats can vary; this is a useful initial correlation filter.
            query_parts.append(f"uriLIKE{record_sys_id}")

        if event_name:
            if "^" in event_name:
                raise ValueError("Invalid event_name.")
            query_parts.append(f"name={event_name}")

        return self._get_records(
            table_name="sysevent",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id", "name", "table", "uri", "parm1", "parm2",
                "state", "queue", "sys_created_on", "process_on",
                "processed", "processing_duration", "user_name",
            ],
            order_by="sys_created_on",
        )

    # ======================================================
    # EMAIL LOGS
    # sys_email
    # ======================================================

    def get_email_logs(
        self,
        table_name=None,
        record_sys_id=None,
        subject=None,
        limit=100,
    ):
        """Retrieve email metadata, optionally for a specific target record."""
        query_parts = []

        if table_name:
            self._validate_table_name(table_name)
            query_parts.append(f"target_table={table_name}")

        if record_sys_id:
            if not re.fullmatch(r"[a-fA-F0-9]{32}", record_sys_id):
                raise ValueError("record_sys_id must be a 32-character sys_id.")
            query_parts.append(f"instance={record_sys_id}")

        if subject:
            if "^" in subject:
                raise ValueError("Invalid subject search.")
            query_parts.append(f"subjectLIKE{subject}")

        return self._get_records(
            table_name="sys_email",
            query="^".join(query_parts),
            limit=limit,
            fields=[
                "sys_id", "type", "state", "status", "subject",
                "instance", "target_table", "recipients", "direct",
                "notification_type", "sys_created_on", "sys_created_by",
                "error_string", "message_id",
            ],
            order_by="sys_created_on",
        )

    # ======================================================
    # VALIDATION
    # ======================================================

    @staticmethod
    def _validate_table_name(table_name):

        if not re.fullmatch(
            r"[a-zA-Z0-9_]+",
            table_name,
        ):
            raise ValueError(
                f"Invalid table name: {table_name}"
            )

    # ======================================================
    # CLOSE SESSION
    # ======================================================

    def close(self):
        self.session.close()


# ==========================================================
# TEST EXECUTION
# ==========================================================

if __name__ == "__main__":

    client = ServiceNowClient()

    try:

        print("=" * 60)
        print("SMYD RCA COPILOT - SERVICENOW DISCOVERY")
        print("=" * 60)

        # 1. Test connection
        print("\nTesting connection...")

        print(client.test_connection())

        # 2. Discover tables
        print("\nDiscovering ServiceNow tables...")

        tables = client.get_all_tables(
            page_size=100,
            max_tables=10000,
        )

        print(f"\nTotal tables discovered: {len(tables)}")

        for table in tables[:20]:
            print(
                f"{table.get('name')} | "
                f"{table.get('label')}"
            )

        # 3. Discover Incident fields
        print("\nDiscovering Incident fields...")

        fields = client.get_table_fields(
            table_name="incident",
            limit=1000,
        )

        print(f"Incident fields retrieved: {len(fields)}")

        for field in fields[:20]:
            print(
                f"{field.get('element')} | "
                f"{field.get('column_label')} | "
                f"{field.get('internal_type')}"
            )

        # 4. Test developer component retrieval
        print("\nTesting developer component discovery...")

        tests = [
            (
                "Business Rules",
                lambda: client.get_business_rules(
                    "incident", True, 5
                ),
            ),
            (
                "Client Scripts",
                lambda: client.get_client_scripts(
                    "incident", True, 5
                ),
            ),
            (
                "UI Policies",
                lambda: client.get_ui_policies(
                    "incident", True, 5
                ),
            ),
            (
                "Data Policies",
                lambda: client.get_data_policies(
                    "incident", True, 5
                ),
            ),
            (
                "UI Actions",
                lambda: client.get_ui_actions(
                    "incident", True, 5
                ),
            ),
            (
                "Script Includes",
                lambda: client.get_script_includes(
                    True, 5
                ),
            ),
            (
                "Flows",
                lambda: client.get_flows(
                    True, 5
                ),
            ),
            (
                "Scheduled Jobs",
                lambda: client.get_scheduled_jobs(5),
            ),
            (
                "Scheduled Script Executions",
                lambda: client.get_scheduled_script_executions(5),
            ),
            (
                "Fix Scripts",
                lambda: client.get_fix_scripts(5),
            ),
            (
                "Script Actions",
                lambda: client.get_script_actions(5),
            ),
            (
                "Event Registrations",
                lambda: client.get_event_registrations(5),
            ),
            (
                "Transform Maps",
                lambda: client.get_transform_maps(5),
            ),
            (
                "Transform Scripts",
                lambda: client.get_transform_scripts(5),
            ),
            (
                "System Logs",
                lambda: client.get_system_logs(5),
            ),
            (
                "System Properties",
                lambda: client.get_system_properties(5),
            ),
            (
                "Dictionary Overrides",
                lambda: client.get_dictionary_overrides(
                    "incident", 5
                ),
            ),
            (
                "UI Policy Actions",
                lambda: client.get_ui_policy_actions(5),
            ),
            (
                "Data Policy Rules",
                lambda: client.get_data_policy_rules(5),
            ),
        ]

        for component_name, retrieve in tests:

            print(f"\nTesting {component_name}...")

            try:

                records = retrieve()

                print(
                    f"{component_name}: "
                    f"{len(records)} records retrieved."
                )

            except Exception as error:

                print(
                    f"{component_name} retrieval failed: "
                    f"{error}"
                )

        print("\nDiscovery test completed.")

    except Exception as error:

        print(f"\nServiceNow integration failed: {error}")

    finally:

        client.close()