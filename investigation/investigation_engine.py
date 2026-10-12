import os
import sys
import re
from typing import Any

# Add the Application directory to Python's module search path
APPLICATION_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)

from integrations.servicenow_client import ServiceNowClient


class InvestigationEngine:
    """
    Coordinates ServiceNow configuration retrieval for
    SMYD RCA Copilot.

    This engine gathers evidence. It does not independently
    declare a root cause to be confirmed.
    """

    # Maps common issue descriptions to likely ServiceNow tables.
    TABLE_KEYWORDS = {
        "incident": "incident",
        "incidents": "incident",
        "problem": "problem",
        "problems": "problem",
        "change request": "change_request",
        "change requests": "change_request",
        "change": "change_request",
        "changes": "change_request",
        "catalog item": "sc_cat_item",
        "catalog items": "sc_cat_item",
        "requested item": "sc_req_item",
        "ritm": "sc_req_item",
        "request item": "sc_req_item",
        "service request": "sc_request",
        "knowledge article": "kb_knowledge",
        "knowledge articles": "kb_knowledge",
        "configuration item": "cmdb_ci",
        "configuration items": "cmdb_ci",
        "cmdb": "cmdb_ci",
        "user": "sys_user",
        "users": "sys_user",
        "group": "sys_user_group",
        "groups": "sys_user_group",
        "task": "task",
    }

    # Maps problem symptoms to component categories.
    COMPONENT_KEYWORDS = {
        "business_rules": [
            "business rule",
            "automatically changes",
            "automatically updates",
            "changes automatically",
            "record update",
            "before insert",
            "before update",
            "after update",
            "server side",
            "server-side",
            "assignment group",
            "field value",
        ],
        "client_scripts": [
            "client script",
            "onchange",
            "on change",
            "onload",
            "on load",
            "form field",
            "browser",
            "field changes",
            "field change",
            "form behavior",
        ],
        "ui_policies": [
            "ui policy",
            "mandatory",
            "read only",
            "readonly",
            "hidden field",
            "field visibility",
            "field visible",
        ],
        "data_policies": [
            "data policy",
            "data policies",
            "mandatory field",
            "mandatory fields",
            "data validation",
            "field validation",
            "integration validation",
            "import validation",
        ],
        "ui_actions": [
            "ui action",
            "button",
            "form button",
            "action button",
            "record action",
        ],
        "script_includes": [
            "script include",
            "reusable script",
            "javascript function",
            "called function",
            "server side function",
            "server-side function",
        ],
        "flows": [
            "flow designer",
            "flow",
            "subflow",
            "workflow",
            "flow designer action",
            "async update",
            "asynchronous update",
        ],
        "scheduled_jobs": [
            "scheduled job",
            "scheduled script",
            "scheduled execution",
            "background job",
            "background process",
            "scheduled task",
            "periodic update",
        ],
        "system_logs": [
            "error",
            "exception",
            "failed",
            "failure",
            "stack trace",
            "system log",
            "runtime error",
        ],
        "dictionary": [
            "dictionary",
            "field definition",
            "field type",
            "reference field",
            "dictionary override",
        ],
    }

    def __init__(self, client: ServiceNowClient | None = None):
        """
        Accept an existing client or create a new one.

        If a client is passed in, its lifecycle remains the
        responsibility of the caller.
        """
        self._owns_client = client is None
        self.client = client or ServiceNowClient()

    # --------------------------------------------------
    # QUESTION ANALYSIS
    # --------------------------------------------------

    def identify_table(self, question: str) -> str | None:
        """
        Identify a likely ServiceNow table using keywords.

        This is a lightweight first version, not an LLM-based
        table classifier.
        """
        normalized = question.lower()

        # Check longer phrases first to avoid broad matches.
        for keyword in sorted(
            self.TABLE_KEYWORDS,
            key=len,
            reverse=True,
        ):
            if keyword in normalized:
                return self.TABLE_KEYWORDS[keyword]

        return None

    def identify_field(self, question: str) -> str | None:
        """
        Identify common ServiceNow fields mentioned in a question.

        Returns the field's internal name when recognized.
        """
        normalized = question.lower()

        field_keywords = {
            "assignment group": "assignment_group",
            "assigned to": "assigned_to",
            "assigned user": "assigned_to",
            "short description": "short_description",
            "description": "description",
            "priority": "priority",
            "state": "state",
            "incident state": "incident_state",
            "category": "category",
            "subcategory": "subcategory",
            "caller": "caller_id",
            "caller id": "caller_id",
            "business service": "business_service",
            "configuration item": "cmdb_ci",
            "configuration item field": "cmdb_ci",
            "due date": "due_date",
            "approval": "approval",
            "close code": "close_code",
            "work notes": "work_notes",
            "comments": "comments",
        }

        for keyword in sorted(
            field_keywords,
            key=len,
            reverse=True,
        ):
            if keyword in normalized:
                return field_keywords[keyword]

        return None

    def identify_components(self, question: str) -> list[str]:
        """
        Select investigation components using symptom-based rules.
        """

        normalized = question.lower()
        selected = set()

        # Detect record updates and unexpected field changes
        update_terms = [
            "change",
            "changes",
            "changed",
            "update",
            "updates",
            "updated",
            "automatically",
            "insert",
            "save",
            "saving",
            "assignment",
            "field value",
        ]

        is_record_update_issue = any(
            term in normalized
            for term in update_terms
        )

        # Investigate multiple components for record update issues
        if is_record_update_issue:
            selected.update({
                "business_rules",
                "client_scripts",
                "script_includes",
                "flows",
                "data_policies",
                "ui_policies",
                "scheduled_jobs",
            })

        # Add components based on explicit keywords
        for component, keywords in self.COMPONENT_KEYWORDS.items():
            if any(
                keyword in normalized
                for keyword in keywords
            ):
                selected.add(component)

        # Default components for general diagnostic questions
        if not selected:
            selected.update({
                "business_rules",
                "client_scripts",
                "script_includes",
                "flows",
                "system_logs",
            })

        return sorted(selected)

    # --------------------------------------------------
    # COMPONENT RETRIEVAL
    # --------------------------------------------------

    def _safe_retrieve(
        self,
        component_name: str,
        retrieval_function,
        *args,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Retrieve a component without letting one unavailable
        source terminate the entire investigation.
        """
        try:
            records = retrieval_function(
                *args,
                **kwargs,
            )

            return {
                "component": component_name,
                "status": "success",
                "count": len(records),
                "records": records,
                "error": None,
            }

        except Exception as error:
            return {
                "component": component_name,
                "status": "failed",
                "count": 0,
                "records": [],
                "error": str(error),
            }

    def retrieve_evidence(
        self,
        question: str,
        target_table: str | None = None,
        limit_per_component: int = 10,
    ) -> dict[str, Any]:
        """
        Retrieve configuration relevant to the developer's
        question.

        Script Includes and other reusable components are
        not necessarily tied directly to the target table.
        They are retrieved separately when selected.
        """
        if not question or not question.strip():
            raise ValueError(
                "Please provide a technical question."
            )

        if not 1 <= limit_per_component <= 100:
            raise ValueError(
                "limit_per_component must be between 1 and 100."
            )

        target_table = (
            target_table or self.identify_table(question)
        )

        components = self.identify_components(question)

        evidence = {
            "question": question.strip(),
            "target_table": target_table,
            "target_field": self.identify_field(question),
            "selected_components": components,
            "sources": {},
        }

        # Each selected category has a dedicated retrieval method.
        retrieval_map = {
            "business_rules": (
                self.client.get_business_rules,
                {
                    "table_name": target_table,
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "client_scripts": (
                self.client.get_client_scripts,
                {
                    "table_name": target_table,
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "ui_policies": (
                self.client.get_ui_policies,
                {
                    "table_name": target_table,
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "data_policies": (
                self.client.get_data_policies,
                {
                    "table_name": target_table,
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "ui_actions": (
                self.client.get_ui_actions,
                {
                    "table_name": target_table,
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "script_includes": (
                self.client.get_script_includes,
                {
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "flows": (
                self.client.get_flows,
                {
                    "active_only": True,
                    "limit": limit_per_component,
                },
            ),
            "scheduled_jobs": (
                self.client.get_scheduled_script_executions,
                {
                    "limit": limit_per_component,
                },
            ),
            "system_logs": (
                self.client.get_system_logs,
                {
                    "limit": limit_per_component,
                },
            ),
            "dictionary": (
                self.client.get_table_fields,
                {
                    "table_name": target_table,
                    "limit": limit_per_component,
                },
            ),
        }

        for component in components:
            entry = retrieval_map.get(component)

            if entry is None:
                continue

            function, arguments = entry

            # If the table is unknown, don't query table-specific
            # sources with a missing table name.
            if (
                component in {
                    "business_rules",
                    "client_scripts",
                    "ui_policies",
                    "data_policies",
                    "ui_actions",
                    "dictionary",
                }
                and not target_table
            ):
                evidence["sources"][component] = {
                    "component": component,
                    "status": "skipped",
                    "count": 0,
                    "records": [],
                    "error": (
                        "Target table could not be identified."
                    ),
                }
                continue

            evidence["sources"][component] = self._safe_retrieve(
                component,
                function,
                **arguments,
            )

        return evidence

    # --------------------------------------------------
    # PUBLIC INVESTIGATION METHOD
    # --------------------------------------------------

    def investigate(
        self,
        question: str,
        target_table: str | None = None,
        limit_per_component: int = 10,
    ) -> dict[str, Any]:
        """
        Prepare a structured evidence package for the
        ProblemAnalyzer or another RCA reporting layer.
        """
        evidence = self.retrieve_evidence(
            question=question,
            target_table=target_table,
            limit_per_component=limit_per_component,
        )

        successful_sources = sum(
            1
            for source in evidence["sources"].values()
            if source["status"] == "success"
        )

        failed_sources = sum(
            1
            for source in evidence["sources"].values()
            if source["status"] == "failed"
        )

        evidence["summary"] = {
            "sources_attempted": len(evidence["sources"]),
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "total_records": sum(
                source["count"]
                for source in evidence["sources"].values()
            ),
        }

        return evidence

    def close(self):
        """Close the client only if this engine created it."""
        if self._owns_client:
            self.client.close()


# ------------------------------------------------------
# TEST EXECUTION
# ------------------------------------------------------

if __name__ == "__main__":

    engine = InvestigationEngine()

    try:
        print("=" * 65)
        print("SMYD RCA COPILOT - INVESTIGATION ENGINE")
        print("=" * 65)

        question = input(
            "\nDescribe the ServiceNow issue: "
        ).strip()

        if not question:
            print("Please enter a question.")
        else:
            result = engine.investigate(
                question=question,
                limit_per_component=5,
            )

            print("\nINVESTIGATION SUMMARY")
            print("-" * 65)
            print(f"Question: {result['question']}")
            print(f"Target table: {result['target_table']}")
            print(f"Target field: {result['target_field']}")
            print(
                "Selected components: "
                f"{', '.join(result['selected_components'])}"
            )

            print("\nRETRIEVAL RESULTS")
            print("-" * 65)

            for name, source in result["sources"].items():
                print(
                    f"{name}: {source['status']} | "
                    f"Records: {source['count']}"
                )

                if source["error"]:
                    print(f"  Detail: {source['error']}")

            print("\nTOTALS")
            print("-" * 65)
            print(result["summary"])

    except Exception as error:
        print(f"\nInvestigation failed: {error}")

    finally:
        engine.close()