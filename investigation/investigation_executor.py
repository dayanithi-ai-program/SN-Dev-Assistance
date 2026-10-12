import os
import sys
import re
from typing import Any

# ---------------------------------------------------------
# 1. Configure Python imports
# ---------------------------------------------------------

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_DIR = os.path.dirname(CURRENT_DIR)

if APPLICATION_DIR not in sys.path:
    sys.path.insert(0, APPLICATION_DIR)

from integrations.servicenow_client import ServiceNowClient
from investigation.investigation_planner import InvestigationPlan


# ---------------------------------------------------------
# 2. Dynamic Investigation Plan Executor
# ---------------------------------------------------------

class InvestigationExecutor:
    """
    Executes an AI-generated ServiceNow investigation plan.

    Responsibilities:
    - Validate the investigation plan.
    - Validate allowed source categories.
    - Execute approved ServiceNow retrieval methods.
    - Respect step dependencies.
    - Capture errors without stopping the entire investigation.
    - Return retrieved records with their actual sys_ids.

    This executor performs read-only retrieval.
    It does not modify ServiceNow records.
    """

    MAX_STEPS = 12
    MAX_RECORDS_PER_STEP = 10
    MAX_CANDIDATES_TO_SCAN = 100

    # Map approved plan sources to existing client methods.
    SOURCE_METHODS = {
        "business_rules": "get_business_rules",
        "client_scripts": "get_client_scripts",
        "script_includes": "get_script_includes",
        "ui_policies": "get_ui_policies",
        "data_policies": "get_data_policies",
        "ui_actions": "get_ui_actions",
        "flows": "get_flows",
        "notifications": "get_notifications",
        "system_events": "get_system_events",
        "email_logs": "get_email_logs",
        "scheduled_jobs": "get_scheduled_jobs",
        "scheduled_script_executions": "get_scheduled_script_executions",
        "fix_scripts": "get_fix_scripts",
        "script_actions": "get_script_actions",
        "event_registrations": "get_event_registrations",
        "transform_maps": "get_transform_maps",
        "transform_scripts": "get_transform_scripts",
        "system_logs": "get_system_logs",
        "system_properties": "get_system_properties",
        "dictionary": "get_table_fields",
    }

    # These methods require a target ServiceNow table.
    TABLE_SPECIFIC_SOURCES = {
        "business_rules",
        "client_scripts",
        "ui_policies",
        "data_policies",
        "ui_actions",
        "dictionary",
    }

    APPROVED_SOURCES = set(SOURCE_METHODS)

    def __init__(
        self,
        client: ServiceNowClient | None = None,
        max_records_per_step: int = 10,
    ):
        self._owns_client = client is None
        self.client = client or ServiceNowClient()

        if not 1 <= max_records_per_step <= 100:
            raise ValueError(
                "max_records_per_step must be between 1 and 100."
            )

        self.max_records_per_step = max_records_per_step

    # -----------------------------------------------------
    # Normalize plan input
    # -----------------------------------------------------

    @staticmethod
    def _normalize_plan(
        plan: InvestigationPlan | dict[str, Any],
    ) -> dict[str, Any]:
        if isinstance(plan, InvestigationPlan):
            plan_data = plan.model_dump()
        elif isinstance(plan, dict):
            plan_data = plan
        else:
            raise TypeError(
                "Plan must be an InvestigationPlan or dictionary."
            )

        if not isinstance(plan_data.get("investigation_steps"), list):
            raise ValueError(
                "The plan must contain investigation_steps as a list."
            )

        if not isinstance(plan_data.get("hypotheses"), list):
            raise ValueError(
                "The plan must contain hypotheses as a list."
            )

        if not plan_data.get("problem_summary"):
            raise ValueError("The plan must contain problem_summary.")

        return plan_data

    # -----------------------------------------------------
    # Validate target table names
    # -----------------------------------------------------

    @staticmethod
    def _validate_table_name(
        table_name: str | None,
    ) -> str | None:
        if table_name is None:
            return None

        if not isinstance(table_name, str):
            raise ValueError("target_table must be a string or None.")

        table_name = table_name.strip()

        if not table_name:
            return None

        # Allow only simple ServiceNow table names.
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table_name):
            raise ValueError(
                f"Invalid ServiceNow table name: {table_name}"
            )

        return table_name

    # -----------------------------------------------------
    # Validate the generated plan
    # -----------------------------------------------------

    def validate_plan(self, plan_data: dict[str, Any]) -> None:
        steps = plan_data["investigation_steps"]

        if not steps:
            raise ValueError(
                "The AI generated an empty investigation plan."
            )

        if len(steps) > self.MAX_STEPS:
            raise ValueError(
                f"The plan contains {len(steps)} steps. "
                f"Maximum allowed: {self.MAX_STEPS}."
            )

        if not isinstance(plan_data["hypotheses"], list):
            raise ValueError("hypotheses must be a list.")

        known_step_ids = set()

        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Every investigation step must be a dictionary.")

            step_id = step.get("step_id")
            source = step.get("source")
            hypothesis_id = step.get("hypothesis_id")

            if not isinstance(step_id, str) or not step_id.strip():
                raise ValueError(
                    "Every investigation step must have a non-empty step_id."
                )

            if step_id in known_step_ids:
                raise ValueError(
                    f"Duplicate investigation step ID: {step_id}"
                )

            if source not in self.APPROVED_SOURCES:
                raise ValueError(
                    f"Unapproved investigation source: {source}"
                )

            if not isinstance(hypothesis_id, str) or not hypothesis_id:
                raise ValueError(
                    f"Step {step_id} has no valid hypothesis_id."
                )

            self._validate_table_name(step.get("target_table"))

            dependencies = step.get("depends_on", [])
            if not isinstance(dependencies, list):
                raise ValueError(
                    f"depends_on for step {step_id} must be a list."
                )

            known_step_ids.add(step_id)

        hypothesis_ids = {
            hypothesis.get("hypothesis_id")
            for hypothesis in plan_data["hypotheses"]
            if isinstance(hypothesis, dict)
        }

        for step in steps:
            step_id = step["step_id"]

            if step["hypothesis_id"] not in hypothesis_ids:
                raise ValueError(
                    f"Step {step_id} references an unknown hypothesis."
                )

            for dependency in step.get("depends_on", []):
                if dependency not in known_step_ids:
                    raise ValueError(
                        f"Step {step_id} references unknown dependency "
                        f"{dependency}."
                    )

                if dependency == step_id:
                    raise ValueError(
                        f"Step {step_id} cannot depend on itself."
                    )

        self._validate_dependency_order(steps)

    # -----------------------------------------------------
    # Validate dependency order and circular references
    # -----------------------------------------------------

    @staticmethod
    def _validate_dependency_order(
        steps: list[dict[str, Any]],
    ) -> None:
        positions = {
            step["step_id"]: index
            for index, step in enumerate(steps)
        }

        # Every dependency must appear before the step that uses it.
        for step in steps:
            for dependency in step.get("depends_on", []):
                if positions[dependency] >= positions[step["step_id"]]:
                    raise ValueError(
                        f"Dependency {dependency} must appear before "
                        f"step {step['step_id']}."
                    )

    # -----------------------------------------------------
    # Build retrieval arguments
    # -----------------------------------------------------

    def _build_arguments(
        self,
        source: str,
        target_table: str | None,
        step: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Retrieve a bounded candidate pool, then rank locally against the plan.
        # This reduces first-page bias but is not a complete instance-wide search.
        limit = min(self.MAX_CANDIDATES_TO_SCAN, 100)
        step = step or {}

        if source in {
            "business_rules",
            "client_scripts",
            "ui_policies",
            "data_policies",
            "ui_actions",
        }:
            return {
                "table_name": target_table,
                "active_only": True,
                "limit": limit,
            }

        if source == "dictionary":
            return {
                "table_name": target_table,
                "limit": limit,
            }

        if source == "notifications":
            return {
                "table_name": target_table,
                "active_only": True,
                "limit": limit,
            }

        if source == "system_events":
            return {
                "table_name": target_table,
                "record_sys_id": step.get("record_sys_id"),
                "event_name": step.get("event_name"),
                "limit": limit,
                "offset": 0,
            }

        if source == "email_logs":
            return {
                "table_name": target_table,
                "record_sys_id": step.get("record_sys_id"),
                "subject": step.get("subject"),
                "limit": limit,
            }

        if source in {"script_includes", "flows"}:
            return {
                "active_only": True,
                "limit": limit,
            }

        if source in {
            "scheduled_jobs",
            "scheduled_script_executions",
            "fix_scripts",
            "script_actions",
            "event_registrations",
            "transform_maps",
            "transform_scripts",
            "system_logs",
            "system_properties",
        }:
            return {"limit": limit}

        raise NotImplementedError(
            f"No retrieval arguments are configured for {source}."
        )

    # -----------------------------------------------------
    # Execute one investigation step
    # -----------------------------------------------------

    @staticmethod
    def _search_terms(step: dict[str, Any], problem_context: str) -> list[str]:
        """Extract high-value terms from the problem and planner instructions."""
        values = [
            problem_context,
            step.get("objective", ""),
            step.get("search_strategy", ""),
            step.get("evidence_to_find", ""),
            step.get("target_table", ""),
        ]
        fields = step.get("fields_to_inspect", [])
        if isinstance(fields, list):
            values.extend(str(field) for field in fields)

        text = " ".join(str(value) for value in values if value)
        # Keep underscore identifiers (e.g. assignment_group) as complete terms.
        tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text.lower())
        stop = {
            "the", "and", "or", "to", "of", "in", "on", "for", "a", "an",
            "is", "are", "be", "with", "that", "this", "from", "by", "as",
            "it", "may", "might", "could", "should", "would", "record",
            "records", "identify", "inspect", "review", "search", "find",
            "check", "related", "relevant", "possible", "cause", "causes",
            "during", "when", "where", "what", "how", "active", "table",
            "script", "condition", "logic", "configuration", "service",
            "now", "incident", "update", "updates", "updating",
        }
        unique = []
        for token in tokens:
            if len(token) < 3 or token in stop:
                continue
            if token not in unique:
                unique.append(token)
        return unique[:40]

    @staticmethod
    def _record_search_text(record: dict[str, Any]) -> str:
        """Flatten returned fields so ranking considers actual script/condition data."""
        parts = []
        for key, value in record.items():
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple)):
                value = json.dumps(value, ensure_ascii=False, default=str)
            parts.append(f"{key} {value}")
        return " ".join(parts).lower()

    def _rank_candidates(
        self,
        records: list[dict[str, Any]],
        step: dict[str, Any],
        problem_context: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Rank a bounded candidate pool using problem-specific terms.
        Ranking is a retrieval heuristic, not causal verification.
        """
        terms = self._search_terms(step, problem_context)
        target_field = str(
            step.get("target_field") or ""
        ).strip().lower()
        if not target_field:
            # Planner context often includes the affected field in its instructions.
            field_candidates = re.findall(
                r"\b[a-z][a-z0-9_]*_[a-z0-9_]+\b",
                " ".join([
                    str(problem_context),
                    str(step.get("search_strategy", "")),
                    str(step.get("evidence_to_find", "")),
                ]).lower(),
            )
            if field_candidates:
                target_field = field_candidates[0]

        scored = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            text = self._record_search_text(record)
            matched_terms = [term for term in terms if term in text]
            score = len(matched_terms)
            field_match = bool(target_field and target_field in text)
            if field_match:
                score += 8
            # Script bodies and conditions are stronger signals than names alone.
            logic_text = " ".join(
                str(record.get(key, "") or "")
                for key in (
                    "script", "condition", "advanced_condition",
                    "field", "element", "actions", "conditions",
                )
            ).lower()
            logic_matches = [term for term in terms if term in logic_text]
            score += min(len(logic_matches), 5) * 2

            enriched = dict(record)
            enriched["_retrieval_match"] = {
                "score": score,
                "matched_terms": matched_terms[:20],
                "matched_logic_terms": logic_matches[:20],
                "target_field_match": field_match,
                "ranking_method": "local_keyword_heuristic",
            }
            scored.append((score, index, enriched))

        # Stable sorting preserves original order for equal scores.
        scored.sort(key=lambda item: (-item[0], item[1]))
        selected = [item[2] for item in scored[: self.max_records_per_step]]
        stats = {
            "candidates_scanned": len(records),
            "records_selected": len(selected),
            "records_ranked_out": max(0, len(records) - len(selected)),
            "terms_used": terms,
            "target_field_used": target_field or None,
            "ranking_method": "local_keyword_heuristic",
            "warning": (
                "Ranking only covers the bounded candidate pool returned by "
                "ServiceNow. It does not prove causation or guarantee that all "
                "matching records in the instance were retrieved."
            ),
        }
        return selected, stats

    def _execute_step(
        self,
        step: dict[str, Any],
        problem_context: str = "",
    ) -> dict[str, Any]:
        step_id = step["step_id"]
        source = step["source"]

        target_table = self._validate_table_name(
            step.get("target_table")
        )

        if source in self.TABLE_SPECIFIC_SOURCES and not target_table:
            return {
                "step_id": step_id,
                "hypothesis_id": step.get("hypothesis_id"),
                "objective": step.get("objective"),
                "source": source,
                "status": "skipped",
                "count": 0,
                "records": [],
                "error": (
                    "This source requires a target_table, but the plan "
                    "did not provide one."
                ),
            }

        method_name = self.SOURCE_METHODS[source]
        retrieval_method = getattr(self.client, method_name, None)

        if not callable(retrieval_method):
            return {
                "step_id": step_id,
                "hypothesis_id": step.get("hypothesis_id"),
                "objective": step.get("objective"),
                "source": source,
                "method": method_name,
                "target_table": target_table,
                "status": "unavailable",
                "count": 0,
                "records": [],
                "error": (
                    f"ServiceNowClient does not implement callable method "
                    f"'{method_name}'."
                ),
            }

        arguments = self._build_arguments(
            source=source,
            target_table=target_table,
            step=step,
        )

        try:
            records = retrieval_method(**arguments)

            if not isinstance(records, list):
                raise TypeError(
                    f"{method_name} returned {type(records).__name__}; "
                    "expected a list."
                )

            selected_records, ranking_stats = self._rank_candidates(
                records=records,
                step=step,
                problem_context=problem_context,
            )

            # For selected UI Policy parents, retrieve their child actions by
            # parent sys_id. Do not scan an unrelated first page of actions.
            related_actions_count = 0
            related_actions_error = None
            if source == "ui_policies" and selected_records:
                action_method = getattr(
                    self.client, "get_ui_policy_actions", None
                )
                policy_ids = [
                    str(record.get("sys_id", ""))
                    for record in selected_records
                    if re.fullmatch(
                        r"[a-fA-F0-9]{32}",
                        str(record.get("sys_id", "")),
                    )
                ]
                if callable(action_method) and policy_ids:
                    try:
                        # Fetch up to 100 actions specifically for selected parents.
                        actions = action_method(
                            limit=100,
                            policy_sys_ids=policy_ids,
                        )
                        if not isinstance(actions, list):
                            raise TypeError(
                                "get_ui_policy_actions returned a non-list result."
                            )
                        by_policy = {}
                        selected_id_set = set(policy_ids)
                        for action in actions:
                            if not isinstance(action, dict):
                                continue
                            parent_id = str(action.get("ui_policy", ""))
                            if parent_id not in selected_id_set:
                                continue
                            by_policy.setdefault(parent_id, []).append(action)
                        for policy in selected_records:
                            children = by_policy.get(
                                str(policy.get("sys_id", "")), []
                            )
                            policy["_related_ui_policy_actions"] = children
                            related_actions_count += len(children)
                    except Exception as action_error:
                        related_actions_error = (
                            f"{type(action_error).__name__}: {action_error}"
                        )
                        for policy in selected_records:
                            policy["_related_ui_policy_actions"] = []

            return {
                "step_id": step_id,
                "hypothesis_id": step.get("hypothesis_id"),
                "objective": step.get("objective"),
                "source": source,
                "method": method_name,
                "target_table": target_table,
                "status": "success",
                "count": len(selected_records),
                "candidate_count": len(records),
                "ranking": ranking_stats,
                "related_ui_policy_actions_count": related_actions_count,
                "related_ui_policy_actions_error": related_actions_error,
                "records": selected_records,
                "error": None,
            }

        except Exception as error:
            return {
                "step_id": step_id,
                "hypothesis_id": step.get("hypothesis_id"),
                "objective": step.get("objective"),
                "source": source,
                "method": method_name,
                "target_table": target_table,
                "status": "failed",
                "count": 0,
                "records": [],
                "error": f"{type(error).__name__}: {error}",
            }

    # -----------------------------------------------------
    # Execute the entire investigation plan
    # -----------------------------------------------------

    def execute_plan(
        self,
        plan: InvestigationPlan | dict[str, Any],
    ) -> dict[str, Any]:
        plan_data = self._normalize_plan(plan)
        self.validate_plan(plan_data)

        results: dict[str, dict[str, Any]] = {}
        execution_order = []

        context_parts = [
            str(plan_data.get("problem_summary") or ""),
            str(plan_data.get("target_table") or ""),
            str(plan_data.get("target_field") or ""),
        ]
        for hypothesis in plan_data.get("hypotheses", []):
            if isinstance(hypothesis, dict):
                context_parts.extend(
                    str(hypothesis.get(key) or "")
                    for key in ("title", "description", "hypothesis", "reasoning")
                )
        problem_context = " ".join(part for part in context_parts if part)

        for step in plan_data["investigation_steps"]:
            step_id = step["step_id"]
            dependencies = step.get("depends_on", [])

            failed_dependencies = [
                dependency
                for dependency in dependencies
                if results.get(dependency, {}).get("status") != "success"
            ]

            if failed_dependencies:
                results[step_id] = {
                    "step_id": step_id,
                    "hypothesis_id": step.get("hypothesis_id"),
                    "objective": step.get("objective"),
                    "source": step["source"],
                    "status": "skipped",
                    "count": 0,
                    "records": [],
                    "error": (
                        "Dependency did not succeed: "
                        + ", ".join(failed_dependencies)
                    ),
                }
            else:
                results[step_id] = self._execute_step(step, problem_context)

            execution_order.append(step_id)

        summary = {
            "steps_attempted": len(results),
            "successful_steps": sum(
                item["status"] == "success"
                for item in results.values()
            ),
            "failed_steps": sum(
                item["status"] == "failed"
                for item in results.values()
            ),
            "unavailable_steps": sum(
                item["status"] == "unavailable"
                for item in results.values()
            ),
            "skipped_steps": sum(
                item["status"] == "skipped"
                for item in results.values()
            ),
            "total_records": sum(
                item["count"]
                for item in results.values()
            ),
            "total_candidates_scanned": sum(
                item.get("candidate_count", item.get("count", 0))
                for item in results.values()
            ),
            "records_ranked_out": sum(
                item.get("ranking", {}).get("records_ranked_out", 0)
                for item in results.values()
            ),
        }

        return {
            "problem_summary": plan_data["problem_summary"],
            "target_table": plan_data.get("target_table"),
            "target_field": plan_data.get("target_field"),
            "hypotheses": plan_data["hypotheses"],
            "investigation_plan": plan_data["investigation_steps"],
            "execution_order": execution_order,
            "results": results,
            "summary": summary,
        }

    # -----------------------------------------------------
    # Print execution results
    # -----------------------------------------------------

    @staticmethod
    def print_results(result: dict[str, Any]) -> None:
        print("\n" + "=" * 70)
        print("SMYD RCA COPILOT - PLAN EXECUTION")
        print("=" * 70)

        print(f"\nProblem: {result.get('problem_summary')}")
        print(f"Target table: {result.get('target_table')}")
        print("\nEXECUTION RESULTS")

        for step_id, item in result["results"].items():
            print(
                f"\nStep: {step_id}"
                f"\nSource: {item.get('source')}"
                f"\nStatus: {item.get('status')}"
                f"\nRecords retrieved: {item.get('count', 0)}"
            )

            if item.get("error"):
                print(f"Detail: {item['error']}")

            for record in item.get("records", []):
                if not isinstance(record, dict):
                    print(f"  Record: {record}")
                    continue

                print(
                    "  Record: "
                    f"{record.get('name', record.get('subject', '(name unavailable)'))}"
                    " | sys_id: "
                    f"{record.get('sys_id', '(sys_id unavailable)')}"
                )

        print("\nSUMMARY")
        print(result["summary"])
        print("\n" + "=" * 70)

    # -----------------------------------------------------
    # Close owned client
    # -----------------------------------------------------

    def close(self) -> None:
        if self._owns_client:
            self.client.close()


# ---------------------------------------------------------
# 3. Standalone test
# ---------------------------------------------------------

def main() -> None:
    from investigation.investigation_planner import InvestigationPlanner

    planner = InvestigationPlanner()
    executor = InvestigationExecutor(max_records_per_step=5)

    try:
        problem = input(
            "\nDescribe the ServiceNow problem: "
        ).strip()

        if not problem:
            print("Please enter a problem.")
            return

        print("\nGenerating AI investigation plan...")
        plan = planner.create_plan(problem)
        planner.print_plan(plan)

        approval = input(
            "\nExecute this plan against ServiceNow? (yes/no): "
        ).strip().lower()

        if approval != "yes":
            print("Plan execution cancelled.")
            return

        print("\nExecuting approved investigation steps...")
        result = executor.execute_plan(plan)
        executor.print_results(result)

    except Exception as error:
        print(
            f"\nInvestigation execution failed: "
            f"{type(error).__name__}: {error}"
        )

    finally:
        executor.close()


if __name__ == "__main__":
    main()
