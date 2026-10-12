import re
from typing import Any


class EvidenceFilter:
    """Classify ServiceNow investigation records by heuristic relevance.

    This filter prioritizes evidence for later analysis. It does not prove
    that a configuration record caused the reported behavior.
    """

    SOURCE_KEYWORDS = {
        "business_rules": {
            "assignment", "assignment_group", "current.assignment_group",
            "setvalue", "set_value", "abortaction", "setabortaction",
            "changes", "changesto", "before", "after", "insert",
        },
        "client_scripts": {
            "onsubmit", "onchange", "onload", "g_form", "setvalue",
            "setmandatory", "setreadonly", "submit", "save",
        },
        "script_includes": {
            "assignment", "assignment_group", "update", "setvalue",
            "set_value", "gliderecord", "function",
        },
        "ui_policies": {
            "setmandatory", "setreadonly", "setvisible", "field",
        },
        "ui_policy_actions": {
            "mandatory", "visible", "disabled", "field", "ui_policy",
        },
        "data_policies": {
            "mandatory", "readonly", "validation", "field",
        },
        "data_policy_rules": {
            "mandatory", "read_only", "readonly", "field", "sys_data_policy",
        },
        "ui_actions": {
            "onclick", "onsubmit", "submit", "action", "current.update",
        },
        "flows": {
            "trigger", "update record", "update_record", "assignment_group",
            "incident", "flow", "action",
        },
         "notifications": {
            "email", "notification", "notifications", "recipient", "send",
            "worknotes", "work_notes", "journal", "commented", "event_name",
            "advanced_condition", "action_update", "action_insert", "condition",
        },
        "system_events": {"event", "queue", "trigger", "notification"},
        "email_logs": {"email", "notification", "sent", "error", "recipient"},
        "scheduled_jobs": {"scheduled", "job", "script", "execution"},
        "scheduled_script_executions": {"scheduled", "execution", "error", "script"},
        "system_logs": {"error", "exception", "failed", "transaction", "update"},
        "dictionary": {"field", "type", "reference", "mandatory", "readonly"},
        "system_properties": {"property", "configuration", "setting"},
    }

    # Domain synonyms help match ServiceNow terminology without assuming causation.
    SYNONYM_GROUPS = (
        {"required", "require", "requires", "mandatory", "setmandatory", "ismandatory"},
        {"readonly", "read_only", "setreadonly", "read-only"},
        {"visible", "visibility", "setvisible", "hidden", "hide"},
        {"onchange", "changes", "changesto", "change_to", "statechange"},
        {"client_script", "clientscript", "g_form"},
        {"ui_policy", "uipolicy", "ui_policy_action", "uipolicyaction"},
        {"business_rule", "businessrule", "sys_script"},
        {"data_policy", "datapolicy", "sys_data_policy2"},
    )

    # Words that are too general to count as problem-specific matches.
    GENERIC_TERMS = {
        "incident", "record", "update", "updated", "updating", "change",
        "changed", "state", "field", "script", "condition", "current",
        "previous", "table", "service", "now", "automatically", "automatic",
        "problem", "issue", "working", "work", "fail", "fails", "failed",
        "not", "get", "getting", "does", "doesnt", "isnt", "cant",
        "required", "require", "requires", "mandatory", "setmandatory",
        "changes", "changesto", "change_to", "onchange", "statechange",
    }

    STOP_WORDS = {
        "the", "a", "an", "is", "are", "was", "were", "to", "of",
        "in", "on", "for", "and", "or", "my", "me", "it", "this",
        "that", "when", "why", "how", "what", "with", "from", "not",
        "does", "do", "did", "can", "could", "would", "should", "i",
        "we", "our", "please", "find", "possible", "cause", "causing",
        "after", "before", "while", "by", "be", "been", "being", "as",
        "at", "if", "then", "but", "into", "about", "myself",
    }

    def __init__(self, minimum_score: int = 1):
        if not isinstance(minimum_score, int) or minimum_score < 1:
            raise ValueError("minimum_score must be an integer of at least 1.")
        self.minimum_score = minimum_score

    @staticmethod
    def _normalize(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list, tuple, set)):
            value = " ".join(map(str, value))
        return str(value).lower()

    @classmethod
    def _extract_record_text(cls, record: dict[str, Any]) -> str:
        """Build searchable text from all fields in the retrieved record."""
        parts = []
        for field, value in record.items():
            # Internal retrieval metadata must not influence relevance scoring.
            if str(field).startswith("_"):
                continue
            normalized = cls._normalize(value)
            if normalized:
                parts.append(f"{field} {normalized}")
        return " ".join(parts)

    @classmethod
    def _extract_problem_terms(cls, question: str) -> set[str]:
        words = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", question.lower())
        return {
            word for word in words
            if len(word) > 1 and word not in cls.STOP_WORDS
        }

    @staticmethod
    def _contains_term(text: str, term: str) -> bool:
        """Match a term as a token/phrase, not as an arbitrary substring."""
        escaped = re.escape(term.lower()).replace(r"\ ", r"\s+")
        return re.search(rf"(?<![a-zA-Z0-9_]){escaped}(?![a-zA-Z0-9_])", text) is not None

    @staticmethod
    def _get_record_table(record: dict[str, Any]) -> str | None:
        for key in ("collection", "table", "name_table", "table_name"):
            value = record.get(key)
            if value and not isinstance(value, (dict, list)):
                return str(value).strip()
        return None

    @staticmethod
    def _get_record_name(record: dict[str, Any]) -> str | None:
        for key in ("name", "short_description", "subject", "title", "label"):
            value = record.get(key)
            if value and not isinstance(value, (dict, list)):
                return str(value)
        return None

    @classmethod
    def _expand_synonyms(cls, terms: set[str]) -> set[str]:
        expanded = set(terms)
        for group in cls.SYNONYM_GROUPS:
            if terms.intersection(group):
                expanded.update(group)
        return expanded

    def _classify_record(
        self,
        question: str,
        source: str,
        target_table: str | None,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        record_text = self._extract_record_text(record)
        question_terms = self._expand_synonyms(self._extract_problem_terms(question))
        specific_terms = question_terms - self.GENERIC_TERMS

        # A match on a domain synonym is useful for discovery, not causal proof.
        semantic_terms = question_terms - self._extract_problem_terms(question)

        matched_problem_terms = sorted(
            term for term in specific_terms
            if self._contains_term(record_text, term)
        )
        matched_semantic_terms = sorted(
            term for term in semantic_terms
            if self._contains_term(record_text, term)
        )

        source_keywords = self.SOURCE_KEYWORDS.get(source, set())
        meaningful_source_keywords = source_keywords - self.GENERIC_TERMS
        matched_source_terms = sorted(
            term for term in meaningful_source_keywords
            if self._contains_term(record_text, term)
        )

        record_table = self._get_record_table(record)
        table_matches = bool(
            target_table and record_table
            and record_table.casefold() == target_table.casefold()
        )

        # A table match is contextual only; it cannot independently make
        # a record "relevant". Specific question terms carry more weight.
        score = min(len(matched_problem_terms), 3) * 2
        if matched_semantic_terms:
            score += 2
        if matched_source_terms:
            score += 1
        if table_matches:
            score += 1

        if len(matched_problem_terms) >= 2:
            relevance = "relevant"
        elif (matched_problem_terms or matched_semantic_terms) and (matched_source_terms or table_matches):
            relevance = "potentially_relevant"
        elif matched_semantic_terms and source in {"ui_policies", "client_scripts", "data_policies", "business_rules"}:
            relevance = "potentially_relevant"
        elif matched_source_terms:
            relevance = "potentially_relevant"
        else:
            relevance = "low_relevance"

        # Prioritize notification configurations for notification-related symptoms.
        # This is a discovery rule only and does not imply causation.
        question_lower = question.lower()
        notification_problem = any(
            term in question_lower
            for term in ("notification", "notifications", "email", "worknotes", "work_notes", "work notes")
        )
        notification_candidate = source == "notifications" and notification_problem
        if notification_candidate and relevance == "low_relevance":
            relevance = "potentially_relevant"
            score = max(score, 1)

        reasons = []
        if notification_candidate:
            reasons.append(
                "Prioritized because the reported symptom concerns notifications/email; discovery clue only, not proof of causation"
            )
        if matched_problem_terms:
            reasons.append("Matches problem-specific terms: " + ", ".join(matched_problem_terms))
        if matched_semantic_terms:
            reasons.append(
                "Matches domain synonyms (discovery clue only): "
                + ", ".join(matched_semantic_terms)
            )
        if matched_source_terms:
            reasons.append("Contains source-related terms: " + ", ".join(matched_source_terms))
        if table_matches:
            reasons.append(f"Record table matches {target_table}; this is contextual, not causal evidence")
        if not reasons:
            reasons.append("No meaningful problem-specific or source-specific match found")

        return {
            "source": source,
            "step_id": None,
            "sys_id": record.get("sys_id"),
            "name": self._get_record_name(record),
            "table": record_table or target_table,
            "relevance": relevance,
            "relevance_score": score,
            "matched_problem_terms": matched_problem_terms,
            "matched_semantic_terms": matched_semantic_terms,
            "matched_source_terms": matched_source_terms,
            "table_matches": table_matches,
            "reasons": reasons,
            "record": record,
        }

    @staticmethod
    def _related_children(record: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """Return nested UI Policy Actions/Data Policy Rules as separate evidence.

        The parent remains evidence too. Child rows are classified independently
        so mandatory/read-only settings are not hidden inside parent metadata.
        """
        children: list[tuple[str, dict[str, Any]]] = []
        child_specs = (
            ("_related_ui_policy_actions", "ui_policy_actions", "ui_policy"),
            ("_related_data_policy_rules", "data_policy_rules", "sys_data_policy"),
        )
        for key, child_source, parent_ref_field in child_specs:
            values = record.get(key, [])
            if not isinstance(values, list):
                continue
            for child in values:
                if not isinstance(child, dict):
                    continue
                # Copy rather than mutate executor-owned records.
                child_copy = dict(child)
                child_copy["_evidence_parent_sys_id"] = record.get("sys_id")
                child_copy["_evidence_parent_name"] = (
                    record.get("name") or record.get("short_description")
                )
                child_copy["_evidence_parent_source"] = (
                    "ui_policies" if child_source == "ui_policy_actions" else "data_policies"
                )
                child_copy["_evidence_parent_reference_field"] = parent_ref_field
                children.append((child_source, child_copy))
        return children

    def filter_evidence(
        self,
        question: str,
        execution_result: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(question, str) or not question.strip():
            raise ValueError("Please provide a technical problem.")
        if not isinstance(execution_result, dict):
            raise ValueError("execution_result must be a dictionary.")

        step_results = execution_result.get("results", {})
        if not isinstance(step_results, dict):
            raise ValueError("execution_result.results must be a dictionary.")

        target_table = execution_result.get("target_table")
        all_records = []
        relevant_records = []
        potentially_relevant_records = []
        low_relevance_records = []
        retrieval_issues = []

        # Track raw occurrences separately from unique records.
        # A record repeated across steps is classified once, not lost silently.
        seen = set()
        raw_record_occurrences = 0
        duplicate_occurrences_removed = 0
        related_child_records_classified = 0

        def add_classified_record(
            source_name: str, step_id: str, step_table: str | None, record_data: dict[str, Any]
        ) -> None:
            nonlocal duplicate_occurrences_removed, related_child_records_classified
            nonlocal raw_record_occurrences
            raw_record_occurrences += 1
            sys_id_value = record_data.get("sys_id")
            dedupe_key_value = (source_name, str(sys_id_value)) if sys_id_value else None
            if dedupe_key_value and dedupe_key_value in seen:
                duplicate_occurrences_removed += 1
                return
            if dedupe_key_value:
                seen.add(dedupe_key_value)

            classified_item = self._classify_record(
                question=question, source=source_name,
                target_table=step_table or target_table, record=record_data,
            )
            classified_item["step_id"] = step_id
            if source_name in {"ui_policy_actions", "data_policy_rules"}:
                classified_item["evidence_kind"] = "related_policy_child"
                classified_item["parent_sys_id"] = record_data.get("_evidence_parent_sys_id")
                classified_item["parent_name"] = record_data.get("_evidence_parent_name")
                classified_item["parent_source"] = record_data.get("_evidence_parent_source")
                related_child_records_classified += 1
            else:
                classified_item["evidence_kind"] = "primary_record"

            all_records.append(classified_item)
            if classified_item["relevance"] == "relevant":
                relevant_records.append(classified_item)
            elif classified_item["relevance"] == "potentially_relevant":
                potentially_relevant_records.append(classified_item)
            else:
                low_relevance_records.append(classified_item)

        for step_id, step in step_results.items():
            if not isinstance(step, dict):
                continue

            source = step.get("source", "unknown")
            status = step.get("status", "unknown")
            if status != "success":
                retrieval_issues.append({
                    "step_id": step_id,
                    "source": source,
                    "status": status,
                    "error": step.get("error"),
                })

            records = step.get("records", [])
            if not isinstance(records, list):
                continue

            for record in records:
                if not isinstance(record, dict):
                    continue

                add_classified_record(
                    source_name=source,
                    step_id=step_id,
                    step_table=step.get("target_table"),
                    record_data=record,
                )

                # Explicitly classify related UI Policy Actions and Data Policy
                # Rules as separate evidence rows, while retaining their parent.
                for child_source, child_record in self._related_children(record):
                    add_classified_record(
                        source_name=child_source,
                        step_id=step_id,
                        step_table=step.get("target_table"),
                        record_data=child_record,
                    )

        return {
            "problem": question,
            "target_table": target_table,
            "counts": {
                "raw_record_occurrences": raw_record_occurrences,
                "duplicate_occurrences_removed": duplicate_occurrences_removed,
                "unique_records_classified": len(all_records),
                "total_records": len(all_records),
                "relevant": len(relevant_records),
                "potentially_relevant": len(potentially_relevant_records),
                "low_relevance": len(low_relevance_records),
                "retrieval_issues": len(retrieval_issues),
                "related_policy_child_records_classified": related_child_records_classified,
            },
            "relevant_evidence": relevant_records,
            "potentially_relevant_evidence": potentially_relevant_records,
            "low_relevance_evidence": low_relevance_records,
            "retrieval_issues": retrieval_issues,
            "limitations": [
                "Keyword matching is heuristic and does not establish causation.",
                "Domain synonym expansion improves recall but may add false positives.",
                "Evidence is limited to records returned by the executor; records ranked out or not queried were not classified.",
                "Low relevance does not prove a record is unrelated.",
                "Runtime execution evidence is required to confirm many causal claims.",
                "Nested UI Policy Actions and Data Policy Rules are classified as separate evidence, but this classification remains heuristic.",
                "A child policy action/rule identifies configured field behavior; it does not by itself prove the parent condition was met or the behavior executed at runtime.",
            ],
        }


if __name__ == "__main__":
    import json

    evidence_filter = EvidenceFilter()
    sample_execution_result = {
        "target_table": "incident",
        "results": {
            "S1": {
                "source": "business_rules",
                "target_table": "incident",
                "status": "success",
                "records": [
                    {
                        "sys_id": "example123",
                        "name": "Update Incident Assignment Group",
                        "collection": "incident",
                        "active": "true",
                        "script": (
                            "if (current.category == 'software') "
                            "{ current.assignment_group = 'some_group_sys_id'; }"
                        ),
                    },
                    {
                        "sys_id": "example456",
                        "name": "Unrelated Assessment Rule",
                        "collection": "incident",
                        "active": "true",
                        "script": "// Example placeholder",
                    },
                ],
            }
        },
    }

    question = "My Incident assignment group changes automatically when I update the record."
    filtered = evidence_filter.filter_evidence(question, sample_execution_result)

    print("\nEVIDENCE FILTER RESULTS")
    print("=" * 60)
    print(json.dumps(filtered["counts"], indent=2))
    for item in (
        filtered["relevant_evidence"]
        + filtered["potentially_relevant_evidence"]
        + filtered["low_relevance_evidence"]
    ):
        print(
            f"\nSource: {item['source']}"
            f"\nName: {item['name']}"
            f"\nSys ID: {item['sys_id']}"
            f"\nRelevance: {item['relevance']}"
            f"\nScore: {item['relevance_score']}"
            f"\nReasons: {item['reasons']}"
        )
