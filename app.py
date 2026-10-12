import json

from investigation.investigation_planner import InvestigationPlanner
from investigation.investigation_executor import InvestigationExecutor
from investigation.evidence_filter import EvidenceFilter
from investigation.root_cause_analyzer import RootCauseAnalyzer


class SMYDRCACopilot:
    """
    Dynamic ServiceNow investigation workflow:
    planner -> executor -> evidence filter -> RCA analyzer.
    """

    def __init__(self):
        self.planner = InvestigationPlanner()
        self.executor = InvestigationExecutor(max_records_per_step=10)
        self.evidence_filter = EvidenceFilter()
        self.root_cause_analyzer = RootCauseAnalyzer()

    def investigate(self, question: str) -> str:
        if not isinstance(question, str) or not question.strip():
            raise ValueError(
                "Please enter a technical problem to investigate."
            )

        print("\n[1/4] Generating investigation plan...")
        plan = self.planner.create_plan(question)

        print("\nINVESTIGATION PLAN")
        print("-" * 60)
        self.planner.print_plan(plan)

        print("\n[2/4] Retrieving ServiceNow evidence...")
        execution_result = self.executor.execute_plan(plan)
        summary = execution_result.get("summary", {})

        print("\nEXECUTION SUMMARY")
        print(json.dumps(summary, indent=2))

        for step_id, step_result in execution_result.get(
            "results", {}
        ).items():
            if step_result.get("status") != "success":
                print(
                    f"\nStep {step_id}: {step_result.get('status')}"
                )
                if step_result.get("error"):
                    print(f"Detail: {step_result['error']}")

        print("\n[3/4] Classifying retrieved evidence...")
        filtered_evidence = self.evidence_filter.filter_evidence(
            question=question,
            execution_result=execution_result,
        )

        print("\nEVIDENCE FILTER SUMMARY")
        print(json.dumps(filtered_evidence.get("counts", {}), indent=2))

        # Display classifications without dumping full scripts or record payloads.
        for group in (
            "relevant_evidence",
            "potentially_relevant_evidence",
            "low_relevance_evidence",
        ):
            for item in filtered_evidence.get(group, []):
                print(
                    f"- [{item.get('relevance')}] "
                    f"{item.get('source')} | "
                    f"{item.get('name') or '(name unavailable)'} | "
                    f"sys_id={item.get('sys_id') or '(unavailable)'}"
                )

        if filtered_evidence.get("retrieval_issues"):
            print("\nRetrieval issues were detected; see RCA limitations.")

        if summary.get("total_records", 0) == 0:
            return (
                "ROOT CAUSE ASSESSMENT: UNDETERMINED\n\n"
                "No records were retrieved. Review the plan, target tables, "
                "permissions, and retrieval errors before drawing a conclusion."
            )

        print("\n[4/4] Assessing evidence and generating RCA...")
        return self.root_cause_analyzer.analyze(
            question=question,
            execution_result=execution_result,
            filtered_evidence=filtered_evidence,
        )

    def close(self):
        self.executor.close()


def main():
    print("=" * 70)
    print("                    SMYD RCA COPILOT")
    print("             ServiceNow Root Cause Analysis")
    print("=" * 70)

    copilot = None
    try:
        copilot = SMYDRCACopilot()
        print("\nDescribe the ServiceNow problem.")
        print("Example: An incident assignment group changes unexpectedly.")
        question = input("\nYour problem: ").strip()

        if not question:
            print("Please enter a valid problem.")
            return

        report = copilot.investigate(question)
        print("\n" + "=" * 70)
        print("                         RCA REPORT")
        print("=" * 70)
        print(report)
        print("\n" + "=" * 70)

    except KeyboardInterrupt:
        print("\nInvestigation cancelled.")
    except Exception as error:
        print(
            f"\nInvestigation failed: {type(error).__name__}: {error}"
        )
    finally:
        if copilot is not None:
            copilot.close()


if __name__ == "__main__":
    main()
