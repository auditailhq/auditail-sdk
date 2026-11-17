"""
Human approval for an agent payout in LangGraph, with Auditail.

The graph pauses with interrupt() when Auditail says a payout needs a human, and resumes with Command(resume=...)
on the same thread once someone decides. In production the resume comes from Auditail's signed callback (see the
docs); here the script polls resume() so it runs without a public URL.

    AUDITAIL_API_KEY=atl_live_... python payout_graph.py 4200
"""
import os
import sys
import time
import uuid
from typing import Optional, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from auditail import Auditail

auditail = Auditail(api_key=os.environ["AUDITAIL_API_KEY"], server_policy=True, log_level="warn",
                    **({"base_url": os.environ["AUDITAIL_BASE_URL"]} if os.environ.get("AUDITAIL_BASE_URL") else {}))


class State(TypedDict, total=False):
    thread_id: str
    payout: dict
    result: str
    payment_id: Optional[str]


def execute_payout(payout: dict, receipt: str) -> str:
    """Your payment client. Pass the receipt so the payout service can check it (check_receipt) before paying."""
    print(f"[payouts] PAID {payout['amount']} {payout['currency']} to {payout['beneficiary']['id']} (receipt {receipt[:18]}...)")
    return f"po_{int(time.time() * 1000)}"


def pay(state: State) -> State:
    # This node runs again from the top when the graph resumes. The idempotency key makes the second guard()
    # return the original decision instead of opening another approval.
    r = auditail.guard("create_payout", state["payout"], agent_id="payout-agent", wait=False,
                       session_id=state["thread_id"], correlation_id=state["thread_id"],
                       idempotency_key=f"{state['thread_id']}-pay")
    receipt = r.receipt
    if r.pending:
        approval_id = interrupt({"waiting_for": r.approval.id, "reason": r.reason})  # the graph stops here
        final = auditail.resume(approval_id)
        if not final["approved"]:
            return {"result": f"not approved: {final['reason']}"}
        receipt = final["receipt"]
    elif not r.approved:
        return {"result": f"blocked ({r.code}): {r.reason}"}
    payment_id = execute_payout(state["payout"], receipt)
    auditail.report_outcome("settled", receipt=receipt, external_tx_id=payment_id)
    return {"result": "paid", "payment_id": payment_id}


graph = StateGraph(State)
graph.add_node("pay", pay)
graph.add_edge(START, "pay")
graph.add_edge("pay", END)
app = graph.compile(checkpointer=InMemorySaver())  # use a durable checkpointer (Postgres, Redis) in production

if __name__ == "__main__":
    amount = float(sys.argv[1]) if len(sys.argv) > 1 else 4200
    thread_id = f"payout-{uuid.uuid4().hex[:8]}"
    config = {"configurable": {"thread_id": thread_id}}
    out = app.invoke({"thread_id": thread_id, "payout": {"amount": amount, "currency": "EUR", "beneficiary": {"id": "ben_big"}}}, config)
    if "__interrupt__" in out:
        waiting = out["__interrupt__"][0].value
        print(f"Paused: {waiting['reason']}\nApprove or deny {waiting['waiting_for']} in the Auditail dashboard (or Slack)...")
        while auditail.resume(waiting["waiting_for"])["pending"]:
            time.sleep(3)
        out = app.invoke(Command(resume=waiting["waiting_for"]), config)
    print("Result:", out["result"])
