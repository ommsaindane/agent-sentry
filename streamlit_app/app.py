from __future__ import annotations

import json

import streamlit as st

from data_access import (
    ApiConfig,
    ApiError,
    get_hitl_item,
    get_request,
    list_hitl_queue,
    list_requests,
    send_chat,
    resolve_hitl,
)


def _json_preview(obj):
    try:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(obj)


st.set_page_config(page_title="AgentSentry", layout="wide")

st.title("AgentSentry")
st.caption("Request log + HITL review UI")

try:
    cfg = ApiConfig.from_env()
except ApiError as exc:
    st.error(str(exc))
    st.stop()


requests_tab, hitl_tab = st.tabs(["Requests", "HITL Queue"])

with requests_tab:
    st.subheader("Requests")

    st.markdown("**Send chat**")
    with st.form("chat_form", clear_on_submit=False):
        chat_message = st.text_area("Message", value="", height=120)
        chat_max_tokens = st.number_input(
            "max_output_tokens",
            min_value=1,
            max_value=8192,
            value=256,
            step=1,
        )
        submitted = st.form_submit_button("Send")

    if submitted:
        if not isinstance(chat_message, str) or not chat_message.strip():
            st.error("Message is required")
        else:
            try:
                st.session_state["last_chat_response"] = send_chat(
                    cfg=cfg,
                    message=str(chat_message),
                    max_output_tokens=int(chat_max_tokens),
                )
            except ApiError as exc:
                st.error(str(exc))

    last = st.session_state.get("last_chat_response")
    if isinstance(last, dict):
        st.markdown("**Last /chat response**")
        st.code(_json_preview(last), language="json")

    try:
        items = list_requests(cfg=cfg, limit=100, offset=0)
    except ApiError as exc:
        st.error(str(exc))
        st.stop()

    if not items:
        st.info("No requests logged yet.")
    else:
        st.dataframe(items, use_container_width=True, hide_index=True)

        request_ids = [str(i.get("request_id")) for i in items if i.get("request_id")]
        selected = st.selectbox("Request", options=request_ids, index=0)

        try:
            detail = get_request(cfg=cfg, request_id=str(selected))
        except ApiError as exc:
            st.error(str(exc))
            st.stop()

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Summary**")
            st.write({k: detail.get(k) for k in ["request_id", "created_at", "decision", "status", "risk_score", "policy_risk_score", "queue_id"]})
            st.markdown("**Input (raw)**")
            st.text(detail.get("input_raw") or "")
            st.markdown("**Input (sanitized)**")
            st.text(detail.get("input_sanitized") or "")
            st.markdown("**Output**")
            st.text(detail.get("output_text") or "")

        with c2:
            st.markdown("**Guard**")
            st.code(_json_preview(detail.get("guard_obj") or {}), language="json")
            st.markdown("**Policy**")
            st.code(_json_preview(detail.get("policy_obj") or {}), language="json")
            st.markdown("**Agent**")
            st.code(_json_preview(detail.get("agent_obj") or {}), language="json")
            st.markdown("**Output Guard**")
            st.code(_json_preview(detail.get("output_obj") or {}), language="json")

with hitl_tab:
    st.subheader("HITL Queue")

    try:
        queue_items = list_hitl_queue(cfg=cfg, status="pending_review", limit=100, offset=0)
    except ApiError as exc:
        st.error(str(exc))
        st.stop()

    if not queue_items:
        st.info("No pending HITL items.")
    else:
        st.dataframe(queue_items, use_container_width=True, hide_index=True)

        queue_ids = [int(i.get("queue_id")) for i in queue_items if i.get("queue_id") is not None]
        selected_qid = st.selectbox("Queue item", options=queue_ids, index=0)

        try:
            q_detail = get_hitl_item(cfg=cfg, queue_id=int(selected_qid))
        except ApiError as exc:
            st.error(str(exc))
            st.stop()

        c1, c2 = st.columns(2)

        with c1:
            st.markdown("**Summary**")
            st.write({k: q_detail.get(k) for k in ["queue_id", "request_id", "created_at", "risk_score", "decision", "status"]})
            st.markdown("**Input (raw)**")
            st.text(q_detail.get("input_raw") or "")
            st.markdown("**Input (sanitized)**")
            st.text(q_detail.get("input_sanitized") or "")

            st.markdown("**Review**")
            note = st.text_area("Note", value="", height=100)
            max_tokens = st.number_input("max_output_tokens (approve only)", min_value=1, max_value=8192, value=256, step=1)

            b1, b2 = st.columns(2)
            with b1:
                if st.button("Approve", type="primary"):
                    try:
                        resp = resolve_hitl(
                            cfg=cfg,
                            queue_id=int(selected_qid),
                            action="approve",
                            note=note,
                            max_output_tokens=int(max_tokens),
                        )
                        st.success("Approved")
                        st.code(_json_preview(resp), language="json")
                    except ApiError as exc:
                        st.error(str(exc))
            with b2:
                if st.button("Decline"):
                    try:
                        resp = resolve_hitl(
                            cfg=cfg,
                            queue_id=int(selected_qid),
                            action="decline",
                            note=note,
                            max_output_tokens=None,
                        )
                        st.warning("Declined")
                        st.code(_json_preview(resp), language="json")
                    except ApiError as exc:
                        st.error(str(exc))

        with c2:
            st.markdown("**Guard**")
            st.code(_json_preview(q_detail.get("guard_obj") or {}), language="json")
            st.markdown("**Policy**")
            st.code(_json_preview(q_detail.get("policy_obj") or {}), language="json")
            st.markdown("**Agent**")
            st.code(_json_preview(q_detail.get("agent_obj") or {}), language="json")
            st.markdown("**Review metadata**")
            st.write({k: q_detail.get(k) for k in ["review_note", "reviewed_at"]})
