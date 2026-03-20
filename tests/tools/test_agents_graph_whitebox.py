from types import SimpleNamespace

import strix.agents as agents_module
from strix.llm.config import LLMConfig
from strix.tools.agents_graph import agents_graph_actions


def test_create_agent_inherits_parent_whitebox_flag(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()
    agents_graph_actions._agent_messages.clear()
    agents_graph_actions._running_agents.clear()
    agents_graph_actions._agent_instances.clear()
    agents_graph_actions._agent_states.clear()

    parent_id = "parent-agent"
    parent_llm = LLMConfig(timeout=123, scan_mode="standard", is_whitebox=True)
    agents_graph_actions._agent_instances[parent_id] = SimpleNamespace(
        llm_config=parent_llm,
        non_interactive=True,
    )

    captured_config: dict[str, object] = {}

    class FakeStrixAgent:
        def __init__(self, config: dict[str, object]):
            captured_config["agent_config"] = config

    class FakeThread:
        def __init__(self, target, args, daemon, name):
            self.target = target
            self.args = args
            self.daemon = daemon
            self.name = name

        def start(self) -> None:
            return None

    monkeypatch.setattr(agents_module, "StrixAgent", FakeStrixAgent)
    monkeypatch.setattr(agents_graph_actions.threading, "Thread", FakeThread)

    agent_state = SimpleNamespace(
        agent_id=parent_id,
        get_conversation_history=list,
    )
    result = agents_graph_actions.create_agent(
        agent_state=agent_state,
        task="source-aware child task",
        name="SourceAwareChild",
        inherit_context=False,
    )

    assert result["success"] is True
    llm_config = captured_config["agent_config"]["llm_config"]
    assert isinstance(llm_config, LLMConfig)
    assert llm_config.timeout == 123
    assert llm_config.scan_mode == "standard"
    assert llm_config.is_whitebox is True


def test_delegation_prompt_includes_wiki_memory_instruction_in_whitebox(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()
    agents_graph_actions._agent_messages.clear()
    agents_graph_actions._running_agents.clear()
    agents_graph_actions._agent_instances.clear()
    agents_graph_actions._agent_states.clear()

    parent_id = "parent-1"
    child_id = "child-1"
    agents_graph_actions._agent_graph["nodes"][parent_id] = {"name": "Parent", "status": "running"}
    agents_graph_actions._agent_graph["nodes"][child_id] = {"name": "Child", "status": "running"}

    class FakeState:
        def __init__(self) -> None:
            self.agent_id = child_id
            self.agent_name = "Child"
            self.parent_id = parent_id
            self.task = "analyze source risks"
            self.stop_requested = False
            self.messages: list[tuple[str, str]] = []

        def add_message(self, role: str, content: str) -> None:
            self.messages.append((role, content))

        def model_dump(self) -> dict[str, str]:
            return {"agent_id": self.agent_id}

    class FakeAgent:
        def __init__(self) -> None:
            self.llm_config = LLMConfig(is_whitebox=True)

        async def agent_loop(self, _task: str) -> dict[str, bool]:
            return {"ok": True}

    state = FakeState()
    agent = FakeAgent()
    result = agents_graph_actions._run_agent_in_thread(agent, state, inherited_messages=[])

    assert result["result"] == {"ok": True}
    task_messages = [msg for role, msg in state.messages if role == "user"]
    assert task_messages
    assert 'list_notes(category="wiki")' in task_messages[-1]
