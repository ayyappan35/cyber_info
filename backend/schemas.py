from typing import Any, List, Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class SignupRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str = "user"


class LogoutResponse(BaseModel):
    revoked: bool


class MeResponse(BaseModel):
    username: str
    role: str = "user"


class UserOut(BaseModel):
    username: str
    email: Optional[str] = None
    role: str
    locked: bool
    created_at: str


class SetRoleRequest(BaseModel):
    role: str


class ConversationOut(BaseModel):
    id: str
    title: str
    created_at: str


class MessageOut(BaseModel):
    role: str
    content: str
    sources: List[str] = []
    transcript: List[Any] = []
    ts: str


class QueryRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None


class QueryResponse(BaseModel):
    conversation_id: str
    answer: str
    sources: List[str] = []
    transcript: List[Any] = []


class UploadResponse(BaseModel):
    filename: str
    chunks_ingested: int
    document_id: Optional[str] = None
    trust_status: Optional[str] = None
    chunks_quarantined: int = 0
    quarantined_chunk_ids: List[str] = []


class TrainingFileOut(BaseModel):
    filename: str
    filesize: int
    trained_by: str
    date: str


class SetLlmProviderRequest(BaseModel):
    provider: str


class AgentOut(BaseModel):
    agent_id: str
    role: str
    allowed_tools: List[str]
    disabled: bool
    created_at: str


class RegisterAgentRequest(BaseModel):
    agent_id: str
    role: str
    allowed_tools: List[str]


class ChangeAgentRoleRequest(BaseModel):
    role: str


class AgentMessageRequest(BaseModel):
    session_id: str
    sender_agent_id: str
    requested_tool: str
    message_content: str = ""
    source_ip: Optional[str] = None  # only meaningful when requested_tool is get_ip_reputation


class AgentMessageResponse(BaseModel):
    action: str
    reasoning: str
    skill_ids: List[str] = []
    tool_executed: bool
    tool_result: Optional[Any] = None
    tool_denied_reason: Optional[str] = None
