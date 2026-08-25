from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

import auth
import webapp_db as db
from schemas import ConversationOut, MessageOut

router = APIRouter(prefix="/api/conversations", tags=["conversations"])


@router.get("", response_model=List[ConversationOut])
def list_conversations(username: str = Depends(auth.get_current_user)):
    return db.list_conversations(username)


@router.post("", response_model=ConversationOut)
def create_conversation(username: str = Depends(auth.get_current_user)):
    conv_id = db.create_conversation(username)
    return db.get_conversation(conv_id, username)


@router.get("/{conversation_id}/messages", response_model=List[MessageOut])
def get_messages(conversation_id: str, username: str = Depends(auth.get_current_user)):
    if db.get_conversation(conversation_id, username) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")
    return db.get_messages(conversation_id)


@router.delete("/{conversation_id}")
def delete_conversation(conversation_id: str, username: str = Depends(auth.get_current_user)):
    if db.get_conversation(conversation_id, username) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")
    db.delete_conversation(conversation_id, username)
    return {"deleted": True}
