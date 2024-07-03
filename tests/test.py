import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import pytest
from fastapi.testclient import TestClient
from src.main import app, create_access_token, create_refresh_token, hash_token
from sqlalchemy.orm import Session
from src.models import User, Role
import src.crud as crud

client = TestClient(app)

@pytest.fixture(scope="module")
def db():
    # Создайте временную базу данных для тестирования
    from database import Base, engine, SessionLocal
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="module")
def test_user(db: Session):
    role = Role(name="test_role")
    db.add(role)
    db.commit()
    db.refresh(role)
    user = User(username="testuser", email="testuser@example.com", password_hash="hashedpassword", role_id=role.id)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture(scope="module")
def access_token(test_user):
    return create_access_token(test_user)

@pytest.fixture(scope="module")
def refresh_token(test_user):
    return create_refresh_token(test_user)

def test_create_user(db):
    response = client.post("/create", json={"username": "newuser", "email": "newuser@example.com", "password": "newpassword"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@example.com"

def test_login_for_access_token(db, test_user):
    response = client.post("/token", data={"username": test_user.username, "password": "hashedpassword"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

def test_refresh_token(db, refresh_token):
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

def test_get_my_sessions(db, access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/my_sessions", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "sessions" in data

def test_logout(db, access_token, refresh_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.post("/logout", headers=headers, json={"refresh_token": refresh_token})
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Session was successfully deleted"

def test_revoke_session(db, access_token, test_user):
    # Сначала создаем сессию
    hashed_refresh_token = hash_token(refresh_token)
    session = crud.create_session(db, test_user.id, hashed_refresh_token, "127.0.0.1", "Test User Agent")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.post("/revoke", headers=headers, json={"sessionId": session.id})
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Session was successfully deleted"
