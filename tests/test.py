import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import pytest
from fastapi.testclient import TestClient
from src.main import app, create_access_token, create_refresh_token, hash_token
from sqlalchemy.orm import Session
from src.models import User, UserRole
import src.crud as crud

client = TestClient(app)

@pytest.fixture(scope="module")
def db():
    # Создайте временную базу данных для тестирования
    from src.database import engine, SessionLocal
    from src.models import Base
    db = SessionLocal()
    yield db
    db.close()

# !! Пока что закомментил эти тесты, так как хз, нужны ли они
# @pytest.fixture(scope="module")
# def test_user(db: Session):
#     role = UserRole(name="test_role")
#     db.add(role)
#     db.commit()
#     db.refresh(role)
#     user = User(username="testuser", email="testuser@example.com", password_hash="hashedpassword", role_id=role.id)
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return user

# @pytest.fixture(scope="module")
# def access_token(test_user):
#     return create_access_token(test_user)

# @pytest.fixture(scope="module")
# def refresh_token(test_user):
#     return create_refresh_token(test_user)
# !! Пока что закомментил эти тесты, так как хз, нужны ли они

def test_create_user():
    # TODO
    # здесь надо протестить 
    # 1) запрос с отсутствующими полями (все комбинации)
    # 2) запрос с невалидным паролем (нет спец символа, невалидное количество символов, нет цифры)
    # 3) запрос с уже зарегнным юзернеймом
    # 4) запрос с уже зарегнным email
    # 5) разные пароли
    # 6) полностью валидный запрос
    response = client.post("/create", json={"username": "correct_user", "email": "correct_user@example.com", 
                                            "password": "c0rRect_password", "password2": "c0rRect_password"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "correct_user"
    assert data["email"] == "correct_user@example.com"

def test_login_for_access_token(test_user):
    # TODO
    # не нужно передавать захешированный пароль, это тест логина, 
    # он просто по паролю производится, надо передавать такой же пароль как 
    # и в предыдущем тесте (при создании пользователя)
    # здесь надо протестить:
    # 1) Тест логина с неправильным паролем
    # 2) Тест логина с правильным паролем
    response = client.post("/token", data={"username": "correct_user", "password": "c0rRect_password"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

def test_refresh_token(db, refresh_token):
    # TODO: разобраться как соединять разные тесты между собой, 
    # в частности как взять рефреш токен сюда, разобраться в ФИКСТУРАХ
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

# def test_get_my_sessions(db, access_token):
#     headers = {"Authorization": f"Bearer {access_token}"}
#     response = client.get("/my_sessions", headers=headers)
#     assert response.status_code == 200
#     data = response.json()
#     assert "sessions" in data

# def test_logout(db, access_token, refresh_token):
#     headers = {"Authorization": f"Bearer {access_token}"}
#     response = client.post("/logout", headers=headers, json={"refresh_token": refresh_token})
#     assert response.status_code == 200
#     data = response.json()
#     assert data["message"] == "Session was successfully deleted"

# def test_revoke_session(db, access_token, test_user):
#     # Сначала создаем сессию
#     hashed_refresh_token = hash_token(refresh_token)
#     session = crud.create_session(db, test_user.id, hashed_refresh_token, "127.0.0.1", "Test User Agent")
    
#     headers = {"Authorization": f"Bearer {access_token}"}
#     response = client.post("/revoke", headers=headers, json={"sessionId": session.id})
#     assert response.status_code == 200
#     data = response.json()
#     assert data["message"] == "Session was successfully deleted"
