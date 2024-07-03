from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated, List
import jwt

from crypto import check_password, create_access_token, create_refresh_token, hash_token, verify_jwt_token
from schemas import LoginResponse, LogoutRequest, MySessionsResponse, RefreshRequest, RevokeTokenRequest, Role, SessionBase, UpdateTokenResponse, UserCreate, UserResponse
from database import SessionLocal
import crud
import models
from utils import parse_user_agent

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    response = Response("Internal server error", status_code=500)
    try:
        request.state.db = SessionLocal()
        response = await call_next(request)
    finally:
        request.state.db.close()
    return response

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def authenticate_user(db: Session, username: str, password: str):
    db_user = crud.get_user_by_username(db, username)
    if not db_user or not check_password(password, db_user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    return db_user

def create_user_response(db_user: models.User) -> UserResponse:
    role = Role.model_validate(db_user.role.__dict__)
    return UserResponse(
        id=db_user.id,
        username=db_user.username,
        email=db_user.email,
        password_hash=db_user.password_hash,
        last_password_update=db_user.last_password_update,
        role=role
    )

@app.post("/create", response_model=UserResponse)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

@app.post("/token", response_model=LoginResponse)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
                                 request: Request, 
                                 db: Session = Depends(get_db)):
    db_user = authenticate_user(db, form_data.username, form_data.password)
    user_response = create_user_response(db_user)
    access_token = create_access_token(user_response)
    refresh_token = create_refresh_token(user_response)

    device_ip = request.headers.get('X-Real-IP')
    if not device_ip:
        device_ip = request.headers.get('X-Forwarded-For')
    device_info = parse_user_agent(request.headers.get('User-Agent'))

    crud.create_session(db, db_user.id, hash_token(refresh_token), device_ip, device_info)

    return LoginResponse(access_token=access_token, refresh_token=refresh_token)

@app.post('/refresh', response_model=UpdateTokenResponse)
async def refresh_token(refresh_request: RefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = verify_jwt_token(refresh_request.refresh_token)
        db_user = crud.get_user_by_id(db, id=payload['id'])
        session = crud.get_session_by_refresh_token_hash(db, hash_token(refresh_request.refresh_token))

        if not db_user or not session:
            raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})

        user_response = create_user_response(db_user)
        access_token = create_access_token(user_response)
        crud.update_session_timestamp(db, session)

        return UpdateTokenResponse(access_token=access_token)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired", headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)) -> UserResponse:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = verify_jwt_token(token)
        username = payload.get("username")
        if username is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired", headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        raise credentials_exception

    db_user = crud.get_user_by_username(db, username=username)
    if db_user is None:
        raise credentials_exception

    return create_user_response(db_user)

def logout_check(current_user: UserResponse, session: models.Session):
    if current_user.id != session.user_id:
        raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})

def logout_apply(session: models.Session, current_user: UserResponse, db: Session):
    if not session:
        return JSONResponse(status_code=200, content={"message": "Session not found"})
    logout_check(current_user, session)
    db.delete(session)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Session was successfully deleted"})

@app.post('/logout')
async def logout(current_user: Annotated[UserResponse, Depends(get_current_user)], logoutRequest: LogoutRequest, db: Session = Depends(get_db)):
    session = crud.get_session_by_refresh_token_hash(db, hash_token(logoutRequest.refresh_token))
    return logout_apply(session, current_user, db)

@app.post('/revoke')
async def revoke_session(current_user: Annotated[UserResponse, Depends(get_current_user)], revokeTokenRequest: RevokeTokenRequest, db: Session = Depends(get_db)):
    session = crud.get_session_by_id(db, revokeTokenRequest.sessionId)
    return logout_apply(session, current_user, db)

@app.get('/my_sessions', response_model=MySessionsResponse)
async def my_sessions(current_user: Annotated[UserResponse, Depends(get_current_user)], db: Session = Depends(get_db)):
    sessions = crud.get_sessions_by_user_id(db, current_user.id)
    sessions_list = [SessionBase(**session.__dict__) for session in sessions]
    return MySessionsResponse(sessions=sessions_list)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
