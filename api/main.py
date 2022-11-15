from datetime import datetime, timedelta
from io import BytesIO
from typing import Union
from PIL import Image
import PIL.ImageOps
from fastapi import Depends, FastAPI, File, HTTPException, Response, UploadFile, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import uvicorn
from os import environ

SECRET_KEY = "480d3fcbb6cbf65a4fe5e4243e7d6c9ab9890da1672b1df6378048e96214c179"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_user = {
    "bennym8": {
        "username": "bennym8",
        "hashed_password": "$2b$12$xsKuVK.DbxsA6H1JrNMzVuB79diO/pdSHjolhh65FlUTu29tbaCk2",
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    full_name: Union[str, None] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_user, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def image_to_bytes(image):
    img_byte_arr = BytesIO()
    image.save(img_byte_arr, format="JPEG")
    return img_byte_arr.getvalue()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_user, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/time/")
async def get_time(current_user: User = Depends(get_current_user)):
    print(current_user)
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    return {"Current time: ": current_time}

@app.get("/prime/{number}")
async def isPrime(number: int):
    if number & 1 == 0:
        return {number: "is not a prime number"}
    d = 3
    while d * d <= number:
        if number % d == 0:
            return {number: "is not a prime number"}
        d = d + 2
    return {number: "is a prime number"}

@app.post("/picture/invert/")
async def invert_image(file: UploadFile = File(...)):
    image = PIL.ImageOps.invert(Image.open(file.filename))
    image = image_to_bytes(image)
    return Response(content=image, media_type="image/jpeg")

if __name__ == '__main__':
    uvicorn.run("main:app", host='0.0.0.0', port=environ.get("PORT", 5000))