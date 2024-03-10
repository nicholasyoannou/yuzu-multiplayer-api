import hashlib
import requests

from fastapi import FastAPI, Request, HTTPException
import multipart
import json
import jwt
from datetime import datetime, timedelta
import uuid
from fastapi.responses import JSONResponse, PlainTextResponse

from typing import List
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from uuid import UUID, uuid4
from collections import defaultdict

app = FastAPI()
localhost_enabled = True  # Set to False if API and room are not on the same server


class Member:
    nickname: str = ""
    username: str = ""
    gameName: str = ""
    avatarUrl: str = ""
    gameId: int


class Room:
    externalGuid: str = ""
    id: str = ""
    address: str = ""
    name: str = ""
    description: str = ""
    owner: str = ""
    port: int = ""
    preferredGameName: str = ""
    preferredGameId: int = ""
    maxPlayers: int = ""
    netVersion: int = ""
    hasPassword: bool = ""
    players = []


class Rooms:
    def __init__(self):
        self.rooms = {}
        self.usage = {}


rooms = Rooms()


def verifySecurityUser(req: Request):
    authorization = req.headers.get('authorization')
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.replace("Bearer " + '"', "")[0:-1]
    decoded = jwt.decode(jwt=token, key=PUBLIC_KEY, algorithms=["RS256"])
    return decoded


# Define a secret key for signing the token (keep this secure in a production environment)
with open("private_key.pem", "rb") as f:
    SECRET_KEY = f.read()
with open("public_key.pem", "rb") as f:
    PUBLIC_KEY = f.read()

ALGORITHM = "RS256"  # pip install python-jose[cryptography] , pip install pyjwt[crypto]

# Define the expiration time for the token (e.g., 30 minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 10000


# Function to generate JWT token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="RS256")
    return encoded_jwt


tokentoData = {'citrusfruit': {'username': 'janeberru', 'displayName': 'janeberru',
                               'avatarUrl': 'https://i.pinimg.com/736x/9a/b2/40/9ab2409771e7180dd275ec36fca9d370--field-of-flowers-spring-time.jpg',
                               "roles": ["user", "moderator"]}}
sessionData = []


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post('/jwt/internal')
async def process_jwt_request(req: Request):
    token = req.headers.get('x-token')
    if token in tokentoData:  # if username in tokendata, generate session
        # For demonstration purposes, let's generate a token with a user ID
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data=tokentoData[token], expires_delta=access_token_expires
        )
        print(access_token)
        return JSONResponse(content=access_token, headers={
            "Content-Type": "text/html"})
    else:
        pass


@app.get('/jwt/external/key.pem')
async def jwt_external_key():
    return PlainTextResponse(PUBLIC_KEY)


# This route needs security. It can be brute forced even though keys are relatively long, this endpoint doesn't need
# to be requested often per user.
@app.get('/profile')
async def profile(req: Request):
    print(req.headers)
    authorization = req.headers.get('authorization')
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    # Extract the token by removing "Bearer " prefix
    token = authorization.replace("Bearer " + '"', "")[0:-1]
    decoded = jwt.decode(jwt=token, key=PUBLIC_KEY, algorithms=["RS256"])
    return JSONResponse(content=decoded, headers={
        "Content-Type": "application/json"})


@app.get('/lobby')
async def get_lobbies():
    return {"rooms": list(rooms.rooms.values())}


@app.post('/lobby')
async def lobby(req: Request):
    global rooms
    data = await req.body()
    json_data = json.loads(data)
    decoded = verifySecurityUser(req)

    if localhost_enabled:
        addr = '127.0.0.1'
    else:
        addr = req.client.host

    if addr in rooms.usage and rooms.usage[addr] >= 3:
        raise HTTPException(status_code=429, detail="Too Many Requests")

    room = Room()
    room.address = addr
    room.externalGuid = str(uuid4())
    room.id = room.externalGuid
    room.owner = decoded['username']
    room.name = json_data['name']
    room.netVersion = int(json_data['netVersion'])
    room.hasPassword = bool(json_data['hasPassword'])
    room.port = int(json_data['port'])
    room.description = json_data['description']
    room.maxPlayers = int(json_data['maxPlayers'])
    room.preferredGameId = int(json_data['preferredGameId'])
    room.preferredGameName = json_data['preferredGameName']
    rooms.rooms[room.id] = room

    # Before finalising, increase usage of IP by one
    co = rooms.usage[addr] if addr in rooms.usage else 0
    rooms.usage[addr] = co + 1 if addr in rooms.usage else 1

    return room


@app.post('/lobby/{lobby_id}')  # To update server with players currently in server.
async def post_lobby_update(req: Request, lobby_id: str):
    global rooms
    if lobby_id not in rooms.rooms:
        raise HTTPException(status_code=404, detail="Room not found")
    data = await req.body()
    json_data = json.loads(data)
    print(json_data)

    # Check if owner of room doing this
    decoded = verifySecurityUser(req)
    if decoded['username'] == rooms.rooms[lobby_id].owner:
        rooms.rooms[lobby_id].players = json_data['players']
        return {"message": "Lobby updated successfully"}
    else:
        raise HTTPException(status_code=403, detail="Action forbidden")


@app.delete('/lobby/{lobby_id}')
async def lobbyRoomDel(req: Request, lobby_id: str):
    global rooms
    if lobby_id not in rooms.rooms:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if owner of room doing this
    decoded = verifySecurityUser(req)
    if decoded['username'] == rooms.rooms[lobby_id].owner:
        addr = rooms.rooms[lobby_id].address
        del rooms.rooms[lobby_id]
        rooms.usage[addr] -= 1
        return {"message": "Lobby deleted successfully"}
    else:
        raise HTTPException(status_code=403, detail="Action forbidden")
